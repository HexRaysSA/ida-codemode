import http.client
import json
import math
import socket
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from .registry import HOST, REGISTRY_DIR, SPAWN_DIR, RegistryEntry
from .resolver import resolve_instance


class ClientError(RuntimeError):
    pass


class InstanceDisconnectedError(ClientError):
    pass


# The server reaps an idle HTTP/1.1 connection after 30 seconds. Reconnect
# proactively with headroom rather than discovering the close during a POST,
# which cannot safely be retried after its execution status becomes ambiguous.
RPC_CONNECTION_MAX_IDLE_SECONDS = 20.0
MAX_KEEPALIVE_SECONDS = 3600.0


class RemoteError(ClientError):
    def __init__(
        self,
        code: str,
        message: str,
        status: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}


class DatabaseHandle:
    """A shared Code Mode instance plus one lifetime SSE client lease."""

    def __init__(
        self,
        path: str,
        entry: RegistryEntry,
        *,
        keepalive: float = 0.0,
        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,
    ) -> None:
        if not math.isfinite(keepalive) or not 0 <= keepalive <= MAX_KEEPALIVE_SECONDS:
            raise ValueError(
                f"keepalive must be between 0 and {MAX_KEEPALIVE_SECONDS:g} seconds"
            )
        self.path = path
        self.keepalive = float(keepalive)
        self._lease_id = uuid.uuid4().hex
        self._on_disconnect = on_disconnect
        self._lock = threading.Lock()
        self._request_lock = threading.Lock()
        self._closed = threading.Event()
        self._disconnected = threading.Event()
        self._disconnect_reason: str | None = None
        self._entry = entry
        self._rpc_connection: http.client.HTTPConnection | None = None
        self._rpc_last_used: float | None = None
        self._active_operation_id: str | None = None
        self._lease_connection: http.client.HTTPConnection | None = None
        self._lease_response: http.client.HTTPResponse | None = None
        self._lease_socket: socket.socket | None = None
        self._lease_thread: threading.Thread | None = None
        self._install_lease(entry)
        thread = threading.Thread(
            target=self._monitor_lease,
            name=f"ida-codemode-lease-{entry.pid}",
            daemon=True,
        )
        self._lease_thread = thread
        thread.start()

    @classmethod
    def open(
        cls,
        path: str,
        *,
        spawn: bool = True,
        timeout: float = 120.0,
        registry_dir: str | Path = REGISTRY_DIR,
        spawn_dir: str | Path = SPAWN_DIR,
        output_database: str | Path | None = None,
        auto_analysis: bool = False,
        image_base: int | None = None,
        new_database: bool = False,
        compiler: str | None = None,
        first_pass_directives: Sequence[str] = (),
        second_pass_directives: Sequence[str] = (),
        disable_fpp: bool = False,
        entry_point: int | None = None,
        jit_debugger: bool | None = None,
        log_file: str | Path | None = None,
        disable_mouse: bool = False,
        plugin_options: str | None = None,
        processor: str | None = None,
        db_compression: str | None = None,
        run_debugger: str | None = None,
        load_resources: bool = False,
        script_file: str | Path | None = None,
        script_args: Sequence[str] = (),
        file_type: str | None = None,
        file_member: str | None = None,
        empty_database: bool = False,
        windows_dir: str | Path | None = None,
        no_segmentation: bool = False,
        debug_flags: int | Sequence[str] = 0,
        keepalive: float = 0.0,
        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,
    ) -> Self:
        """Attach to a shared instance, spawning a configured worker if needed.

        IDA command options are spawn-only: they configure a newly imported
        idalib database and cannot reconfigure a reused GUI or worker. ``image_base``
        is a byte address and must be 16-byte aligned; the worker converts it to
        IDA's paragraph-based ``-b`` value.
        """

        def resolve() -> RegistryEntry:
            return resolve_instance(
                path,
                spawn=spawn,
                timeout=timeout,
                registry_dir=registry_dir,
                spawn_dir=spawn_dir,
                output_database=output_database,
                auto_analysis=auto_analysis,
                image_base=image_base,
                new_database=new_database,
                compiler=compiler,
                first_pass_directives=first_pass_directives,
                second_pass_directives=second_pass_directives,
                disable_fpp=disable_fpp,
                entry_point=entry_point,
                jit_debugger=jit_debugger,
                log_file=log_file,
                disable_mouse=disable_mouse,
                plugin_options=plugin_options,
                processor=processor,
                db_compression=db_compression,
                run_debugger=run_debugger,
                load_resources=load_resources,
                script_file=script_file,
                script_args=script_args,
                file_type=file_type,
                file_member=file_member,
                empty_database=empty_database,
                windows_dir=windows_dir,
                no_segmentation=no_segmentation,
                debug_flags=debug_flags,
            )

        entry = resolve()
        try:
            return cls(
                path,
                entry,
                keepalive=keepalive,
                on_disconnect=on_disconnect,
            )
        except ClientError:
            # The worker may cross its zero-lease shutdown boundary between
            # resolve and the SSE handshake. Resolve once more as promised by
            # the instance lifecycle contract.
            time.sleep(0.05)
            replacement = resolve()
            return cls(
                path,
                replacement,
                keepalive=keepalive,
                on_disconnect=on_disconnect,
            )

    @property
    def entry(self) -> RegistryEntry:
        with self._lock:
            return self._entry

    @property
    def connected(self) -> bool:
        return not self._closed.is_set() and not self._disconnected.is_set()

    @property
    def disconnect_reason(self) -> str | None:
        return self._disconnect_reason

    def set_disconnect_callback(
        self,
        callback: Callable[["DatabaseHandle", str], None],
    ) -> None:
        self._on_disconnect = callback
        if self._disconnected.is_set():
            callback(self, self._disconnect_reason or "database connection closed")

    def _open_lease(
        self, entry: RegistryEntry
    ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse, socket.socket]:
        connection = http.client.HTTPConnection(HOST, entry.port, timeout=10.0)
        try:
            connection.request(
                "GET",
                f"/health?sse=1&lease_id={self._lease_id}&keepalive={self.keepalive:g}",
                headers={
                    "Accept": "text/event-stream",
                    "Authorization": f"Bearer {entry.token}",
                },
            )
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            connection.close()
            raise ClientError(f"failed to establish instance lease: {exc}") from exc
        if response.status != 200:
            body = response.read(4096).decode("utf-8", errors="replace")
            connection.close()
            raise ClientError(
                f"failed to establish instance lease: HTTP {response.status}: {body}"
            )
        # The 10-second timeout bounds only the handshake. A lease is an
        # indefinite SSE stream; leaving that timeout on the socket can falsely
        # disconnect healthy instances if a heartbeat is delayed by scheduling
        # or system sleep.
        lease_socket = connection.sock
        if lease_socket is None and response.fp is not None:
            raw = getattr(response.fp, "raw", None)
            lease_socket = getattr(raw, "_sock", None)
        if lease_socket is None:
            response.close()
            connection.close()
            raise ClientError("failed to establish instance lease: socket unavailable")
        lease_socket.settimeout(None)
        return connection, response, lease_socket

    def _install_lease(self, entry: RegistryEntry) -> None:
        connection, response, lease_socket = self._open_lease(entry)
        with self._lock:
            if self._closed.is_set():
                response.close()
                connection.close()
                raise ClientError("database handle is closed")
            old_response = self._lease_response
            old_connection = self._lease_connection
            old_socket = self._lease_socket
            self._entry = entry
            self._lease_connection = connection
            self._lease_response = response
            self._lease_socket = lease_socket
        if old_socket is not None:
            try:
                old_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if old_response is not None:
            old_response.close()
        if old_connection is not None:
            old_connection.close()

    def _monitor_lease(self) -> None:
        with self._lock:
            response = self._lease_response
        reason = "database connection closed"
        try:
            if response is not None:
                while not self._closed.is_set() and response.readline():
                    pass
        except (OSError, ValueError, http.client.HTTPException) as exc:
            reason = f"database connection failed: {exc}"
        if self._closed.is_set():
            return
        self._mark_disconnected(reason)

    def _mark_disconnected(self, reason: str) -> None:
        if self._closed.is_set() or self._disconnected.is_set():
            return
        self._disconnect_reason = reason
        self._disconnected.set()
        with self._lock:
            response = self._lease_response
            connection = self._lease_connection
            rpc_connection = self._rpc_connection
            self._lease_response = None
            self._lease_connection = None
            self._lease_socket = None
            self._rpc_connection = None
            self._rpc_last_used = None
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        if rpc_connection is not None:
            rpc_connection.close()
        if self._on_disconnect is not None:
            self._on_disconnect(self, reason)

    def _rpc_connection_for(
        self,
        entry: RegistryEntry,
        timeout: float | None,
    ) -> http.client.HTTPConnection:
        now = time.monotonic()
        stale: http.client.HTTPConnection | None = None
        with self._lock:
            if self._closed.is_set():
                raise ClientError("database handle is closed")
            connection = self._rpc_connection
            if connection is not None and (
                connection.port != entry.port
                or (
                    self._rpc_last_used is not None
                    and now - self._rpc_last_used >= RPC_CONNECTION_MAX_IDLE_SECONDS
                )
            ):
                stale = connection
                connection = None
                self._rpc_connection = None
                self._rpc_last_used = None
            if connection is None:
                connection = http.client.HTTPConnection(
                    HOST,
                    entry.port,
                    timeout=timeout,
                )
                self._rpc_connection = connection
            connection.timeout = timeout
            sock = connection.sock
        if stale is not None:
            stale.close()
        if sock is not None:
            sock.settimeout(timeout)
        return connection

    def _discard_rpc_connection(
        self,
        connection: http.client.HTTPConnection,
    ) -> None:
        with self._lock:
            if self._rpc_connection is connection:
                self._rpc_connection = None
                self._rpc_last_used = None
        connection.close()

    def _request(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        unwrap_result: bool = True,
        operation_id: str | None = None,
    ) -> Any:
        request_payload = {**payload, "lease_id": self._lease_id}
        if operation_id is not None:
            request_payload["operation_id"] = operation_id
        body = json.dumps(request_payload).encode("utf-8")
        with self._request_lock:
            if self._closed.is_set():
                raise ClientError("database handle is closed")
            if self._disconnected.is_set():
                raise InstanceDisconnectedError(
                    self._disconnect_reason or "database instance disconnected"
                )
            entry = self.entry
            connection = self._rpc_connection_for(entry, timeout)
            if operation_id is not None:
                with self._lock:
                    self._active_operation_id = operation_id
            try:
                connection.request(
                    "POST",
                    endpoint,
                    body=body,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {entry.token}",
                    },
                )
                response = connection.getresponse()
                try:
                    status = response.status
                    response_body = response.read()
                finally:
                    response.close()
            except (TimeoutError, OSError, http.client.HTTPException) as exc:
                # Do not retry a POST: the server may have executed it before
                # the connection failed. The next operation gets a fresh socket.
                self._discard_rpc_connection(connection)
                raise ClientError(f"Code Mode request failed: {exc}") from exc
            finally:
                if operation_id is not None:
                    with self._lock:
                        if self._active_operation_id == operation_id:
                            self._active_operation_id = None
            with self._lock:
                if self._rpc_connection is connection:
                    self._rpc_last_used = time.monotonic()

        try:
            response_payload = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if status != 200:
                raise ClientError(
                    f"Code Mode request failed with HTTP {status}"
                ) from exc
            raise ClientError("Code Mode response was not valid JSON") from exc
        if not isinstance(response_payload, dict):
            raise ClientError("Code Mode response was not a JSON object")
        if status != 200 or (unwrap_result and not response_payload.get("ok")):
            error = response_payload.get("error")
            if isinstance(error, dict):
                details = {
                    str(key): value
                    for key, value in error.items()
                    if key not in {"code", "message"}
                }
                raise RemoteError(
                    str(error.get("code", "remote_error")),
                    str(error.get("message", "Code Mode request failed")),
                    status,
                    details,
                )
            raise ClientError(f"Code Mode request failed with HTTP {status}")
        return response_payload.get("result") if unwrap_result else response_payload

    def execute_python(
        self,
        code: str,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
        persist_globals: bool = False,
    ) -> Any:
        """Execute Python; stateless execution resets this handle's namespace."""

        payload: dict[str, Any] = {
            "code": code,
            "persist_globals": persist_globals,
        }
        if timeout is not None:
            payload["timeout"] = timeout
        # Leave enough HTTP time for the server to return its structured
        # operation-timeout response.
        http_timeout = None if timeout is None else timeout + 5.0
        return self._request(
            "/execute_python",
            payload,
            timeout=http_timeout,
            operation_id=operation_id or uuid.uuid4().hex,
        )

    def wait_autoanalysis(
        self,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Wait for initial autoanalysis through the public Code Mode route."""
        payload: dict[str, Any] = {}
        if timeout is not None:
            payload["timeout"] = timeout
        http_timeout = None if timeout is None else timeout + 5.0
        result = self._request(
            "/wait_autoanalysis",
            payload,
            timeout=http_timeout,
            unwrap_result=False,
            operation_id=operation_id or uuid.uuid4().hex,
        )
        if not isinstance(result, dict) or not isinstance(result.get("complete"), bool):
            raise ClientError("wait_autoanalysis returned an invalid result")
        return result

    def cancel_operation(self, operation_id: str) -> bool:
        """Cancel one identified in-flight operation over a control connection."""
        with self._lock:
            if self._active_operation_id != operation_id:
                return False
            entry = self._entry

        connection = http.client.HTTPConnection(HOST, entry.port, timeout=2.0)
        try:
            body = json.dumps(
                {
                    "lease_id": self._lease_id,
                    "operation_id": operation_id,
                }
            ).encode("utf-8")
            connection.request(
                "POST",
                "/cancel_operation",
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {entry.token}",
                },
            )
            response = connection.getresponse()
            try:
                payload = json.loads(response.read())
                return bool(
                    response.status == 200
                    and isinstance(payload, dict)
                    and isinstance(payload.get("result"), dict)
                    and payload["result"].get("cancelled") is True
                )
            finally:
                response.close()
        except (
            TimeoutError,
            OSError,
            http.client.HTTPException,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return False
        finally:
            connection.close()

    def cancel_active(self, timeout: float = 2.0) -> bool:
        """Cancel this handle's in-flight operation over a control connection."""
        deadline = time.monotonic() + timeout
        with self._lock:
            operation_id = self._active_operation_id
        if operation_id is None:
            return False

        while True:
            if self.cancel_operation(operation_id):
                return True
            with self._lock:
                if self._active_operation_id != operation_id:
                    return False
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def save_database(self) -> dict[str, Any]:
        result = self._request("/save_database", {}, timeout=305.0)
        if not isinstance(result, dict):
            raise ClientError("save_database returned an invalid result")
        return result

    def _release_remote_lease(self) -> None:
        """Best-effort lease release over a connection independent of RPC work."""

        entry = self.entry
        connection = http.client.HTTPConnection(HOST, entry.port, timeout=2.0)
        try:
            body = json.dumps({"lease_id": self._lease_id}).encode("utf-8")
            connection.request(
                "POST",
                "/release_lease",
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {entry.token}",
                },
            )
            response = connection.getresponse()
            try:
                response.read()
            finally:
                response.close()
        except (TimeoutError, OSError, http.client.HTTPException):
            # Closing the SSE socket below remains the authoritative fallback.
            pass
        finally:
            connection.close()

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._release_remote_lease()
        with self._lock:
            response = self._lease_response
            connection = self._lease_connection
            lease_socket = self._lease_socket
            rpc_connection = self._rpc_connection
            thread = self._lease_thread
            self._lease_response = None
            self._lease_connection = None
            self._lease_socket = None
            self._rpc_connection = None
            self._rpc_last_used = None
        if lease_socket is not None:
            try:
                lease_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        # On Windows, shutdown() does not wake a BufferedReader blocked in
        # readline() when HTTPResponse owns the socket through SocketIO. Close
        # that raw stream directly; HTTPResponse.close() would instead wait for
        # the BufferedReader lock until the next SSE heartbeat.
        raw_stream = None
        if response is not None and response.fp is not None:
            raw_stream = getattr(response.fp, "raw", None)
        if raw_stream is not None:
            try:
                raw_stream.close()
            except OSError:
                pass
        if rpc_connection is not None:
            rpc_connection.close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        if response is not None:
            try:
                response.close()
            except (OSError, ValueError):
                # The raw stream was intentionally closed above to wake the
                # monitor; HTTPResponse.flush() may observe that closed stream.
                pass
        if connection is not None:
            connection.close()

    disconnect = close

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
