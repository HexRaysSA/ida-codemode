import http.client
import json
import socket
import threading
import time
from collections.abc import Callable
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
        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,
    ) -> None:
        self.path = path
        self._on_disconnect = on_disconnect
        self._lock = threading.Lock()
        self._request_lock = threading.Lock()
        self._closed = threading.Event()
        self._disconnected = threading.Event()
        self._disconnect_reason: str | None = None
        self._entry = entry
        self._rpc_connection: http.client.HTTPConnection | None = None
        self._rpc_last_used: float | None = None
        self._lease_connection: http.client.HTTPConnection | None = None
        self._lease_response: http.client.HTTPResponse | None = None
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
        on_disconnect: Callable[["DatabaseHandle", str], None] | None = None,
    ) -> "DatabaseHandle":
        entry = resolve_instance(
            path,
            spawn=spawn,
            timeout=timeout,
            registry_dir=registry_dir,
            spawn_dir=spawn_dir,
        )
        try:
            return cls(path, entry, on_disconnect=on_disconnect)
        except ClientError:
            # The worker may cross its zero-lease shutdown boundary between
            # resolve and the SSE handshake. Resolve once more as promised by
            # the instance lifecycle contract.
            time.sleep(0.05)
            replacement = resolve_instance(
                path,
                spawn=spawn,
                timeout=timeout,
                registry_dir=registry_dir,
                spawn_dir=spawn_dir,
            )
            return cls(path, replacement, on_disconnect=on_disconnect)

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
    ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
        connection = http.client.HTTPConnection(HOST, entry.port, timeout=10.0)
        try:
            connection.request(
                "GET",
                "/health?sse=1",
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
        return connection, response

    def _install_lease(self, entry: RegistryEntry) -> None:
        connection, response = self._open_lease(entry)
        with self._lock:
            if self._closed.is_set():
                response.close()
                connection.close()
                raise ClientError("database handle is closed")
            old_response = self._lease_response
            old_connection = self._lease_connection
            self._entry = entry
            self._lease_connection = connection
            self._lease_response = response
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
    ) -> Any:
        body = json.dumps(payload).encode("utf-8")
        with self._request_lock:
            if self._closed.is_set():
                raise ClientError("database handle is closed")
            if self._disconnected.is_set():
                raise InstanceDisconnectedError(
                    self._disconnect_reason or "database instance disconnected"
                )
            entry = self.entry
            connection = self._rpc_connection_for(entry, timeout)
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
        if status != 200 or not response_payload.get("ok"):
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
        return response_payload.get("result")

    def execute_python(self, code: str, timeout: float | None = None) -> Any:
        payload: dict[str, Any] = {"code": code}
        if timeout is not None:
            payload["timeout"] = timeout
        # Leave enough HTTP time for the server to return its structured
        # operation-timeout response.
        http_timeout = None if timeout is None else timeout + 5.0
        return self._request("/execute_python", payload, timeout=http_timeout)

    def save_database(self) -> dict[str, Any]:
        result = self._request("/save_database", {}, timeout=305.0)
        if not isinstance(result, dict):
            raise ClientError("save_database returned an invalid result")
        return result

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        with self._lock:
            response = self._lease_response
            connection = self._lease_connection
            rpc_connection = self._rpc_connection
            thread = self._lease_thread
            self._lease_response = None
            self._lease_connection = None
            self._rpc_connection = None
            self._rpc_last_used = None
        if connection is not None and connection.sock is not None:
            try:
                connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        if rpc_connection is not None:
            rpc_connection.close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

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
