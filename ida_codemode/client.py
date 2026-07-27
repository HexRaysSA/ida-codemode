from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from types import TracebackType
from typing import Any, Self
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .registry import HOST, RegistryEntry
from .resolver import ResolveError, resolve_instance


class ClientError(RuntimeError):
    pass


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
        resolve_timeout: float = 120.0,
    ) -> None:
        self.path = path
        self.resolve_timeout = resolve_timeout
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._entry = entry
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
    ) -> DatabaseHandle:
        entry = resolve_instance(path, spawn=spawn, timeout=timeout)
        try:
            return cls(path, entry, resolve_timeout=timeout)
        except ClientError:
            # The worker may cross its zero-lease shutdown boundary between
            # resolve and the SSE handshake. Resolve once more as promised by
            # the instance lifecycle contract.
            time.sleep(0.05)
            replacement = resolve_instance(path, spawn=spawn, timeout=timeout)
            return cls(path, replacement, resolve_timeout=timeout)

    @property
    def entry(self) -> RegistryEntry:
        with self._lock:
            return self._entry

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
        while not self._closed.is_set():
            with self._lock:
                response = self._lease_response
            try:
                if response is not None:
                    while not self._closed.is_set() and response.readline():
                        pass
            except (OSError, ValueError, http.client.HTTPException):
                pass
            if self._closed.is_set():
                return

            # The grace period on managed workers leaves time to reconnect a
            # transiently interrupted lease. If the instance exited, resolve()
            # finds or spawns its replacement.
            while not self._closed.wait(0.5):
                try:
                    entry = resolve_instance(self.path, timeout=self.resolve_timeout)
                    self._install_lease(entry)
                    break
                except (ClientError, ResolveError, OSError, ValueError):
                    continue

    def _request(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> Any:
        if self._closed.is_set():
            raise ClientError("database handle is closed")
        entry = self.entry
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"http://{HOST}:{entry.port}{endpoint}",
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {entry.token}",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                response_payload = json.loads(response.read())
                status = response.status
        except HTTPError as exc:
            status = exc.code
            try:
                response_payload = json.loads(exc.read())
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ClientError(
                    f"Code Mode request failed with HTTP {status}"
                ) from exc
        except (TimeoutError, URLError, OSError) as exc:
            raise ClientError(f"Code Mode request failed: {exc}") from exc
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
            thread = self._lease_thread
            self._lease_response = None
            self._lease_connection = None
        if connection is not None and connection.sock is not None:
            try:
                connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
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
