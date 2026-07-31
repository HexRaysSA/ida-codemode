import atexit
import json
import logging
import math
import os
import threading
import time
import uuid
from collections.abc import Callable
from io import BufferedIOBase
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs

from .http import HOST, HTTPResponse, LocalHTTPServer, json_response
from .registry import InstanceIdentity, InstanceRegistration, RegistryEntry
from .runtime import AnalysisState, APIError

logger = logging.getLogger(__name__)
DEFAULT_LEASE_GRACE_SECONDS = 20.0
DEFAULT_SSE_HEARTBEAT_SECONDS = 5.0


class CodeModeBackend(Protocol):
    def execute_python(self, code: str, timeout: float | None) -> Any: ...

    def wait_autoanalysis(self, timeout: float | None) -> dict[str, Any]: ...

    def save_database(self) -> dict[str, Any]: ...


class CodeModeHTTPServer:
    """Authenticated local Code Mode API, registration, and client leases."""

    def __init__(
        self,
        backend: CodeModeBackend,
        identity: InstanceIdentity,
        analysis_state: AnalysisState,
        registry_dir: str | os.PathLike[str],
        *,
        token: str | None = None,
        record_suffix: str | None = None,
        lease_grace: float = DEFAULT_LEASE_GRACE_SECONDS,
        heartbeat_interval: float = DEFAULT_SSE_HEARTBEAT_SECONDS,
        on_shutdown: Callable[[], None] | None = None,
    ) -> None:
        self.backend = backend
        self.identity = identity
        self.analysis_state = analysis_state
        self.registry_dir = Path(registry_dir)
        if lease_grace < 0:
            raise ValueError("lease_grace must not be negative")
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")
        self.token = token or str(uuid.uuid4())
        self.record_suffix = record_suffix
        self.lease_grace = lease_grace
        self.heartbeat_interval = heartbeat_interval
        self.on_shutdown = on_shutdown

        self._lock = threading.Lock()
        self._activity = threading.Condition()
        self._httpd: LocalHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._watchdog: threading.Thread | None = None
        self._registration: InstanceRegistration | None = None
        self._entry: RegistryEntry | None = None
        self._atexit_registered = False
        self._draining = False
        self._active_leases = 0
        self._active_requests = 0
        self._zero_since = time.monotonic()
        self._stream_stop = threading.Event()

    @property
    def port(self) -> int | None:
        return self._httpd.port if self._httpd is not None else None

    @property
    def url(self) -> str | None:
        return f"http://{HOST}:{self.port}" if self.port is not None else None

    @property
    def entry(self) -> RegistryEntry | None:
        return self._entry

    def start(self) -> None:
        with self._lock:
            if self._httpd is not None:
                return
            self._draining = False
            self._stream_stop.clear()
            registration = InstanceRegistration(
                self.registry_dir,
                self.identity,
                token=self.token,
                record_suffix=self.record_suffix,
            )
            httpd = LocalHTTPServer(self.token, self._dispatch)
            serving = threading.Event()
            thread = threading.Thread(
                target=self._serve,
                args=(httpd, serving),
                name="ida-codemode-http",
                daemon=True,
            )
            self._registration = registration
            self._httpd = httpd
            self._thread = thread

        try:
            thread.start()
            if not serving.wait(timeout=2.0) or not thread.is_alive():
                raise RuntimeError("HTTP server thread did not start")
            self._entry = registration.publish(httpd.port)
            if not self._atexit_registered:
                atexit.register(self._withdraw_registration)
                self._atexit_registered = True
            if self.identity.managed:
                watchdog = threading.Thread(
                    target=self._watch_leases,
                    name="ida-codemode-leases",
                    daemon=True,
                )
                self._watchdog = watchdog
                watchdog.start()
        except Exception:
            self.stop()
            raise

    @staticmethod
    def _serve(httpd: LocalHTTPServer, serving: threading.Event) -> None:
        serving.set()
        try:
            httpd.serve_forever(poll_interval=0.1)
        except Exception:
            logger.exception("Code Mode HTTP server stopped unexpectedly")

    def _withdraw_registration(self) -> None:
        registration = self._registration
        if registration is not None:
            registration.withdraw()

    def release_registration(self) -> None:
        """Release the lifetime lock after the owning IDB has been closed."""

        registration = self._registration
        self._registration = None
        self._entry = None
        if registration is not None:
            registration.release()
        if self._atexit_registered:
            atexit.unregister(self._withdraw_registration)
            self._atexit_registered = False

    def stop(self) -> None:
        # Withdrawal precedes listener shutdown; the lifetime lock remains held
        # until release_registration() is called after the database closes.
        self._withdraw_registration()
        self._stream_stop.set()
        with self._activity:
            self._draining = True
            self._activity.notify_all()
        with self._lock:
            httpd = self._httpd
            thread = self._thread
            watchdog = self._watchdog
            self._httpd = None
            self._thread = None
            self._watchdog = None

        if httpd is not None:
            # BaseServer.shutdown() deadlocks if serve_forever() never started.
            if thread is not None and thread.is_alive():
                httpd.shutdown()
                if thread is not threading.current_thread():
                    thread.join(timeout=5.0)
            httpd.server_close()
        if (
            watchdog is not None
            and watchdog.is_alive()
            and watchdog is not threading.current_thread()
        ):
            watchdog.join(timeout=2.0)

    def _watch_leases(self) -> None:
        while not self._stream_stop.is_set():
            with self._activity:
                while not self._draining:
                    now = time.monotonic()
                    eligible = (
                        self._active_leases == 0
                        and self._active_requests == 0
                        and self._zero_since is not None
                    )
                    if eligible:
                        remaining = self.lease_grace - (now - self._zero_since)
                        if remaining <= 0:
                            self._draining = True
                            break
                        self._activity.wait(timeout=min(remaining, 1.0))
                    else:
                        self._activity.wait(timeout=1.0)
                    if self._stream_stop.is_set():
                        return
                if not self._draining or self._stream_stop.is_set():
                    return

            # No lease or operation can enter after _draining is set. Publish
            # disappearance before stopping the listener.
            self._withdraw_registration()
            self.stop()
            if self.on_shutdown is not None:
                try:
                    self.on_shutdown()
                except Exception:
                    logger.exception("Code Mode shutdown callback failed")
            return

    def _lease_opened(self) -> bool:
        with self._activity:
            if self._draining:
                return False
            self._active_leases += 1
            self._zero_since = None
            self._activity.notify_all()
            return True

    def _lease_closed(self) -> None:
        with self._activity:
            if self._active_leases > 0:
                self._active_leases -= 1
            if self._active_leases == 0:
                self._zero_since = time.monotonic()
            self._activity.notify_all()

    def _request_started(self) -> bool:
        with self._activity:
            if self._draining:
                return False
            self._active_requests += 1
            return True

    def _request_finished(self) -> None:
        with self._activity:
            if self._active_requests > 0:
                self._active_requests -= 1
            if self._active_leases == 0 and self._active_requests == 0:
                self._zero_since = time.monotonic()
            self._activity.notify_all()

    def _health_payload(self) -> dict[str, Any]:
        entry = self._entry
        if entry is None:
            raise APIError(
                "instance_starting",
                "The instance has not finished registration",
                status=503,
            )
        return {"status": "ok", **entry.health_identity()}

    def _lease_response(self) -> HTTPResponse:
        if not self._lease_opened():
            return self._failure(
                APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            )
        try:
            payload = json.dumps(self._health_payload(), separators=(",", ":"))
        except Exception:
            self._lease_closed()
            raise

        def stream(file: BufferedIOBase) -> None:
            file.write(f"event: health\ndata: {payload}\n\n".encode())
            file.flush()
            while not self._stream_stop.wait(self.heartbeat_interval):
                file.write(b": keepalive\n\n")
                file.flush()

        return HTTPResponse(
            status=200,
            content_type="text/event-stream",
            stream=stream,
            after_send=self._lease_closed,
        )

    @staticmethod
    def _decode_object(body: bytes | None) -> dict[str, Any]:
        if not body:
            return {}
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise APIError("invalid_json", "Request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise APIError("invalid_request", "Request body must be a JSON object")
        return payload

    @staticmethod
    def _timeout(payload: dict[str, Any]) -> float | None:
        timeout = payload.get("timeout")
        if timeout is None:
            return None
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise APIError("invalid_timeout", "timeout must be a positive number")
        timeout = float(timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise APIError(
                "invalid_timeout", "timeout must be a positive finite number"
            )
        return timeout

    @staticmethod
    def _success(result: Any) -> HTTPResponse:
        return json_response(200, {"ok": True, "result": result})

    @staticmethod
    def _failure(error: APIError) -> HTTPResponse:
        payload: dict[str, Any] = {
            "ok": False,
            "error": {
                "code": error.code,
                "message": str(error),
            },
        }
        payload["error"].update(error.details)
        return json_response(error.status, payload)

    def _dispatch(
        self,
        method: str,
        path: str,
        query: str,
        body: bytes | None,
    ) -> HTTPResponse:
        try:
            if method == "GET" and path == "/health":
                parameters = parse_qs(query, keep_blank_values=True)
                if parameters.get("sse") == ["1"]:
                    return self._lease_response()
                return json_response(200, self._health_payload())

            if not self._request_started():
                raise APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            try:
                if method == "GET" and path == "/poll_autoanalysis":
                    return json_response(200, self.analysis_state.snapshot())
                if method == "GET" and path == "/wait_autoanalysis":
                    return json_response(200, self.backend.wait_autoanalysis(None))
                if method == "POST" and path == "/wait_autoanalysis":
                    payload = self._decode_object(body)
                    return json_response(
                        200,
                        self.backend.wait_autoanalysis(self._timeout(payload)),
                    )
                if method == "POST" and path == "/execute_python":
                    payload = self._decode_object(body)
                    code = payload.get("code")
                    if not isinstance(code, str) or not code.strip():
                        raise APIError(
                            "invalid_code", "code must be a non-empty string"
                        )
                    return self._success(
                        self.backend.execute_python(code, self._timeout(payload))
                    )
                if method == "POST" and path == "/save_database":
                    self._decode_object(body)
                    return self._success(self.backend.save_database())
                return json_response(404, {"ok": False, "error": "Not Found"})
            finally:
                self._request_finished()
        except APIError as exc:
            return self._failure(exc)
        except Exception as exc:
            logger.exception("Unhandled Code Mode API failure")
            return self._failure(
                APIError("internal_error", str(exc) or type(exc).__name__, status=500)
            )
