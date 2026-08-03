import json
import logging
import math
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
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
MAX_KEEPALIVE_SECONDS = 3600.0


@dataclass
class _Lease:
    keepalive: float
    stop: threading.Event


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
        if not math.isfinite(lease_grace) or lease_grace < 0:
            raise ValueError("lease_grace must be a finite non-negative number")
        if not math.isfinite(heartbeat_interval) or heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be a positive finite number")
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
        self._draining = False
        self._active_leases = 0
        self._active_requests = 0
        self._leases: dict[str, _Lease] = {}
        self._shutdown_at: float | None = time.monotonic() + self.lease_grace
        self._backend_lock = threading.Lock()
        self._running_lease_id: str | None = None
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
            self._shutdown_at = time.monotonic() + self.lease_grace
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

    def release_registration(self) -> None:
        """Withdraw ownership after the owning IDB has detached or closed."""

        registration = self._registration
        self._registration = None
        self._entry = None
        if registration is not None:
            registration.release()

    def stop(self) -> None:
        # Keep the registry record and lifetime lock together until the owning
        # IDB has detached or closed. While the listener is stopped, discovery
        # classifies this record as BLOCKED instead of spawning over it.
        self._stream_stop.set()
        with self._activity:
            self._draining = True
            for lease in self._leases.values():
                lease.stop.set()
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
                    shutdown_at = self._shutdown_at
                    eligible = (
                        self._active_leases == 0
                        and self._active_requests == 0
                        and shutdown_at is not None
                    )
                    if eligible and shutdown_at is not None:
                        remaining = shutdown_at - now
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

            # No lease or operation can enter after _draining is set. Keep the
            # ownership record published while the worker saves and closes.
            self.stop()
            if self.on_shutdown is not None:
                try:
                    self.on_shutdown()
                except Exception:
                    logger.exception("Code Mode shutdown callback failed")
            return

    def _lease_opened(self, lease_id: str, keepalive: float) -> _Lease | None:
        with self._activity:
            if self._draining or lease_id in self._leases:
                return None
            lease = _Lease(keepalive=keepalive, stop=threading.Event())
            self._leases[lease_id] = lease
            self._active_leases = len(self._leases)
            self._shutdown_at = None
            self._activity.notify_all()
            return lease

    def _lease_closed(self, lease_id: str) -> None:
        cancel_active = False
        with self._activity:
            lease = self._leases.pop(lease_id, None)
            if lease is None:
                return
            lease.stop.set()
            self._active_leases = len(self._leases)
            if self._running_lease_id == lease_id:
                cancel_active = True
            if self._active_leases == 0:
                self._shutdown_at = time.monotonic() + lease.keepalive
            self._activity.notify_all()
        if cancel_active:
            cancel = getattr(self.backend, "cancel_active", None)
            if cancel is not None:
                try:
                    cancel()
                except Exception:
                    logger.exception("Code Mode operation cancellation failed")

    def _request_started(self, lease_id: str | None) -> None:
        with self._activity:
            if self._draining:
                raise APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            if lease_id is not None and lease_id not in self._leases:
                raise APIError(
                    "lease_released", "The client lease is no longer active", status=409
                )
            self._active_requests += 1

    def _request_finished(self) -> None:
        with self._activity:
            if self._active_requests > 0:
                self._active_requests -= 1
            self._activity.notify_all()

    def _run_operation(self, lease_id: str | None, operation: Callable[[], Any]) -> Any:
        with self._backend_lock:
            with self._activity:
                if lease_id is not None and lease_id not in self._leases:
                    raise APIError(
                        "lease_released",
                        "The client lease is no longer active",
                        status=409,
                    )
                self._running_lease_id = lease_id
            try:
                return operation()
            finally:
                with self._activity:
                    if self._running_lease_id == lease_id:
                        self._running_lease_id = None
                    self._activity.notify_all()

    def _health_payload(self) -> dict[str, Any]:
        with self._activity:
            if self._draining:
                raise APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            entry = self._entry
        if entry is None:
            raise APIError(
                "instance_starting",
                "The instance has not finished registration",
                status=503,
            )
        return {"status": "ok", **entry.health_identity()}

    @staticmethod
    def _lease_parameters(parameters: dict[str, list[str]]) -> tuple[str, float]:
        values = parameters.get("lease_id")
        lease_id = values[0] if values and len(values) == 1 else uuid.uuid4().hex
        if not lease_id or len(lease_id) > 128:
            raise APIError("invalid_lease", "lease_id must be 1 to 128 characters")
        keepalive_values = parameters.get("keepalive")
        raw_keepalive = keepalive_values[0] if keepalive_values else "0"
        try:
            keepalive = float(raw_keepalive)
        except (TypeError, ValueError) as exc:
            raise APIError(
                "invalid_keepalive", "keepalive must be a non-negative number"
            ) from exc
        if (
            not math.isfinite(keepalive)
            or keepalive < 0
            or keepalive > MAX_KEEPALIVE_SECONDS
        ):
            raise APIError(
                "invalid_keepalive",
                f"keepalive must be between 0 and {MAX_KEEPALIVE_SECONDS:g} seconds",
            )
        return lease_id, keepalive

    def _lease_response(self, parameters: dict[str, list[str]]) -> HTTPResponse:
        lease_id, keepalive = self._lease_parameters(parameters)
        lease = self._lease_opened(lease_id, keepalive)
        if lease is None:
            return self._failure(
                APIError(
                    "instance_draining", "The instance is shutting down", status=503
                )
            )
        try:
            payload = json.dumps(self._health_payload(), separators=(",", ":"))
        except Exception:
            self._lease_closed(lease_id)
            raise

        def stream(file: BufferedIOBase) -> None:
            file.write(f"event: health\ndata: {payload}\n\n".encode())
            file.flush()
            while not lease.stop.wait(self.heartbeat_interval):
                if self._stream_stop.is_set():
                    return
                file.write(b": keepalive\n\n")
                file.flush()

        return HTTPResponse(
            status=200,
            content_type="text/event-stream",
            stream=stream,
            after_send=lambda: self._lease_closed(lease_id),
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
    def _payload_lease_id(payload: dict[str, Any]) -> str | None:
        lease_id = payload.get("lease_id")
        if lease_id is None:
            return None
        if not isinstance(lease_id, str) or not lease_id or len(lease_id) > 128:
            raise APIError("invalid_lease", "lease_id must be 1 to 128 characters")
        return lease_id

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
                    return self._lease_response(parameters)
                return json_response(200, self._health_payload())

            if method == "POST" and path == "/release_lease":
                payload = self._decode_object(body)
                lease_id = self._payload_lease_id(payload)
                if lease_id is None:
                    raise APIError("invalid_lease", "lease_id is required")
                release_id: str = lease_id

                def release() -> None:
                    self._lease_closed(release_id)

                return json_response(
                    200,
                    {"ok": True, "result": {"released": True}},
                    after_send=release,
                )

            payload = (
                self._decode_object(body)
                if method == "POST"
                and path in {"/wait_autoanalysis", "/execute_python", "/save_database"}
                else {}
            )
            lease_id = self._payload_lease_id(payload)
            self._request_started(lease_id)
            try:
                if method == "GET" and path == "/poll_autoanalysis":
                    return json_response(200, self.analysis_state.snapshot())
                if method == "GET" and path == "/wait_autoanalysis":
                    return json_response(
                        200,
                        self._run_operation(
                            None, lambda: self.backend.wait_autoanalysis(None)
                        ),
                    )
                if method == "POST" and path == "/wait_autoanalysis":
                    return json_response(
                        200,
                        self._run_operation(
                            lease_id,
                            lambda: self.backend.wait_autoanalysis(
                                self._timeout(payload)
                            ),
                        ),
                    )
                if method == "POST" and path == "/execute_python":
                    code = payload.get("code")
                    if not isinstance(code, str) or not code.strip():
                        raise APIError(
                            "invalid_code", "code must be a non-empty string"
                        )
                    return self._success(
                        self._run_operation(
                            lease_id,
                            lambda: self.backend.execute_python(
                                code, self._timeout(payload)
                            ),
                        )
                    )
                if method == "POST" and path == "/save_database":
                    return self._success(
                        self._run_operation(lease_id, self.backend.save_database)
                    )
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
