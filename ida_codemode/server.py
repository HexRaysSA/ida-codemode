from __future__ import annotations

import atexit
from dataclasses import asdict
import json
import logging
import os
from pathlib import Path
import threading
from typing import Any, Callable, Protocol
import uuid

from .http import HOST, HTTPResponse, LocalHTTPServer, json_response
from .registry import (
    InstanceIdentity,
    RegistryEntry,
    publish_entry,
    remove_entry,
)
from .runtime import APIError, AnalysisState


logger = logging.getLogger(__name__)


class CodeModeBackend(Protocol):
    def execute_python(self, code: str, timeout: float | None) -> Any: ...

    def wait_autoanalysis(self, timeout: float | None) -> dict[str, Any]: ...

    def save_database(self) -> dict[str, Any]: ...

    def close_database(self) -> dict[str, Any]: ...


class CodeModeHTTPServer:
    """Authenticated local Code Mode API and discovery lifecycle."""

    def __init__(
        self,
        backend: CodeModeBackend,
        identity: InstanceIdentity,
        analysis_state: AnalysisState,
        registry_dir: str | os.PathLike[str],
        *,
        token: str | None = None,
        on_shutdown: Callable[[], None] | None = None,
    ) -> None:
        self.backend = backend
        self.identity = identity
        self.analysis_state = analysis_state
        self.registry_dir = Path(registry_dir)
        self.token = token or str(uuid.uuid4())
        self.on_shutdown = on_shutdown

        self._lock = threading.Lock()
        self._httpd: LocalHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._registry_path: Path | None = None
        self._atexit_registered = False
        self._shutdown_requested = False

    @property
    def port(self) -> int | None:
        return self._httpd.port if self._httpd is not None else None

    @property
    def url(self) -> str | None:
        return f"http://{HOST}:{self.port}" if self.port is not None else None

    def start(self) -> None:
        with self._lock:
            if self._httpd is not None:
                return
            self._shutdown_requested = False
            httpd = LocalHTTPServer(self.token, self._dispatch)
            serving = threading.Event()
            thread = threading.Thread(
                target=self._serve,
                args=(httpd, serving),
                name="ida-codemode-http",
                daemon=True,
            )
            self._httpd = httpd
            self._thread = thread

        try:
            thread.start()
            if not serving.wait(timeout=2.0) or not thread.is_alive():
                raise RuntimeError("HTTP server thread did not start")
            entry = RegistryEntry(
                port=httpd.port,
                token=self.token,
                **asdict(self.identity),
            )
            self._registry_path = publish_entry(self.registry_dir, entry)
            if not self._atexit_registered:
                atexit.register(self._remove_registry)
                self._atexit_registered = True
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

    def _remove_registry(self) -> None:
        path = self._registry_path
        self._registry_path = None
        remove_entry(path, self.token)

    def stop(self) -> None:
        with self._lock:
            httpd = self._httpd
            thread = self._thread
            self._httpd = None
            self._thread = None

        self._remove_registry()
        if self._atexit_registered:
            try:
                atexit.unregister(self._remove_registry)
            except Exception:
                pass
            self._atexit_registered = False

        if httpd is not None:
            # BaseServer.shutdown() deadlocks if serve_forever() never started.
            if thread is not None and thread.is_alive():
                httpd.shutdown()
                if thread is not threading.current_thread():
                    thread.join(timeout=5.0)
            httpd.server_close()

    def _request_shutdown_after_response(self) -> None:
        with self._lock:
            if self._shutdown_requested:
                return
            self._shutdown_requested = True

        def shutdown() -> None:
            self.stop()
            if self.on_shutdown is not None:
                try:
                    self.on_shutdown()
                except Exception:
                    logger.exception("Code Mode shutdown callback failed")

        threading.Thread(
            target=shutdown,
            name="ida-codemode-shutdown",
            daemon=True,
        ).start()

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
        if timeout <= 0:
            raise APIError("invalid_timeout", "timeout must be a positive number")
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

    def _dispatch(self, method: str, path: str, body: bytes | None) -> HTTPResponse:
        try:
            if method == "GET" and path == "/health":
                return json_response(
                    200,
                    {
                        "status": "ok",
                        "token": self.token,
                        **asdict(self.identity),
                    },
                )
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
                    raise APIError("invalid_code", "code must be a non-empty string")
                return self._success(
                    self.backend.execute_python(code, self._timeout(payload))
                )
            if method == "POST" and path == "/save_database":
                self._decode_object(body)
                return self._success(self.backend.save_database())
            if method == "POST" and path == "/close_database":
                self._decode_object(body)
                result = self.backend.close_database()
                return json_response(
                    200,
                    {"ok": True, "result": result},
                    after_send=self._request_shutdown_after_response,
                )
            return json_response(404, {"ok": False, "error": "Not Found"})
        except APIError as exc:
            return self._failure(exc)
        except Exception as exc:
            logger.exception("Unhandled Code Mode API failure")
            return self._failure(
                APIError("internal_error", str(exc) or type(exc).__name__, status=500)
            )
