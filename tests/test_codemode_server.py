import gzip
import json
import socket
import threading
import time
from http.client import HTTPConnection
from pathlib import Path

from ida_codemode._http import POST_BODY_LIMIT
from ida_codemode._registry import InstanceIdentity, load_registry_entry
from ida_codemode._runtime import AnalysisState
from ida_codemode._server import CodeModeHTTPServer


class RecordingBackend:
    def __init__(self, analysis: AnalysisState) -> None:
        self.analysis = analysis
        self.calls: list[tuple[object, ...]] = []

    def execute_python(
        self,
        code: str,
        timeout: float | None,
        *,
        lease_id: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ):
        self.calls.append(("execute_python", code, timeout, lease_id, persist_globals))
        if code == "return-bytes":
            return {"bytes": b"not-json"}
        return {"code": code}

    def cancel_active(self) -> None:
        pass

    def release_session(self, lease_id: str) -> None:
        del lease_id

    def wait_autoanalysis(self, timeout: float | None):
        self.calls.append(("wait", timeout))
        self.analysis.mark_complete()
        return self.analysis.snapshot()

    def save_database(self):
        self.calls.append(("save",))
        return {"saved": True, "idb_path": "/tmp/test.i64"}


def request(
    server: CodeModeHTTPServer,
    method: str,
    path: str,
    payload: object | None = None,
    *,
    token: str | None = None,
    headers: dict[str, str] | None = None,
):
    body = None if payload is None else json.dumps(payload).encode()
    connection = HTTPConnection("127.0.0.1", server.port, timeout=3)
    request_headers = {
        "Authorization": f"Bearer {token or server.token}",
        **(headers or {}),
    }
    connection.request(method, path, body=body, headers=request_headers)
    response = connection.getresponse()
    data = response.read()
    result = response.status, json.loads(data), dict(response.getheaders())
    connection.close()
    return result


def raw_request(server: CodeModeHTTPServer, data: bytes):
    connection = socket.create_connection(("127.0.0.1", server.port), timeout=3)
    try:
        connection.sendall(data)
        response = b""
        while b"\r\n\r\n" not in response:
            response += connection.recv(4096)
        head, body = response.split(b"\r\n\r\n", 1)
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1])
        while len(body) < length:
            body += connection.recv(4096)
        return int(head.split(b" ", 2)[1]), body[:length]
    finally:
        connection.close()


def make_server(tmp_path: Path, *, gui: bool = False):
    analysis = AnalysisState()
    backend = RecordingBackend(analysis)
    identity = InstanceIdentity(
        idb_path="/tmp/test.i64",
        exe_path="/tmp/test.exe",
        backend="gui" if gui else "idalib",
    )
    server = CodeModeHTTPServer(
        backend,
        identity,
        analysis,
        tmp_path,
        token="test-token",
        heartbeat_interval=0.05,
    )
    server.start()
    return server, backend


def test_http_handler_workers_are_prewarmed_and_stopped(tmp_path: Path):
    server, _ = make_server(tmp_path)
    httpd = server._httpd
    assert httpd is not None
    try:
        with httpd._worker_condition:
            assert httpd._idle_worker_count >= 4
        for _ in range(10):
            assert request(server, "GET", "/health")[0] == 200
    finally:
        server.stop()
        server.release_registration()
    with httpd._worker_condition:
        assert httpd._worker_count == 0


def test_server_stop_closes_idle_keep_alive_connection(tmp_path: Path):
    server, _ = make_server(tmp_path)
    connection = HTTPConnection("127.0.0.1", server.port, timeout=3)
    try:
        connection.request(
            "GET",
            "/health",
            headers={"Authorization": f"Bearer {server.token}"},
        )
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        sock = connection.sock
        assert sock is not None

        server.stop()
        sock.settimeout(1)
        assert sock.recv(1) == b""
    finally:
        connection.close()
        server.stop()
        server.release_registration()


def test_server_rejects_nonfinite_lifecycle_intervals(tmp_path: Path):
    analysis = AnalysisState()
    identity = InstanceIdentity("/tmp/test.i64", "/tmp/test.exe", "idalib")
    parameter_sets: tuple[tuple[str, float, float], ...] = (
        ("lease_grace", float("nan"), 1.0),
        ("lease_grace", float("inf"), 1.0),
        ("heartbeat_interval", 1.0, float("nan")),
        ("heartbeat_interval", 1.0, float("inf")),
    )
    for name, lease_grace, heartbeat_interval in parameter_sets:
        try:
            CodeModeHTTPServer(
                RecordingBackend(analysis),
                identity,
                analysis,
                tmp_path,
                lease_grace=lease_grace,
                heartbeat_interval=heartbeat_interval,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid {name}")


def test_health_registry_and_authentication(tmp_path: Path):
    server, _ = make_server(tmp_path)
    try:
        status, payload, headers = request(server, "GET", "/health")
        assert status == 200
        assert server.entry is not None
        assert payload == {"status": "ok", **server.entry.health_identity()}
        assert headers["Server"].strip().split("/")[0] == "ida-codemode"

        entry = load_registry_entry(tmp_path / f"{server.entry.record_id}.json")
        assert entry.backend == "idalib"
        assert entry._token == "test-token"

        status, body = raw_request(
            server,
            (
                f"GET /health HTTP/1.0\r\nAuthorization: Bearer {server.token}\r\n\r\n"
            ).encode(),
        )
        assert status == 200
        assert json.loads(body) == {"status": "ok", **server.entry.health_identity()}

        status, _ = raw_request(
            server,
            (
                f"GET /health HTTP/1.1\r\nAuthorization: Bearer {server.token}\r\n\r\n"
            ).encode(),
        )
        assert status == 403

        status, payload, _ = request(server, "GET", "/health", token="wrong")
        assert status == 401
        assert payload == {"status": "unauthorized"}
    finally:
        server.stop()
        server.release_registration()
    assert not list(tmp_path.glob("*.json"))


def test_execute_wait_and_save_routes(tmp_path: Path):
    server, backend = make_server(tmp_path)
    try:
        status, payload, _ = request(
            server,
            "POST",
            "/execute_python",
            {"code": "lambda: 1", "timeout": 2.5},
        )
        assert status == 200
        assert payload == {"ok": True, "result": {"code": "lambda: 1"}}

        status, payload, _ = request(server, "GET", "/poll_autoanalysis")
        assert payload == {"status": "running", "complete": False}

        status, payload, _ = request(
            server,
            "POST",
            "/wait_autoanalysis",
            {"timeout": 4},
        )
        assert status == 200
        assert payload == {"status": "complete", "complete": True}

        status, payload, _ = request(server, "POST", "/save_database", {})
        assert status == 200
        assert payload["result"]["saved"] is True
        assert backend.calls == [
            ("execute_python", "lambda: 1", 2.5, None, False),
            ("wait", 4.0),
            ("save",),
        ]
    finally:
        server.stop()
        server.release_registration()


def test_execute_rejects_non_json_result(tmp_path: Path):
    server, _ = make_server(tmp_path)
    try:
        status, payload, _ = request(
            server,
            "POST",
            "/execute_python",
            {"code": "return-bytes"},
        )
        assert status == 500
        assert payload["error"]["code"] == "invalid_result"
        assert "must be valid JSON" in payload["error"]["message"]
    finally:
        server.stop()
        server.release_registration()


def test_execute_rejects_invalid_timeouts(tmp_path: Path):
    server, backend = make_server(tmp_path)
    try:
        for timeout in (0, -1, float("nan"), float("inf"), "1", True):
            status, payload, _ = request(
                server,
                "POST",
                "/execute_python",
                {"code": "lambda: 1", "timeout": timeout},
            )
            assert status == 400
            assert payload["error"]["code"] == "invalid_timeout"
        assert backend.calls == []
    finally:
        server.stop()
        server.release_registration()


def test_persistent_globals_require_boolean_and_active_lease(tmp_path: Path):
    server, backend = make_server(tmp_path)
    try:
        status, payload, _ = request(
            server,
            "POST",
            "/execute_python",
            {"code": "value = 1", "persist_globals": "yes"},
        )
        assert status == 400
        assert payload["error"]["code"] == "invalid_persist_globals"

        status, payload, _ = request(
            server,
            "POST",
            "/execute_python",
            {"code": "value = 1", "persist_globals": True},
        )
        assert status == 400
        assert payload["error"]["code"] == "invalid_lease"
        assert backend.calls == []
    finally:
        server.stop()
        server.release_registration()


def test_compressed_request_body(tmp_path: Path):
    server, backend = make_server(tmp_path)
    try:
        body = gzip.compress(json.dumps({"code": "lambda: 7"}).encode())
        connection = HTTPConnection("127.0.0.1", server.port, timeout=3)
        connection.request(
            "POST",
            "/execute_python",
            body=body,
            headers={
                "Authorization": f"Bearer {server.token}",
                "Content-Encoding": "gzip",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()
        assert backend.calls == [("execute_python", "lambda: 7", None, None, False)]
    finally:
        server.stop()
        server.release_registration()


def test_chunked_framing_browser_gate_and_size_limit(tmp_path: Path):
    server, backend = make_server(tmp_path)
    try:
        body = json.dumps({"code": "lambda: 9"}).encode()
        chunks = (
            b"".join(
                f"{len(part):X}\r\n".encode() + part + b"\r\n"
                for part in (body[:7], body[7:])
            )
            + b"0\r\n\r\n"
        )
        prefix = (
            f"POST /execute_python HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.port}\r\n"
            f"Authorization: Bearer {server.token}\r\n"
        ).encode()
        status, response_body = raw_request(
            server,
            prefix + b"Transfer-Encoding: chunked\r\n\r\n" + chunks,
        )
        assert status == 200
        assert json.loads(response_body)["result"] == {"code": "lambda: 9"}
        assert backend.calls == [("execute_python", "lambda: 9", None, None, False)]

        malformed_trailer = f"{len(body):X}\r\n".encode() + body + b"\r\n0\r\n \r\n\r\n"
        status, _ = raw_request(
            server,
            prefix + b"Transfer-Encoding: chunked\r\n\r\n" + malformed_trailer,
        )
        assert status == 400

        status, _ = raw_request(
            server,
            prefix + b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        assert status == 400

        status, _ = raw_request(
            server,
            prefix + f"Content-Length: +{len(body)}\r\n\r\n".encode() + body,
        )
        assert status == 400

        status, _ = raw_request(
            server,
            prefix
            + b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"
            + b"Expect: 100-continue\r\n\r\n",
        )
        assert status == 400

        status, _ = raw_request(
            server,
            prefix
            + f"Content-Length: {POST_BODY_LIMIT + 1}\r\n".encode()
            + b"Expect: 100-continue\r\n\r\n",
        )
        assert status == 413

        status, _, _ = request(
            server,
            "GET",
            "/health",
            headers={"Origin": "http://127.0.0.1"},
        )
        assert status == 403
        status, _ = raw_request(
            server,
            (
                f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n"
                f"Authorization: Bearer {server.token}\r\nContent-Length: 1\r\n\r\nx"
            ).encode(),
        )
        assert status == 400

        bomb = gzip.compress(b"0" * (POST_BODY_LIMIT + 1))
        connection = HTTPConnection("127.0.0.1", server.port, timeout=3)
        connection.request(
            "POST",
            "/execute_python",
            body=bomb,
            headers={
                "Authorization": f"Bearer {server.token}",
                "Content-Encoding": "gzip",
            },
        )
        response = connection.getresponse()
        assert response.status == 413
        response.read()
        connection.close()
    finally:
        server.stop()
        server.release_registration()


def test_close_database_route_is_not_exposed(tmp_path: Path):
    server, backend = make_server(tmp_path)
    try:
        status, payload, _ = request(server, "POST", "/close_database", {})
        assert status == 404
        assert payload == {"ok": False, "error": "Not Found"}
        assert backend.calls == []
        assert request(server, "GET", "/health")[0] == 200
    finally:
        server.stop()
        server.release_registration()


def test_sse_health_holds_and_releases_a_client_lease(tmp_path: Path):
    server, _ = make_server(tmp_path)
    connection = HTTPConnection("127.0.0.1", server.port, timeout=3)
    try:
        connection.request(
            "GET",
            "/health?sse=1",
            headers={
                "Authorization": f"Bearer {server.token}",
                "Accept": "text/event-stream",
            },
        )
        response = connection.getresponse()
        assert response.status == 200
        assert response.getheader("Content-Type") == "text/event-stream"
        assert response.readline() == b"event: health\n"
        deadline = time.monotonic() + 1
        while server._active_leases != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server._active_leases == 1
        response.close()
        connection.close()
        deadline = time.monotonic() + 2
        while server._active_leases and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server._active_leases == 0
    finally:
        connection.close()
        server.stop()
        server.release_registration()


def test_execute_state_is_scoped_to_and_released_with_lease(tmp_path: Path):
    class SessionBackend(RecordingBackend):
        def execute_python(
            self,
            code: str,
            timeout: float | None,
            *,
            lease_id: str | None = None,
            persist_globals: bool = False,
            filename: str | None = None,
        ):
            self.calls.append(
                (
                    "execute",
                    lease_id,
                    code,
                    timeout,
                    persist_globals,
                )
            )
            return {"lease_id": lease_id}

        def release_session(self, lease_id: str) -> None:
            self.calls.append(("release_session", lease_id))

    analysis = AnalysisState()
    backend = SessionBackend(analysis)
    identity = InstanceIdentity("/tmp/test.i64", "/tmp/test.exe", "idalib")
    server = CodeModeHTTPServer(
        backend,
        identity,
        analysis,
        tmp_path,
        token="test-token",
        heartbeat_interval=0.05,
    )
    server.start()
    lease = HTTPConnection("127.0.0.1", server.port, timeout=3)
    try:
        lease.request(
            "GET",
            "/health?sse=1&lease_id=scoped",
            headers={
                "Accept": "text/event-stream",
                "Authorization": "Bearer test-token",
            },
        )
        response = lease.getresponse()
        assert response.status == 200
        assert response.readline() == b"event: health\n"

        status, payload, _ = request(
            server,
            "POST",
            "/execute_python",
            {
                "lease_id": "scoped",
                "code": "result = 1",
                "persist_globals": True,
            },
        )
        assert status == 200
        assert payload["result"] == {"lease_id": "scoped"}
        release_status, release_payload, _ = request(
            server,
            "POST",
            "/release_lease",
            {"lease_id": "scoped"},
        )
        assert release_status == 200
        assert release_payload["result"] == {
            "released": True,
            "shutdown_pending": False,
        }
        deadline = time.monotonic() + 1
        while ("release_session", "scoped") not in backend.calls:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert backend.calls == [
            ("execute", "scoped", "result = 1", None, True),
            ("release_session", "scoped"),
        ]
    finally:
        lease.close()
        server.stop()
        server.release_registration()


def test_disconnected_sse_skips_startup_grace(tmp_path: Path):
    stopped = threading.Event()
    analysis = AnalysisState()
    backend = RecordingBackend(analysis)
    server = CodeModeHTTPServer(
        backend,
        InstanceIdentity("/tmp/test.i64", "/tmp/test.exe", "idalib", managed=True),
        analysis,
        tmp_path,
        lease_grace=30,
        heartbeat_interval=0.02,
        on_shutdown=stopped.set,
    )
    server.start()
    connection = HTTPConnection("127.0.0.1", server.port, timeout=3)
    try:
        connection.request(
            "GET",
            "/health?sse=1&lease_id=abandoned&keepalive=0",
            headers={
                "Authorization": f"Bearer {server.token}",
                "Accept": "text/event-stream",
            },
        )
        response = connection.getresponse()
        assert response.status == 200
        assert response.readline() == b"event: health\n"
        response.close()
        connection.close()
        assert stopped.wait(1)
    finally:
        connection.close()
        server.stop()
        server.release_registration()
