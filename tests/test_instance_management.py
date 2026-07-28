from __future__ import annotations

import threading
import time
from pathlib import Path

import ida_codemode_mcp as mcp_app
from ida_codemode.client import DatabaseHandle
from ida_codemode.registry import (
    FileLock,
    InstanceIdentity,
    InstanceRegistration,
    canonical_path,
    scan_instances,
)
from ida_codemode.resolver import resolve_instance
from ida_codemode.runtime import AnalysisState
from ida_codemode.server import CodeModeHTTPServer


class StaticBackend:
    def execute_python(self, code: str, timeout: float | None):
        return {"code": code, "timeout": timeout}

    def wait_autoanalysis(self, timeout: float | None):
        return {"status": "complete", "complete": True}

    def save_database(self):
        return {"saved": True, "idb_path": "/tmp/test.i64"}


def test_file_lock_excludes_other_open_descriptions(tmp_path: Path) -> None:
    first = FileLock(tmp_path / "test.lock")
    second = FileLock(tmp_path / "test.lock")
    first.acquire(0)
    try:
        assert second.try_acquire() is False
    finally:
        second.close()
        first.close()


def test_scan_reaps_a_record_after_its_lifetime_lock_dies(tmp_path: Path) -> None:
    registration = InstanceRegistration(
        tmp_path,
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib"),
        token="token",
    )
    entry = registration.publish(12345)
    registration.lock.close()  # Simulate kernel release after a hard process exit.
    assert (tmp_path / f"{entry.record_id}.json").exists()

    assert scan_instances(tmp_path, timeout=0.01) == []
    assert not (tmp_path / f"{entry.record_id}.json").exists()
    registration.release()


def test_resolver_prefers_gui_executable_identity(tmp_path: Path) -> None:
    executable = tmp_path / "sample.exe"
    funny_idb = tmp_path / "saved-elsewhere.i64"
    executable.write_bytes(b"binary")
    funny_idb.write_bytes(b"idb")
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(funny_idb), str(executable), "gui"),
        AnalysisState(),
        tmp_path / "instances",
    )
    server.start()
    try:
        entry = resolve_instance(
            executable,
            spawn=False,
            registry_dir=tmp_path / "instances",
            spawn_dir=tmp_path / "spawn",
        )
        assert entry.backend == "gui"
        assert entry.idb_path.endswith("saved-elsewhere.i64")
    finally:
        server.stop()
        server.release_registration()


def test_database_manager_only_traces_during_mcp_lifecycle(
    tmp_path: Path, monkeypatch
) -> None:
    class FakeTrace:
        path = tmp_path / "session.jsonl"

        def __init__(self) -> None:
            self.events: list[str] = []

        def emit(self, event: str, **_fields: object) -> None:
            self.events.append(event)

    trace = FakeTrace()
    monkeypatch.setattr(mcp_app, "TRACE", trace)
    manager = mcp_app._DatabaseManager(tmp_path / "instances", tmp_path / "spawn")

    manager._emit("database_opened")
    assert trace.events == []

    manager.start("stdio")
    manager._emit("database_opened")
    manager.shutdown()
    assert trace.events == ["mcp_started", "database_opened", "mcp_stopped"]


def test_list_databases_uses_idb_when_gui_executable_is_missing(tmp_path: Path) -> None:
    registry_dir = tmp_path / "instances"
    idb_path = tmp_path / "open.i64"
    idb_path.write_bytes(b"idb")
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(tmp_path / "missing.exe"), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    entry = server.entry
    try:
        result = mcp_app._DatabaseManager(registry_dir).list_databases()
    finally:
        server.stop()
        server.release_registration()

    assert result == {
        "instances": [
            {
                "path": entry.idb_path,
                "backend": "gui",
                "status": "available",
                "instance_id": None,
                "error": None,
            }
        ]
    }


def test_list_databases_prefers_existing_gui_executable(tmp_path: Path) -> None:
    registry_dir = tmp_path / "instances"
    idb_path = tmp_path / "open.i64"
    executable = tmp_path / "open.exe"
    idb_path.write_bytes(b"idb")
    executable.write_bytes(b"binary")
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    try:
        result = mcp_app._DatabaseManager(registry_dir).list_databases()
    finally:
        server.stop()
        server.release_registration()

    assert result["instances"][0]["path"] == canonical_path(executable)


def test_gui_disconnect_invalidates_mcp_instance_without_spawning(tmp_path: Path) -> None:
    registry_dir = tmp_path / "instances"
    spawn_dir = tmp_path / "spawn"
    idb_path = tmp_path / "open.i64"
    executable = tmp_path / "open.exe"
    idb_path.write_bytes(b"idb")
    executable.write_bytes(b"binary")
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    manager = mcp_app._DatabaseManager(registry_dir, spawn_dir)
    opened = manager.open_database(str(executable), set_current=True)

    server.stop()
    server.release_registration()
    deadline = time.monotonic() + 2
    while manager.list_databases()["instances"] and time.monotonic() < deadline:
        time.sleep(0.01)

    assert manager.list_databases() == {"instances": []}
    try:
        manager.execute_python("lambda: 1", opened["instance_id"])
    except mcp_app.McpToolError as exc:
        assert "disconnected since it was last used" in str(exc)
    else:
        raise AssertionError("disconnected instance remained executable")
    assert not list(registry_dir.glob("*.json"))
    manager.shutdown()


def test_multiple_leases_share_one_managed_server(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        tmp_path / "instances",
        lease_grace=0.1,
        heartbeat_interval=0.02,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    first = DatabaseHandle("/tmp/test", server.entry)
    second = DatabaseHandle("/tmp/test", server.entry)
    try:
        first.close()
        time.sleep(0.15)
        assert not stopped.is_set()
        assert second.execute_python("lambda: 1", 1) == {
            "code": "lambda: 1",
            "timeout": 1.0,
        }
    finally:
        second.close()
    assert stopped.wait(2)
    server.release_registration()
