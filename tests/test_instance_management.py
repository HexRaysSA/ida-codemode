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
    scan_instances,
)
from ida_codemode.resolver import resolve_instance
from ida_codemode.runtime import AnalysisState
from ida_codemode.server import CodeModeHTTPServer


class FakeBackend:
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
        FakeBackend(),
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


def test_list_databases_discovers_unattached_gui_instance(tmp_path: Path) -> None:
    registry_dir = tmp_path / "instances"
    server = CodeModeHTTPServer(
        FakeBackend(),
        InstanceIdentity("/tmp/open.i64", "/tmp/open.exe", "gui"),
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

    assert result["count"] == 1
    assert result["attached_count"] == 0
    assert result["current_instance_id"] is None
    assert result["instances"] == [
        {
            "record_id": entry.record_id,
            "backend": "gui",
            "pid": entry.pid,
            "port": entry.port,
            "idb_path": entry.idb_path,
            "idb_key": entry.idb_key,
            "exe_path": entry.exe_path,
            "managed": False,
            "started_at": entry.started_at,
            "worker_log_path": None,
            "availability": "ready",
            "availability_detail": None,
            "instance_id": None,
            "requested_path": None,
            "attached": False,
            "current": False,
        }
    ]
    assert "token" not in result["instances"][0]


def test_multiple_leases_share_one_managed_server(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = CodeModeHTTPServer(
        FakeBackend(),
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
