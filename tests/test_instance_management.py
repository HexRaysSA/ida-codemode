import threading
import time
from pathlib import Path
from typing import Any

import ida_codemode_mcp as mcp_app
from ida_codemode.client import DatabaseHandle
from ida_codemode.database import DatabaseError, DatabaseManager
from ida_codemode.registry import (
    FileLock,
    InstanceIdentity,
    InstanceRegistration,
    RegistryEntry,
    canonical_path,
    find_gui_owner,
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


def test_find_gui_owner_checks_the_lifetime_lock(tmp_path: Path) -> None:
    registration = InstanceRegistration(
        tmp_path,
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        token="token",
    )
    entry = registration.publish(12345)
    try:
        assert find_gui_owner("/tmp/test.i64", tmp_path) == entry
        assert find_gui_owner("/tmp/other.i64", tmp_path) is None

        registration.lock.close()  # Simulate the owning process exiting.
        assert find_gui_owner("/tmp/test.i64", tmp_path) is None
    finally:
        registration.release()


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


def test_mcp_session_trace_metadata(tmp_path: Path, monkeypatch) -> None:
    class FakeTrace:
        path = tmp_path / "session.jsonl"

        def __init__(self) -> None:
            self.records: list[tuple[str, dict[str, object]]] = []

        def emit(self, event: str, **fields: object) -> None:
            self.records.append((event, fields))

    trace = FakeTrace()
    manager = DatabaseManager(
        tmp_path / "instances",
        tmp_path / "spawn",
        on_event=mcp_app._trace_database_event,
    )
    monkeypatch.setattr(mcp_app, "TRACE", trace)
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(mcp_app, "_TRACE_STARTED", False)
    monkeypatch.setattr(mcp_app, "_TRACE_STOPPED", False)

    mcp_app._start_mcp_trace("stdio", "test-agent")
    mcp_app.mcp.registry.methods["initialize"](
        "2025-06-18",
        {},
        {"name": "test-client", "version": "1.0"},
        {"model": "test-model"},
    )
    manager._emit("database_opened", instance_id="test-instance")
    mcp_app._shutdown_server_state()

    assert [event for event, _fields in trace.records] == [
        "mcp_started",
        "mcp_initialized",
        "database_opened",
        "mcp_stopped",
    ]
    assert trace.records[0][1]["agent"] == "test-agent"
    assert trace.records[1][1]["clientInfo"] == {
        "name": "test-client",
        "version": "1.0",
    }
    assert trace.records[1][1]["_meta"] == {"model": "test-model"}
    assert trace.records[2][1]["instance_id"] == "test-instance"


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
        result = DatabaseManager(registry_dir).list_databases()
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
        result = DatabaseManager(registry_dir).list_databases()
    finally:
        server.stop()
        server.release_registration()

    assert result["instances"][0]["path"] == canonical_path(executable)


def test_paths_preserve_case_but_matching_is_case_insensitive(tmp_path: Path) -> None:
    # Regression: real paths must keep their on-disk case (so IDBs are created
    # exactly as IDA would name them, not lowercased), while discovery matching
    # stays case-insensitive on macOS/Windows and works for either the
    # executable or the .i64 path.
    import sys

    from ida_codemode.resolver import expected_idb_path, resolve_instance

    idb_path = tmp_path / "MixedCase.exe.i64"
    executable = tmp_path / "MixedCase.exe"
    idb_path.write_bytes(b"idb")
    executable.write_bytes(b"binary")

    # Real paths keep case; the fold lives only in the identity key.
    assert canonical_path(executable).endswith("MixedCase.exe")
    assert expected_idb_path(executable).endswith("MixedCase.exe.i64")

    registry_dir = tmp_path / "instances"
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    try:
        # The listed path preserves case (no more lowercase databases).
        result = DatabaseManager(registry_dir).list_databases()
        assert result["instances"][0]["path"].endswith("MixedCase.exe")

        # The model may pass the executable or the .i64; both find the one
        # instance without spawning a worker.
        variants = [executable, idb_path]
        if sys.platform in ("darwin", "win32"):
            # Case-insensitive volumes: differently-cased spellings name the
            # same file and must resolve to the same instance.
            variants += [tmp_path / "mixedcase.exe", tmp_path / "mixedcase.exe.i64"]
        record_ids = {
            resolve_instance(str(p), spawn=False, registry_dir=registry_dir).record_id
            for p in variants
        }
        assert record_ids == {server.entry.record_id}
    finally:
        server.stop()
        server.release_registration()


def test_resolves_live_instance_when_idb_not_on_disk(tmp_path: Path) -> None:
    # Regression: a freshly-opened GUI database has no .i64 on disk until it is
    # saved. Attaching to that live instance must work via either the .i64 path
    # (which does not exist yet) or the executable path, without a premature
    # "database path does not exist" rejection.
    from ida_codemode.resolver import resolve_instance

    executable = tmp_path / "Fresh.exe"
    executable.write_bytes(b"binary")
    idb_path = tmp_path / "Fresh.exe.i64"  # intentionally NOT created on disk
    assert not idb_path.exists()

    registry_dir = tmp_path / "instances"
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    try:
        for lookup in (idb_path, executable):
            entry = resolve_instance(
                str(lookup), spawn=False, registry_dir=registry_dir
            )
            assert entry.record_id == server.entry.record_id
    finally:
        server.stop()
        server.release_registration()


def test_get_session_waits_for_in_flight_startup_open(tmp_path: Path) -> None:
    # Regression: the agent's first tool call must not race a --database startup
    # open. _get_session waits for the background thread to finish attaching.
    manager = DatabaseManager(tmp_path / "instances", tmp_path / "spawn")
    sentinel: Any = object()

    def _startup() -> None:
        time.sleep(0.2)  # attach lands after the first tool call arrives
        with manager._lock:
            manager._instances["inst-1"] = sentinel
            manager._current_instance_id = "inst-1"

    thread = threading.Thread(target=_startup, daemon=True)
    manager._startup_open_thread = thread
    thread.start()

    # A naive lookup would fail here; _get_session must block on the thread.
    target_id, session = manager._get_session(None)
    assert target_id == "inst-1"
    assert session is sentinel


def test_shutdown_during_open_releases_the_late_handle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    open_started = threading.Event()
    finish_open = threading.Event()
    handle_closed = threading.Event()
    failures: list[Exception] = []

    entry = RegistryEntry(
        record_id="123-abcdef",
        backend="gui",
        pid=123,
        port=12345,
        token="token",
        version=1,
        idb_path="/tmp/test.i64",
        idb_key="test-key",
        exe_path="/tmp/test",
        managed=False,
        started_at=0.0,
    )

    class SlowHandle:
        def __init__(self) -> None:
            self.entry = entry
            self.disconnect_reason = None
            self._connected = True

        @property
        def connected(self) -> bool:
            return self._connected

        @classmethod
        def open(cls, *_args, **_kwargs):
            open_started.set()
            assert finish_open.wait(2)
            return cls()

        def set_disconnect_callback(self, _callback) -> None:
            pass

        def close(self) -> None:
            self._connected = False
            handle_closed.set()

    monkeypatch.setattr("ida_codemode.database.DatabaseHandle", SlowHandle)
    manager = DatabaseManager(tmp_path / "instances", tmp_path / "spawn")

    def open_database() -> None:
        try:
            manager.open_database("/tmp/test", set_current=True)
        except Exception as exc:  # noqa: BLE001 - captured for the assertion
            failures.append(exc)

    thread = threading.Thread(target=open_database)
    thread.start()
    assert open_started.wait(1)

    # Reproduction: shutdown completes while handle creation is still blocked.
    manager.shutdown()
    finish_open.set()
    thread.join(2)

    assert not thread.is_alive()
    assert handle_closed.is_set()
    assert len(failures) == 1
    assert isinstance(failures[0], DatabaseError)
    assert "shutting down" in str(failures[0])
    assert manager._instances == {}


def test_get_session_raises_without_startup_open(tmp_path: Path) -> None:
    manager = DatabaseManager(tmp_path / "instances", tmp_path / "spawn")
    try:
        manager._get_session(None)
    except DatabaseError as exc:
        assert "no open database instance" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected DatabaseError")


def test_get_session_raises_after_failed_startup_open(tmp_path: Path) -> None:
    # A startup open that finishes without setting a current DB (i.e. it failed)
    # must not hang the tool call: waiting ends when the thread ends.
    manager = DatabaseManager(tmp_path / "instances", tmp_path / "spawn")
    thread = threading.Thread(target=lambda: None, daemon=True)
    manager._startup_open_thread = thread
    thread.start()
    try:
        manager._get_session(None)
    except DatabaseError as exc:
        assert "no open database instance" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected DatabaseError")


def test_gui_disconnect_invalidates_mcp_instance_without_spawning(
    tmp_path: Path,
) -> None:
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
    manager = DatabaseManager(registry_dir, spawn_dir)
    opened = manager.open_database(str(executable), set_current=True)

    server.stop()
    server.release_registration()
    deadline = time.monotonic() + 2
    while manager.list_databases()["instances"] and time.monotonic() < deadline:
        time.sleep(0.01)

    assert manager.list_databases() == {"instances": []}
    try:
        manager.execute_python("lambda: 1", opened["instance_id"])
    except DatabaseError as exc:
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
