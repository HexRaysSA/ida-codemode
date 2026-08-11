import argparse
import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, replace
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import ida_codemode.client as client_mod
import ida_codemode.resolver as resolver_mod
import ida_codemode.worker as worker_mod
import ida_codemode_mcp as mcp_app
from ida_codemode.client import DatabaseHandle
from ida_codemode.database import DatabaseError, DatabaseManager
from ida_codemode.http import RequestHandler
from ida_codemode.registry import (
    PROTOCOL_VERSION,
    REGISTRY_DIR,
    FileLock,
    InstanceIdentity,
    InstanceRegistration,
    InstanceState,
    RegistryEntry,
    canonical_path,
    find_gui_owner,
    scan_instances,
)
from ida_codemode.resolver import resolve_instance
from ida_codemode.runtime import AnalysisState
from ida_codemode.server import CodeModeHTTPServer
from ida_codemode.worker import (
    _build_ida_options,
    _image_base_to_paragraphs,
    _parse_image_base,
    _work_around_idapro_idausr_path_list,
)
from ida_codemode.worker import (
    _parser as worker_parser,
)


class StaticBackend:
    def execute_python(
        self,
        code: str,
        timeout: float | None,
        *,
        lease_id: str | None = None,
        persist_globals: bool = False,
    ):
        del lease_id, persist_globals
        return {"code": code, "timeout": timeout}

    def cancel_active(self) -> None:
        pass

    def release_session(self, lease_id: str) -> None:
        del lease_id

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


def test_lifecycle_apis_reject_nonfinite_timeouts(tmp_path: Path) -> None:
    for timeout in (float("nan"), float("inf")):
        lock = FileLock(tmp_path / "invalid.lock")
        try:
            lock.acquire(timeout)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid lock timeout: {timeout}")

        try:
            resolve_instance(
                tmp_path / "missing.exe",
                timeout=timeout,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid resolver timeout: {timeout}")

        parameter_sets = (
            ("open", timeout, 1.0),
            ("execute", 1.0, timeout),
        )
        for name, open_timeout, execute_timeout in parameter_sets:
            try:
                DatabaseManager(
                    open_timeout=open_timeout,
                    execute_timeout=execute_timeout,
                )
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted invalid {name} timeout: {timeout}")


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


def test_scan_blocks_an_unsupported_protocol_version(tmp_path: Path) -> None:
    registry_dir = REGISTRY_DIR
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    unsupported = replace(server.entry, version=PROTOCOL_VERSION + 1)
    server._entry = unsupported
    record_path = registry_dir / f"{unsupported.record_id}.json"
    record_path.write_text(json.dumps(asdict(unsupported)), encoding="utf-8")

    try:
        discovered = scan_instances(registry_dir)
    finally:
        server.stop()
        server.release_registration()

    assert len(discovered) == 1
    assert discovered[0].entry == unsupported
    assert discovered[0].state is InstanceState.BLOCKED
    assert discovered[0].detail == (
        f"unsupported protocol version {PROTOCOL_VERSION + 1}; "
        f"expected {PROTOCOL_VERSION}"
    )


def test_scan_accepts_additive_protocol_fields(tmp_path: Path, monkeypatch) -> None:
    registry_dir = REGISTRY_DIR
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        AnalysisState(),
        registry_dir,
    )
    server.start()
    assert server.entry is not None
    entry = server.entry
    record_path = registry_dir / f"{entry.record_id}.json"
    payload = json.loads(record_path.read_text(encoding="utf-8"))
    payload["future_registry_field"] = {"optional": True}
    record_path.write_text(json.dumps(payload), encoding="utf-8")
    original_health_payload = server._health_payload

    def health_payload() -> dict[str, Any]:
        return {**original_health_payload(), "future_health_field": True}

    monkeypatch.setattr(server, "_health_payload", health_payload)

    try:
        discovered = scan_instances(registry_dir)
    finally:
        server.stop()
        server.release_registration()

    assert len(discovered) == 1
    assert discovered[0].entry == entry
    assert discovered[0].state is InstanceState.READY


def test_resolver_timeout_is_shared_across_registry_probes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_dir = REGISTRY_DIR
    registrations = [
        InstanceRegistration(
            registry_dir,
            InstanceIdentity(
                f"/tmp/unrelated-{index}.i64",
                f"/tmp/unrelated-{index}",
                "gui",
            ),
            token=f"token-{index}",
        )
        for index in range(2)
    ]
    for index, registration in enumerate(registrations):
        registration.publish(12000 + index)

    def slow_probe(_entry, timeout: float):
        time.sleep(timeout)
        return False, "timeout"

    monkeypatch.setattr("ida_codemode.registry.probe_health", slow_probe)
    started = time.monotonic()
    try:
        try:
            resolve_instance(
                tmp_path / "missing.exe",
                spawn=False,
                timeout=0.05,
            )
        except TimeoutError:
            pass
        else:  # pragma: no cover
            raise AssertionError("expected the resolver deadline to expire")
    finally:
        for registration in registrations:
            registration.release()

    # The timeout is one budget for the whole scan, not one budget per record.
    assert time.monotonic() - started < 0.15


def test_database_handle_forwards_import_options(monkeypatch) -> None:
    captured = {}
    entry = SimpleNamespace(record_id="test-entry")

    def fake_resolve(path, **options):
        captured.update(path=path, options=options)
        return entry

    class CapturingHandle(DatabaseHandle):
        def __init__(self, path, resolved_entry, keepalive=0, on_disconnect=None):
            self.opened = (path, resolved_entry, keepalive, on_disconnect)

    monkeypatch.setattr(client_mod, "resolve_instance", fake_resolve)
    handle = CapturingHandle.open(
        "firmware.bin",
        output_database="firmware.i64",
        auto_analysis=True,
        image_base=0x8000,
        new_database=True,
        compiler="gcc",
        first_pass_directives=("FIRST=1",),
        second_pass_directives=("SECOND=1",),
        disable_fpp=True,
        entry_point=0x8010,
        jit_debugger=False,
        log_file="ida.log",
        disable_mouse=True,
        plugin_options="sample:option",
        processor="arm",
        db_compression="pack",
        run_debugger="linux",
        load_resources=True,
        script_file="startup.py",
        script_args=("arg",),
        file_type="ZIP",
        file_member="nested.bin",
        empty_database=True,
        windows_dir="windows",
        no_segmentation=True,
        debug_flags=("ldr",),
    )

    assert handle.opened[:2] == ("firmware.bin", entry)
    assert captured["path"] == "firmware.bin"
    assert captured["options"] == {
        "spawn": True,
        "timeout": 120.0,
        "output_database": "firmware.i64",
        "auto_analysis": True,
        "image_base": 0x8000,
        "new_database": True,
        "compiler": "gcc",
        "first_pass_directives": ("FIRST=1",),
        "second_pass_directives": ("SECOND=1",),
        "disable_fpp": True,
        "entry_point": 0x8010,
        "jit_debugger": False,
        "log_file": "ida.log",
        "disable_mouse": True,
        "plugin_options": "sample:option",
        "processor": "arm",
        "db_compression": "pack",
        "run_debugger": "linux",
        "load_resources": True,
        "script_file": "startup.py",
        "script_args": ("arg",),
        "file_type": "ZIP",
        "file_member": "nested.bin",
        "empty_database": True,
        "windows_dir": "windows",
        "no_segmentation": True,
        "debug_flags": ("ldr",),
    }


def test_resolver_builds_worker_import_options(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "firmware.bin"
    output = tmp_path / "analysis" / "firmware.i64"
    source.write_bytes(b"binary")
    captured = {}
    entry = SimpleNamespace(record_id="worker")

    def fake_spawner(
        source_path: str,
        expected_idb: str,
        lease_grace: float,
        options: resolver_mod.WorkerLaunchOptions,
    ) -> tuple[subprocess.Popen[bytes], Path]:
        captured.update(
            source=source_path,
            expected_idb=expected_idb,
            lease_grace=lease_grace,
            options=options,
        )
        process = cast(subprocess.Popen[bytes], SimpleNamespace(pid=1))
        return process, tmp_path / "worker.log"

    monkeypatch.setattr(resolver_mod, "_scan_until", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        resolver_mod,
        "_await_ready",
        lambda *args, **kwargs: entry,
    )

    result = resolve_instance(
        source,
        output_database=output,
        auto_analysis=True,
        image_base=0x8000,
        new_database=True,
        compiler="gcc",
        first_pass_directives="FIRST=1",
        second_pass_directives=["SECOND=1"],
        disable_fpp=True,
        entry_point=0x8010,
        jit_debugger=False,
        log_file=tmp_path / "ida.log",
        disable_mouse=True,
        plugin_options="sample:option",
        processor="arm",
        db_compression="no_pack",
        run_debugger="linux",
        load_resources=True,
        script_file=tmp_path / "startup.py",
        script_args="argument",
        file_type="ZIP",
        file_member="nested.bin",
        empty_database=True,
        windows_dir=tmp_path / "windows",
        no_segmentation=True,
        debug_flags="ldr",
        spawner=fake_spawner,
    )

    assert result is entry
    assert captured["source"] == str(source.resolve())
    assert captured["expected_idb"] == str(output.resolve())
    assert captured["options"] == resolver_mod.WorkerLaunchOptions(
        auto_analysis=True,
        image_base=0x8000,
        new_database=True,
        compiler="gcc",
        first_pass_directives=("FIRST=1",),
        second_pass_directives=("SECOND=1",),
        disable_fpp=True,
        entry_point=0x8010,
        jit_debugger=False,
        log_file=str(tmp_path / "ida.log"),
        disable_mouse=True,
        plugin_options="sample:option",
        processor="arm",
        db_compression="no_pack",
        run_debugger="linux",
        load_resources=True,
        script_file=str(tmp_path / "startup.py"),
        script_args=("argument",),
        file_type="ZIP",
        file_member="nested.bin",
        empty_database=True,
        windows_dir=str(tmp_path / "windows"),
        no_segmentation=True,
        debug_flags=("ldr",),
    )


def test_handle_close_does_not_wait_for_sse_heartbeat(tmp_path: Path) -> None:
    executable = tmp_path / "sample.exe"
    idb_path = tmp_path / "sample.exe.i64"
    executable.write_bytes(b"binary")
    idb_path.write_bytes(b"idb")
    registry_dir = REGISTRY_DIR
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        AnalysisState(),
        registry_dir,
        heartbeat_interval=30.0,
    )
    server.start()
    handle = DatabaseHandle.open(
        str(executable),
        spawn=False,
    )
    try:
        # Let the monitor consume the initial event and block waiting for the
        # deliberately distant heartbeat.
        time.sleep(0.05)
        started = time.monotonic()
        handle.close()
        elapsed = time.monotonic() - started
        assert elapsed < 1.0
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_resolver_prefers_gui_executable_identity(tmp_path: Path) -> None:
    executable = tmp_path / "sample.exe"
    funny_idb = tmp_path / "saved-elsewhere.i64"
    executable.write_bytes(b"binary")
    funny_idb.write_bytes(b"idb")
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(funny_idb), str(executable), "gui"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    server.start()
    try:
        entry = resolve_instance(
            executable,
            spawn=False,
        )
        assert entry.backend == "gui"
        assert entry.idb_path.endswith("saved-elsewhere.i64")
        try:
            resolve_instance(
                executable,
                spawn=False,
                new_database=True,
            )
        except resolver_mod.IdbBusy as exc:
            assert "cannot create a fresh database" in str(exc)
        else:
            raise AssertionError("fresh open reused a live GUI owner")
    finally:
        server.stop()
        server.release_registration()


def test_mcp_unsets_empty_forwarded_environment_variables(monkeypatch) -> None:
    monkeypatch.setenv("IDA_CODEMODE_ID", "")
    monkeypatch.setenv("IDAUSR", "/tmp/ida-user")
    monkeypatch.setenv("IDA_CODEMODE_STATE_DIR", "")

    mcp_app._unset_empty_environment_variables()

    assert "IDA_CODEMODE_ID" not in mcp_app.os.environ
    assert mcp_app.os.environ["IDAUSR"] == "/tmp/ida-user"
    assert "IDA_CODEMODE_STATE_DIR" not in mcp_app.os.environ


def test_mcp_gui_plugin_requires_current_or_newer_version(
    tmp_path: Path, monkeypatch
) -> None:
    plugin_dir = tmp_path / "plugins" / "ida-codemode"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "ida_codemode_plugin.py").touch()
    manifest = plugin_dir / "ida-plugin.json"

    monkeypatch.setattr(mcp_app, "get_idausr_dir", lambda: tmp_path)
    monkeypatch.setattr(mcp_app, "PACKAGE_VERSION", "1.2.3.dev2")

    cases = {
        "1.2.2": False,
        "1.2.3-dev.1": False,
        "1.2.3-dev.2": True,
        "1.2.3": True,
        "1.3.0": True,
    }
    for plugin_version, expected in cases.items():
        manifest.write_text(
            json.dumps({"plugin": {"version": plugin_version}}), encoding="utf-8"
        )
        assert mcp_app._gui_plugin_installed() is expected


def test_mcp_gui_plugin_rejects_missing_or_invalid_version(
    tmp_path: Path, monkeypatch
) -> None:
    plugin_dir = tmp_path / "plugins" / "ida-codemode"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "ida_codemode_plugin.py").touch()
    manifest = plugin_dir / "ida-plugin.json"

    monkeypatch.setattr(mcp_app, "get_idausr_dir", lambda: tmp_path)
    monkeypatch.setattr(mcp_app, "PACKAGE_VERSION", "1.2.3")

    assert mcp_app._gui_plugin_installed() is False
    for contents in ("not json", "{}", '{"plugin":{"version":"invalid"}}'):
        manifest.write_text(contents, encoding="utf-8")
        assert mcp_app._gui_plugin_installed() is False


def test_pi_package_includes_runtime_peers_and_gui_manifest() -> None:
    root = Path(__file__).parents[1]
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    assert package["peerDependencies"]["@earendil-works/pi-tui"] == "*"
    assert "ida-plugin.json" in package["files"]


def test_mcp_execute_owns_autoanalysis_policy(monkeypatch) -> None:
    class FakeManager:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []

        def resolve_instance_id(self, instance_id: str | None) -> str:
            self.calls.append(("resolve_instance_id", instance_id))
            assert instance_id is not None
            return instance_id

        def ensure_autoanalysis(
            self,
            instance_id: str | None,
            *,
            operation_id: str | None = None,
        ) -> None:
            self.calls.append(("ensure_autoanalysis", instance_id, operation_id))

        def execute_python(
            self,
            code: str,
            instance_id: str | None,
            timeout: float | None = None,
            *,
            operation_id: str | None = None,
            persist_globals: bool = False,
        ):
            assert persist_globals
            self.calls.append(
                ("execute_python", code, instance_id, timeout, operation_id)
            )
            return {"result": 1, "stdout": "", "stderr": ""}

    manager = FakeManager()
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda *_args, **_kwargs: None),
    )

    result = asyncio.run(mcp_app.execute_python("lambda: 1", "test-instance"))
    assert result == {
        "result": 1,
        "stdout": "",
        "stderr": "",
    }
    assert manager.calls[0] == ("resolve_instance_id", "test-instance")
    operation_id = manager.calls[1][2]
    assert isinstance(operation_id, str) and len(operation_id) == 32
    assert manager.calls[1:] == [
        ("ensure_autoanalysis", "test-instance", operation_id),
        ("execute_python", "lambda: 1", "test-instance", 360, operation_id),
    ]


def test_mcp_execute_honors_cancellation_notification(monkeypatch) -> None:
    class BlockingManager:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()
            self.executed = threading.Event()
            self.cancel_calls: list[tuple[str, str]] = []

        @staticmethod
        def resolve_instance_id(instance_id: str | None) -> str:
            assert instance_id is not None
            return instance_id

        def ensure_autoanalysis(
            self,
            _instance_id: str | None,
            *,
            operation_id: str | None = None,
        ) -> None:
            assert operation_id is not None
            self.started.set()
            assert self.release.wait(2)
            # Successful completion races with the accepted cancellation. User
            # code must still not start after the MCP request was cancelled.

        def execute_python(self, *_args, **_kwargs):
            self.executed.set()
            raise AssertionError("execution should not follow cancelled analysis")

        def cancel_operation(self, instance_id: str, operation_id: str) -> bool:
            self.cancel_calls.append((instance_id, operation_id))
            self.release.set()
            return True

    manager = BlockingManager()
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda *_args, **_kwargs: None),
    )
    result: dict[str, object] = {}

    def call() -> None:
        result["response"] = mcp_app.mcp._dispatch_mcp(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "execute_python",
                    "arguments": {
                        "code": "1",
                        "instance_id": "test-instance",
                    },
                },
                "id": "cancel-me",
            }
        )

    thread = threading.Thread(target=call, daemon=True)
    thread.start()
    assert manager.started.wait(1)
    mcp_app.mcp._dispatch_mcp(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "cancel-me", "reason": "client timeout"},
        }
    )
    thread.join(2)

    assert not thread.is_alive()
    assert result["response"] is None
    assert not manager.executed.is_set()
    assert manager.cancel_calls
    assert {instance for instance, _operation in manager.cancel_calls} == {
        "test-instance"
    }
    assert len({operation for _instance, operation in manager.cancel_calls}) == 1


def test_cancelling_queued_mcp_execution_does_not_cancel_running_request(
    monkeypatch,
) -> None:
    class QueuedManager:
        def __init__(self) -> None:
            self.operation_lock = threading.Lock()
            self.state_lock = threading.Lock()
            self.active: tuple[str, str] | None = None
            self.operation_ids: dict[str, str] = {}
            self.first_started = threading.Event()
            self.first_release = threading.Event()
            self.second_waiting = threading.Event()
            self.second_started = threading.Event()
            self.second_release = threading.Event()
            self.cancel_attempted = threading.Event()
            self.cancel_calls: list[str] = []

        @staticmethod
        def resolve_instance_id(instance_id: str | None) -> str:
            assert instance_id is not None
            return instance_id

        @staticmethod
        def ensure_autoanalysis(
            _instance_id: str,
            *,
            operation_id: str | None = None,
        ) -> None:
            assert operation_id is not None

        def execute_python(
            self,
            code: str,
            _instance_id: str,
            timeout: float | None = None,
            *,
            operation_id: str | None = None,
            persist_globals: bool = False,
        ) -> dict[str, object]:
            assert timeout == 360
            assert persist_globals
            assert operation_id is not None
            self.operation_ids[code] = operation_id
            if code == "second":
                self.second_waiting.set()
            with self.operation_lock:
                with self.state_lock:
                    self.active = (code, operation_id)
                if code == "first":
                    self.first_started.set()
                    assert self.first_release.wait(2)
                else:
                    self.second_started.set()
                    assert self.second_release.wait(2)
                with self.state_lock:
                    self.active = None
            if code == "second":
                raise RuntimeError("second operation cancelled")
            return {"result": code, "stdout": "", "stderr": ""}

        def cancel_operation(self, _instance_id: str, operation_id: str) -> bool:
            self.cancel_calls.append(operation_id)
            self.cancel_attempted.set()
            with self.state_lock:
                active = self.active
            if active is None or active[1] != operation_id:
                return False
            if active[0] == "first":
                self.first_release.set()
            else:
                self.second_release.set()
            return True

    manager = QueuedManager()
    monkeypatch.setattr(mcp_app, "DATABASE_MANAGER", manager)
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda *_args, **_kwargs: None),
    )
    results: dict[str, object] = {}

    def call(code: str, request_id: str) -> None:
        results[request_id] = mcp_app.mcp._dispatch_mcp(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "execute_python",
                    "arguments": {"code": code, "instance_id": "test-instance"},
                },
                "id": request_id,
            }
        )

    first = threading.Thread(target=call, args=("first", "first-request"))
    second = threading.Thread(target=call, args=("second", "second-request"))
    first.start()
    assert manager.first_started.wait(1)
    second.start()
    assert manager.second_waiting.wait(1)

    mcp_app.mcp._dispatch_mcp(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "second-request", "reason": "client timeout"},
        }
    )
    assert manager.cancel_attempted.wait(1)
    manager.first_release.set()
    assert manager.second_started.wait(1)
    first.join(2)
    second.join(2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert results["first-request"] is not None
    assert results["second-request"] is None
    assert manager.operation_ids["first"] != manager.operation_ids["second"]
    assert set(manager.cancel_calls) == {manager.operation_ids["second"]}


def test_stdio_eof_starts_shutdown_once() -> None:
    shutdown_calls: list[None] = []
    stdin = mcp_app._ShutdownOnEOFInput(
        BytesIO(b'{"jsonrpc":"2.0"}\n'),
        lambda: shutdown_calls.append(None),
    )

    assert stdin.readline() == b'{"jsonrpc":"2.0"}\n'
    assert shutdown_calls == []
    assert stdin.readline() == b""
    assert stdin.readline() == b""
    assert shutdown_calls == [None]


def test_mcp_execute_schema_exposes_numeric_timeout_default() -> None:
    tools = mcp_app.mcp.registry.methods["tools/list"]()["tools"]
    execute_tool = next(tool for tool in tools if tool["name"] == "execute_python")
    timeout_schema = execute_tool["inputSchema"]["properties"]["timeout"]

    assert timeout_schema == {
        "type": "number",
        "description": (
            "Python execution timeout in seconds. This does not include the separate "
            "initial autoanalysis wait."
        ),
        "default": 360,
    }


def test_mcp_session_trace_metadata(tmp_path: Path, monkeypatch) -> None:
    class FakeTrace:
        path = tmp_path / "session.jsonl"

        def __init__(self) -> None:
            self.records: list[tuple[str, dict[str, object]]] = []

        def emit(self, event: str, **fields: object) -> None:
            self.records.append((event, fields))

    trace = FakeTrace()
    manager = DatabaseManager(
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


def test_database_event_inherits_active_trace_call_id(monkeypatch) -> None:
    records: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        mcp_app,
        "TRACE",
        SimpleNamespace(emit=lambda event, **fields: records.append((event, fields))),
    )

    token = mcp_app._TRACE_CALL_ID.set("tool-call-id")
    try:
        mcp_app._trace_database_event("database_opened", {"instance_id": "instance-1"})
    finally:
        mcp_app._TRACE_CALL_ID.reset(token)

    assert len(records) == 1
    event, fields = records[0]
    assert event == "database_opened"
    assert fields["instance_id"] == "instance-1"
    assert fields["call_id"] == "tool-call-id"


def test_list_databases_uses_idb_when_gui_executable_is_missing(tmp_path: Path) -> None:
    registry_dir = REGISTRY_DIR
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
        result = DatabaseManager().list_databases()
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
    registry_dir = REGISTRY_DIR
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
        result = DatabaseManager().list_databases()
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

    registry_dir = REGISTRY_DIR
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
        result = DatabaseManager().list_databases()
        assert result["instances"][0]["path"].endswith("MixedCase.exe")

        # The model may pass the executable or the .i64; both find the one
        # instance without spawning a worker.
        variants = [executable, idb_path]
        if sys.platform in ("darwin", "win32"):
            # Case-insensitive volumes: differently-cased spellings name the
            # same file and must resolve to the same instance.
            variants += [tmp_path / "mixedcase.exe", tmp_path / "mixedcase.exe.i64"]
        record_ids = {resolve_instance(str(p), spawn=False).record_id for p in variants}
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

    registry_dir = REGISTRY_DIR
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
            entry = resolve_instance(str(lookup), spawn=False)
            assert entry.record_id == server.entry.record_id
    finally:
        server.stop()
        server.release_registration()


def test_get_session_waits_for_in_flight_startup_open(tmp_path: Path) -> None:
    # Regression: the agent's first tool call must not race a --database startup
    # open. _get_session waits for the background thread to finish attaching.
    manager = DatabaseManager()
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
    manager = DatabaseManager()

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
    manager = DatabaseManager()
    try:
        manager._get_session(None)
    except DatabaseError as exc:
        assert "no open database instance" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected DatabaseError")


def test_get_session_raises_after_failed_startup_open(tmp_path: Path) -> None:
    # A startup open that finishes without setting a current DB (i.e. it failed)
    # must not hang the tool call: waiting ends when the thread ends.
    manager = DatabaseManager()
    thread = threading.Thread(target=lambda: None, daemon=True)
    manager._startup_open_thread = thread
    thread.start()
    try:
        manager._get_session(None)
    except DatabaseError as exc:
        assert "no open database instance" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected DatabaseError")


def test_mcp_execution_waits_for_autoanalysis_once_per_database(
    tmp_path: Path,
) -> None:
    class RecordingBackend(StaticBackend):
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
        ):
            self.calls.append(("execute", code, timeout))
            return super().execute_python(
                code,
                timeout,
                lease_id=lease_id,
                persist_globals=persist_globals,
            )

        def wait_autoanalysis(self, timeout: float | None):
            self.calls.append(("wait", timeout))
            self.analysis.mark_complete()
            return self.analysis.snapshot()

    executable = tmp_path / "sample.exe"
    idb_path = tmp_path / "sample.i64"
    executable.write_bytes(b"binary")
    idb_path.write_bytes(b"idb")
    analysis = AnalysisState()
    backend = RecordingBackend(analysis)
    server = CodeModeHTTPServer(
        backend,
        InstanceIdentity(str(idb_path), str(executable), "gui"),
        analysis,
        REGISTRY_DIR,
    )
    server.start()
    manager = DatabaseManager(
        execute_timeout=7,
    )
    try:
        opened = manager.open_database(str(executable), set_current=True)

        manager.ensure_autoanalysis(opened["instance_id"])
        assert manager.execute_python("lambda: 1", opened["instance_id"]) == {
            "code": "lambda: 1",
            "timeout": 7.0,
        }
        manager.ensure_autoanalysis(opened["instance_id"])
        assert manager.execute_python("lambda: 2", opened["instance_id"], 9) == {
            "code": "lambda: 2",
            "timeout": 9.0,
        }
        assert backend.calls == [
            ("wait", None),
            ("execute", "lambda: 1", 7.0),
            ("execute", "lambda: 2", 9.0),
        ]
    finally:
        manager.shutdown()
        server.stop()
        server.release_registration()


def test_gui_disconnect_invalidates_mcp_instance_without_spawning(
    tmp_path: Path,
) -> None:
    registry_dir = REGISTRY_DIR
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
    manager = DatabaseManager()
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


def test_database_handle_reuses_http11_rpc_connection(tmp_path: Path) -> None:
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle("/tmp/test", server.entry)
    try:
        assert handle.execute_python("lambda: 1", 1)["code"] == "lambda: 1"
        connection = handle._rpc_connection
        assert connection is not None
        sock = connection.sock
        assert sock is not None

        assert handle.execute_python("lambda: 2", 1)["code"] == "lambda: 2"
        assert handle._rpc_connection is connection
        assert connection.sock is sock
        assert RequestHandler.disable_nagle_algorithm is True
    finally:
        handle.close()
        server.stop()
        server.release_registration()


def test_windows_console_launcher_can_exit_before_worker_child() -> None:
    assert resolver_mod._launcher_exit_is_fatal(0, "nt") is False
    assert resolver_mod._launcher_exit_is_fatal(1, "nt") is True
    assert resolver_mod._launcher_exit_is_fatal(0, "posix") is True


def test_worker_uses_primary_idausr_entry_for_idapro(
    tmp_path: Path, monkeypatch
) -> None:
    primary = tmp_path / "primary"
    secondary = tmp_path / "secondary"
    monkeypatch.setenv("IDAUSR", f"{primary}{os.pathsep}{secondary}")

    _work_around_idapro_idausr_path_list()

    assert os.environ["IDAUSR"] == str(primary)


def test_worker_hook_lifetime_surrounds_database_lifetime(
    tmp_path: Path, monkeypatch
) -> None:
    events: list[str] = []
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"binary")
    monkeypatch.delenv("IDAUSR", raising=False)
    monkeypatch.setattr(worker_mod, "_redirect_output", lambda _record_id: tmp_path)
    monkeypatch.setattr(worker_mod, "probe", lambda: None)
    monkeypatch.setattr(worker_mod.signal, "signal", lambda _signum, _handler: None)

    class FakeHook:
        def hook(self) -> None:
            events.append("hook")

        def unhook(self) -> None:
            events.append("unhook")

    class FakeDatabaseHandle:
        def close(self, save: bool) -> None:
            assert save is True
            events.append("close")

    database_handle = FakeDatabaseHandle()

    class FakeDatabase:
        @classmethod
        def open(cls, path: str, *, args, save_on_close: bool):
            assert path == str(input_path)
            assert save_on_close is True
            events.append("open")
            return database_handle

    class FakeOptions:
        def __init__(self, **_kwargs) -> None:
            pass

    class FakeRuntime:
        def __init__(self, *, backend: str, database, analysis_state) -> None:
            assert backend == "idalib"
            self.database = database

    class FakeServer:
        url = "http://127.0.0.1:1"

        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self) -> None:
            events.append("server-start")

        def stop(self) -> None:
            events.append("server-stop")

        def release_registration(self) -> None:
            events.append("release")

    fake_kernwin = SimpleNamespace(
        serve=lambda: events.append("serve"),
        stop_serving=lambda: None,
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        SimpleNamespace(auto_is_ok=lambda: True),
    )
    monkeypatch.setitem(sys.modules, "ida_kernwin", fake_kernwin)
    monkeypatch.setitem(
        sys.modules,
        "ida_loader",
        SimpleNamespace(
            PATH_TYPE_IDB=1, get_path=lambda _kind: str(tmp_path / "x.i64")
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_nalt",
        SimpleNamespace(get_input_file_path=lambda: str(input_path)),
    )
    monkeypatch.setitem(
        sys.modules, "ida_domain", SimpleNamespace(Database=FakeDatabase)
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_domain.database",
        SimpleNamespace(IdaCommandOptions=FakeOptions),
    )
    monkeypatch.setattr(
        worker_mod, "create_autoanalysis_hook", lambda _state: FakeHook()
    )
    monkeypatch.setattr(worker_mod, "IDARuntime", FakeRuntime)
    monkeypatch.setattr(worker_mod, "CodeModeHTTPServer", FakeServer)

    assert worker_mod.main([str(input_path)]) == 0
    assert events.index("open") < events.index("hook")
    assert events.index("unhook") < events.index("close")


def test_image_base_uses_byte_units_and_requires_paragraph_alignment() -> None:
    assert _parse_image_base("0x8000") == 0x8000
    assert _image_base_to_paragraphs(0x8000) == 0x800
    assert _image_base_to_paragraphs(None) is None
    parsed = worker_parser().parse_args(["input.bin", "--debug-mask", "0x80"])
    assert _build_ida_options(parsed, lambda **kwargs: kwargs)["debug_flags"] == 0x80
    for value in ("-1", "0x8001", "not-an-address"):
        try:
            _parse_image_base(value)
        except argparse.ArgumentTypeError:
            pass
        else:
            raise AssertionError(f"invalid image base accepted: {value}")
    try:
        resolver_mod.WorkerLaunchOptions(image_base=0x8001)
    except ValueError as exc:
        assert "16-byte aligned" in str(exc)
    else:
        raise AssertionError("unaligned API image base accepted")


def test_fresh_worker_opens_source_instead_of_existing_idb(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "sample.exe"
    expected_idb = tmp_path / "sample.exe.i64"
    source.write_bytes(b"binary")
    expected_idb.write_bytes(b"old idb")
    captured = {}

    def fake_popen(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(resolver_mod, "find_console_script", lambda name: "worker")
    monkeypatch.setattr(resolver_mod.subprocess, "Popen", fake_popen)
    _process, _log = resolver_mod.spawn_worker(
        str(source),
        str(expected_idb),
        20.0,
        resolver_mod.WorkerLaunchOptions(
            image_base=0x8000,
            new_database=True,
        ),
    )

    command = captured["command"]
    assert command[1] == str(source)
    assert command[command.index("--output-database") + 1] == str(expected_idb)
    assert command[command.index("--image-base") + 1] == "0x8000"
    assert "--new-database" in command
    if resolver_mod.os.name == "nt":
        create_no_window = resolver_mod.subprocess.CREATE_NO_WINDOW
        detached_process = resolver_mod.subprocess.DETACHED_PROCESS
        assert captured["creationflags"] & create_no_window
        assert not captured["creationflags"] & detached_process


def test_worker_launch_forwards_all_ida_command_options(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "firmware.bin"
    expected_idb = tmp_path / "firmware.i64"
    source.write_bytes(b"binary")
    log_file = tmp_path / "ida kernel.log"
    script_file = tmp_path / "startup.py"
    windows_dir = tmp_path / "windows"
    captured = {}

    def fake_popen(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(pid=456)

    monkeypatch.setattr(resolver_mod, "find_console_script", lambda name: "worker")
    monkeypatch.setattr(resolver_mod.subprocess, "Popen", fake_popen)
    resolver_mod.spawn_worker(
        str(source),
        str(expected_idb),
        7.5,
        resolver_mod.WorkerLaunchOptions(
            auto_analysis=True,
            image_base=0x8000,
            new_database=True,
            compiler="gcc:sysv",
            first_pass_directives=("FIRST=1", "FIRST=2"),
            second_pass_directives=("SECOND=1",),
            disable_fpp=True,
            entry_point=0x8010,
            jit_debugger=False,
            log_file=str(log_file),
            disable_mouse=True,
            plugin_options="sample:option",
            processor="arm",
            db_compression="compress",
            run_debugger="linux",
            load_resources=True,
            script_file=str(script_file),
            script_args=("--flag", "argument two"),
            file_type="ZIP",
            file_member="nested.bin",
            empty_database=True,
            windows_dir=str(windows_dir),
            no_segmentation=True,
            debug_flags=("ldr", "debugger"),
        ),
    )

    command = captured["command"]
    assert "--auto-analysis" in command
    assert command[command.index("--image-base") + 1] == "0x8000"
    assert "--new-database" in command
    assert "--compiler=gcc:sysv" in command
    assert "--first-pass-directive=FIRST=1" in command
    assert "--first-pass-directive=FIRST=2" in command
    assert "--second-pass-directive=SECOND=1" in command
    assert "--disable-fpp" in command
    assert command[command.index("--entry-point") + 1] == "0x8010"
    assert "--no-jit-debugger" in command
    assert command[command.index("--log-file") + 1] == str(log_file)
    assert "--disable-mouse" in command
    assert "--plugin-options=sample:option" in command
    assert command[command.index("--processor") + 1] == "arm"
    assert command[command.index("--db-compression") + 1] == "compress"
    assert "--run-debugger=linux" in command
    assert "--load-resources" in command
    assert command[command.index("--script-file") + 1] == str(script_file)
    assert "--script-arg=--flag" in command
    assert "--script-arg=argument two" in command
    assert command[command.index("--file-type") + 1] == "ZIP"
    assert command[command.index("--file-member") + 1] == "nested.bin"
    assert "--empty-database" in command
    assert command[command.index("--windows-dir") + 1] == str(windows_dir)
    assert "--no-segmentation" in command
    assert "--debug-flag=ldr" in command
    assert "--debug-flag=debugger" in command

    parsed = worker_parser().parse_args(command[1:])
    ida_options = _build_ida_options(parsed, lambda **kwargs: kwargs)
    assert ida_options == {
        "auto_analysis": True,
        "loading_address": 0x800,
        "new_database": True,
        "compiler": "gcc:sysv",
        "first_pass_directives": ["FIRST=1", "FIRST=2"],
        "second_pass_directives": ["SECOND=1"],
        "disable_fpp": True,
        "entry_point": 0x8010,
        "jit_debugger": False,
        "log_file": str(log_file.resolve()),
        "disable_mouse": True,
        "plugin_options": "sample:option",
        "output_database": str(expected_idb.resolve()),
        "processor": "arm",
        "db_compression": "compress",
        "run_debugger": "linux",
        "load_resources": True,
        "script_file": str(script_file.resolve()),
        "script_args": ["--flag", "argument two"],
        "file_type": "ZIP",
        "file_member": "nested.bin",
        "empty_database": True,
        "windows_dir": str(windows_dir.resolve()),
        "no_segmentation": True,
        "debug_flags": ["ldr", "debugger"],
    }


def test_await_ready_accepts_console_launcher_child_pid(
    tmp_path: Path, monkeypatch
) -> None:
    expected_idb = str(tmp_path / "sample.i64")
    entry = SimpleNamespace(
        pid=222,
        record_id="222-abcdef",
        idb_key=resolver_mod.idb_key(expected_idb),
        idb_path=expected_idb,
    )
    discovered = SimpleNamespace(
        entry=entry,
        state=resolver_mod.InstanceState.READY,
        detail=None,
    )
    process = cast(subprocess.Popen[bytes], SimpleNamespace(pid=111, poll=lambda: None))
    monkeypatch.setattr(
        resolver_mod, "scan_instances", lambda *args, **kwargs: [discovered]
    )

    result = resolver_mod._await_ready(
        process,
        expected_idb,
        tmp_path / "111-abcdef.log",
        time.monotonic() + 1,
    )

    assert result is entry


def test_multiple_leases_share_one_managed_server(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
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
        assert second.wait_autoanalysis(1) == {
            "status": "complete",
            "complete": True,
        }
    finally:
        second.close()
    assert stopped.wait(2)
    server.release_registration()


def test_final_explicit_release_skips_startup_grace(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        heartbeat_interval=30,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle("/tmp/test", server.entry)
    handle.close()
    assert stopped.wait(1)
    server.release_registration()


def test_draining_owner_remains_discoverable_until_database_close(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.exe.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"database")
    stopped = threading.Event()
    registry_dir = REGISTRY_DIR
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        registry_dir,
        lease_grace=30,
        heartbeat_interval=30,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    record_path = registry_dir / f"{server.entry.record_id}.json"
    handle = DatabaseHandle(str(executable), server.entry)
    handle.close()
    assert stopped.wait(1)

    discovered = scan_instances(registry_dir)
    assert len(discovered) == 1
    assert discovered[0].state is InstanceState.BLOCKED
    assert record_path.is_file()
    assert server._registration is not None
    assert server._registration.lock._locked

    spawned = False

    def unexpected_spawner(*_args: Any):
        nonlocal spawned
        spawned = True
        raise AssertionError("spawned over a draining IDB owner")

    try:
        resolve_instance(
            executable,
            timeout=1,
            spawner=unexpected_spawner,
        )
    except resolver_mod.IdbBusy:
        pass
    else:
        raise AssertionError("draining owner was not reported as busy")
    assert not spawned

    # The lifecycle owner calls this only after database.close()/unhook().
    server.release_registration()
    assert not record_path.exists()


def test_handle_keepalive_retains_idle_managed_worker(tmp_path: Path) -> None:
    stopped = threading.Event()
    server = CodeModeHTTPServer(
        StaticBackend(),
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        heartbeat_interval=0.02,
        on_shutdown=stopped.set,
    )
    server.start()
    assert server.entry is not None
    handle = DatabaseHandle("/tmp/test", server.entry, keepalive=0.25)
    handle.close()
    assert not stopped.wait(0.1)
    assert server.entry is not None
    replacement = DatabaseHandle("/tmp/test", server.entry, keepalive=0.1)
    replacement.close()
    assert not stopped.wait(0.05)
    assert stopped.wait(1)
    server.release_registration()


def test_operation_cancellation_cannot_reach_successor(tmp_path: Path) -> None:
    class HandoffBackend(StaticBackend):
        def __init__(self) -> None:
            self.current: str | None = None
            self.first_started = threading.Event()
            self.first_release = threading.Event()
            self.second_started = threading.Event()
            self.second_release = threading.Event()
            self.cancel_entered = threading.Event()
            self.cancel_release = threading.Event()
            self.cancelled_target: str | None = None

        def cancel_active(self) -> None:
            self.cancel_entered.set()
            assert self.cancel_release.wait(2)
            self.cancelled_target = self.current

    backend = HandoffBackend()
    server = CodeModeHTTPServer(
        backend,
        InstanceIdentity("/tmp/test.i64", "/tmp/test", "gui"),
        AnalysisState(),
        REGISTRY_DIR,
    )
    assert server._lease_opened("test-lease", 0) is not None
    failures: list[BaseException] = []

    def run(operation_id: str, operation) -> None:
        try:
            server._run_operation("test-lease", operation, operation_id)
        except BaseException as error:  # noqa: BLE001 - collected for the assertion
            failures.append(error)

    def first_operation() -> None:
        backend.current = "first"
        backend.first_started.set()
        assert backend.first_release.wait(2)
        backend.current = None

    def second_operation() -> None:
        backend.current = "second"
        backend.second_started.set()
        assert backend.second_release.wait(2)
        backend.current = None

    first = threading.Thread(target=run, args=("first", first_operation))
    second = threading.Thread(target=run, args=("second", second_operation))
    cancel = threading.Thread(
        target=lambda: server._cancel_operation("test-lease", "first")
    )
    first.start()
    assert backend.first_started.wait(1)
    second.start()
    cancel.start()
    assert backend.cancel_entered.wait(1)

    backend.first_release.set()
    # cancel_active() still owns the handoff barrier, so the successor cannot
    # become the backend's active generation until cancellation returns.
    assert not backend.second_started.wait(0.1)
    backend.cancel_release.set()
    assert backend.second_started.wait(1)
    backend.second_release.set()

    first.join(2)
    second.join(2)
    cancel.join(2)
    assert not first.is_alive() and not second.is_alive() and not cancel.is_alive()
    assert failures == []
    assert backend.cancelled_target != "second"
    server._lease_closed("test-lease")


def test_cancel_active_preserves_database_handle(tmp_path: Path) -> None:
    class CancellableBackend(StaticBackend):
        def __init__(self) -> None:
            self.started = threading.Event()
            self.cancelled = threading.Event()

        def execute_python(
            self,
            code: str,
            timeout: float | None,
            *,
            lease_id: str | None = None,
            persist_globals: bool = False,
        ):
            if code == "second":
                return super().execute_python(
                    code,
                    timeout,
                    lease_id=lease_id,
                    persist_globals=persist_globals,
                )
            self.started.set()
            assert self.cancelled.wait(2)
            raise RuntimeError("cancelled")

        def cancel_active(self) -> None:
            self.cancelled.set()

    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    backend = CancellableBackend()
    server = CodeModeHTTPServer(
        backend,
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        on_shutdown=lambda: None,
    )
    server.start()
    manager = DatabaseManager()
    opened = manager.open_database(str(idb), set_current=True)
    failures: list[Exception] = []

    def execute() -> None:
        try:
            manager.execute_python("first", opened["instance_id"])
        except Exception as exc:  # noqa: BLE001 - asserted below
            failures.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert backend.started.wait(1)
    assert manager.cancel_active(opened["instance_id"]) is True
    thread.join(2)

    assert not thread.is_alive()
    assert failures
    assert manager.execute_python("second", opened["instance_id"], 1) == {
        "code": "second",
        "timeout": 1.0,
    }
    manager.shutdown()
    server.stop()
    server.release_registration()


def test_database_close_cancels_its_active_execution(tmp_path: Path) -> None:
    class BlockingBackend(StaticBackend):
        def __init__(self) -> None:
            self.started = threading.Event()
            self.cancelled = threading.Event()

        def execute_python(
            self,
            code: str,
            timeout: float | None,
            *,
            lease_id: str | None = None,
            persist_globals: bool = False,
        ):
            del lease_id, persist_globals
            self.started.set()
            assert self.cancelled.wait(2)
            raise RuntimeError("cancelled")

        def cancel_active(self) -> None:
            self.cancelled.set()

    executable = tmp_path / "test.exe"
    idb = tmp_path / "test.i64"
    executable.write_bytes(b"binary")
    idb.write_bytes(b"idb")
    backend = BlockingBackend()
    server = CodeModeHTTPServer(
        backend,
        InstanceIdentity(str(idb), str(executable), "idalib", managed=True),
        AnalysisState(),
        REGISTRY_DIR,
        lease_grace=30,
        on_shutdown=lambda: None,
    )
    server.start()
    manager = DatabaseManager()
    opened = manager.open_database(str(idb), set_current=True)
    failures: list[Exception] = []

    def execute() -> None:
        try:
            manager.execute_python("while True: pass", opened["instance_id"])
        except Exception as exc:  # noqa: BLE001 - asserted below
            failures.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert backend.started.wait(1)
    started = time.monotonic()
    manager.close_database(opened["instance_id"])
    assert time.monotonic() - started < 1
    assert backend.cancelled.wait(1)
    thread.join(2)
    assert not thread.is_alive()
    assert failures
    server.stop()
    server.release_registration()
