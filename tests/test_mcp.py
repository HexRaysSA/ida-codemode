from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import ida_codemode_mcp as app
from ida_codemode.registry import RegistryEntry


class FakeHandle:
    def __init__(self, entry: RegistryEntry) -> None:
        self.entry = entry
        self.closed = False

    def execute_python(self, code: str, timeout: float | None = None):
        return {"code": code, "timeout": timeout}

    def save_database(self):
        return {"saved": True, "idb_path": self.entry.idb_path}

    def close(self) -> None:
        self.closed = True


def make_entry() -> RegistryEntry:
    return RegistryEntry(
        record_id="123-abcdef",
        backend="gui",
        pid=123,
        port=54321,
        token="token",
        version=1,
        idb_path="/tmp/test.i64",
        idb_key="0123456789abcdef",
        exe_path="/tmp/test",
        managed=False,
        started_at=1.0,
    )


def test_manager_reuses_one_local_handle_and_releases_it(tmp_path: Path) -> None:
    manager = app._DatabaseManager()
    handles: list[FakeHandle] = []

    def open_handle(path: str, *, timeout: float):
        handle = FakeHandle(make_entry())
        handles.append(handle)
        return handle

    target = tmp_path / "test"
    target.write_bytes(b"binary")
    old_path = app.TRACE.path
    app.TRACE.path = tmp_path / "manager.jsonl"
    try:
        with patch.object(app.DatabaseHandle, "open", side_effect=open_handle):
            first = manager.open_database(str(target), set_current=True)
            second = manager.open_database(str(target), set_current=True)

        assert first["instance_id"] == second["instance_id"]
        assert second["reused"] is True
        assert handles[1].closed is True
        assert manager.execute("lambda: 1", None)["result"]["code"] == "lambda: 1"
        assert manager.save_database(None)["saved"] is True
        assert manager.close_database(None)["released"] is True
        assert handles[0].closed is True
        manager.shutdown()
    finally:
        app.TRACE.path = old_path


def test_tool_trace_records_agent_metadata_and_reference(tmp_path: Path) -> None:
    old_path = app.TRACE.path
    app.TRACE.path = tmp_path / "trace.jsonl"
    try:
        with patch.object(
            app,
            "_session_fields",
            return_value={"pi_session_path": "/tmp/pi-session.jsonl"},
        ):
            result = app._run_traced_tool(
                "reference",
                {"query": "Database.open"},
                lambda: "reference result",
            )
        assert result == "reference result"
        records = [json.loads(line) for line in app.TRACE.path.read_text().splitlines()]
        assert [record["event"] for record in records] == [
            "tool_call",
            "tool_result",
        ]
        assert records[0]["call_id"] == records[1]["call_id"]
        assert records[0]["session"]["pi_session_path"] == "/tmp/pi-session.jsonl"
        assert records[1]["output"] == "reference result"
        assert records[0]["pid"] > 0
    finally:
        app.TRACE.path = old_path
