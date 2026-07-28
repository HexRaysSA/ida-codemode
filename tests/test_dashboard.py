import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import ida_codemode_dashboard as dashboard


def write_session(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


class SessionDashboardTests(unittest.TestCase):
    def test_sessions_are_scanned_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sessions = Path(temp_dir)
            old = sessions / "old.jsonl"
            new = sessions / "new.jsonl"
            write_session(
                old,
                [
                    {
                        "schema": 1,
                        "ts": "2026-01-01T10:00:00+00:00",
                        "mcp_server_id": "old",
                        "pid": 999999,
                        "event": "mcp_started",
                    },
                    {
                        "schema": 1,
                        "ts": "2026-01-01T13:00:00+00:00",
                        "mcp_server_id": "old",
                        "pid": 999999,
                        "event": "mcp_stopped",
                    },
                ],
            )
            write_session(
                new,
                [
                    {
                        "schema": 1,
                        "ts": "2026-01-01T12:00:00+00:00",
                        "mcp_server_id": "new",
                        "pid": 999999,
                        "event": "mcp_started",
                    }
                ],
            )
            with patch.object(dashboard, "SESSIONS_DIR", sessions):
                summaries = dashboard._scan_sessions()
                rendered = dashboard.render_index()

        self.assertEqual([item.session_id for item in summaries], ["new", "old"])
        self.assertEqual(summaries[0].status, "killed")
        self.assertEqual(summaries[1].status, "closed")
        self.assertLess(rendered.index("new.jsonl"), rendered.index("old.jsonl"))

    def test_summary_and_timeline_use_semantic_tool_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sessions = Path(temp_dir)
            trace = sessions / "session-id.jsonl"
            session_meta = {
                "codemode_id": "benchmark-7",
                "pi_session_path": "/tmp/pi-session.jsonl",
            }
            target = {
                "instance_id": "local-id",
                "record_id": "123-abcdef",
                "backend": "gui",
                "pid": 123,
                "idb_path": "/tmp/sample.i64",
                "exe_path": "/tmp/sample",
            }
            write_session(
                trace,
                [
                    {
                        "schema": 1,
                        "ts": "2026-01-01T10:00:00+00:00",
                        "mcp_server_id": "session-id",
                        "pid": 999999,
                        "event": "database_opened",
                        "session": session_meta,
                        "target": target,
                    },
                    {
                        "schema": 1,
                        "ts": "2026-01-01T10:00:01+00:00",
                        "mcp_server_id": "session-id",
                        "pid": 999999,
                        "event": "tool_call",
                        "call_id": "execute-python-1",
                        "tool": "execute_python",
                        "session": session_meta,
                        "input": {"code": "lambda: 42"},
                    },
                    {
                        "schema": 1,
                        "ts": "2026-01-01T10:00:02+00:00",
                        "mcp_server_id": "session-id",
                        "pid": 999999,
                        "event": "tool_result",
                        "call_id": "execute-python-1",
                        "tool": "execute_python",
                        "session": session_meta,
                        "duration_ms": 1000,
                        "output": {"result": 42},
                    },
                    {
                        "schema": 1,
                        "ts": "2026-01-01T10:00:03+00:00",
                        "mcp_server_id": "session-id",
                        "pid": 999999,
                        "event": "tool_call",
                        "call_id": "reference-1",
                        "tool": "reference",
                        "session": session_meta,
                        "input": {"query": "Database.open"},
                    },
                    {
                        "schema": 1,
                        "ts": "2026-01-01T10:00:04+00:00",
                        "mcp_server_id": "session-id",
                        "pid": 999999,
                        "event": "tool_result",
                        "call_id": "reference-1",
                        "tool": "reference",
                        "session": session_meta,
                        "output": "IDA Domain API reference",
                    },
                ],
            )
            with patch.object(dashboard, "SESSIONS_DIR", sessions):
                summary = dashboard._summarize_session(trace)
                rendered = dashboard.render_session(trace.name)

        self.assertEqual(summary.executes, 1)
        self.assertEqual(summary.tool_calls, 2)
        self.assertEqual(summary.codemode_id, "benchmark-7")
        self.assertEqual(summary.targets[0]["record_id"], "123-abcdef")
        self.assertIn(("pi", "/tmp/pi-session.jsonl"), summary.agent_session_refs)
        self.assertIsNotNone(rendered)
        assert rendered is not None
        self.assertIn("sample.i64", rendered)
        self.assertIn("lambda", rendered)
        self.assertIn("IDA Domain API reference", rendered)


class ToolNameTests(unittest.TestCase):
    def test_ida_tools_are_recognized_and_rendered(self) -> None:
        for name in (
            "ida_execute_python",
            "ida_reference",
            "ida_open_database",
            "ida_save_database",
            "ida_close_database",
        ):
            self.assertIsNotNone(dashboard._codemode_tool_name(name))
        self.assertEqual(
            dashboard._tool_display_name("ida_open_database"),
            "ida · open_database",
        )
        rendered = dashboard._tool_input_html(
            "ida_execute_python", {"code": "def run():\n    return 1"}
        )
        self.assertIn("<pre><code>", rendered)
        self.assertIn("def", rendered)


class TranscriptTests(unittest.TestCase):
    def test_inline_transcript_keeps_non_ida_tools_only(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        items = [
            dashboard.TranscriptItem(ts, "tool", "ida", tool_name="ida_execute_python"),
            dashboard.TranscriptItem(ts, "tool", "bash", tool_name="bash"),
        ]
        summary = dashboard.SessionSummary(
            path=Path("session.jsonl"),
            session_id="session",
            size=0,
            agent_sessions={"pi": "/tmp/pi-session.jsonl"},
        )
        added: list[str] = []
        with (
            patch.object(dashboard, "_transcript_window", return_value=(None, None)),
            patch.object(
                dashboard,
                "_load_agent_items",
                return_value=(items, {}, "pi", dashboard._blank_totals()),
            ),
        ):
            count = dashboard._interleave_transcript(
                summary, "session.jsonl", lambda _ts, html: added.append(html)
            )
        self.assertEqual(count, 1)
        self.assertIn("bash", added[0])
        self.assertNotIn("ida", added[0])

    def test_active_pi_branch_keeps_tool_names(self) -> None:
        records = [
            {
                "type": "session",
                "version": 3,
                "id": "session-id",
                "timestamp": "2026-01-01T00:00:00Z",
                "cwd": "/tmp/project",
            },
            {
                "type": "message",
                "id": "root",
                "parentId": None,
                "timestamp": "2026-01-01T00:00:01Z",
                "message": {"role": "user", "content": "prompt"},
            },
            {
                "type": "message",
                "id": "call",
                "parentId": "root",
                "timestamp": "2026-01-01T00:00:02Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "toolCall",
                            "id": "ida-call",
                            "name": "ida_execute_python",
                            "arguments": {"code": "lambda: 1"},
                        }
                    ],
                },
            },
            {
                "type": "message",
                "id": "result",
                "parentId": "call",
                "timestamp": "2026-01-01T00:00:03Z",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "ida-call",
                    "toolName": "ida_execute_python",
                    "content": [{"type": "text", "text": "1"}],
                    "isError": False,
                },
            },
        ]
        items, meta = dashboard._pi_items(records)
        self.assertEqual(meta["version"], "3")
        self.assertEqual(
            [item.tool_name for item in items if item.category == "tool"],
            ["ida_execute_python"],
        )
        self.assertIn("ida · execute_python", "".join(item.html for item in items))


if __name__ == "__main__":
    unittest.main()
