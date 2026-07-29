import json
import tempfile
import unittest
from pathlib import Path

import ida_codemode_dashboard as dashboard


class TranscriptTests(unittest.TestCase):
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

    def test_extracts_models_from_supported_agent_transcripts(self) -> None:
        self.assertEqual(
            dashboard._agent_models(
                [{"type": "assistant", "message": {"model": "claude-opus-5"}}],
                "claude",
            ),
            ["claude-opus-5"],
        )
        self.assertEqual(
            dashboard._agent_models(
                [
                    {"type": "model_change", "modelId": "gpt-5.6"},
                    {
                        "type": "message",
                        "message": {"role": "assistant", "model": "gpt-5.6"},
                    },
                ],
                "pi",
            ),
            ["gpt-5.6"],
        )
        self.assertEqual(
            dashboard._agent_models(
                [
                    {
                        "type": "turn_context",
                        "payload": {"model": "gpt-5.5"},
                    }
                ],
                "codex",
            ),
            ["gpt-5.5"],
        )


class SemanticSessionTests(unittest.TestCase):
    def test_scan_hides_traces_without_tool_or_agent_activity(self) -> None:
        def write(path: Path, records: list[dict[str, object]]) -> None:
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

        base = {
            "schema": 1,
            "ts": "2026-01-01T00:00:00Z",
            "pid": 999999,
        }
        with tempfile.TemporaryDirectory() as directory:
            sessions_dir = Path(directory)
            agent_path = sessions_dir / "agent.trace"
            write(
                agent_path,
                [
                    {"type": "session", "version": 3, "id": "pi-session"},
                    {
                        "type": "message",
                        "message": {"role": "assistant", "model": "gpt-5.6"},
                    },
                ],
            )
            write(
                sessions_dir / "empty.jsonl",
                [{**base, "event": "mcp_stopped", "mcp_server_id": "empty"}],
            )
            write(
                sessions_dir / "lifecycle.jsonl",
                [
                    {
                        **base,
                        "event": "database_opened",
                        "mcp_server_id": "lifecycle",
                        "target": {"idb_path": "/tmp/pytest/open.i64"},
                    }
                ],
            )
            write(
                sessions_dir / "tool.jsonl",
                [
                    {
                        **base,
                        "event": "tool_call",
                        "mcp_server_id": "tool",
                        "tool": "reference",
                    }
                ],
            )
            write(
                sessions_dir / "agent.jsonl",
                [
                    {
                        **base,
                        "event": "mcp_started",
                        "mcp_server_id": "agent",
                        "agent": "pi",
                        "session": {"pi_session_path": str(agent_path)},
                    }
                ],
            )

            original = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            try:
                summaries = dashboard._scan_sessions()
                index = dashboard.render_index()
            finally:
                dashboard.SESSIONS_DIR = original

        self.assertIn("gpt-5.6", index)
        self.assertEqual(
            next(s.agent for s in summaries if s.session_id == "agent"), "pi"
        )
        self.assertEqual(
            {summary.session_id for summary in summaries},
            {"tool", "agent"},
        )


if __name__ == "__main__":
    unittest.main()
