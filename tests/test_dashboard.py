import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import ida_codemode_dashboard as dashboard


class IndexSortingTests(unittest.TestCase):
    def test_sessions_default_to_most_recent_start_not_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logs_dir = Path(temp_dir)
            old_log = logs_dir / "old-target-oldid.jsonl"
            new_log = logs_dir / "new-target-newid.jsonl"
            old_log.write_text(
                "\n".join(
                    json.dumps(record)
                    for record in [
                        {"ts": "2026-01-01T10:00:00Z", "event": "instance_started"},
                        {"ts": "2026-01-01T13:00:00Z", "event": "bridge_output"},
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            new_log.write_text(
                json.dumps(
                    {"ts": "2026-01-01T12:00:00Z", "event": "instance_started"}
                )
                + "\n",
                encoding="utf-8",
            )

            with patch.object(dashboard, "LOGS_DIR", logs_dir):
                summaries = dashboard._scan_bridge_logs()
                rendered = dashboard.render_index()

        self.assertEqual(
            [summary.path.name for summary in summaries],
            [new_log.name, old_log.name],
        )
        self.assertLess(rendered.index(new_log.name), rendered.index(old_log.name))
        self.assertIn('<th class="sort-desc" data-dir="desc">Started</th>', rendered)


class AnalysisGroupingTests(unittest.TestCase):
    def test_codemode_id_groups_benchmark_logs_without_agent_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logs_dir = Path(temp_dir)
            for name, target, minute in (
                ("first.bin-one.jsonl", "first.bin", "00"),
                ("second.bin-two.jsonl", "second.bin", "01"),
            ):
                (logs_dir / name).write_text(
                    json.dumps(
                        {
                            "ts": f"2026-01-01T10:{minute}:00Z",
                            "event": "instance_started",
                            "codemode_id": "benchmark-run-42",
                            "payload": {"path": f"/tmp/{target}"},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            with patch.object(dashboard, "LOGS_DIR", logs_dir):
                summaries = dashboard._scan_bridge_logs()
                groups, flat = dashboard._group_analysis_sessions(summaries)
                index_html = dashboard.render_index()
                analysis_html = dashboard.render_analysis_session(
                    codemode_id="benchmark-run-42"
                )

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].group_type, "codemode")
        self.assertEqual(groups[0].group_id, "benchmark-run-42")
        self.assertEqual(flat, [])
        self.assertIn("/analysis?id=benchmark-run-42", index_html)
        self.assertIsNotNone(analysis_html)
        assert analysis_html is not None
        self.assertIn("benchmark-run-42", analysis_html)
        self.assertIn("none recorded", analysis_html)

    def test_one_log_with_multiple_agent_sessions_is_grouped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logs_dir = Path(temp_dir)
            log_path = logs_dir / "sample.bin-instance.jsonl"
            log_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "ts": "2026-01-01T10:00:00Z",
                                "event": "instance_started",
                                "pi_session_path": "/tmp/pi-one.jsonl",
                            }
                        ),
                        json.dumps(
                            {
                                "ts": "2026-01-01T11:00:00Z",
                                "event": "request",
                                "pi_session_path": "/tmp/pi-two.jsonl",
                                "payload": {"command": "execute", "code": "lambda: 1"},
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with patch.object(dashboard, "LOGS_DIR", logs_dir):
                summary = dashboard._summarize_bridge_log(log_path)
                groups, flat = dashboard._group_analysis_sessions([summary])

        self.assertEqual(len(summary.agent_session_refs), 2)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].group_type, "agent")
        self.assertEqual(len(groups[0].agent_sessions), 2)
        self.assertEqual(flat, [])

    def test_shared_agent_session_groups_logs_and_renders_combined_page(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            shared_session = root / "shared-session.jsonl"
            singleton_session = root / "singleton-session.jsonl"
            shared_session.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "type": "session",
                                "version": 3,
                                "id": "shared",
                                "timestamp": "2026-01-01T09:59:00Z",
                                "cwd": "/tmp/analysis",
                            }
                        ),
                        json.dumps(
                            {
                                "type": "message",
                                "id": "user",
                                "parentId": None,
                                "timestamp": "2026-01-01T10:00:00Z",
                                "message": {
                                    "role": "user",
                                    "content": "analyze both binaries",
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            singleton_session.write_text(
                json.dumps(
                    {
                        "type": "session",
                        "version": 3,
                        "id": "singleton",
                        "timestamp": "2026-01-01T08:00:00Z",
                        "cwd": "/tmp/analysis",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            def write_bridge(
                filename: str, target: str, ts: str, session_path: Path | None
            ) -> None:
                metadata = (
                    {"pi_session_path": str(session_path)} if session_path else {}
                )
                records = [
                    {
                        "ts": ts,
                        "event": "instance_started",
                        "instance_id": filename,
                        **metadata,
                    },
                    {
                        "ts": ts,
                        "event": "request",
                        "request_id": f"open-{filename}",
                        "payload": {"command": "open", "path": f"/tmp/{target}"},
                        **metadata,
                    },
                    {
                        "ts": ts,
                        "event": "response",
                        "request_id": f"open-{filename}",
                        "payload": {"ok": True, "result": {"opened": True}},
                    },
                ]
                (logs_dir / filename).write_text(
                    "\n".join(json.dumps(record) for record in records) + "\n",
                    encoding="utf-8",
                )

            write_bridge(
                "first.bin-firstid.jsonl",
                "first.bin",
                "2026-01-01T10:01:00Z",
                shared_session,
            )
            write_bridge(
                "second.bin-secondid.jsonl",
                "second.bin",
                "2026-01-01T10:02:00Z",
                shared_session,
            )
            write_bridge(
                "single.bin-singleid.jsonl",
                "single.bin",
                "2026-01-01T08:01:00Z",
                singleton_session,
            )
            write_bridge(
                "unlinked.bin-unlinkedid.jsonl",
                "unlinked.bin",
                "2026-01-01T07:01:00Z",
                None,
            )

            dashboard._AGENT_ITEMS_CACHE.clear()
            with patch.object(dashboard, "LOGS_DIR", logs_dir):
                summaries = dashboard._scan_bridge_logs()
                groups, flat = dashboard._group_analysis_sessions(summaries)
                index_html = dashboard.render_index()
                analysis_html = dashboard.render_analysis_session(str(shared_session))
                binary_html = dashboard.render_bridge_log("first.bin-firstid.jsonl")

        self.assertEqual(len(groups), 1)
        self.assertEqual(
            {summary.target for summary in groups[0].summaries},
            {"first.bin", "second.bin"},
        )
        self.assertEqual(
            {summary.target for summary in flat},
            {"single.bin", "unlinked.bin"},
        )
        self.assertEqual(index_html.count("/analysis?path="), 1)
        self.assertIn("first.bin-firstid.jsonl", index_html)
        self.assertIn("second.bin-secondid.jsonl", index_html)
        self.assertIn("single.bin-singleid.jsonl", index_html)
        self.assertIsNotNone(analysis_html)
        assert analysis_html is not None
        self.assertIn("first.bin", analysis_html)
        self.assertIn("second.bin", analysis_html)
        self.assertIn("analyze both binaries", analysis_html)
        self.assertIn("Combined timeline", analysis_html)
        self.assertIsNotNone(binary_html)
        assert binary_html is not None
        self.assertIn("/analysis?path=", binary_html)


class ToolNameTests(unittest.TestCase):
    def test_pi_prefixed_ida_tools_are_recognized_and_rendered(self) -> None:
        self.assertEqual(dashboard._codemode_tool_name("ida_execute"), "execute")
        self.assertEqual(
            dashboard._tool_display_name("ida_open_database"),
            "ida · open_database",
        )
        self.assertIsNone(dashboard._codemode_tool_name("bash"))

        rendered = dashboard._tool_input_html(
            "ida_execute", {"code": "def run():\n    return 1"}
        )
        self.assertIn("<pre><code>", rendered)
        self.assertIn("def", rendered)
        self.assertNotIn("other arguments", rendered)


class PiSessionTests(unittest.TestCase):
    def test_inline_transcript_keeps_non_ida_tools_only(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        items = [
            dashboard.TranscriptItem(ts, "tool", "ida", tool_name="ida_execute"),
            dashboard.TranscriptItem(ts, "tool", "bash", tool_name="bash"),
        ]
        summary = dashboard.BridgeLogSummary(
            path=Path("bridge.jsonl"),
            target="target",
            instance_id="instance",
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
                summary, "bridge.jsonl", lambda _ts, html: added.append(html)
            )

        self.assertEqual(count, 1)
        self.assertEqual(len(added), 1)
        self.assertIn("bash", added[0])
        self.assertNotIn("ida", added[0])

    def test_only_active_pi_branch_is_rendered_with_tool_names(self) -> None:
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
                "message": {"role": "user", "content": "active prompt"},
            },
            {
                "type": "message",
                "id": "abandoned",
                "parentId": "root",
                "timestamp": "2026-01-01T00:00:02Z",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "abandoned reply"}],
                },
            },
            {
                "type": "message",
                "id": "active-call",
                "parentId": "root",
                "timestamp": "2026-01-01T00:00:03Z",
                "message": {
                    "role": "assistant",
                    "provider": "test",
                    "model": "model",
                    "content": [
                        {"type": "thinking", "thinking": "active reasoning"},
                        {
                            "type": "toolCall",
                            "id": "ida-call",
                            "name": "ida_execute",
                            "arguments": {"code": "lambda: 1"},
                        },
                        {
                            "type": "toolCall",
                            "id": "bash-call",
                            "name": "bash",
                            "arguments": {"command": "pwd"},
                        },
                    ],
                },
            },
            {
                "type": "message",
                "id": "ida-result",
                "parentId": "active-call",
                "timestamp": "2026-01-01T00:00:04Z",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "ida-call",
                    "toolName": "ida_execute",
                    "content": [{"type": "text", "text": "1"}],
                    "isError": False,
                },
            },
            {
                "type": "message",
                "id": "bash-result",
                "parentId": "ida-result",
                "timestamp": "2026-01-01T00:00:05Z",
                "message": {
                    "role": "toolResult",
                    "toolCallId": "bash-call",
                    "toolName": "bash",
                    "content": [{"type": "text", "text": "/tmp/project"}],
                    "isError": False,
                },
            },
        ]

        items, meta = dashboard._pi_items(records)

        self.assertEqual(meta["version"], "3")
        self.assertNotIn("abandoned reply", "".join(item.html for item in items))
        self.assertIn("active reasoning", "".join(item.html for item in items))
        self.assertEqual(
            [item.tool_name for item in items if item.category == "tool"],
            ["ida_execute", "bash"],
        )
        self.assertIn("ida · execute", "".join(item.html for item in items))


if __name__ == "__main__":
    unittest.main()
