import json
import os
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock

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

    def test_transcript_cache_replaces_changed_file_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pi.jsonl"
            path.write_text(
                json.dumps({"type": "session", "version": 3, "id": "pi-session"})
                + "\n",
                encoding="utf-8",
            )
            dashboard._AGENT_ITEMS_CACHE.clear()
            first = dashboard._load_agent_items(str(path))

            with path.open("a", encoding="utf-8") as file:
                file.write(
                    json.dumps(
                        {
                            "type": "message",
                            "message": {
                                "role": "assistant",
                                "model": "gpt-5.6",
                                "content": [],
                            },
                        }
                    )
                    + "\n"
                )
            second = dashboard._load_agent_items(str(path))

        self.assertEqual(len(dashboard._AGENT_ITEMS_CACHE), 1)
        self.assertIsNot(first, second)
        self.assertEqual(second[1]["model"], "gpt-5.6")

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


class SessionTimelineTests(unittest.TestCase):
    def test_plugin_install_events_are_rendered(self) -> None:
        events: list[str] = []
        dashboard._add_session_timeline(
            [
                {
                    "ts": "2026-01-01T00:00:00Z",
                    "event": "plugin_install_failed",
                    "mcp_server_id": "s1",
                    "error": {"type": "FileNotFoundError", "message": "not found"},
                }
            ],
            lambda _ts, html: events.append(html),
        )
        self.assertEqual(len(events), 1)
        self.assertIn("plugin_install_failed", events[0])
        self.assertIn("FileNotFoundError", events[0])

    def test_unknown_events_fall_through_generic_else_branch(self) -> None:
        events: list[str] = []
        dashboard._add_session_timeline(
            [
                {
                    "ts": "2026-01-01T00:00:00Z",
                    "event": "some_future_event",
                    "mcp_server_id": "s1",
                    "detail": "unhandled but should still show up",
                }
            ],
            lambda _ts, html: events.append(html),
        )
        self.assertEqual(len(events), 1)
        self.assertIn("some_future_event", events[0])
        self.assertIn("unhandled but should still show up", events[0])


class SemanticSessionTests(unittest.TestCase):
    def test_dashboard_host_policy_blocks_loopback_dns_rebinding(self) -> None:
        for host in ("localhost:8736", "127.0.0.1:8736", "[::1]:8736"):
            self.assertTrue(dashboard._dashboard_host_allowed("127.0.0.1", host))
        self.assertFalse(
            dashboard._dashboard_host_allowed("127.0.0.1", "attacker.example:8736")
        )
        self.assertFalse(dashboard._dashboard_host_allowed("127.0.0.1", None))
        self.assertFalse(
            dashboard._dashboard_host_allowed("127.0.0.1", "localhost:not-a-port")
        )
        # Deliberately remote dashboard bindings retain their existing behavior.
        self.assertTrue(
            dashboard._dashboard_host_allowed("0.0.0.0", "dashboard.example:8736")
        )

    def test_dashboard_handler_enforces_host_policy(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        original_sessions_dir = dashboard.SESSIONS_DIR
        dashboard.SESSIONS_DIR = Path(temporary.name)
        server = dashboard.ThreadingHTTPServer(
            ("127.0.0.1", 0), dashboard.DashboardHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def status(host: str) -> int:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                connection.putrequest("GET", "/", skip_host=True)
                connection.putheader("Host", host)
                connection.endheaders()
                response = connection.getresponse()
                response.read()
                return response.status
            finally:
                connection.close()

        try:
            self.assertEqual(status(f"localhost:{server.server_port}"), 200)
            self.assertEqual(status(f"attacker.example:{server.server_port}"), 403)
        finally:
            server.shutdown()
            thread.join(2)
            server.server_close()
            dashboard.SESSIONS_DIR = original_sessions_dir
            temporary.cleanup()

    def test_pid_liveness_uses_a_safe_windows_probe(self) -> None:
        with (
            mock.patch.object(dashboard.os, "name", "nt"),
            mock.patch.object(
                dashboard, "_windows_pid_alive", return_value=True
            ) as windows_probe,
            mock.patch.object(dashboard.os, "kill") as kill,
        ):
            self.assertTrue(dashboard._pid_alive(1234))

        windows_probe.assert_called_once_with(1234)
        kill.assert_not_called()
        self.assertFalse(dashboard._pid_alive(0))

        if os.name == "nt":
            self.assertTrue(dashboard._windows_pid_alive(os.getpid()))

    def test_pid_liveness_handles_a_broken_posix_probe(self) -> None:
        with (
            mock.patch.object(dashboard.os, "name", "posix"),
            mock.patch.object(
                dashboard.os,
                "kill",
                side_effect=SystemError(
                    "<built-in function kill> returned a result with an exception set"
                ),
            ),
        ):
            self.assertFalse(dashboard._pid_alive(1234))

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

    def test_benchmark_autodetect_and_agent_resolution(self) -> None:
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
            run_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            run_dir = sessions_dir / run_id
            logs_dir = run_dir / "logs"
            mcp_dir = logs_dir / "ida-codemode"
            mcp_dir.mkdir(parents=True)

            (run_dir / "result.json").write_text("{}", encoding="utf-8")

            write(
                logs_dir / "session.jsonl",
                [
                    {"type": "user", "message": {"role": "user", "content": "hi"}},
                    {
                        "type": "assistant",
                        "message": {
                            "role": "assistant",
                            "model": "claude-opus-5",
                            "content": [{"type": "text", "text": "hello"}],
                        },
                    },
                ],
            )

            write(
                mcp_dir / "session.jsonl",
                [
                    {
                        **base,
                        "event": "mcp_started",
                        "mcp_server_id": "bench-test",
                        "agent": "claude-code",
                        "session": {
                            "claude_session_path": "/root/.claude/nonexistent.jsonl",
                        },
                    },
                    {
                        **base,
                        "event": "tool_call",
                        "mcp_server_id": "bench-test",
                        "tool": "execute_python",
                    },
                ],
            )

            original_dir = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            try:
                self.assertTrue(dashboard._is_benchmark_dir(sessions_dir))
                summaries = dashboard._scan_sessions()
                index = dashboard.render_index()
                self.assertEqual(len(summaries), 1)
                self.assertIn("bench-test", index)
                summary = summaries[0]
                self.assertEqual(summary.session_id, "bench-test")
                resolved = summary.agent_sessions.get("claude")
                assert resolved is not None
                self.assertEqual(
                    Path(resolved),
                    logs_dir / "session.jsonl",
                )
            finally:
                dashboard.SESSIONS_DIR = original_dir

    def test_schema_validation_rejects_non_matching_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sessions_dir = Path(directory)
            (sessions_dir / "random.jsonl").write_text(
                '{"foo": "bar"}\n', encoding="utf-8"
            )
            (sessions_dir / "empty.jsonl").write_text("", encoding="utf-8")
            (sessions_dir / "bad.jsonl").write_text("not json\n", encoding="utf-8")

            original = dashboard.SESSIONS_DIR
            dashboard.SESSIONS_DIR = sessions_dir
            try:
                summaries = dashboard._scan_sessions()
            finally:
                dashboard.SESSIONS_DIR = original

            self.assertEqual(len(summaries), 0)


if __name__ == "__main__":
    unittest.main()
