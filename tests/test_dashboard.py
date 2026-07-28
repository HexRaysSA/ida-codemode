import unittest

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


if __name__ == "__main__":
    unittest.main()
