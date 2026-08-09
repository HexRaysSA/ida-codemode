#!/usr/bin/env python3
"""Standalone ZeroMCP server for observing client timeout and cancellation behavior.

Run it directly as an MCP stdio server, or let test_mcp_client.ts spawn it. All
human-readable diagnostics go to stderr so stdout remains a valid MCP stream.
"""

import argparse
import asyncio
import json
import os
import sys
import tempfile
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO, cast

from zeromcp import McpServer

mcp = McpServer("timeout-test", version="1.0.0")
STARTED = time.monotonic()
DEFAULT_LOG_PATH = Path(tempfile.gettempdir()) / "zeromcp-timeout-test.jsonl"
LOG_PATH: Path | None = None
LOG_LOCK = threading.Lock()


def log(event: str, **fields: Any) -> None:
    record = {
        "source": "python-server",
        "elapsed_ms": round((time.monotonic() - STARTED) * 1000, 3),
        "event": event,
        "pid": os.getpid(),
        "thread": threading.current_thread().name,
        **fields,
    }
    encoded = json.dumps(record, separators=(",", ":"))
    with LOG_LOCK:
        if LOG_PATH is not None:
            with LOG_PATH.open("a", encoding="utf-8") as file:
                file.write(encoded + "\n")
        print(encoded, file=sys.stderr, flush=True)


def wire_message(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"raw": data.decode("utf-8", errors="replace").rstrip("\r\n")}


class LoggingInput:
    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    def readline(self, size: int = -1) -> bytes:
        data = self.stream.readline(size)
        if data:
            log("mcp_inbound", message=wire_message(data))
        else:
            log("mcp_input_eof")
        return data

    def __getattr__(self, name: str) -> Any:
        return getattr(self.stream, name)


class LoggingOutput:
    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    def write(self, data: bytes) -> int:
        log("mcp_outbound", message=wire_message(data))
        return self.stream.write(data)

    def flush(self) -> None:
        self.stream.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.stream, name)


@mcp.tool
async def sleep(
    seconds: float = 5.0,
    poll_interval: float = 0.05,
    ignore_cancellation: bool = False,
) -> dict[str, Any]:
    """Sleep while racing normal completion against MCP cancellation."""

    if seconds < 0:
        raise ValueError("seconds must be non-negative")
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")

    request_id = mcp.context.request_id
    started = time.monotonic()
    operation = asyncio.create_task(asyncio.sleep(seconds))
    log(
        "tool_started",
        request_id=request_id,
        seconds=seconds,
        poll_interval=poll_interval,
        ignore_cancellation=ignore_cancellation,
    )
    try:
        try:
            await asyncio.shield(operation)
        except asyncio.CancelledError as error:
            reason = error.args[0] if error.args else None
            log(
                "cancellation_observed",
                request_id=request_id,
                reason=reason,
                tool_elapsed_ms=round((time.monotonic() - started) * 1000, 3),
            )
            if not ignore_cancellation:
                operation.cancel()
                with suppress(asyncio.CancelledError):
                    await operation
                raise
            await asyncio.shield(operation)

        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        log(
            "tool_completed",
            request_id=request_id,
            tool_elapsed_ms=elapsed_ms,
            ignore_cancellation=ignore_cancellation,
        )
        return {
            "completed": True,
            "elapsed_ms": elapsed_ms,
            "ignore_cancellation": ignore_cancellation,
            "pid": os.getpid(),
        }
    finally:
        log(
            "tool_finished",
            request_id=request_id,
            tool_elapsed_ms=round((time.monotonic() - started) * 1000, 3),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stdio-mode",
        choices=("async", "sync"),
        default="async",
        help=(
            "async reads cancellation notifications concurrently (the default); "
            "sync intentionally cannot read them while a tool call is blocking"
        ),
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path(os.environ.get("TEST_MCP_LOG", DEFAULT_LOG_PATH)),
        help=f"JSONL event and wire log (default: {DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "--append-log",
        action="store_true",
        help="append instead of truncating the log at startup",
    )
    return parser.parse_args()


def main() -> int:
    global LOG_PATH

    args = parse_args()
    LOG_PATH = args.log_file.expanduser().resolve()
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not args.append_log:
        LOG_PATH.write_text("", encoding="utf-8")

    # ZeroMCP only calls the intercepted methods on these transparent proxies,
    # but its public annotations require the concrete BinaryIO type.
    stdin = cast(BinaryIO, LoggingInput(sys.stdin.buffer))
    stdout = cast(BinaryIO, LoggingOutput(sys.stdout.buffer))
    log("server_started", stdio_mode=args.stdio_mode, log_path=str(LOG_PATH))
    try:
        if args.stdio_mode == "async":
            asyncio.run(mcp.stdio_async(stdin=stdin, stdout=stdout))
        else:
            mcp.stdio(stdin=stdin, stdout=stdout)
    finally:
        log("server_stopped", stdio_mode=args.stdio_mode, log_path=str(LOG_PATH))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
