"""IDA Domain Code Mode MCP server.

This server exposes a compact Code Mode surface for the ida-domain API:
- reference(query): look up the active ida-domain API reference
- open_database(...): attach to a GUI database or shared idalib worker
- execute(code): run Python against an already-open database
- list_databases(): inspect this MCP server's active database handles
- save_database(...): explicitly save an active database
- close_database(...): release this MCP server's handle and lease
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import signal
import sys
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

from zeromcp import McpServer, McpToolError

from ida_codemode.client import ClientError, DatabaseHandle, RemoteError
from ida_codemode.reference import (
    find_ida_domain_package_path,
    get_ida_domain_version,
    render_reference,
)
from ida_codemode.registry import LOG_DIR
from ida_codemode.resolver import ResolveError

STATE_DIR = Path.home() / ".ida-codemode"
SESSIONS_DIR = STATE_DIR / "sessions"
OPEN_TIMEOUT_SECONDS = 300
EXECUTE_TIMEOUT_SECONDS = 300

mcp = McpServer("ida", version="0.2.0")


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _resolve_user_path(path: str) -> str:
    return str(Path(path).expanduser().resolve())


def _session_fields() -> dict[str, Any]:
    try:
        meta = mcp.context.meta or {}
    except (AttributeError, LookupError, RuntimeError):
        # The shutdown path may run outside an MCP request context.
        meta = {}
    fields: dict[str, Any] = {
        "codemode_id": os.environ.get("IDA_CODEMODE_ID") or None,
    }
    for name in (
        "claude_session_path",
        "codex_session_path",
        "pi_session_path",
    ):
        value = meta.get(name)
        if isinstance(value, str) and value:
            fields[name] = value
    return fields


def _trace_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _trace_jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _trace_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_trace_jsonable(item) for item in value]
    return repr(value)


class _TraceLogger:
    """Thread-safe semantic MCP trace shared by all database handles."""

    def __init__(self) -> None:
        self.server_id = uuid.uuid4().hex[:12]
        SESSIONS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            SESSIONS_DIR.chmod(0o700)
        except OSError:
            if os.name != "nt":
                raise
        self.path = SESSIONS_DIR / f"{self.server_id}.jsonl"
        self._lock = threading.Lock()

    def emit(self, event: str, **fields: Any) -> None:
        record = {
            "schema": 1,
            "ts": _utc_now_iso(),
            "mcp_server_id": self.server_id,
            "pid": os.getpid(),
            "event": event,
            **fields,
        }
        encoded = (
            json.dumps(
                _trace_jsonable(record),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )
        with self._lock:
            fd = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            with os.fdopen(fd, "a", encoding="utf-8") as file:
                file.write(encoded)
                file.flush()


TRACE = _TraceLogger()


def _install_hook_input_meta_adapter() -> None:
    """Promote Claude/Codex hook metadata from arguments into MCP request metadata."""

    original_tools_call = mcp.registry.methods["tools/call"]

    def tools_call_with_meta(
        name: str,
        arguments: dict[str, Any] | None = None,
        _meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        clean_arguments = arguments
        request_meta = dict(_meta) if isinstance(_meta, dict) else {}

        if isinstance(arguments, dict):
            clean_arguments = dict(arguments)
            input_meta = clean_arguments.pop("_meta", None)
            if isinstance(input_meta, dict):
                request_meta.update(input_meta)

        return original_tools_call(name, clean_arguments, request_meta or None)

    mcp.registry.methods["tools/call"] = tools_call_with_meta


_install_hook_input_meta_adapter()


def _target_fields(handle: DatabaseHandle) -> dict[str, Any]:
    entry = handle.entry
    return {
        "record_id": entry.record_id,
        "backend": entry.backend,
        "pid": entry.pid,
        "port": entry.port,
        "idb_path": entry.idb_path,
        "idb_key": entry.idb_key,
        "exe_path": entry.exe_path,
        "managed": entry.managed,
        "started_at": entry.started_at,
        "worker_log_path": (
            str(LOG_DIR / f"{entry.record_id}.log")
            if entry.backend == "idalib"
            else None
        ),
    }


def _error_fields(error: Exception) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "type": type(error).__name__,
        "message": str(error),
        "traceback": traceback.format_exc(),
    }
    if isinstance(error, RemoteError):
        fields.update(
            code=error.code,
            status=error.status,
            details=error.details,
        )
    return fields


def _as_tool_error(error: Exception) -> McpToolError:
    if isinstance(error, McpToolError):
        return error
    if isinstance(error, RemoteError):
        message = str(error)
        remote_traceback = error.details.get("traceback")
        if isinstance(remote_traceback, str) and remote_traceback:
            message = f"{message}\n\n{remote_traceback}"
        return McpToolError(message)
    if isinstance(error, (ClientError, ResolveError, FileNotFoundError, ValueError)):
        return McpToolError(str(error))
    return McpToolError(str(error) or type(error).__name__)


def _run_traced_tool(
    tool: str,
    arguments: dict[str, Any],
    action: Callable[[], Any],
) -> Any:
    call_id = uuid.uuid4().hex
    session = _session_fields()
    TRACE.emit(
        "tool_call",
        call_id=call_id,
        tool=tool,
        session=session,
        input=arguments,
    )
    started = time.monotonic()
    try:
        result = action()
    except Exception as error:
        TRACE.emit(
            "tool_error",
            call_id=call_id,
            tool=tool,
            session=session,
            duration_ms=round((time.monotonic() - started) * 1000, 3),
            error=_error_fields(error),
        )
        tool_error = _as_tool_error(error)
        if tool_error is error:
            raise
        raise tool_error from error
    TRACE.emit(
        "tool_result",
        call_id=call_id,
        tool=tool,
        session=session,
        duration_ms=round((time.monotonic() - started) * 1000, 3),
        output=result,
    )
    return result


@dataclass
class _DatabaseSession:
    instance_id: str
    requested_path: str
    handle: DatabaseHandle
    record_id: str
    operation_lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
    )


class _DatabaseManager:
    def __init__(self) -> None:
        self._instances: dict[str, _DatabaseSession] = {}
        self._current_instance_id: str | None = None
        self._lock = threading.RLock()
        self._open_lock = threading.Lock()
        self._shutdown_started = False
        self._trace_lifecycle_started = False

    def start(self, transport: str) -> None:
        with self._lock:
            if self._trace_lifecycle_started:
                return
            self._trace_lifecycle_started = True
        TRACE.emit(
            "mcp_started",
            session=_session_fields(),
            transport=transport,
            trace_path=str(TRACE.path),
        )

    def _database_info(self, session: _DatabaseSession) -> dict[str, Any]:
        return {
            "instance_id": session.instance_id,
            "requested_path": session.requested_path,
            **_target_fields(session.handle),
        }

    def _note_binding(self, session: _DatabaseSession) -> None:
        entry = session.handle.entry
        if entry.record_id == session.record_id:
            return
        previous = session.record_id
        session.record_id = entry.record_id
        TRACE.emit(
            "database_rebound",
            session=_session_fields(),
            instance_id=session.instance_id,
            previous_record_id=previous,
            target=_target_fields(session.handle),
        )

    def open_database(self, path: str, *, set_current: bool) -> dict[str, Any]:
        resolved_path = _resolve_user_path(path)
        if not Path(resolved_path).exists():
            raise McpToolError(f"database path does not exist: {resolved_path}")

        # Serialize local opens so duplicate calls create at most one retained
        # lease in this MCP server. Other MCP servers retain their own leases.
        with self._open_lock:
            handle = DatabaseHandle.open(
                resolved_path,
                timeout=OPEN_TIMEOUT_SECONDS,
            )
            entry = handle.entry
            with self._lock:
                existing = next(
                    (
                        session
                        for session in self._instances.values()
                        if session.handle.entry.record_id == entry.record_id
                    ),
                    None,
                )
                if existing is not None:
                    if set_current or self._current_instance_id is None:
                        self._current_instance_id = existing.instance_id
                    current = self._current_instance_id
                else:
                    instance_id = uuid.uuid4().hex[:12]
                    existing = _DatabaseSession(
                        instance_id=instance_id,
                        requested_path=resolved_path,
                        handle=handle,
                        record_id=entry.record_id,
                    )
                    self._instances[instance_id] = existing
                    if set_current or self._current_instance_id is None:
                        self._current_instance_id = instance_id
                    current = self._current_instance_id

            reused = existing.handle is not handle
            if reused:
                handle.close()
                event = "database_reused"
            else:
                event = "database_opened"
            database = self._database_info(existing)
            TRACE.emit(
                event,
                session=_session_fields(),
                instance_id=existing.instance_id,
                target=database,
            )
            return {
                "opened": True,
                "reused": reused,
                "instance_id": existing.instance_id,
                "current_instance_id": current,
                "database": database,
                "log_path": str(TRACE.path),
                **_session_fields(),
            }

    def _get_session(self, instance_id: str | None) -> tuple[str, _DatabaseSession]:
        with self._lock:
            target_id = instance_id or self._current_instance_id
            if target_id is None:
                raise McpToolError(
                    "no open database instance; call open_database() first"
                )
            session = self._instances.get(target_id)
        if session is None:
            raise McpToolError(f"unknown database instance: {target_id}")
        return target_id, session

    def execute(self, code: str, instance_id: str | None) -> dict[str, Any]:
        target_id, session = self._get_session(instance_id)
        with session.operation_lock:
            self._note_binding(session)
            result = session.handle.execute_python(
                code,
                timeout=EXECUTE_TIMEOUT_SECONDS,
            )
            self._note_binding(session)
            return {
                "instance_id": target_id,
                "current_instance_id": self.current_instance_id,
                "record_id": session.record_id,
                "database": self._database_info(session),
                "log_path": str(TRACE.path),
                "result": result,
            }

    def save_database(self, instance_id: str | None) -> dict[str, Any]:
        target_id, session = self._get_session(instance_id)
        with session.operation_lock:
            self._note_binding(session)
            result = session.handle.save_database()
            self._note_binding(session)
            TRACE.emit(
                "database_saved",
                session=_session_fields(),
                instance_id=target_id,
                target=self._database_info(session),
                result=result,
            )
            return {
                "instance_id": target_id,
                "current_instance_id": self.current_instance_id,
                "record_id": session.record_id,
                "log_path": str(TRACE.path),
                **result,
            }

    @property
    def current_instance_id(self) -> str | None:
        with self._lock:
            return self._current_instance_id

    def list_databases(self) -> dict[str, Any]:
        with self._lock:
            sessions = list(self._instances.values())
            current = self._current_instance_id
        instances = []
        for session in sessions:
            with session.operation_lock:
                self._note_binding(session)
                instances.append(
                    {
                        **self._database_info(session),
                        "current": session.instance_id == current,
                    }
                )
        return {
            "current_instance_id": current,
            "instances": instances,
            "count": len(instances),
            "log_path": str(TRACE.path),
        }

    def close_database(self, instance_id: str | None) -> dict[str, Any]:
        target_id, session = self._get_session(instance_id)
        with session.operation_lock:
            self._note_binding(session)
            database = self._database_info(session)
            with self._lock:
                current_session = self._instances.get(target_id)
                if current_session is not session:
                    raise McpToolError(f"unknown database instance: {target_id}")
                self._instances.pop(target_id)
                if self._current_instance_id == target_id:
                    self._current_instance_id = next(iter(self._instances), None)
                current = self._current_instance_id
            session.handle.close()
        TRACE.emit(
            "database_released",
            session=_session_fields(),
            instance_id=target_id,
            target=database,
        )
        return {
            "released": True,
            "instance_id": target_id,
            "current_instance_id": current,
            "database": database,
            "log_path": str(TRACE.path),
        }

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown_started:
                return
            self._shutdown_started = True
            sessions = list(self._instances.values())
            self._instances.clear()
            self._current_instance_id = None
        for session in sessions:
            try:
                with session.operation_lock:
                    session.handle.close()
            except Exception as error:  # noqa: BLE001 -- best-effort shutdown tracing
                TRACE.emit(
                    "database_release_error",
                    session=_session_fields(),
                    instance_id=session.instance_id,
                    error=_error_fields(error),
                )
        if self._trace_lifecycle_started:
            TRACE.emit("mcp_stopped", session=_session_fields())


DATABASE_MANAGER = _DatabaseManager()
atexit.register(DATABASE_MANAGER.shutdown)


def _install_server_shutdown_handlers() -> None:
    def cleanup_and_exit(signum: int, _frame: Any) -> None:
        DATABASE_MANAGER.shutdown()
        try:
            mcp.stop()
        finally:
            raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)


@mcp.tool
def reference(
    query: Annotated[
        str,
        "Class, method, or reverse-engineering concept to look up in the IDA reference.",
    ],
) -> str:
    """Look up the active ida-domain API and return a plain-text IDA reference."""

    return _run_traced_tool(
        "reference", {"query": query}, lambda: render_reference(query)
    )


@mcp.tool
def open_database(
    path: Annotated[
        str,
        "Path to a local executable or IDB. A GUI instance is used when available.",
    ],
    set_current: Annotated[
        bool,
        "Whether this database should become the default target for execute().",
    ] = True,
) -> dict[str, Any]:
    """Attach to a GUI database or shared managed idalib worker."""

    return _run_traced_tool(
        "open_database",
        {"path": path, "set_current": set_current},
        lambda: DATABASE_MANAGER.open_database(path, set_current=set_current),
    )


@mcp.tool
def execute(
    code: Annotated[
        str,
        (
            "Python code that runs against an already-open database. "
            "Use the IDA reference tool before calling execute; do not guess the API shape. "
            "The runtime exposes db, ida_domain, Database, IdaCommandOptions, database_path, "
            "database_options, json, and to_jsonable(). Return JSON-serializable data. "
            "Define run(...), execute(...), main(...), or pass a lambda expression."
        ),
    ],
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, use the current target.",
    ] = None,
) -> dict[str, Any]:
    """Execute Python against an open database. Use the IDA reference tool first."""

    return _run_traced_tool(
        "execute",
        {"code": code, "instance_id": instance_id},
        lambda: DATABASE_MANAGER.execute(code, instance_id),
    )


@mcp.tool
def list_databases() -> dict[str, Any]:
    """List this MCP server's active database handles and current default target."""

    return _run_traced_tool(
        "list_databases",
        {},
        DATABASE_MANAGER.list_databases,
    )


@mcp.tool
def save_database(
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, save the current target.",
    ] = None,
) -> dict[str, Any]:
    """Explicitly save an active GUI or idalib database."""

    return _run_traced_tool(
        "save_database",
        {"instance_id": instance_id},
        lambda: DATABASE_MANAGER.save_database(instance_id),
    )


@mcp.tool
def close_database(
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, release the current target.",
    ] = None,
) -> dict[str, Any]:
    """Release this MCP server's handle without disrupting other clients.

    If this is the final lease on a managed idalib worker, the worker saves and
    exits after its lease grace period. GUI databases are never closed here.
    """

    return _run_traced_tool(
        "close_database",
        {"instance_id": instance_id},
        lambda: DATABASE_MANAGER.close_database(instance_id),
    )


def _serve(transport: str) -> None:
    _install_server_shutdown_handlers()
    DATABASE_MANAGER.start(transport)

    if transport == "stdio":
        try:
            mcp.stdio()
        finally:
            DATABASE_MANAGER.shutdown()
        return

    url = urlparse(transport)
    if url.hostname is None or url.port is None:
        raise ValueError(f"Invalid transport URL: {transport}")

    print("Starting IDA Code Mode MCP server...")
    print(
        f"Using ida-domain {get_ida_domain_version()} from {find_ida_domain_package_path()}"
    )
    print(f"Writing semantic trace to {TRACE.path}")
    print("Available tools:")
    for name, func in mcp.tools.methods.items():
        print(f"  - {name}: {(func.__doc__ or '').strip()}")
    print()

    mcp.serve(url.hostname, url.port)

    try:
        input("Server is running, press Enter or Ctrl+C to stop...")
    except (KeyboardInterrupt, EOFError):
        print("\nStopping server...")
    finally:
        DATABASE_MANAGER.shutdown()
        mcp.stop()


def _report_claude_session(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = payload.get("input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    existing_meta = tool_input.get("_meta")
    if not isinstance(existing_meta, dict):
        existing_meta = {}

    transcript_path = payload.get("transcript_path")
    updated_input = dict(tool_input)

    updated_meta = dict(existing_meta)
    if isinstance(transcript_path, str) and transcript_path:
        updated_meta["claude_session_path"] = transcript_path

    if updated_meta:
        updated_input["_meta"] = updated_meta

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated_input,
        }
    }


def _report_codex_session(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = payload.get("input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    existing_meta = tool_input.get("_meta")
    if not isinstance(existing_meta, dict):
        existing_meta = {}

    transcript_path = payload.get("transcript_path")
    updated_input = dict(tool_input)

    updated_meta = dict(existing_meta)
    if isinstance(transcript_path, str) and transcript_path:
        updated_meta["codex_session_path"] = transcript_path

    if updated_meta:
        updated_input["_meta"] = updated_meta

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
        }
    }


def _report_session_main(platform: str) -> int:
    """Inject agent transcript/session metadata into a PreToolUse tool input."""

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"report-session: invalid JSON on stdin: {exc}", file=sys.stderr)
        return 1

    match platform:
        case "claude":
            response = _report_claude_session(payload)
        case "codex":
            response = _report_codex_session(payload)
        case _:
            print(f"report-session: unsupported platform: {platform}", file=sys.stderr)
            return 2

    print(json.dumps(response))
    return 0


def cli() -> int:
    parser = argparse.ArgumentParser(
        prog="ida-codemode-mcp",
        description="IDA Domain Code Mode MCP server",
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        help="Transport (stdio or http://host:port). Defaults to stdio.",
    )
    parser.add_argument(
        "--report-session",
        choices=["claude", "codex"],
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    if args.report_session is not None:
        return _report_session_main(args.report_session)

    _serve(args.transport)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
