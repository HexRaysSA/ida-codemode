"""IDA Domain Code Mode MCP server.

This server exposes a compact Code Mode surface for the ida-domain API:
- reference(query): look up the active ida-domain API reference
- open_database(...): attach to a GUI database or shared idalib worker
- execute_python(code): run Python against an already-open database
- list_databases(): discover registered GUI and idalib database instances
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
from typing import Annotated, Any, Literal, TypedDict
from urllib.parse import urlparse

from zeromcp import McpServer, McpToolError

from ida_codemode.client import ClientError, DatabaseHandle, RemoteError
from ida_codemode.reference import (
    find_ida_domain_package_path,
    get_ida_domain_version,
    render_reference,
)
from ida_codemode.registry import (
    LOG_DIR,
    REGISTRY_DIR,
    SPAWN_DIR,
    RegistryEntry,
    canonical_path,
    scan_instances,
)
from ida_codemode.resolver import ResolveError, expected_idb_path
from ida_codemode.runtime import PythonExecutionResult

STATE_DIR = Path.home() / ".ida-codemode"
SESSIONS_DIR = STATE_DIR / "sessions"
OPEN_TIMEOUT_SECONDS = 300
EXECUTE_TIMEOUT_SECONDS = 300

mcp = McpServer("ida", version="0.2.0")


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _resolve_user_path(path: str) -> str:
    return canonical_path(path)


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


def _entry_target_fields(entry: RegistryEntry) -> dict[str, Any]:
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


def _target_fields(handle: DatabaseHandle) -> dict[str, Any]:
    return _entry_target_fields(handle.entry)


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
        sections = [str(error)]
        for label in ("stdout", "stderr", "traceback"):
            value = error.details.get(label)
            if isinstance(value, str) and value:
                sections.append(f"{label}:\n{value.rstrip()}")
        return McpToolError("\n\n".join(sections))
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


DatabaseStatus = Literal["available", "attached", "current", "unavailable"]


class DatabaseListing(TypedDict):
    path: str
    backend: Annotated[str, "Instance backend: gui or idalib."]
    status: Annotated[
        str,
        "Action state: available, attached, current, or unavailable.",
    ]
    instance_id: str | None
    error: str | None


class ListDatabasesResult(TypedDict):
    instances: list[DatabaseListing]


class OpenDatabaseResult(TypedDict):
    instance_id: str
    backend: Annotated[str, "Instance backend: gui or idalib."]
    status: Annotated[str, "Attachment state: attached or current."]
    log_path: str
    codemode_id: str | None
    hint: str


class SaveDatabaseResult(TypedDict):
    path: str


class CloseDatabaseResult(TypedDict):
    closed: bool


@dataclass(frozen=True)
class _AttachedDatabase:
    entry: RegistryEntry
    instance_id: str
    current: bool


@dataclass
class _DatabaseSession:
    instance_id: str
    requested_path: str
    handle: DatabaseHandle
    operation_lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
    )


class _DatabaseManager:
    def __init__(
        self,
        registry_dir: Path = REGISTRY_DIR,
        spawn_dir: Path = SPAWN_DIR,
    ) -> None:
        self.registry_dir = registry_dir
        self.spawn_dir = spawn_dir
        self._instances: dict[str, _DatabaseSession] = {}
        self._disconnected_instances: dict[str, str] = {}
        self._disconnected_default: str | None = None
        self._current_instance_id: str | None = None
        self._lock = threading.RLock()
        self._open_lock = threading.Lock()
        self._shutdown_started = False
        self._trace_lifecycle_started = False

    def _emit(self, event: str, **fields: Any) -> None:
        """Emit manager events only while this manager is serving an MCP session."""
        with self._lock:
            if not self._trace_lifecycle_started:
                return
        TRACE.emit(event, **fields)

    def start(self, transport: str) -> None:
        with self._lock:
            if self._trace_lifecycle_started:
                return
            self._trace_lifecycle_started = True
        self._emit(
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

    def _handle_disconnected(self, handle: DatabaseHandle, reason: str) -> None:
        with self._lock:
            session = next(
                (
                    candidate
                    for candidate in self._instances.values()
                    if candidate.handle is handle
                ),
                None,
            )
            if session is None:
                return
            self._instances.pop(session.instance_id, None)
            self._disconnected_instances[session.instance_id] = reason
            if self._current_instance_id == session.instance_id:
                self._current_instance_id = None
                self._disconnected_default = session.instance_id
        self._emit(
            "database_disconnected",
            session=_session_fields(),
            instance_id=session.instance_id,
            target=self._database_info(session),
            reason=reason,
        )

    def open_database(self, path: str, *, set_current: bool) -> OpenDatabaseResult:
        resolved_path = _resolve_user_path(path)
        if not Path(resolved_path).exists():
            raise McpToolError(f"database path does not exist: {resolved_path}")

        # Serialize local opens so duplicate calls create at most one retained
        # lease in this MCP server. Other MCP servers retain their own leases.
        with self._open_lock:
            with self._lock:
                candidate = next(
                    (
                        session
                        for session in self._instances.values()
                        if session.requested_path == resolved_path
                        and session.handle.connected
                    ),
                    None,
                )

            existing: _DatabaseSession | None = None
            if candidate is not None:
                with candidate.operation_lock, self._lock:
                    if self._instances.get(candidate.instance_id) is candidate:
                        existing = candidate
                        if set_current or self._current_instance_id is None:
                            self._current_instance_id = candidate.instance_id
                            self._disconnected_default = None
                        current = self._current_instance_id

            if existing is None:
                handle = DatabaseHandle.open(
                    resolved_path,
                    timeout=OPEN_TIMEOUT_SECONDS,
                    registry_dir=self.registry_dir,
                    spawn_dir=self.spawn_dir,
                )
                if not handle.connected:
                    reason = handle.disconnect_reason or "database connection closed"
                    handle.close()
                    raise McpToolError(f"database disconnected while opening: {reason}")
                entry = handle.entry
                with self._lock:
                    existing = next(
                        (
                            session
                            for session in self._instances.values()
                            if session.handle.connected
                            and session.handle.entry.record_id == entry.record_id
                        ),
                        None,
                    )
                    if existing is not None:
                        if set_current or self._current_instance_id is None:
                            self._current_instance_id = existing.instance_id
                            self._disconnected_default = None
                        current = self._current_instance_id
                    else:
                        instance_id = uuid.uuid4().hex[:12]
                        existing = _DatabaseSession(
                            instance_id=instance_id,
                            requested_path=resolved_path,
                            handle=handle,
                        )
                        self._instances[instance_id] = existing
                        if set_current or self._current_instance_id is None:
                            self._current_instance_id = instance_id
                            self._disconnected_default = None
                        current = self._current_instance_id

                if existing.handle is not handle:
                    handle.close()
                    event = "database_reused"
                else:
                    handle.set_disconnect_callback(self._handle_disconnected)
                    if not handle.connected:
                        reason = handle.disconnect_reason or "database connection closed"
                        raise McpToolError(f"database disconnected while opening: {reason}")
                    event = "database_opened"
            else:
                event = "database_reused"

            session_fields = _session_fields()
            self._emit(
                event,
                session=session_fields,
                instance_id=existing.instance_id,
                target=self._database_info(existing),
            )
            codemode_id = session_fields.get("codemode_id")
            return OpenDatabaseResult(
                instance_id=existing.instance_id,
                backend=existing.handle.entry.backend,
                status="current" if current == existing.instance_id else "attached",
                log_path=str(TRACE.path),
                codemode_id=codemode_id if isinstance(codemode_id, str) else None,
                hint=(
                    "Call reference(query) to inspect the IDA Domain API before "
                    "using execute_python; `db` and `ida_domain` are available globally."
                ),
            )

    @staticmethod
    def _disconnected_tool_error(instance_id: str) -> McpToolError:
        return McpToolError(
            f"database instance {instance_id} disconnected since it was last used "
            "and is no longer valid; call list_databases() and open_database() again"
        )

    def _get_session(self, instance_id: str | None) -> tuple[str, _DatabaseSession]:
        with self._lock:
            target_id = instance_id or self._current_instance_id
            if target_id is None:
                target_id = self._disconnected_default
                if target_id is None:
                    raise McpToolError(
                        "no open database instance; call open_database() first"
                    )
            session = self._instances.get(target_id)
            disconnected = self._disconnected_instances.get(target_id)
        if session is None and disconnected is not None:
            raise self._disconnected_tool_error(target_id)
        if session is None:
            raise McpToolError(f"unknown database instance: {target_id}")
        return target_id, session

    def execute_python(
        self,
        code: str,
        instance_id: str | None,
    ) -> PythonExecutionResult:
        target_id, session = self._get_session(instance_id)
        with session.operation_lock:
            if not session.handle.connected:
                raise self._disconnected_tool_error(target_id)
            try:
                return session.handle.execute_python(
                    code,
                    timeout=EXECUTE_TIMEOUT_SECONDS,
                )
            except ClientError:
                if not session.handle.connected:
                    raise self._disconnected_tool_error(target_id) from None
                raise

    def save_database(self, instance_id: str | None) -> SaveDatabaseResult:
        target_id, session = self._get_session(instance_id)
        with session.operation_lock:
            if not session.handle.connected:
                raise self._disconnected_tool_error(target_id)
            try:
                result = session.handle.save_database()
            except ClientError:
                if not session.handle.connected:
                    raise self._disconnected_tool_error(target_id) from None
                raise
            self._emit(
                "database_saved",
                session=_session_fields(),
                instance_id=target_id,
                target=self._database_info(session),
                result=result,
            )
            path = result.get("idb_path")
            if not isinstance(path, str):
                raise McpToolError("save_database returned an invalid path")
            return SaveDatabaseResult(path=path)

    @staticmethod
    def _listing_path(entry: RegistryEntry) -> str:
        """Return a path that open_database() can use to reach this instance."""

        if (
            entry.exe_path
            and Path(entry.exe_path).exists()
            and (
                entry.backend == "gui"
                or expected_idb_path(entry.exe_path) == entry.idb_path
            )
        ):
            return entry.exe_path
        return entry.idb_path

    def list_databases(self) -> ListDatabasesResult:
        with self._lock:
            sessions = list(self._instances.values())
            current = self._current_instance_id

        attached: dict[str, _AttachedDatabase] = {}
        for session in sessions:
            with session.operation_lock:
                entry = session.handle.entry
                attached[entry.record_id] = _AttachedDatabase(
                    entry=entry,
                    instance_id=session.instance_id,
                    current=session.instance_id == current,
                )

        instances: list[DatabaseListing] = []
        for discovered in scan_instances(self.registry_dir):
            entry = discovered.entry
            local = attached.pop(entry.record_id, None)
            if discovered.state.value != "ready":
                status: DatabaseStatus = "unavailable"
            elif local is None:
                status = "available"
            elif local.current:
                status = "current"
            else:
                status = "attached"
            instances.append(
                DatabaseListing(
                    path=self._listing_path(entry),
                    backend=entry.backend,
                    status=status,
                    instance_id=local.instance_id if local else None,
                    error=discovered.detail if status == "unavailable" else None,
                )
            )

        # A local lease remains actionable during a transient registry scan,
        # so do not hide it merely because discovery missed its record.
        for local in attached.values():
            instances.append(
                DatabaseListing(
                    path=self._listing_path(local.entry),
                    backend=local.entry.backend,
                    status="current" if local.current else "attached",
                    instance_id=local.instance_id,
                    error=None,
                )
            )

        status_order = {"current": 0, "attached": 1, "available": 2, "unavailable": 3}
        instances.sort(
            key=lambda item: (
                status_order[item["status"]],
                item["backend"] != "gui",
                item["path"],
            )
        )
        return {"instances": instances}

    def close_database(self, instance_id: str | None) -> CloseDatabaseResult:
        target_id, session = self._get_session(instance_id)
        with session.operation_lock:
            database = self._database_info(session)
            with self._lock:
                current_session = self._instances.get(target_id)
                if current_session is not session:
                    raise McpToolError(f"unknown database instance: {target_id}")
                self._instances.pop(target_id)
                if self._current_instance_id == target_id:
                    self._current_instance_id = next(iter(self._instances), None)
            session.handle.close()
        self._emit(
            "database_released",
            session=_session_fields(),
            instance_id=target_id,
            target=database,
        )
        return CloseDatabaseResult(closed=True)

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown_started:
                return
            self._shutdown_started = True
            sessions = list(self._instances.values())
            self._instances.clear()
            self._disconnected_instances.clear()
            self._disconnected_default = None
            self._current_instance_id = None
        for session in sessions:
            try:
                with session.operation_lock:
                    session.handle.close()
            except Exception as error:  # noqa: BLE001 -- best-effort shutdown tracing
                self._emit(
                    "database_release_error",
                    session=_session_fields(),
                    instance_id=session.instance_id,
                    error=_error_fields(error),
                )
        if self._trace_lifecycle_started:
            self._emit("mcp_stopped", session=_session_fields())


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
        "Whether this database should become the default target for execute_python().",
    ] = True,
) -> OpenDatabaseResult:
    """Attach to a GUI database or shared managed idalib worker."""

    return _run_traced_tool(
        "open_database",
        {"path": path, "set_current": set_current},
        lambda: DATABASE_MANAGER.open_database(path, set_current=set_current),
    )


@mcp.tool
def execute_python(
    code: Annotated[
        str,
        (
            "Python code that runs against an already-open database. Call reference(query) "
            "first; do not guess the API shape. `db` is the current ida-domain Database, "
            "and `ida_domain` is also imported globally. A single or trailing expression "
            "is returned. "
            "For function-style code, define run(db), execute(db), or main(db); "
            "it is invoked automatically when there is no trailing expression."
        ),
    ],
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, use the current target.",
    ] = None,
) -> PythonExecutionResult:
    """Execute Python and return its result plus captured stdout and stderr."""

    return _run_traced_tool(
        "execute_python",
        {"code": code, "instance_id": instance_id},
        lambda: DATABASE_MANAGER.execute_python(code, instance_id),
    )


@mcp.tool
def list_databases() -> ListDatabasesResult:
    """Discover registered GUI and idalib databases, including local attachments."""

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
) -> SaveDatabaseResult:
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
) -> CloseDatabaseResult:
    """Release this MCP server's handle without disrupting other clients.

    If this is the final lease on a managed idalib worker, the worker saves and
    exits after its lease grace period. GUI databases are never closed here.
    """

    return _run_traced_tool(
        "close_database",
        {"instance_id": instance_id},
        lambda: DATABASE_MANAGER.close_database(instance_id),
    )


def _schedule_startup_open(path: str) -> None:
    """Open and activate a database at startup so agents can skip open_database().

    Runs in a background daemon thread so opening (which may spawn a managed
    idalib worker) never delays the MCP initialize handshake. The database
    becomes the current target once the open completes; agents may still call
    open_database() themselves if the startup open fails.
    """

    def _open() -> None:
        try:
            DATABASE_MANAGER.open_database(path, set_current=True)
            print(f"Startup database ready: {path}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - report and let agents retry
            print(f"Startup open failed for {path!r}: {exc}", file=sys.stderr)

    threading.Thread(target=_open, name="startup-open", daemon=True).start()


def _serve(transport: str, database: str | None = None) -> None:
    _install_server_shutdown_handlers()
    DATABASE_MANAGER.start(transport)

    if database:
        _schedule_startup_open(database)

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
        "--database",
        default=None,
        help="Path to an executable or IDB to open and activate on startup, "
        "so agents don't need to call open_database() first.",
    )
    parser.add_argument(
        "--report-session",
        choices=["claude", "codex"],
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    if args.report_session is not None:
        return _report_session_main(args.report_session)

    _serve(args.transport, database=args.database)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
