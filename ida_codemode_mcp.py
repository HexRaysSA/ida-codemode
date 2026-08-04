"""IDA Domain Code Mode MCP server.

This server exposes a compact Code Mode surface for the ida-domain API:
- reference(query): look up the active ida-domain API reference
- open_database(...): attach to a GUI database or shared idalib worker
- execute_python(code): run Python against an already-open database
- list_databases(): discover registered GUI and idalib database instances
- save_database(...): explicitly save an active database
- close_database(...): release this MCP server's handle and lease
"""

import argparse
import atexit
import inspect
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import wraps
from importlib.metadata import version
from pathlib import Path
from typing import Annotated, Any, NotRequired, ParamSpec, TypeVar
from urllib.parse import urlparse

from packaging.version import InvalidVersion, Version

MCP_ENVIRONMENT_VARIABLES = (
    "IDA_CODEMODE_ID",
    "IDAUSR",
    "IDA_CODEMODE_STATE_DIR",
)


def _unset_empty_environment_variables() -> None:
    """Prevent MCP child processes from inheriting empty overrides."""
    for name in MCP_ENVIRONMENT_VARIABLES:
        if os.environ.get(name) == "":
            del os.environ[name]


from zeromcp import McpServer, McpToolError

from ida_codemode.client import ClientError, RemoteError
from ida_codemode.database import (
    CloseDatabaseResult,
    DatabaseError,
    DatabaseManager,
    ListDatabasesResult,
    OpenDatabaseResult,
    SaveDatabaseResult,
)
from ida_codemode.paths import STATE_DIR, find_console_script, get_idausr_dir
from ida_codemode.reference import (
    find_ida_domain_package_path,
    get_ida_domain_version,
    render_reference,
)
from ida_codemode.registry import FileLock
from ida_codemode.resolver import ResolveError
from ida_codemode.runtime import PythonExecutionResult

SESSIONS_DIR = STATE_DIR / "sessions"
OPEN_TIMEOUT_SECONDS = 300
EXECUTE_TIMEOUT_SECONDS = 300

PACKAGE_VERSION = version("ida-codemode")
mcp = McpServer("ida", version=PACKAGE_VERSION)


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
    """Thread-safe semantic trace owned by this MCP server."""

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
            "ts": datetime.now(UTC).isoformat(),
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


def _session_fields() -> dict[str, Any]:
    try:
        meta = mcp.context.meta or {}
    except (AttributeError, LookupError, RuntimeError):
        # Shutdown and asynchronous database events may have no MCP request.
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


def _install_initialize_trace_adapter() -> None:
    """Record MCP client identity and metadata from the initialize request."""
    original_initialize = mcp.registry.methods["initialize"]

    def initialize_with_trace(
        protocolVersion: str,
        capabilities: dict[str, Any],
        clientInfo: dict[str, Any],
        _meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = original_initialize(protocolVersion, capabilities, clientInfo, _meta)
        TRACE.emit(
            "mcp_initialized",
            session=_session_fields(),
            clientInfo=clientInfo,
            _meta=_meta,
        )
        return result

    mcp.registry.methods["initialize"] = initialize_with_trace


def _install_hook_input_meta_adapter() -> None:
    """Promote Claude/Codex hook metadata into MCP request metadata."""
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


_install_initialize_trace_adapter()
_install_hook_input_meta_adapter()


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
    if isinstance(
        error,
        (DatabaseError, ClientError, ResolveError, FileNotFoundError, ValueError),
    ):
        return McpToolError(str(error))
    return McpToolError(str(error) or type(error).__name__)


def _trace_database_event(event: str, fields: dict[str, Any]) -> None:
    fields = dict(fields)
    error = fields.get("error")
    if isinstance(error, Exception):
        fields["error"] = _error_fields(error)
    TRACE.emit(event, session=_session_fields(), **fields)


DATABASE_MANAGER = DatabaseManager(
    on_event=_trace_database_event,
    open_timeout=OPEN_TIMEOUT_SECONDS,
    execute_timeout=EXECUTE_TIMEOUT_SECONDS,
)

_TRACE_LIFECYCLE_LOCK = threading.Lock()
_TRACE_STARTED = False
_TRACE_STOPPED = False


def _start_mcp_trace(transport: str, agent: str | None) -> None:
    global _TRACE_STARTED
    with _TRACE_LIFECYCLE_LOCK:
        if _TRACE_STARTED:
            return
        _TRACE_STARTED = True
    TRACE.emit(
        "mcp_started",
        session=_session_fields(),
        transport=transport,
        agent=agent,
        trace_path=str(TRACE.path),
    )


def _shutdown_server_state() -> None:
    global _TRACE_STOPPED
    DATABASE_MANAGER.shutdown()
    with _TRACE_LIFECYCLE_LOCK:
        if not _TRACE_STARTED or _TRACE_STOPPED:
            return
        _TRACE_STOPPED = True
    TRACE.emit("mcp_stopped", session=_session_fields())


atexit.register(_shutdown_server_state)


P = ParamSpec("P")
R = TypeVar("R")


def tool(func: Callable[P, R]) -> Callable[P, R]:
    """Register an MCP tool and trace each invocation."""
    signature = inspect.signature(func)

    @wraps(func)
    def traced(*args: P.args, **kwargs: P.kwargs) -> R:
        name = getattr(func, "__name__", "<unnamed>")
        arguments = signature.bind(*args, **kwargs)
        arguments.apply_defaults()
        call_id = uuid.uuid4().hex
        session = _session_fields()
        TRACE.emit(
            "tool_call",
            call_id=call_id,
            tool=name,
            session=session,
            input=dict(arguments.arguments),
        )
        started = time.monotonic()
        try:
            result = func(*args, **kwargs)
        except Exception as error:
            TRACE.emit(
                "tool_error",
                call_id=call_id,
                tool=name,
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
            tool=name,
            session=session,
            duration_ms=round((time.monotonic() - started) * 1000, 3),
            output=result,
        )
        return result

    return mcp.tool(traced)


@tool
def reference(
    query: Annotated[
        str,
        "Class, method, or reverse-engineering concept to look up in the IDA reference.",
    ],
) -> str:
    """Look up the active ida-domain API and return a plain-text IDA reference."""

    return render_reference(query)


class OpenDatabaseToolResult(OpenDatabaseResult):
    log_path: str
    codemode_id: str | None
    hint: str


@tool
def open_database(
    path: Annotated[
        str,
        "Path to a local executable or IDB. A GUI instance is used when available.",
    ],
    set_current: Annotated[
        bool,
        "Whether this database should become the default target for execute_python().",
    ] = True,
) -> OpenDatabaseToolResult:
    """Attach to a GUI database or shared managed idalib worker."""

    result = DATABASE_MANAGER.open_database(path, set_current=set_current)
    session = _session_fields()
    codemode_id = session.get("codemode_id")
    return OpenDatabaseToolResult(
        **result,
        log_path=str(TRACE.path),
        codemode_id=codemode_id if isinstance(codemode_id, str) else None,
        hint=(
            "Call reference(query) to inspect the IDA Domain API before using "
            "execute_python; `db` and `ida_domain` are available globally."
        ),
    )


@tool
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

    DATABASE_MANAGER.ensure_autoanalysis(instance_id)
    return DATABASE_MANAGER.execute_python(code, instance_id)


def _gui_plugin_installed() -> bool:
    """Check whether a compatible ida-codemode GUI plugin is installed."""
    plugin_dir = get_idausr_dir() / "plugins" / "ida-codemode"
    plugin_manifest = plugin_dir / "ida-plugin.json"
    plugin_entrypoint = plugin_dir / "ida_codemode_plugin.py"
    if not plugin_entrypoint.is_file():
        return False

    try:
        document = json.loads(plugin_manifest.read_text(encoding="utf-8"))
        plugin_version = document["plugin"]["version"]
        if not isinstance(plugin_version, str):
            return False
        return Version(plugin_version) >= Version(PACKAGE_VERSION)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        InvalidVersion,
    ):
        return False


def _emit_plugin_install_failure(project_dir: Path, error: Exception) -> None:
    """Best-effort logging for an optional operation that must not stop MCP."""
    try:
        TRACE.emit(
            "plugin_install_failed",
            session=_session_fields(),
            project_dir=str(project_dir),
            error=_error_fields(error),
        )
    except Exception:  # noqa: BLE001 - optional logging must not affect MCP startup
        return


def _install_gui_plugin(project_dir: Path) -> None:
    """Install the GUI plugin from *project_dir* without raising to the caller."""
    try:
        lock_path = get_idausr_dir() / "codemode" / "plugin-install.lock"
        with FileLock(lock_path):
            # Another MCP may have completed installation while this one waited.
            if _gui_plugin_installed():
                return

            # Prefer the mandatory hcli dependency from this Python environment.
            # The PATH fallback also supports manually packaged MCP launchers.
            hcli = find_console_script("hcli") or shutil.which("hcli")
            if hcli is None:
                raise FileNotFoundError(
                    "Could not find hcli; install it to enable the IDA GUI plugin"
                )

            command = [hcli, "plugin", "install", str(project_dir)]
            TRACE.emit(
                "plugin_install_started",
                session=_session_fields(),
                command=command,
                project_dir=str(project_dir),
            )
            try:
                completed = subprocess.run(
                    command,
                    cwd=project_dir,
                    env={**os.environ, "HCLI_DEBUG": "1"},
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except (OSError, subprocess.CalledProcessError) as error:
                fields: dict[str, Any] = {
                    "session": _session_fields(),
                    "command": command,
                    "project_dir": str(project_dir),
                    "error": _error_fields(error),
                }
                if isinstance(error, subprocess.CalledProcessError):
                    fields.update(stdout=error.stdout, stderr=error.stderr)
                TRACE.emit("plugin_install_failed", **fields)
                return

            TRACE.emit(
                "plugin_install_succeeded",
                session=_session_fields(),
                command=command,
                project_dir=str(project_dir),
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
    except Exception as error:  # noqa: BLE001 - plugin installation is optional
        _emit_plugin_install_failure(project_dir, error)


def _schedule_gui_plugin_install() -> threading.Thread | None:
    """Start eventual GUI plugin installation without delaying MCP startup."""
    project_dir = Path(__file__).resolve().parent
    try:
        if _gui_plugin_installed():
            return None

        thread = threading.Thread(
            target=_install_gui_plugin,
            args=(project_dir,),
            name="plugin-install",
            daemon=True,
        )
        thread.start()
        return thread
    except Exception as error:  # noqa: BLE001 - MCP must start without the plugin
        _emit_plugin_install_failure(project_dir, error)
        return None


class ListDatabasesToolResult(ListDatabasesResult):
    hint: NotRequired[str]


@tool
def list_databases() -> ListDatabasesToolResult:
    """Discover registered GUI and idalib databases."""
    result = ListDatabasesToolResult(**DATABASE_MANAGER.list_databases())
    if not _gui_plugin_installed():
        result["hint"] = (
            "To enable GUI database discovery, install the ida-codemode plugin: hcli plugin install https://github.com/HexRaysSA/ida-codemode"
        )
    return result


@tool
def save_database(
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, save the current target.",
    ] = None,
) -> SaveDatabaseResult:
    """Explicitly save an active GUI or idalib database."""

    return DATABASE_MANAGER.save_database(instance_id)


@tool
def close_database(
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, release the current target.",
    ] = None,
) -> CloseDatabaseResult:
    """Release this MCP server's handle without disrupting other clients.

    If this is the final lease on a managed idalib worker, orphaned execution is
    cancelled and the worker saves and exits. GUI databases are never closed here.
    """

    return DATABASE_MANAGER.close_database(instance_id)


def _install_server_shutdown_handlers() -> None:
    def cleanup_and_exit(signum: int, _frame: Any) -> None:
        _shutdown_server_state()
        try:
            mcp.stop()
        finally:
            raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)


def _serve(
    transport: str,
    database: str | None = None,
    agent: str | None = None,
    install_plugin: bool = False,
) -> None:
    _unset_empty_environment_variables()
    _install_server_shutdown_handlers()
    _start_mcp_trace(transport, agent)

    if install_plugin:
        _schedule_gui_plugin_install()

    if database:
        DATABASE_MANAGER.schedule_startup_open(database)

    if transport == "stdio":
        try:
            mcp.stdio()
        finally:
            _shutdown_server_state()
        return

    url = urlparse(transport)
    if url.hostname is None or url.port is None:
        raise ValueError(f"Invalid transport URL: {transport}")

    try:
        loopback = ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        loopback = url.hostname.casefold() == "localhost"
    if not loopback:
        print(
            "WARNING: MCP HTTP transport is bound to a non-loopback host without "
            "built-in authentication; execute_python may be reachable over the network.",
            file=sys.stderr,
        )

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
        _shutdown_server_state()
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
        "--agent",
        default=None,
        help="Agent name to record in the MCP session trace.",
    )
    parser.add_argument(
        "--install-plugin",
        action="store_true",
        help="Install the IDA GUI plugin in the background if it is not installed.",
    )
    parser.add_argument(
        "--report-session",
        choices=["claude", "codex"],
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    if args.report_session is not None:
        return _report_session_main(args.report_session)

    _serve(
        args.transport,
        database=args.database,
        agent=args.agent,
        install_plugin=args.install_plugin,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
