"""IDA Domain Code Mode MCP server.

This server exposes a compact Code Mode surface for the ida-domain API:
- reference(query): look up the active ida-domain API reference
- open_database(...): spawn a long-lived idalib bridge instance for a local target
- execute(code): run Python against an already-open database with ida-domain preloaded
- list_databases(): inspect active bridge instances
- close_database(...): close a bridge instance
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import atexit
import builtins
import importlib.metadata
import importlib.util
import inspect
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections import deque
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

from zeromcp import McpServer, McpToolError
from ida_codemode.reference import (
    render_reference,
    get_ida_domain_version,
    find_ida_domain_package_path,
)

MODULE_PATH = Path(__file__).resolve()
STATE_DIR = Path.home() / ".ida-codemode"
JSONL_LOG_DIR = STATE_DIR / "logs"
BRIDGE_MARKER = "CODEMODE_BRIDGE_JSON:"
OPEN_TIMEOUT_SECONDS = 300
EXECUTE_TIMEOUT_SECONDS = 300
CLOSE_TIMEOUT_SECONDS = 60
LOG_TAIL_LINES = 100

mcp = McpServer("ida", version="0.2.0")


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _resolve_user_path(path: str) -> str:
    return str(Path(path).expanduser().resolve())


def _safe_filename_component(value: str) -> str:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in value)
    return safe.strip("._") or "database"


def _jsonl_log_path(instance_id: str, database_path: str) -> Path:
    stem = _safe_filename_component(Path(database_path).name)
    return JSONL_LOG_DIR / f"{stem}-{instance_id}.jsonl"


def _session_fields() -> dict[str, Any]:
    meta = mcp.context.meta or {}
    fields: dict[str, Any] = {}

    fields["codemode_id"] = os.environ.get("IDA_CODEMODE_ID") or None

    claude_session_path = meta.get("claude_session_path")
    if isinstance(claude_session_path, str) and claude_session_path:
        fields["claude_session_path"] = claude_session_path

    codex_session_path = meta.get("codex_session_path")
    if isinstance(codex_session_path, str) and codex_session_path:
        fields["codex_session_path"] = codex_session_path

    pi_session_path = meta.get("pi_session_path")
    if isinstance(pi_session_path, str) and pi_session_path:
        fields["pi_session_path"] = pi_session_path

    return fields


def _write_jsonl(log_path: Path, event: dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": _utc_now_iso(), **event}
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()


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


def _find_callable_from_code(
    code: str,
    global_ns: dict[str, Any],
    preferred_names: list[str],
) -> Any:
    stripped = code.strip()
    if not stripped:
        raise ValueError("code must not be empty")

    try:
        candidate = eval(stripped, global_ns, {})
    except SyntaxError:
        candidate = None
    except Exception as exc:
        raise ValueError(f"failed to evaluate code expression: {exc}") from exc

    if callable(candidate):
        return candidate

    local_ns: dict[str, Any] = {}
    exec(stripped, global_ns, local_ns)  # noqa: S102 -- this is the Code Mode execution surface

    for name in preferred_names:
        value = local_ns.get(name)
        if callable(value):
            return value

    discovered = [
        value
        for key, value in local_ns.items()
        if callable(value) and key not in preferred_names and not key.startswith("__")
    ]
    if len(discovered) == 1:
        return discovered[0]

    raise ValueError(
        "code must evaluate to a callable or define one callable named "
        + ", ".join(preferred_names)
    )


async def _invoke_user_callable(func: Any, runtime: dict[str, Any]) -> Any:
    signature = inspect.signature(func)
    args: list[Any] = []
    kwargs: dict[str, Any] = {}

    for parameter in signature.parameters.values():
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            continue
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            for name, value in runtime.items():
                kwargs.setdefault(name, value)
            continue

        if parameter.name not in runtime:
            if parameter.default is inspect.Parameter.empty:
                raise ValueError(
                    f"missing runtime value for parameter '{parameter.name}'. "
                    f"Available names: {', '.join(sorted(runtime))}"
                )
            continue

        value = runtime[parameter.name]
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[parameter.name] = value

    result = func(*args, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    return result


def _jsonify(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _jsonify(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonify(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonify(item) for item in value]
    if hasattr(value, "__dict__"):
        public = {
            key: val for key, val in vars(value).items() if not key.startswith("_")
        }
        if public:
            return _jsonify(public)
    return repr(value)


def _database_info(db: Any, state: dict[str, Any]) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": state["path"],
        "auto_analysis": state.get("auto_analysis", True),
        "new_database": state.get("new_database", False),
        "save_on_close": True,
        "options": state.get("options", {}),
    }

    for attr in [
        "minimum_ea",
        "maximum_ea",
        "path",
        "architecture",
        "bitness",
        "format",
    ]:
        try:
            value = getattr(db, attr)
        except Exception:  # noqa: BLE001, S112 -- ida_domain properties may raise arbitrary errors
            continue
        info[attr] = _jsonify(value)

    metadata = getattr(db, "metadata", None)
    if metadata is not None:
        try:
            info["metadata"] = _jsonify(metadata)
        except Exception:  # noqa: BLE001, S110 -- metadata is best-effort, never fatal
            pass

    return info


async def _run_bridge_execute(code: str, runtime: dict[str, Any]) -> Any:
    global_ns = {
        "__builtins__": builtins.__dict__,
        "__name__": "__codemode_bridge_execute__",
        **runtime,
    }
    func = _find_callable_from_code(code, global_ns, ["run", "execute", "main"])
    result = await _invoke_user_callable(func, runtime)
    return _jsonify(result)


class _BridgeInstance:
    def __init__(self, instance_id: str, log_path: Path):
        self.instance_id = instance_id
        self.log_path = log_path
        _write_jsonl(
            self.log_path,
            {
                "event": "instance_started",
                "instance_id": self.instance_id,
                "pid": None,
                **_session_fields(),
            },
        )
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(MODULE_PATH),
                "--internal-mode",
                "bridge-worker",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _write_jsonl(
            self.log_path,
            {
                "event": "process_started",
                "instance_id": self.instance_id,
                "pid": self.process.pid,
            },
        )
        self._responses: queue.Queue[dict[str, Any]] = queue.Queue()
        self._logs: deque[str] = deque(maxlen=LOG_TAIL_LINES)
        self._lock = threading.Lock()
        self.summary: dict[str, Any] | None = None
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reader.start()

    def _read_output(self) -> None:
        assert self.process.stdout is not None
        for raw_line in self.process.stdout:
            line = raw_line.rstrip("\n")
            if line.startswith(BRIDGE_MARKER):
                try:
                    payload = json.loads(line[len(BRIDGE_MARKER) :])
                except json.JSONDecodeError:
                    self._logs.append(line)
                    continue
                self._responses.put(payload)
            elif line:
                self._logs.append(line)
                _write_jsonl(
                    self.log_path,
                    {
                        "event": "bridge_output",
                        "instance_id": self.instance_id,
                        "line": line,
                    },
                )

    def is_alive(self) -> bool:
        return self.process.poll() is None

    def logs_tail(self) -> list[str]:
        return list(self._logs)

    def request(self, command: dict[str, Any], timeout: int) -> dict[str, Any]:
        with self._lock:
            if not self.is_alive():
                _write_jsonl(
                    self.log_path,
                    {
                        "event": "request_failed",
                        "instance_id": self.instance_id,
                        "reason": "process_not_running",
                        "command": command,
                    },
                )
                raise McpToolError(
                    f"instance {self.instance_id} is not running anymore\n\n"
                    + "\n".join(self.logs_tail())
                )

            request_id = uuid.uuid4().hex
            payload = {**command, "request_id": request_id}
            _write_jsonl(
                self.log_path,
                {
                    "event": "request",
                    "instance_id": self.instance_id,
                    "request_id": request_id,
                    "payload": payload,
                    **_session_fields(),
                },
            )
            assert self.process.stdin is not None
            self.process.stdin.write(json.dumps(payload) + "\n")
            self.process.stdin.flush()

            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _write_jsonl(
                        self.log_path,
                        {
                            "event": "timeout",
                            "instance_id": self.instance_id,
                            "request_id": request_id,
                            "timeout_seconds": timeout,
                        },
                    )
                    raise McpToolError(
                        f"timed out waiting for response from instance {self.instance_id}\n\n"
                        + "\n".join(self.logs_tail())
                    )
                try:
                    response = self._responses.get(timeout=remaining)
                except queue.Empty as exc:
                    _write_jsonl(
                        self.log_path,
                        {
                            "event": "timeout",
                            "instance_id": self.instance_id,
                            "request_id": request_id,
                            "timeout_seconds": timeout,
                        },
                    )
                    raise McpToolError(
                        f"timed out waiting for response from instance {self.instance_id}\n\n"
                        + "\n".join(self.logs_tail())
                    ) from exc
                if response.get("request_id") != request_id:
                    continue
                _write_jsonl(
                    self.log_path,
                    {
                        "event": "response",
                        "instance_id": self.instance_id,
                        "request_id": request_id,
                        "payload": response,
                    },
                )
                if not response.get("ok"):
                    message = response.get("error", "unknown error")
                    tb = response.get("traceback", "")
                    logs = "\n".join(self.logs_tail())
                    extra = f"\n\nBridge logs:\n{logs}" if logs else ""
                    raise McpToolError(f"{message}\n\n{tb}{extra}".strip())
                result = response.get("result", {})
                if isinstance(result, dict) and result.get("database") is not None:
                    self.summary = result["database"]
                return result

    def terminate(self) -> None:
        if self.process.poll() is not None:
            _write_jsonl(
                self.log_path,
                {
                    "event": "process_already_exited",
                    "instance_id": self.instance_id,
                    "returncode": self.process.returncode,
                },
            )
            return
        _write_jsonl(
            self.log_path,
            {"event": "process_terminate", "instance_id": self.instance_id},
        )
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _write_jsonl(
                self.log_path,
                {"event": "process_kill", "instance_id": self.instance_id},
            )
            self.process.kill()
            self.process.wait(timeout=5)
        _write_jsonl(
            self.log_path,
            {
                "event": "process_exited",
                "instance_id": self.instance_id,
                "returncode": self.process.returncode,
            },
        )


class _BridgeManager:
    def __init__(self) -> None:
        self._instances: dict[str, _BridgeInstance] = {}
        self._current_instance_id: str | None = None
        self._lock = threading.Lock()
        self._shutdown_started = False

    def open_database(
        self,
        path: str,
        *,
        auto_analysis: bool,
        new_database: bool,
        options: dict[str, Any] | None,
        set_current: bool,
    ) -> dict[str, Any]:
        resolved_path = _resolve_user_path(path)
        if not Path(resolved_path).exists():
            raise McpToolError(f"database path does not exist: {resolved_path}")

        instance_id = uuid.uuid4().hex[:12]
        log_path = _jsonl_log_path(instance_id, resolved_path)
        instance = _BridgeInstance(instance_id, log_path)
        try:
            result = instance.request(
                {
                    "command": "open",
                    "path": resolved_path,
                    "auto_analysis": auto_analysis,
                    "new_database": new_database,
                    "options": options or {},
                },
                OPEN_TIMEOUT_SECONDS,
            )
        except Exception:
            instance.terminate()
            raise

        with self._lock:
            self._instances[instance_id] = instance
            if set_current or self._current_instance_id is None:
                self._current_instance_id = instance_id

        return {
            **result,
            "instance_id": instance_id,
            "current_instance_id": self._current_instance_id,
            "log_path": str(instance.log_path),
            **_session_fields(),
        }

    def _get_instance(self, instance_id: str | None) -> tuple[str, _BridgeInstance]:
        with self._lock:
            target_id = instance_id or self._current_instance_id
            if target_id is None:
                raise McpToolError(
                    "no open database instance; call open_database() first"
                )
            instance = self._instances.get(target_id)
        if instance is None:
            raise McpToolError(f"unknown database instance: {target_id}")
        if not instance.is_alive():
            raise McpToolError(
                f"database instance is no longer running: {target_id}\n\n"
                + "\n".join(instance.logs_tail())
            )
        return target_id, instance

    def execute(self, code: str, instance_id: str | None) -> dict[str, Any]:
        target_id, instance = self._get_instance(instance_id)
        result = instance.request(
            {"command": "execute", "code": code}, EXECUTE_TIMEOUT_SECONDS
        )
        return {
            "instance_id": target_id,
            "current_instance_id": self.current_instance_id,
            "log_path": str(instance.log_path),
            "result": result,
        }

    @property
    def current_instance_id(self) -> str | None:
        with self._lock:
            return self._current_instance_id

    def list_databases(self) -> dict[str, Any]:
        with self._lock:
            items = list(self._instances.items())
            current = self._current_instance_id

        instances = []
        dead_ids = []
        for instance_id, instance in items:
            alive = instance.is_alive()
            if not alive:
                dead_ids.append(instance_id)
            instances.append(
                {
                    "instance_id": instance_id,
                    "current": instance_id == current,
                    "alive": alive,
                    "database": instance.summary,
                    "log_path": str(instance.log_path),
                    "logs_tail": instance.logs_tail()[-10:],
                }
            )

        if dead_ids:
            with self._lock:
                for dead_id in dead_ids:
                    self._instances.pop(dead_id, None)
                    if self._current_instance_id == dead_id:
                        self._current_instance_id = next(iter(self._instances), None)
                current = self._current_instance_id
        return {
            "current_instance_id": current,
            "instances": instances,
            "count": len(instances),
        }

    def close_database(self, instance_id: str | None) -> dict[str, Any]:
        target_id, instance = self._get_instance(instance_id)
        log_path = instance.log_path
        result: dict[str, Any]
        try:
            result = instance.request({"command": "close"}, CLOSE_TIMEOUT_SECONDS)
        finally:
            instance.terminate()
            with self._lock:
                self._instances.pop(target_id, None)
                if self._current_instance_id == target_id:
                    self._current_instance_id = next(iter(self._instances), None)
        return {
            **result,
            "instance_id": target_id,
            "current_instance_id": self.current_instance_id,
            "log_path": str(log_path),
        }

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown_started:
                return
            self._shutdown_started = True
            items = list(self._instances.items())
            self._instances.clear()
            self._current_instance_id = None
        for _, instance in items:
            try:
                if instance.is_alive():
                    try:
                        instance.request({"command": "close"}, CLOSE_TIMEOUT_SECONDS)
                    except Exception:  # noqa: BLE001, S110 -- best-effort close during shutdown
                        pass
            finally:
                instance.terminate()


BRIDGE_MANAGER = _BridgeManager()
atexit.register(BRIDGE_MANAGER.shutdown)


def _install_server_shutdown_handlers() -> None:
    def cleanup_and_exit(signum: int, _frame: Any) -> None:
        BRIDGE_MANAGER.shutdown()
        try:
            mcp.stop()
        finally:
            raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)


def _bridge_emit(payload: dict[str, Any]) -> None:
    print(f"{BRIDGE_MARKER}{json.dumps(payload)}", flush=True)


def _bridge_instance_main() -> int:
    import ida_domain
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    db: Any | None = None
    state: dict[str, Any] | None = None

    def open_db(
        path: str,
        *,
        auto_analysis: bool,
        new_database: bool,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        nonlocal db, state
        if db is not None:
            raise RuntimeError("database is already open in this instance")
        ida_options = IdaCommandOptions(
            auto_analysis=auto_analysis,
            new_database=new_database,
            **options,
        )
        # Databases are always persisted to disk; opting out is not allowed.
        db = Database.open(path, ida_options, True)
        state = {
            "path": path,
            "auto_analysis": auto_analysis,
            "new_database": new_database,
            "save_on_close": True,
            "options": options,
        }
        return _database_info(db, state)

    def close_db() -> dict[str, Any]:
        nonlocal db, state
        if db is None:
            return {"closed": False, "reason": "no database was open"}
        if state is None:
            raise RuntimeError("database state is missing")
        info = _database_info(db, state)
        db.close(save=True)
        db = None
        state = None
        return {
            "closed": True,
            "saved": True,
            "database": info,
        }

    def bridge_cleanup_and_exit(signum: int, _frame: Any) -> None:
        try:
            close_db()
        except Exception:  # noqa: BLE001, S110 -- signal handler must not raise
            pass
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, bridge_cleanup_and_exit)
    signal.signal(signal.SIGTERM, bridge_cleanup_and_exit)

    try:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            request = json.loads(line)
            request_id = request.get("request_id")
            try:
                command = request.get("command")
                if command == "open":
                    result = {
                        "opened": True,
                        "database": open_db(
                            request["path"],
                            auto_analysis=request.get("auto_analysis", True),
                            new_database=request.get("new_database", False),
                            options=request.get("options", {}),
                        ),
                    }
                elif command == "execute":
                    if db is None or state is None:
                        raise RuntimeError("no database is currently open")
                    runtime = {
                        "ida_domain": ida_domain,
                        "Database": Database,
                        "IdaCommandOptions": IdaCommandOptions,
                        "db": db,
                        "database_path": state["path"],
                        "database_options": state,
                        "json": json,
                        "to_jsonable": _jsonify,
                    }
                    result = asyncio.run(_run_bridge_execute(request["code"], runtime))
                elif command == "status":
                    result = {
                        "opened": db is not None,
                        "database": _database_info(db, state)
                        if db is not None and state is not None
                        else None,
                    }
                elif command == "close":
                    result = close_db()
                    _bridge_emit(
                        {"request_id": request_id, "ok": True, "result": result}
                    )
                    break
                else:
                    raise RuntimeError(f"unsupported bridge command: {command}")

                _bridge_emit({"request_id": request_id, "ok": True, "result": result})
            except Exception:  # noqa: BLE001 -- must report arbitrary user execute() errors, not crash
                _bridge_emit(
                    {
                        "request_id": request_id,
                        "ok": False,
                        "error": traceback.format_exc().splitlines()[-1],
                        "traceback": traceback.format_exc(),
                    }
                )
    finally:
        if db is not None:
            try:
                db.close(save=True)
            except Exception:  # noqa: BLE001, S110 -- best-effort final save on exit
                pass
    return 0


@mcp.tool
def reference(
    query: Annotated[
        str,
        "Class, method, or reverse-engineering concept to look up in the IDA reference.",
    ],
) -> str:
    """Look up the active ida-domain API and return a plain-text IDA reference."""
    try:
        return render_reference(query)
    except ValueError as e:
        raise McpToolError(str(e))


@mcp.tool
def open_database(
    path: Annotated[
        str,
        "Path to the local binary or database file to open in a new bridge instance.",
    ],
    auto_analysis: Annotated[
        bool, "Whether IDA auto-analysis should run when opening the target."
    ] = True,
    new_database: Annotated[
        bool, "Whether IDA should request creation of a new database."
    ] = False,
    set_current: Annotated[
        bool, "Whether the new instance should become the default target for execute()."
    ] = True,
    options: Annotated[
        dict[str, Any] | None,
        (
            "Additional IdaCommandOptions keyword arguments, for example processor, "
            "output_database, log_file, script_file, or debug_flags."
        ),
    ] = None,
) -> dict[str, Any]:
    """Open a local target in a long-lived idalib bridge instance.

    The database is always persisted to disk when the instance is closed.
    """
    return BRIDGE_MANAGER.open_database(
        path,
        auto_analysis=auto_analysis,
        new_database=new_database,
        options=options,
        set_current=set_current,
    )


@mcp.tool
def execute(
    code: Annotated[
        str,
        (
            "Python code that runs against an already-open database bridge instance. "
            "Use the IDA reference tool before calling execute; do not guess the API shape. "
            "The runtime exposes db, ida_domain, Database, IdaCommandOptions, database_path, "
            "database_options, json, and to_jsonable(). Return JSON-serializable data. "
            "Define run(...), execute(...), main(...), or pass a lambda expression."
        ),
    ],
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, execute() uses the current open_database() target.",
    ] = None,
) -> dict[str, Any]:
    """Execute Python against an open database. Use the IDA reference tool first."""
    return BRIDGE_MANAGER.execute(code, instance_id)


@mcp.tool
def list_databases() -> dict[str, Any]:
    """List active database bridge instances and show the current default target."""
    return BRIDGE_MANAGER.list_databases()


@mcp.tool
def close_database(
    instance_id: Annotated[
        str | None,
        "Optional database instance id. If omitted, the current instance is closed.",
    ] = None,
) -> dict[str, Any]:
    """Close an active database bridge instance, always saving changes to disk."""
    return BRIDGE_MANAGER.close_database(instance_id)


def _serve(transport: str) -> None:
    _install_server_shutdown_handlers()

    if transport == "stdio":
        try:
            mcp.stdio()
        finally:
            BRIDGE_MANAGER.shutdown()
        return

    url = urlparse(transport)
    if url.hostname is None or url.port is None:
        raise ValueError(f"Invalid transport URL: {transport}")

    print("Starting IDA Code Mode MCP server...")
    print(
        f"Using ida-domain {get_ida_domain_version()} from {find_ida_domain_package_path()}"
    )
    print("Available tools:")
    for name, func in mcp.tools.methods.items():
        print(f"  - {name}: {(func.__doc__ or '').strip()}")
    print()

    mcp.serve(url.hostname, url.port)

    try:
        input("Server is running, press Enter or Ctrl+C to stop...")
    except KeyboardInterrupt, EOFError:
        print("\nStopping server...")
    finally:
        BRIDGE_MANAGER.shutdown()
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
        "--internal-mode",
        choices=["bridge-worker"],
        default=None,
        help=argparse.SUPPRESS,
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    mcp_parser = subparsers.add_parser("mcp", help="Run the MCP server")
    mcp_parser.add_argument(
        "--transport",
        default="stdio",
        help="Transport (stdio or http://host:port). Defaults to stdio.",
    )

    report_session_parser = subparsers.add_parser(
        "report-session",
        help="Inject agent session metadata into a PreToolUse tool input.",
    )
    report_session_parser.add_argument(
        "platform",
        choices=["claude", "codex"],
        help="Agent runtime whose hook payload is being processed.",
    )

    args = parser.parse_args()

    if args.internal_mode == "bridge-worker":
        return _bridge_instance_main()
    if args.command == "report-session":
        return _report_session_main(args.platform)
    if args.command == "mcp":
        _serve(args.transport)
        return 0

    parser.error("a subcommand is required (mcp or report-session)")
    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
