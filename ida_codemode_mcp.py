"""IDA Domain Code Mode MCP server.

This server exposes a compact Code Mode surface for the ida-domain API:
- search(code): inspect a generated API spec built from the active ida-domain checkout/package
- open_database(...): spawn a long-lived idalib bridge instance for a local target
- execute(code): run Python against an already-open database with ida-domain preloaded
- list_databases(): inspect active bridge instances
- close_database(...): close a bridge instance
"""

from __future__ import annotations

import argparse
import ast
import atexit
import asyncio
import builtins
import importlib.metadata
import importlib.util
import inspect
import json
import os
import queue
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

MODULE_PATH = Path(__file__).resolve()
JSONL_LOG_DIR = Path.home() / ".ida-codemode" / "logs"
SESSIONS_DIR = Path.home() / ".ida-codemode" / "sessions"
SESSION_FILE_MAX_AGE_SECONDS = 86400
RESULT_MARKER = "CODEMODE_RESULT_JSON:"
BRIDGE_MARKER = "CODEMODE_BRIDGE_JSON:"
SEARCH_TIMEOUT_SECONDS = 15
OPEN_TIMEOUT_SECONDS = 300
EXECUTE_TIMEOUT_SECONDS = 300
CLOSE_TIMEOUT_SECONDS = 60
LOG_TAIL_LINES = 100

SAFE_SEARCH_BUILTINS = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "filter": filter,
    "float": float,
    "getattr": getattr,
    "hasattr": hasattr,
    "int": int,
    "isinstance": isinstance,
    "issubclass": issubclass,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "print": print,
    "range": range,
    "repr": repr,
    "reversed": reversed,
    "round": round,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}

mcp = McpServer("ida", version="0.2.0")
_SEARCH_SPEC_CACHE: dict[str, Any] | None = None


def _find_ida_domain_package_path() -> Path:
    spec = importlib.util.find_spec("ida_domain")
    if spec is None or spec.origin is None:
        raise FileNotFoundError("Installed ida-domain package not found")
    return Path(spec.origin).resolve().parent


def _find_ida_domain_source_root() -> Path:
    return _find_ida_domain_package_path().parent


def _get_ida_domain_version() -> str:
    return importlib.metadata.version("ida-domain")


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


_SESSION_INFO: dict[str, Any] | None = None
_SESSION_INFO_MTIME: float | None = None


def _session_file_path(claude_pid: int | None = None) -> Path:
    pid = os.getppid() if claude_pid is None else claude_pid
    return SESSIONS_DIR / f"{pid}.json"


def _get_session_info() -> dict[str, Any] | None:
    """Look up the Claude session info written by the PreToolUse hook.

    Keyed by the Claude Code parent PID so multiple concurrent sessions don't collide.
    Cached by mtime so we pick up new/updated session files without re-reading on
    every JSONL write.
    """
    global _SESSION_INFO, _SESSION_INFO_MTIME
    path = _session_file_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return _SESSION_INFO
    if mtime == _SESSION_INFO_MTIME:
        return _SESSION_INFO
    try:
        _SESSION_INFO = json.loads(path.read_text(encoding="utf-8"))
        _SESSION_INFO_MTIME = mtime
    except OSError, json.JSONDecodeError:
        pass
    return _SESSION_INFO


def _session_fields() -> dict[str, Any]:
    info = _get_session_info()
    if info is None:
        return {}
    return {
        "claude_session_id": info.get("session_id"),
        "claude_transcript_path": info.get("transcript_path"),
    }


def _prune_stale_sessions() -> None:
    if not SESSIONS_DIR.exists():
        return
    cutoff = time.time() - SESSION_FILE_MAX_AGE_SECONDS
    for entry in SESSIONS_DIR.glob("*.json"):
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink()
        except OSError:
            pass


def _write_jsonl(log_path: Path, event: dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": _utc_now_iso(), **_session_fields(), **event}
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()


def _summarize_text(text: str, max_lines: int = 8) -> str:
    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    return "\n".join(lines[:max_lines])


def _signature_from_function_node(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    def fmt_annotation(annotation: ast.AST | None) -> str:
        return ast.unparse(annotation) if annotation is not None else ""

    def fmt_default(default: ast.AST | None) -> str:
        return f" = {ast.unparse(default)}" if default is not None else ""

    parts: list[str] = []
    posonly = list(node.args.posonlyargs)
    regular = list(node.args.args)
    positional = posonly + regular
    positional_defaults = [None] * (len(positional) - len(node.args.defaults)) + list(
        node.args.defaults
    )

    for index, arg in enumerate(positional):
        part = arg.arg
        annotation = fmt_annotation(arg.annotation)
        if annotation:
            part += f": {annotation}"
        part += fmt_default(positional_defaults[index])
        parts.append(part)
        if posonly and index == len(posonly) - 1:
            parts.append("/")

    if node.args.vararg is not None:
        part = f"*{node.args.vararg.arg}"
        annotation = fmt_annotation(node.args.vararg.annotation)
        if annotation:
            part += f": {annotation}"
        parts.append(part)
    elif node.args.kwonlyargs:
        parts.append("*")

    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        part = arg.arg
        annotation = fmt_annotation(arg.annotation)
        if annotation:
            part += f": {annotation}"
        part += fmt_default(default)
        parts.append(part)

    if node.args.kwarg is not None:
        part = f"**{node.args.kwarg.arg}"
        annotation = fmt_annotation(node.args.kwarg.annotation)
        if annotation:
            part += f": {annotation}"
        parts.append(part)

    return_annotation = fmt_annotation(node.returns)
    signature = f"({', '.join(parts)})"
    if return_annotation:
        signature += f" -> {return_annotation}"
    return signature


def _module_name_for(path: Path, package_root: Path) -> str:
    relative = path.relative_to(package_root.parent).with_suffix("")
    return ".".join(relative.parts)


def _relative_path(path: Path, source_root: Path) -> str:
    try:
        return str(path.relative_to(source_root))
    except ValueError:
        return str(path)


def _public_or_private(name: str) -> str:
    return "private" if name.startswith("_") else "public"


def _build_search_spec() -> dict[str, Any]:
    global _SEARCH_SPEC_CACHE
    if _SEARCH_SPEC_CACHE is not None:
        return _SEARCH_SPEC_CACHE

    package_root = _find_ida_domain_package_path()
    source_root = _find_ida_domain_source_root()

    modules: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []

    for path in sorted(package_root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue

        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        module_name = _module_name_for(path, package_root)
        module_doc = ast.get_docstring(tree) or ""
        module_info: dict[str, Any] = {
            "kind": "module",
            "name": module_name,
            "qualname": module_name,
            "file": _relative_path(path, source_root),
            "doc": module_doc,
            "summary": _summarize_text(module_doc),
            "line": 1,
            "visibility": _public_or_private(path.stem),
            "classes": [],
            "functions": [],
        }
        modules.append(module_info)
        entries.append(
            {
                "kind": "module",
                "name": module_name,
                "qualname": module_name,
                "module": module_name,
                "file": _relative_path(path, source_root),
                "line": 1,
                "doc": module_doc,
                "summary": _summarize_text(module_doc),
                "visibility": _public_or_private(path.stem),
            }
        )

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_info = {
                    "kind": "function",
                    "module": module_name,
                    "name": node.name,
                    "qualname": f"{module_name}.{node.name}",
                    "signature": _signature_from_function_node(node),
                    "file": _relative_path(path, source_root),
                    "line": node.lineno,
                    "doc": ast.get_docstring(node) or "",
                    "summary": _summarize_text(ast.get_docstring(node) or ""),
                    "visibility": _public_or_private(node.name),
                    "async": isinstance(node, ast.AsyncFunctionDef),
                }
                module_info["functions"].append(function_info)
                entries.append(function_info)
                continue

            if isinstance(node, ast.ClassDef):
                class_info: dict[str, Any] = {
                    "kind": "class",
                    "module": module_name,
                    "name": node.name,
                    "qualname": f"{module_name}.{node.name}",
                    "bases": [ast.unparse(base) for base in node.bases],
                    "file": _relative_path(path, source_root),
                    "line": node.lineno,
                    "doc": ast.get_docstring(node) or "",
                    "summary": _summarize_text(ast.get_docstring(node) or ""),
                    "visibility": _public_or_private(node.name),
                    "methods": [],
                }
                module_info["classes"].append(class_info)
                entries.append(class_info)

                for child in node.body:
                    if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    method_info = {
                        "kind": "method",
                        "module": module_name,
                        "class": node.name,
                        "name": child.name,
                        "qualname": f"{module_name}.{node.name}.{child.name}",
                        "signature": _signature_from_function_node(child),
                        "file": _relative_path(path, source_root),
                        "line": child.lineno,
                        "doc": ast.get_docstring(child) or "",
                        "summary": _summarize_text(ast.get_docstring(child) or ""),
                        "visibility": _public_or_private(child.name),
                        "async": isinstance(child, ast.AsyncFunctionDef),
                    }
                    class_info["methods"].append(method_info)
                    entries.append(method_info)

    docs: list[dict[str, Any]] = []
    docs_root = package_root / "_docs"
    if docs_root.exists():
        for path in sorted(docs_root.rglob("*.md")):
            text = path.read_text(encoding="utf-8")
            title = next(
                (
                    line.lstrip("# ").strip()
                    for line in text.splitlines()
                    if line.startswith("#")
                ),
                path.stem,
            )
            docs.append(
                {
                    "path": _relative_path(path, source_root),
                    "title": title,
                    "summary": _summarize_text(text),
                }
            )

    examples: list[dict[str, Any]] = []
    examples_root = package_root / "_examples"
    if examples_root.exists():
        for path in sorted(examples_root.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            doc = ast.get_docstring(tree) or ""
            examples.append(
                {
                    "path": _relative_path(path, source_root),
                    "name": path.stem,
                    "summary": _summarize_text(doc or source),
                }
            )

    _SEARCH_SPEC_CACHE = {
        "package": "ida_domain",
        "version": _get_ida_domain_version(),
        "root": str(source_root),
        "package_root": str(package_root),
        "modules": modules,
        "entries": entries,
        "docs": docs,
        "examples": examples,
        "counts": {
            "modules": len(modules),
            "entries": len(entries),
            "docs": len(docs),
            "examples": len(examples),
        },
    }
    return _SEARCH_SPEC_CACHE


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
    exec(stripped, global_ns, local_ns)

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


async def _run_search_worker(code: str) -> Any:
    spec = _build_search_spec()
    runtime = {
        "spec": spec,
        "entries": spec["entries"],
        "modules": spec["modules"],
        "docs": spec["docs"],
        "examples": spec["examples"],
        "counts": spec["counts"],
        "json": json,
    }
    global_ns = {
        "__builtins__": SAFE_SEARCH_BUILTINS,
        "__name__": "__codemode_search__",
        **runtime,
    }
    func = _find_callable_from_code(code, global_ns, ["run", "search", "main"])
    result = await _invoke_user_callable(func, runtime)
    return _jsonify(result)


def _database_info(db: Any, state: dict[str, Any]) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": state["path"],
        "auto_analysis": state.get("auto_analysis", True),
        "new_database": state.get("new_database", False),
        "save_on_close": state.get("save_on_close", False),
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
        except Exception:
            continue
        info[attr] = _jsonify(value)

    metadata = getattr(db, "metadata", None)
    if metadata is not None:
        try:
            info["metadata"] = _jsonify(metadata)
        except Exception:
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


def _emit_worker_result(payload: dict[str, Any]) -> int:
    print(f"{RESULT_MARKER}{json.dumps(payload)}")
    return 0 if payload.get("ok") else 1


def _worker_main(mode: str) -> int:
    payload = json.load(sys.stdin)
    code = payload.get("code", "")

    try:
        if mode != "search":
            raise ValueError(f"unsupported worker mode: {mode}")
        result = asyncio.run(_run_search_worker(code))
        return _emit_worker_result({"ok": True, "result": result})
    except Exception:
        return _emit_worker_result(
            {
                "ok": False,
                "error": traceback.format_exc().splitlines()[-1],
                "traceback": traceback.format_exc(),
            }
        )


def _extract_worker_payload(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        if line.startswith(RESULT_MARKER):
            return json.loads(line[len(RESULT_MARKER) :])
    raise McpToolError(
        "worker did not produce a structured result. Raw output:\n" + output.strip()
    )


def _run_code_in_subprocess(mode: str, code: str, timeout: int) -> Any:
    payload = json.dumps({"code": code})
    command = [
        sys.executable,
        "-u",
        str(MODULE_PATH),
        "--internal-mode",
        f"{mode}-worker",
    ]

    try:
        completed = subprocess.run(
            command,
            input=payload,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise McpToolError(f"{mode} code timed out after {timeout} seconds") from exc

    combined_output = "\n".join(
        part for part in [completed.stdout.strip(), completed.stderr.strip()] if part
    )
    worker_payload = _extract_worker_payload(completed.stdout)

    if not worker_payload.get("ok"):
        error = worker_payload.get("error", "unknown error")
        tb = worker_payload.get("traceback", "")
        extra = f"\n\nWorker output:\n{combined_output}" if combined_output else ""
        raise McpToolError(f"{error}\n\n{tb}{extra}".strip())

    return worker_payload.get("result")


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
                except Exception:
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
        save_on_close: bool,
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
                    "save_on_close": save_on_close,
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

    def close_database(
        self, instance_id: str | None, save: bool | None
    ) -> dict[str, Any]:
        target_id, instance = self._get_instance(instance_id)
        log_path = instance.log_path
        result: dict[str, Any]
        try:
            result = instance.request(
                {"command": "close", "save": save}, CLOSE_TIMEOUT_SECONDS
            )
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
                        instance.request(
                            {"command": "close", "save": None}, CLOSE_TIMEOUT_SECONDS
                        )
                    except Exception:
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
        save_on_close: bool,
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
        db = Database.open(path, ida_options, save_on_close)
        state = {
            "path": path,
            "auto_analysis": auto_analysis,
            "new_database": new_database,
            "save_on_close": save_on_close,
            "options": options,
        }
        return _database_info(db, state)

    def close_db(save: bool | None) -> dict[str, Any]:
        nonlocal db, state
        if db is None:
            return {"closed": False, "reason": "no database was open"}
        if state is None:
            raise RuntimeError("database state is missing")
        save_value = state.get("save_on_close", False) if save is None else save
        info = _database_info(db, state)
        db.close(save=save_value)
        db = None
        state = None
        return {
            "closed": True,
            "saved": save_value,
            "database": info,
        }

    def bridge_cleanup_and_exit(signum: int, _frame: Any) -> None:
        try:
            close_db(None)
        except Exception:
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
                            save_on_close=request.get("save_on_close", False),
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
                    result = close_db(request.get("save"))
                    _bridge_emit(
                        {"request_id": request_id, "ok": True, "result": result}
                    )
                    break
                else:
                    raise RuntimeError(f"unsupported bridge command: {command}")

                _bridge_emit({"request_id": request_id, "ok": True, "result": result})
            except Exception:
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
                db.close(save=state.get("save_on_close", False) if state else False)
            except Exception:
                pass
    return 0


@mcp.tool
def search(
    code: Annotated[
        str,
        (
            "Python code that searches the active ida-domain API spec. "
            "The runtime exposes spec, entries, modules, docs, examples, and counts. "
            "Return JSON-serializable data. Define run(...), search(...), main(...), "
            "or pass a lambda expression."
        ),
    ],
):
    """Search the active ida-domain API spec."""
    return _run_code_in_subprocess("search", code, SEARCH_TIMEOUT_SECONDS)


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
    save_on_close: Annotated[
        bool, "Whether changes should be saved when the instance is closed."
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
    """Open a local target in a long-lived idalib bridge instance."""
    return BRIDGE_MANAGER.open_database(
        path,
        auto_analysis=auto_analysis,
        new_database=new_database,
        save_on_close=save_on_close,
        options=options,
        set_current=set_current,
    )


@mcp.tool
def execute(
    code: Annotated[
        str,
        (
            "Python code that runs against an already-open database bridge instance. "
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
    """Execute Python code against an already-open ida-domain bridge instance."""
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
    save: Annotated[
        bool | None,
        "Override whether changes are saved before the instance closes. If omitted, use the instance default.",
    ] = None,
) -> dict[str, Any]:
    """Close an active database bridge instance."""
    return BRIDGE_MANAGER.close_database(instance_id, save)


@mcp.resource("ida://spec-summary")
def spec_summary_resource() -> dict[str, Any]:
    """Summary of the generated ida-domain search spec."""
    spec = _build_search_spec()
    return {
        "root": spec["root"],
        "counts": spec["counts"],
        "top_modules": [module["name"] for module in spec["modules"][:10]],
        "top_docs": spec["docs"][:10],
        "top_examples": spec["examples"][:10],
    }


@mcp.resource("ida://instances")
def instances_resource() -> dict[str, Any]:
    """Current database bridge instances."""
    return BRIDGE_MANAGER.list_databases()


@mcp.prompt
def codemode_examples() -> str:
    """Show examples for the search(), open_database(), execute(), and close_database() tools."""
    return """Use search() to inspect the ida-domain API metadata. Then open_database() once, run many execute() calls against the live db object, and finally close_database() when done.

search() example:
```python
lambda entries: [
    {
        "qualname": entry["qualname"],
        "signature": entry.get("signature"),
        "summary": entry.get("summary"),
    }
    for entry in entries
    if entry["kind"] in {"function", "method"}
    and "Database.open" in entry["qualname"]
]
```

open_database() example:
```json
{
  "path": "/path/to/binary-or-idb",
  "auto_analysis": true,
  "save_on_close": false,
  "set_current": true
}
```

execute() example:
```python
def run(db, to_jsonable):
    functions = []
    for index, func in enumerate(db.functions):
        if index >= 10:
            break
        functions.append({
            "name": db.functions.get_name(func),
            "start_ea": hex(func.start_ea),
            "end_ea": hex(func.end_ea),
        })
    return to_jsonable({
        "minimum_ea": hex(db.minimum_ea),
        "maximum_ea": hex(db.maximum_ea),
        "functions": functions,
    })
```

close_database() example:
```json
{
  "save": false
}
```
"""


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
        f"Using ida-domain {_get_ida_domain_version()} from {_find_ida_domain_package_path()}"
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


def _report_session_main() -> int:
    """Record the Claude session info from a PreToolUse hook payload.

    Keyed by the Claude Code parent PID so that concurrent Claude sessions —
    each with their own MCP server child — don't overwrite one another.
    """
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"report-session: invalid JSON on stdin: {exc}", file=sys.stderr)
        return 1

    target = _session_file_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "session_id": payload.get("session_id"),
        "transcript_path": payload.get("transcript_path"),
        "cwd": payload.get("cwd"),
        "hook_event_name": payload.get("hook_event_name"),
        "tool_name": payload.get("tool_name"),
        "claude_pid": os.getppid(),
        "recorded_at": _utc_now_iso(),
    }
    target.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    _prune_stale_sessions()
    return 0


def cli() -> int:
    parser = argparse.ArgumentParser(
        prog="ida-codemode-mcp",
        description="IDA Domain Code Mode MCP server",
    )
    parser.add_argument(
        "--internal-mode",
        choices=["search-worker", "bridge-worker"],
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

    subparsers.add_parser(
        "report-session",
        help="Record the Claude session ID from a PreToolUse hook payload on stdin.",
    )

    args = parser.parse_args()

    if args.internal_mode == "search-worker":
        return _worker_main("search")
    if args.internal_mode == "bridge-worker":
        return _bridge_instance_main()
    if args.command == "report-session":
        return _report_session_main()
    if args.command == "mcp":
        _serve(args.transport)
        return 0

    parser.error("a subcommand is required (mcp or report-session)")
    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
