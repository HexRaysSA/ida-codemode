from __future__ import annotations

import ast
import asyncio
import builtins
import importlib
import inspect
import io
import queue
import sys
import threading
import time
import traceback
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, TypedDict

from .registry import BackendName

DEFAULT_TIMEOUT_SECONDS = 60.0
SAVE_TIMEOUT_SECONDS = 300.0
USER_CODE_FILENAME = "<ida-codemode>"


class APIError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}


class CodeValidationError(ValueError):
    """The supplied code cannot be invoked with the available runtime values."""


class PythonExecutionResult(TypedDict):
    result: Any
    stdout: str
    stderr: str


class AnalysisState:
    """Thread-safe status for initial autoanalysis."""

    def __init__(self) -> None:
        self.complete = threading.Event()

    def mark_complete(self) -> None:
        self.complete.set()

    def snapshot(self) -> dict[str, Any]:
        complete = self.complete.is_set()
        return {
            "status": "complete" if complete else "running",
            "complete": complete,
        }


def to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    if hasattr(value, "__dict__"):
        public = {
            key: item for key, item in vars(value).items() if not key.startswith("_")
        }
        if public:
            return to_jsonable(public)
    return repr(value)


async def _execute_user_code(
    code: str,
    global_ns: dict[str, Any],
    runtime: dict[str, Any],
) -> Any:
    stripped = code.strip()
    if not stripped:
        raise CodeValidationError("code must not be empty")

    module = ast.parse(stripped, filename=USER_CODE_FILENAME, mode="exec")
    namespace = dict(global_ns)

    if len(module.body) == 1 and isinstance(module.body[0], ast.Expr):
        expression = ast.Expression(module.body[0].value)
        return eval(
            compile(expression, USER_CODE_FILENAME, "eval"),
            namespace,
            namespace,
        )

    if module.body and isinstance(module.body[-1], ast.Expr):
        prefix = ast.Module(body=module.body[:-1], type_ignores=module.type_ignores)
        if prefix.body:
            exec(  # noqa: S102 -- intentional Code Mode surface
                compile(prefix, USER_CODE_FILENAME, "exec"),
                namespace,
                namespace,
            )
        expression = ast.Expression(module.body[-1].value)
        return eval(
            compile(expression, USER_CODE_FILENAME, "eval"),
            namespace,
            namespace,
        )

    exec(  # noqa: S102 -- intentional Code Mode surface
        compile(module, USER_CODE_FILENAME, "exec"),
        namespace,
        namespace,
    )
    for name in ("run", "execute", "main"):
        candidate = namespace.get(name)
        if callable(candidate):
            return await _invoke_callable(candidate, runtime)
    return namespace.get("result")


def _format_user_traceback(error: BaseException) -> str | None:
    """Format only the supplied-code portion of an execution failure."""

    if isinstance(error, SyntaxError):
        return "".join(traceback.format_exception_only(error))
    frames = traceback.extract_tb(error.__traceback__)
    first_user_frame = next(
        (
            index
            for index, frame in enumerate(frames)
            if frame.filename == USER_CODE_FILENAME
        ),
        None,
    )
    if first_user_frame is None:
        return None
    return (
        "Traceback (most recent call last):\n"
        + "".join(traceback.format_list(frames[first_user_frame:]))
        + "".join(traceback.format_exception_only(error))
    )


async def _invoke_callable(
    function: Callable[..., Any],
    runtime: dict[str, Any],
) -> Any:
    signature = inspect.signature(function)
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
                raise CodeValidationError(
                    f"missing runtime value for parameter '{parameter.name}'. "
                    f"Available names: {', '.join(sorted(runtime))}"
                )
            continue
        value = runtime[parameter.name]
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[parameter.name] = value
    result = function(*args, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    return result


def create_autoanalysis_hook(analysis_state: AnalysisState) -> Any:
    """Create an IDB hook without importing IDA when this module is imported."""

    import ida_idp

    class AutoAnalysisHook(ida_idp.IDB_Hooks):
        def auto_empty_finally(self) -> None:
            analysis_state.mark_complete()

    # The IDA stubs model SWIG constructors with spurious args/kwargs.
    hook_type: Any = AutoAnalysisHook
    return hook_type()


class IDARuntime:
    """One uniform execute_sync runtime for GUI and idalib sessions."""

    def __init__(
        self,
        *,
        backend: BackendName,
        database: Any,
        analysis_state: AnalysisState,
        default_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # ida-domain loads idapro when running outside IDA, making the
        # IDAPython modules importable before the runtime binds them.
        ida_domain = importlib.import_module("ida_domain")

        import ida_auto
        import ida_kernwin
        import ida_loader
        import idaapi
        import idc
        version = tuple(
            int(part) for part in idaapi.get_kernel_version().split(".")[:2]
        )
        if version < (9, 4):
            raise RuntimeError("IDA Code Mode requires IDA 9.4 or newer")

        self.backend = backend
        self.database = database
        self.analysis_state = analysis_state
        self.default_timeout = default_timeout

        self.ida_auto = ida_auto
        self.ida_kernwin = ida_kernwin
        self.ida_loader = ida_loader
        self.idc = idc
        self.ida_domain = ida_domain

        self._operation_lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active_generation = 0
        self._active_kind: str | None = None
        self._active_cancel_event: threading.Event | None = None

    def _run_sync(
        self,
        function: Callable[[], Any],
        *,
        kind: str,
        timeout: float | None,
        batch: bool = True,
        capture_output: bool = False,
    ) -> Any:
        effective_timeout = self.default_timeout if timeout is None else timeout
        results: queue.Queue[tuple[bool, Any, str | None, str, str]] = queue.Queue(
            maxsize=1
        )

        with self._operation_lock:
            cancel_event = threading.Event()
            with self._active_lock:
                self._active_generation += 1
                generation = self._active_generation
                self._active_kind = kind
                self._active_cancel_event = cancel_event

            def invoke() -> int:
                old_batch: int | None = None
                old_trace = sys.gettrace()
                timer: threading.Timer | None = None
                deadline = (
                    time.monotonic() + effective_timeout
                    if effective_timeout > 0
                    else None
                )
                self.ida_kernwin.clr_cancelled()
                stdout_capture = io.StringIO()
                stderr_capture = io.StringIO()

                def fire_native_cancel() -> None:
                    # Keep the generation check and flag update under one lock.
                    # The outer cleanup clears the flag only after changing the
                    # active generation, preventing a late timer from poisoning
                    # the following request.
                    with self._active_lock:
                        if (
                            self._active_generation == generation
                            and self._active_kind == kind
                        ):
                            self.ida_kernwin.set_cancelled()

                trace_events = 0

                def timeout_trace(frame: Any, event: str, arg: Any) -> Any:
                    nonlocal trace_events
                    # Line tracing cannot interrupt `while True: pass` because
                    # every iteration remains on one source line. Opcode events
                    # make arbitrary Python cancellable; sample them to keep the
                    # tracing overhead reasonable.
                    frame.f_trace_opcodes = True
                    trace_events += 1
                    if event == "opcode" and trace_events % 256:
                        return timeout_trace
                    if cancel_event.is_set():
                        raise APIError(
                            "operation_cancelled",
                            f"{kind} was cancelled",
                            status=409,
                        )
                    if deadline is not None and time.monotonic() >= deadline:
                        raise APIError(
                            "operation_timeout",
                            f"{kind} timed out after {effective_timeout:.2f}s",
                            status=408,
                        )
                    return timeout_trace

                try:
                    if batch:
                        old_batch = self.idc.batch(1)
                    if deadline is not None:
                        timer = threading.Timer(effective_timeout, fire_native_cancel)
                        timer.daemon = True
                        timer.start()
                        sys.settrace(timeout_trace)
                    if capture_output:
                        with redirect_stdout(stdout_capture), redirect_stderr(
                            stderr_capture
                        ):
                            result = function()
                    else:
                        result = function()
                    results.put(
                        (
                            True,
                            result,
                            None,
                            stdout_capture.getvalue(),
                            stderr_capture.getvalue(),
                        )
                    )
                except BaseException as exc:  # noqa: BLE001 -- marshal any IDA callback failure
                    results.put(
                        (
                            False,
                            exc,
                            _format_user_traceback(exc),
                            stdout_capture.getvalue(),
                            stderr_capture.getvalue(),
                        )
                    )
                finally:
                    sys.settrace(old_trace)
                    if timer is not None:
                        timer.cancel()
                    self.ida_kernwin.clr_cancelled()
                    if old_batch is not None:
                        self.idc.batch(old_batch)
                return 1

            try:
                self.ida_kernwin.execute_sync(invoke, self.ida_kernwin.MFF_WRITE)
                try:
                    succeeded, value, formatted_traceback, stdout, stderr = (
                        results.get_nowait()
                    )
                except queue.Empty as exc:
                    raise APIError(
                        "execute_sync_failed",
                        "IDA did not execute the synchronized request",
                        status=500,
                    ) from exc
            finally:
                with self._active_lock:
                    if self._active_generation == generation:
                        self._active_kind = None
                        self._active_cancel_event = None
                # Defend against a timer racing with Timer.cancel().
                self.ida_kernwin.clr_cancelled()

        if succeeded:
            if capture_output:
                return PythonExecutionResult(
                    result=value,
                    stdout=stdout,
                    stderr=stderr,
                )
            return value
        if isinstance(value, APIError):
            if stdout:
                value.details["stdout"] = stdout
            if stderr:
                value.details["stderr"] = stderr
            raise value
        if isinstance(value, CodeValidationError):
            raise APIError("invalid_code", str(value), status=400) from value
        details: dict[str, Any] = {}
        if formatted_traceback is not None:
            details["traceback"] = formatted_traceback
        if stdout:
            details["stdout"] = stdout
        if stderr:
            details["stderr"] = stderr
        raise APIError(
            "execution_failed",
            str(value) or type(value).__name__,
            status=400,
            details=details,
        ) from value

    def execute_python(
        self,
        code: str,
        timeout: float | None,
    ) -> PythonExecutionResult:
        def execute() -> Any:
            runtime = {
                "db": self.database,
                "ida_domain": self.ida_domain,
            }
            global_ns = {
                "__builtins__": builtins.__dict__,
                "__name__": "__ida_codemode_execute__",
                **runtime,
            }
            result = asyncio.run(_execute_user_code(code, global_ns, runtime))
            return to_jsonable(result)

        return self._run_sync(
            execute,
            kind="execute",
            timeout=timeout,
            capture_output=True,
        )

    def wait_autoanalysis(self, timeout: float | None) -> dict[str, Any]:
        if self.analysis_state.complete.is_set():
            return self.analysis_state.snapshot()

        def wait() -> bool:
            previously_enabled = self.ida_auto.enable_auto(True)
            try:
                completed = bool(self.ida_auto.auto_wait())
            finally:
                if not previously_enabled:
                    self.ida_auto.enable_auto(False)
            if completed and self.ida_auto.auto_is_ok():
                self.analysis_state.mark_complete()
            return completed

        completed = self._run_sync(wait, kind="analysis", timeout=timeout)
        status = self.analysis_state.snapshot()
        if not completed and not status["complete"]:
            raise APIError(
                "analysis_cancelled",
                "Autoanalysis was cancelled before completion",
                status=409,
            )
        return status

    def save_database(self) -> dict[str, Any]:
        def save() -> dict[str, Any]:
            path = self.ida_loader.get_path(self.ida_loader.PATH_TYPE_IDB) or ""
            if not path:
                raise APIError(
                    "no_database", "No database is currently open", status=409
                )

            if self.backend == "gui":
                is_temporary = bool(
                    self.ida_loader.is_database_flag(self.ida_loader.DBFL_TEMP)
                )
                if is_temporary:
                    raise APIError(
                        "save_as_required",
                        "Use Save As in the IDA GUI before saving remotely",
                        status=409,
                    )
                saved = bool(self.ida_kernwin.process_ui_action("SaveBase"))
            else:
                saved = bool(self.ida_loader.save_database(path, 0))
            if not saved:
                raise APIError(
                    "save_failed",
                    "IDA failed to save the database",
                    status=500,
                )
            return {"saved": True, "idb_path": str(Path(path).resolve())}

        return self._run_sync(
            save,
            kind="save",
            timeout=SAVE_TIMEOUT_SECONDS,
            batch=False,
        )
