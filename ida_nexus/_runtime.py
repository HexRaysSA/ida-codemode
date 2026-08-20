import ast
import asyncio
import builtins
import ctypes
import heapq
import inspect
import io
import math
import threading
import time
import traceback
import warnings
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from ._registry import BackendName
from .models import PythonExecutionResult

DEFAULT_TIMEOUT_SECONDS = 60.0
SAVE_TIMEOUT_SECONDS = 300.0
USER_CODE_FILENAME = "<ida-nexus>"


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


class _OperationInterrupt(BaseException):
    """Asynchronous exception used to stop Python code without tracing it."""


# Nexus runs on CPython through IDAPython. Injecting one private exception
# into the executing thread keeps pure-Python loops cancellable without
# installing a trace callback on every opcode. Use a void pointer so a null
# value can undo the injection if CPython ever reports multiple matching thread
# states (which should be impossible for a threading.get_ident() value).
_set_async_exc = ctypes.pythonapi.PyThreadState_SetAsyncExc
_set_async_exc.argtypes = (ctypes.c_ulong, ctypes.c_void_p)
_set_async_exc.restype = ctypes.c_int


def _interrupt_thread(thread_id: int) -> bool:
    count = _set_async_exc(thread_id, id(_OperationInterrupt))
    if count > 1:
        _set_async_exc(thread_id, None)
        raise RuntimeError("CPython matched multiple Nexus execution threads")
    return count == 1


class _DeadlineScheduler:
    """One reusable daemon for execution deadlines across all runtimes."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._deadlines: list[tuple[float, int]] = []
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._next_token = 0
        self._thread: threading.Thread | None = None

    def schedule(self, delay: float, callback: Callable[[], None]) -> int:
        deadline = time.monotonic() + delay
        with self._condition:
            self._next_token += 1
            token = self._next_token
            self._callbacks[token] = callback
            heapq.heappush(self._deadlines, (deadline, token))
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run,
                    name="ida-nexus-deadlines",
                    daemon=True,
                )
                self._thread.start()
            self._condition.notify()
            return token

    def cancel(self, token: int) -> None:
        with self._condition:
            if self._callbacks.pop(token, None) is not None:
                self._condition.notify()

    def _run(self) -> None:
        while True:
            callback: Callable[[], None] | None = None
            with self._condition:
                while callback is None:
                    while (
                        self._deadlines and self._deadlines[0][1] not in self._callbacks
                    ):
                        heapq.heappop(self._deadlines)
                    if not self._deadlines:
                        self._condition.wait()
                        continue
                    deadline, token = self._deadlines[0]
                    delay = deadline - time.monotonic()
                    if delay > 0:
                        self._condition.wait(delay)
                        continue
                    heapq.heappop(self._deadlines)
                    callback = self._callbacks.pop(token, None)
            if callback is not None:
                try:
                    callback()
                except BaseException as exc:  # noqa: BLE001 -- keep the scheduler alive
                    warnings.warn(
                        f"Nexus deadline callback failed: {exc}",
                        RuntimeWarning,
                        stacklevel=1,
                    )


_deadline_scheduler = _DeadlineScheduler()


def _execute_user_code(
    code: str,
    namespace: dict[str, Any],
    runtime: dict[str, Any],
    filename: str | None = None,
) -> Any:
    if not filename:
        filename = USER_CODE_FILENAME

    stripped = code.strip()
    if not stripped:
        raise CodeValidationError("code must not be empty")

    module = ast.parse(stripped, filename=filename, mode="exec")
    previous_entrypoints = {
        name: namespace.get(name) for name in ("run", "execute", "main")
    }
    # `result` is the legacy per-call output slot, not durable REPL state.
    # Ordinary names remain untouched in the persistent namespace.
    namespace.pop("result", None)
    try:
        if len(module.body) == 1 and isinstance(module.body[0], ast.Expr):
            expression = ast.Expression(module.body[0].value)
            return eval(
                compile(expression, filename, "eval"),
                namespace,
                namespace,
            )

        if module.body and isinstance(module.body[-1], ast.Expr):
            prefix = ast.Module(body=module.body[:-1], type_ignores=module.type_ignores)
            if prefix.body:
                exec(  # noqa: S102 -- intentional Nexus surface
                    compile(prefix, filename, "exec"),
                    namespace,
                    namespace,
                )
            expression = ast.Expression(module.body[-1].value)
            return eval(
                compile(expression, filename, "eval"),
                namespace,
                namespace,
            )

        exec(  # noqa: S102 -- intentional Nexus surface
            compile(module, filename, "exec"),
            namespace,
            namespace,
        )
        for name in ("run", "execute", "main"):
            candidate = namespace.get(name)
            if callable(candidate) and candidate is not previous_entrypoints[name]:
                return _invoke_callable(candidate, runtime)
        return namespace.get("result")
    finally:
        namespace.pop("result", None)


def _format_user_traceback(error: BaseException, trace_filename: str) -> str | None:
    """Format only the supplied-code portion of an execution failure."""

    if isinstance(error, SyntaxError):
        return "".join(traceback.format_exception_only(error))
    frames = traceback.extract_tb(error.__traceback__)
    first_user_frame = next(
        (
            index
            for index, frame in enumerate(frames)
            if frame.filename == trace_filename
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


def _invoke_callable(
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
    return function(*args, **kwargs)


def _suppress_ida_domain_warnings() -> None:
    warnings.filterwarnings(
        "ignore",
        category=Warning,
        module=r"^ida_domain(?:\.|$)",
    )


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
        # Library warnings would otherwise be captured as stderr and returned
        # to the agent alongside execution output.
        _suppress_ida_domain_warnings()

        # Outside IDA, ida-domain loads idapro and makes IDAPython modules
        # such as idaapi importable.
        import ida_domain as _ida_domain  # noqa: F401
        import idaapi

        version = tuple(
            int(part) for part in idaapi.get_kernel_version().split(".")[:2]
        )
        if version < (9, 4):
            raise RuntimeError("IDA Nexus requires IDA 9.4 or newer")

        if not math.isfinite(default_timeout) or default_timeout <= 0:
            raise ValueError("default_timeout must be a positive finite number")

        self.backend = backend
        self.database = database
        self.analysis_state = analysis_state
        self.default_timeout = default_timeout

        self._operation_lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active_generation = 0
        self._active_kind: str | None = None
        self._active_cancel_event: threading.Event | None = None
        self._active_thread_id: int | None = None
        self._active_interrupt_error: APIError | None = None
        self._session_namespaces: dict[str, dict[str, Any]] = {}

    def _interrupt_active(
        self,
        generation: int,
        kind: str,
        error: APIError,
    ) -> None:
        """Interrupt the active native or Python operation exactly once."""

        import ida_kernwin

        with self._active_lock:
            if (
                self._active_generation != generation
                or self._active_kind != kind
                or self._active_cancel_event is None
                or self._active_interrupt_error is not None
            ):
                return
            self._active_interrupt_error = error
            self._active_cancel_event.set()
            ida_kernwin.set_cancelled()
            if self._active_thread_id is not None:
                _interrupt_thread(self._active_thread_id)

    def _run_sync(
        self,
        function: Callable[[], Any],
        *,
        kind: str,
        timeout: float | None,
        batch: bool = True,
        capture_output: bool = False,
        trace_filename: str | None = None,
    ) -> Any:
        import ida_kernwin
        import idc

        if not trace_filename:
            trace_filename = USER_CODE_FILENAME

        effective_timeout = timeout
        if effective_timeout is not None and (
            not math.isfinite(effective_timeout) or effective_timeout <= 0
        ):
            raise APIError(
                "invalid_timeout",
                "timeout must be a positive finite number",
            )
        outcome: tuple[bool, Any, str | None, str, str] | None = None

        with self._operation_lock:
            cancel_event = threading.Event()
            with self._active_lock:
                self._active_generation += 1
                generation = self._active_generation
                self._active_kind = kind
                self._active_cancel_event = cancel_event
                self._active_thread_id = None
                self._active_interrupt_error = None

            def invoke() -> int:
                nonlocal outcome
                old_batch: int | None = None
                deadline_token: int | None = None
                ida_kernwin.clr_cancelled()
                stdout_capture = io.StringIO()
                stderr_capture = io.StringIO()

                def timeout_operation() -> None:
                    assert effective_timeout is not None
                    self._interrupt_active(
                        generation,
                        kind,
                        APIError(
                            "operation_timeout",
                            f"{kind} timed out after {effective_timeout:.2f}s",
                            status=408,
                        ),
                    )

                def call_function() -> Any:
                    # Limit asynchronous interruption to user execution. Once
                    # this function returns, timeout/cancel callbacks can no
                    # longer replace an error while it is being marshalled.
                    try:
                        with self._active_lock:
                            self._active_thread_id = threading.get_ident()
                            pending_error = self._active_interrupt_error
                        if pending_error is not None:
                            raise pending_error
                        if capture_output:
                            with (
                                redirect_stdout(stdout_capture),
                                redirect_stderr(stderr_capture),
                            ):
                                return function()
                        return function()
                    finally:
                        with self._active_lock:
                            if self._active_generation == generation:
                                self._active_thread_id = None

                try:
                    if batch:
                        old_batch = idc.batch(1)
                    if effective_timeout is not None:
                        deadline_token = _deadline_scheduler.schedule(
                            effective_timeout,
                            timeout_operation,
                        )
                    result = call_function()
                    outcome = (
                        True,
                        result,
                        None,
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                except _OperationInterrupt:
                    with self._active_lock:
                        error = self._active_interrupt_error
                    if error is None:
                        error = APIError(
                            "operation_cancelled",
                            f"{kind} was interrupted",
                            status=409,
                        )
                    outcome = (
                        False,
                        error,
                        None,
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                except SystemExit as exc:
                    outcome = (
                        False,
                        APIError(
                            "system_exit",
                            f"{kind} raised SystemExit({exc.code!r})",
                            status=409,
                            details={
                                "exit_code": exc.code,
                                "stdout": stdout_capture.getvalue(),
                                "stderr": stderr_capture.getvalue(),
                            },
                        ),
                        repr(exc.code),
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                except BaseException as exc:  # noqa: BLE001 -- marshal any IDA callback failure
                    outcome = (
                        False,
                        exc,
                        _format_user_traceback(exc, trace_filename),
                        stdout_capture.getvalue(),
                        stderr_capture.getvalue(),
                    )
                finally:
                    with self._active_lock:
                        if self._active_generation == generation:
                            self._active_thread_id = None
                    if deadline_token is not None:
                        _deadline_scheduler.cancel(deadline_token)
                    ida_kernwin.clr_cancelled()
                    if old_batch is not None:
                        idc.batch(old_batch)
                return 1

            try:
                ida_kernwin.execute_sync(invoke, ida_kernwin.MFF_WRITE)
                if outcome is None:
                    raise APIError(
                        "execute_sync_failed",
                        "IDA did not execute the synchronized request",
                        status=500,
                    )
                succeeded, value, formatted_traceback, stdout, stderr = outcome
            finally:
                with self._active_lock:
                    if self._active_generation == generation:
                        self._active_kind = None
                        self._active_cancel_event = None
                        self._active_thread_id = None
                        self._active_interrupt_error = None
                # Defend against a timeout racing with deadline cancellation.
                ida_kernwin.clr_cancelled()

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

    def cancel_active(self) -> None:
        """Request cancellation of the current IDA operation."""

        with self._active_lock:
            generation = self._active_generation
            kind = self._active_kind
        if kind is not None:
            self._interrupt_active(
                generation,
                kind,
                APIError(
                    "operation_cancelled",
                    f"{kind} was cancelled",
                    status=409,
                ),
            )

    def execute_python(
        self,
        code: str,
        timeout: float | None,
        *,
        lease_id: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ) -> PythonExecutionResult:
        import ida_domain

        if not filename:
            filename = USER_CODE_FILENAME

        def execute() -> Any:
            runtime = {
                "db": self.database,
                "ida_domain": ida_domain,
            }
            if not persist_globals:
                if lease_id is not None:
                    previous = self._session_namespaces.pop(lease_id, None)
                    if previous is not None:
                        previous.clear()
                namespace = {
                    "__builtins__": builtins.__dict__,
                    "__name__": "__ida_nexus_execute__",
                    **runtime,
                }
            else:
                if lease_id is None:
                    raise APIError(
                        "invalid_lease",
                        "persist_globals requires an active lease",
                    )
                namespace = self._session_namespaces.setdefault(lease_id, {})
                # Runtime-owned globals remain valid even if a prior snippet
                # rebound or deleted them; all other names behave like a REPL.
                namespace.update(
                    {
                        "__builtins__": builtins.__dict__,
                        "__name__": "__ida_nexus_execute__",
                        **runtime,
                    }
                )
            result = _execute_user_code(code, namespace, runtime, filename)
            if inspect.isawaitable(result):
                result = asyncio.run(result)
            return result

        return self._run_sync(
            execute,
            kind="execute",
            timeout=self.default_timeout if timeout is None else timeout,
            capture_output=True,
            trace_filename=filename,
        )

    def release_session(self, lease_id: str) -> None:
        """Release process-bound objects retained by one disconnected client."""

        def release() -> None:
            namespace = self._session_namespaces.pop(lease_id, None)
            if namespace is not None:
                # Explicitly break function -> __globals__ -> function cycles
                # so process-bound IDA objects are released with the lease,
                # not at a later cyclic-GC pass.
                namespace.clear()

        self._run_sync(
            release,
            kind="release_session",
            timeout=None,
            batch=False,
        )

    def wait_autoanalysis(self, timeout: float | None) -> dict[str, Any]:
        import ida_auto

        if self.analysis_state.complete.is_set():
            return self.analysis_state.snapshot()

        def wait() -> bool:
            previously_enabled = ida_auto.enable_auto(True)
            try:
                completed = bool(ida_auto.auto_wait())
            finally:
                if not previously_enabled:
                    ida_auto.enable_auto(False)
            if completed and ida_auto.auto_is_ok():
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
        import ida_kernwin
        import ida_loader

        def save() -> dict[str, Any]:
            path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
            if not path:
                raise APIError(
                    "no_database", "No database is currently open", status=409
                )

            if self.backend == "gui":
                is_temporary = bool(ida_loader.is_database_flag(ida_loader.DBFL_TEMP))
                if is_temporary:
                    raise APIError(
                        "save_as_required",
                        "Use Save As in the IDA GUI before saving remotely",
                        status=409,
                    )
                saved = bool(ida_kernwin.process_ui_action("SaveBase"))
            else:
                saved = bool(ida_loader.save_database(path, 0))
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
