from __future__ import annotations

import asyncio
from dataclasses import asdict, is_dataclass
from enum import Enum
import builtins
import inspect
import json
from pathlib import Path
import queue
import sys
import threading
import time
import traceback
from typing import Any, Callable

from .registry import BackendName


DEFAULT_TIMEOUT_SECONDS = 60.0
SAVE_TIMEOUT_SECONDS = 300.0


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


def _find_callable(code: str, global_ns: dict[str, Any]) -> Callable[..., Any]:
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
    preferred_names = ("run", "execute", "main")
    for name in preferred_names:
        value = local_ns.get(name)
        if callable(value):
            return value
    discovered = [
        value
        for name, value in local_ns.items()
        if callable(value) and not name.startswith("__")
    ]
    if len(discovered) == 1:
        return discovered[0]
    raise ValueError(
        "code must evaluate to a callable or define one callable named "
        + ", ".join(preferred_names)
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
        database_path: str,
        database_options: dict[str, Any] | None = None,
        default_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        import ida_auto
        import ida_kernwin
        import ida_loader
        import idaapi
        import idc
        import ida_domain
        from ida_domain import Database
        from ida_domain.database import IdaCommandOptions

        version = tuple(
            int(part) for part in idaapi.get_kernel_version().split(".")[:2]
        )
        if version < (9, 4):
            raise RuntimeError("IDA Code Mode requires IDA 9.4 or newer")

        self.backend = backend
        self.database = database
        self.analysis_state = analysis_state
        self.database_path = database_path
        self.database_options = database_options or {}
        self.default_timeout = default_timeout

        self.ida_auto = ida_auto
        self.ida_kernwin = ida_kernwin
        self.ida_loader = ida_loader
        self.idc = idc
        self.ida_domain = ida_domain
        self.Database = Database
        self.IdaCommandOptions = IdaCommandOptions

        self._operation_lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active_generation = 0
        self._active_kind: str | None = None
        self._active_cancel_event: threading.Event | None = None
        self._closing = threading.Event()

    def _request_cancel(self) -> None:
        with self._active_lock:
            if self._active_kind in {"execute", "analysis"}:
                if self._active_cancel_event is not None:
                    self._active_cancel_event.set()
                self.ida_kernwin.set_cancelled()

    def _run_sync(
        self,
        function: Callable[[], Any],
        *,
        kind: str,
        timeout: float | None,
        batch: bool = True,
    ) -> Any:
        effective_timeout = self.default_timeout if timeout is None else timeout
        results: queue.Queue[tuple[bool, Any, str | None]] = queue.Queue(maxsize=1)

        with self._operation_lock:
            if self._closing.is_set() and kind != "close":
                raise APIError(
                    "database_closing",
                    "The database is closing",
                    status=409,
                )
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
                    result = function()
                    results.put((True, result, None))
                except BaseException as exc:
                    results.put((False, exc, traceback.format_exc()))
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
                    succeeded, value, formatted_traceback = results.get_nowait()
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
            return value
        if isinstance(value, APIError):
            raise value
        raise APIError(
            "execution_failed",
            str(value) or type(value).__name__,
            status=400,
            details={"traceback": formatted_traceback},
        ) from value

    def execute_python(self, code: str, timeout: float | None) -> Any:
        def execute() -> Any:
            runtime = {
                "ida_domain": self.ida_domain,
                "Database": self.Database,
                "IdaCommandOptions": self.IdaCommandOptions,
                "db": self.database,
                "database_path": self.database_path,
                "database_options": self.database_options,
                "json": json,
                "to_jsonable": to_jsonable,
            }
            global_ns = {
                "__builtins__": builtins.__dict__,
                "__name__": "__ida_codemode_execute__",
                **runtime,
            }
            function = _find_callable(code, global_ns)
            return to_jsonable(asyncio.run(_invoke_callable(function, runtime)))

        return self._run_sync(execute, kind="execute", timeout=timeout)

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

    def close_database(self) -> dict[str, Any]:
        if self.backend == "gui":
            raise APIError(
                "gui_database_owned_by_user",
                "The database belongs to an interactive IDA session and cannot be closed remotely",
                status=409,
            )
        self._closing.set()
        self._request_cancel()

        def close() -> dict[str, Any]:
            if self.database is None:
                raise APIError(
                    "no_database", "No database is currently open", status=409
                )
            path = (
                self.ida_loader.get_path(self.ida_loader.PATH_TYPE_IDB)
                or self.database_path
            )
            self.database.close(save=True)
            self.database = None
            return {
                "closed": True,
                "saved": True,
                "idb_path": str(Path(path).resolve()) if path else "",
            }

        try:
            return self._run_sync(
                close,
                kind="close",
                timeout=SAVE_TIMEOUT_SECONDS,
                batch=False,
            )
        except Exception:
            # A failed final save leaves the owned database open and usable.
            self._closing.clear()
            raise
