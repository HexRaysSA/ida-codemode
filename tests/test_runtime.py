import sys
import threading
from types import SimpleNamespace

import ida_codemode.runtime as runtime_mod
from ida_codemode.runtime import AnalysisState, APIError, IDARuntime


def test_autoanalysis_none_waits_without_runtime_deadline(monkeypatch) -> None:
    class FakeKernwin:
        MFF_WRITE = 1

        def clr_cancelled(self) -> None:
            pass

        def set_cancelled(self) -> None:
            pass

        def execute_sync(self, invoke, _flags: int) -> None:
            invoke()

    class FakeAuto:
        @staticmethod
        def enable_auto(_enabled: bool) -> bool:
            return True

        @staticmethod
        def auto_wait() -> bool:
            return True

        @staticmethod
        def auto_is_ok() -> bool:
            return True

    def unexpected_deadline(*_args, **_kwargs):
        raise AssertionError("an unbounded autoanalysis wait created a deadline")

    monkeypatch.setattr(
        runtime_mod._deadline_scheduler,
        "schedule",
        unexpected_deadline,
    )

    runtime = IDARuntime.__new__(IDARuntime)
    runtime.default_timeout = 0.001
    runtime.analysis_state = AnalysisState()
    runtime.ida_auto = FakeAuto()
    runtime.ida_kernwin = FakeKernwin()
    runtime.idc = SimpleNamespace(batch=lambda _enabled: 0)
    runtime._operation_lock = threading.Lock()
    runtime._active_lock = threading.Lock()
    runtime._active_generation = 0
    runtime._active_kind = None
    runtime._active_cancel_event = None

    assert runtime.wait_autoanalysis(None) == {
        "status": "complete",
        "complete": True,
    }


def _fake_runtime() -> IDARuntime:
    class FakeKernwin:
        MFF_WRITE = 1

        def clr_cancelled(self) -> None:
            pass

        def set_cancelled(self) -> None:
            pass

        def execute_sync(self, invoke, _flags: int) -> None:
            invoke()

    runtime = IDARuntime.__new__(IDARuntime)
    runtime.ida_kernwin = FakeKernwin()
    runtime.idc = SimpleNamespace(batch=lambda _enabled: 0)
    runtime._operation_lock = threading.Lock()
    runtime._active_lock = threading.Lock()
    runtime._active_generation = 0
    runtime._active_kind = None
    runtime._active_cancel_event = None
    runtime._active_thread_id = None
    runtime._active_interrupt_error = None
    return runtime


def test_run_sync_does_not_install_python_trace() -> None:
    runtime = _fake_runtime()
    original_trace = sys.gettrace()

    assert runtime._run_sync(
        lambda: sys.gettrace() is original_trace,
        kind="execute",
        timeout=1,
        batch=False,
    )


def test_timeout_interrupts_pure_python_loop_without_tracing() -> None:
    runtime = _fake_runtime()

    def spin() -> None:
        while True:
            pass

    try:
        runtime._run_sync(spin, kind="execute", timeout=0.01, batch=False)
    except APIError as exc:
        assert exc.code == "operation_timeout"
        assert exc.status == 408
    else:
        raise AssertionError("pure Python loop ignored the execution timeout")
