import threading
from types import SimpleNamespace

import ida_codemode.runtime as runtime_mod
from ida_codemode.runtime import AnalysisState, IDARuntime


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

    def unexpected_timer(*_args, **_kwargs):
        raise AssertionError("an unbounded autoanalysis wait created a timer")

    monkeypatch.setattr(runtime_mod.threading, "Timer", unexpected_timer)

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
