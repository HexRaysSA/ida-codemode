from __future__ import annotations

import queue
import sys
import threading
import time
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from ida_codemode.runtime import APIError, IDARuntime, AnalysisState


class FakeDatabase:
    def __init__(self) -> None:
        self.closed = False
        self.saved = False

    def close(self, save=True) -> None:
        self.closed = True
        self.saved = save


@pytest.fixture
def fake_ida(monkeypatch):
    state = SimpleNamespace(cancelled=False, save_actions=0, saved=0)

    kernwin: Any = ModuleType("ida_kernwin")
    kernwin.MFF_WRITE = 1
    kernwin.execute_sync = lambda callback, flags: callback()
    kernwin.clr_cancelled = lambda: setattr(state, "cancelled", False)
    kernwin.set_cancelled = lambda: setattr(state, "cancelled", True)
    kernwin.process_ui_action = lambda name: (
        setattr(state, "save_actions", state.save_actions + 1) or name == "SaveBase"
    )

    auto: Any = ModuleType("ida_auto")
    auto.enable_auto = lambda enabled: False
    auto.auto_wait = lambda: True
    auto.auto_is_ok = lambda: True

    loader: Any = ModuleType("ida_loader")
    loader.PATH_TYPE_IDB = 1
    loader.DBFL_TEMP = 2
    loader.get_path = lambda kind: "/tmp/runtime.i64"
    loader.is_database_flag = lambda flag: False
    loader.save_database = lambda path, flags: (
        setattr(state, "saved", state.saved + 1) or True
    )

    idaapi: Any = ModuleType("idaapi")
    idaapi.get_kernel_version = lambda: "9.4"

    idc: Any = ModuleType("idc")
    idc.batch = lambda value: 0

    domain: Any = ModuleType("ida_domain")
    domain.Database = FakeDatabase
    domain_db: Any = ModuleType("ida_domain.database")
    domain_db.IdaCommandOptions = type("IdaCommandOptions", (), {})

    for name, module in {
        "ida_auto": auto,
        "ida_kernwin": kernwin,
        "ida_loader": loader,
        "idaapi": idaapi,
        "idc": idc,
        "ida_domain": domain,
        "ida_domain.database": domain_db,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    return state


def make_runtime(backend="idalib"):
    return IDARuntime(
        backend=backend,
        database=FakeDatabase(),
        analysis_state=AnalysisState(),
        database_path="/tmp/runtime.i64",
        database_options={"backend": backend},
    )


def test_execute_python_callable_contract(fake_ida):
    runtime = make_runtime()
    result = runtime.execute_python(
        "def run(database_path, database_options):\n"
        "    return {'path': database_path, 'backend': database_options['backend']}",
        1,
    )
    assert result == {"path": "/tmp/runtime.i64", "backend": "idalib"}


def test_python_timeout_does_not_poison_next_request(fake_ida):
    runtime = make_runtime()
    with pytest.raises(APIError) as raised:
        runtime.execute_python("lambda: exec('while True: pass')", 0.01)
    assert raised.value.code == "operation_timeout"
    assert fake_ida.cancelled is False
    assert runtime.execute_python("lambda: 7", 1) == 7


def test_analysis_and_save_use_shared_dispatcher(fake_ida):
    runtime = make_runtime()
    assert runtime.wait_autoanalysis(1)["complete"] is True
    assert runtime.save_database()["saved"] is True
    assert fake_ida.saved == 1


def test_gui_save_uses_savebase_and_close_fails(fake_ida):
    runtime = make_runtime("gui")
    assert runtime.save_database()["saved"] is True
    assert fake_ida.save_actions == 1
    with pytest.raises(APIError) as raised:
        runtime.close_database()
    assert raised.value.code == "gui_database_owned_by_user"
    assert runtime.database.closed is False


def test_idalib_close_saves_owned_database(fake_ida):
    runtime = make_runtime()
    database = runtime.database
    result = runtime.close_database()
    assert result["closed"] is True
    assert result["saved"] is True
    assert database.closed is True
    assert database.saved is True
    assert runtime.database is None


def test_idalib_close_cancels_active_python(fake_ida):
    runtime = make_runtime()
    outcome = queue.Queue(maxsize=1)

    def execute_forever():
        try:
            runtime.execute_python("lambda: exec('while True: pass')", 10)
        except APIError as exc:
            outcome.put(exc.code)

    thread = threading.Thread(target=execute_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2
    while runtime._active_kind != "execute" and time.monotonic() < deadline:
        time.sleep(0.001)

    assert runtime.close_database()["closed"] is True
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert outcome.get_nowait() == "operation_cancelled"
