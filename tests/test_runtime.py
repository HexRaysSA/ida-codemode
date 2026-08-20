from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from ida_nexus._runtime import (
    IDARuntime,
    PythonExecutionResult,
    _execute_user_code,
)


def _namespace() -> dict[str, Any]:
    return {"__builtins__": __builtins__, "db": object()}


def test_execute_user_code_preserves_repl_namespace() -> None:
    namespace = _namespace()
    runtime = {"db": namespace["db"]}

    assert _execute_user_code("offset = 40", namespace, runtime) is None
    assert _execute_user_code("offset + 2", namespace, runtime) == 42
    assert (
        _execute_user_code("def add(value): return offset + value", namespace, runtime)
        is None
    )
    assert _execute_user_code("offset = 41", namespace, runtime) is None
    assert _execute_user_code("add(1)", namespace, runtime) == 42


def test_old_entrypoint_is_not_reused_and_result_is_per_call() -> None:
    namespace = _namespace()
    runtime = {"db": namespace["db"]}

    assert _execute_user_code("def run(db): return 7", namespace, runtime) == 7
    assert _execute_user_code("value = 1", namespace, runtime) is None
    assert _execute_user_code("result = 9", namespace, runtime) == 9
    assert _execute_user_code("result = 9", namespace, runtime) == 9
    assert _execute_user_code("other = 2", namespace, runtime) is None
    with pytest.raises(NameError):
        _execute_user_code("result", namespace, runtime)


def _inline_runtime(monkeypatch: pytest.MonkeyPatch) -> IDARuntime:
    monkeypatch.setitem(__import__("sys").modules, "ida_domain", SimpleNamespace())
    runtime = object.__new__(IDARuntime)
    runtime.database = object()
    runtime.default_timeout = 60.0
    runtime._session_namespaces = {}

    def run_inline(
        function,
        *,
        kind: str,
        timeout: float | None,
        batch: bool = True,
        capture_output: bool = False,
        trace_filename: str | None = None,
    ) -> Any:
        result = function()
        if capture_output:
            return PythonExecutionResult(result=result, stdout="", stderr="")
        return result

    monkeypatch.setattr(runtime, "_run_sync", run_inline)
    return runtime


def test_stateless_execution_discards_persistent_lease_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)

    runtime.execute_python(
        "answer = 42",
        None,
        lease_id="agent",
        persist_globals=True,
    )
    namespace = runtime._session_namespaces["agent"]

    stateless = runtime.execute_python(
        "globals().get('answer')",
        None,
        lease_id="agent",
    )
    resumed = runtime.execute_python(
        "globals().get('answer')",
        None,
        lease_id="agent",
        persist_globals=True,
    )

    assert stateless["result"] is None
    assert resumed["result"] is None
    assert namespace == {}
    assert runtime._session_namespaces["agent"] is not namespace


def test_runtime_namespaces_are_isolated_and_released_per_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _inline_runtime(monkeypatch)

    def execute(code: str, lease_id: str) -> PythonExecutionResult:
        return runtime.execute_python(
            code,
            None,
            lease_id=lease_id,
            persist_globals=True,
        )

    runtime.execute_python("temporary = 1", None, lease_id="agent-a")
    fresh = runtime.execute_python(
        "globals().get('temporary')", None, lease_id="agent-a"
    )
    execute("answer = 42", "agent-a")
    first = execute("answer", "agent-a")
    second = execute("globals().get('answer')", "agent-b")
    execute("_adapter_state = {'retained': object()}", "agent-a")
    execute("db = None", "agent-a")
    refreshed = execute("db is None", "agent-a")

    assert fresh["result"] is None
    assert first["result"] == 42
    assert second["result"] is None
    assert refreshed["result"] is False
    namespace = runtime._session_namespaces["agent-a"]
    assert namespace["_adapter_state"]["retained"] is not None

    runtime.release_session("agent-a")

    assert namespace == {}
    assert "agent-a" not in runtime._session_namespaces
    reopened = execute("globals().get('answer')", "agent-a")
    assert reopened["result"] is None
