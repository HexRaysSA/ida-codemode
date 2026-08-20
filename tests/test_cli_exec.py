from __future__ import annotations

import builtins
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

from ida_nexus.models import PythonExecutionResult

exec_module = importlib.import_module("ida_nexus.cli.exec")


class FakeHandle:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def execute_python(
        self,
        code: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> PythonExecutionResult:
        del timeout
        self.calls.append({"code": code, **kwargs})
        return {"result": None, "stdout": "", "stderr": ""}


@pytest.mark.parametrize(
    ("interactive", "expected_label"),
    [
        (True, "REPL: interactive"),
        (False, "REPL: stdin"),
    ],
)
def test_repl_labels_interactive_and_stdin_execution(
    monkeypatch: pytest.MonkeyPatch,
    interactive: bool,
    expected_label: str,
) -> None:
    handle = FakeHandle()
    inputs: list[str | BaseException] = ["1", EOFError()]

    def fake_input(_prompt: str) -> str:
        value = inputs.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: interactive))
    monkeypatch.setattr(builtins, "input", fake_input)

    exec_module.repl(handle)

    assert handle.calls == [
        {
            "code": "1",
            "operation_label": expected_label,
            "persist_globals": True,
            "filename": "<stdin>",
        }
    ]


def test_main_labels_command_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = FakeHandle()
    monkeypatch.setattr(
        exec_module.DatabaseHandle,
        "open",
        staticmethod(lambda _path: handle),
    )

    assert exec_module.main(["database.i64", "-c", "answer = 42"]) == 0

    assert handle.calls == [
        {
            "code": "answer = 42",
            "operation_label": "REPL: command",
            "persist_globals": True,
            "filename": "<string>",
        }
    ]


def test_main_labels_script_with_absolute_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    script = tmp_path / "rename_functions.py"
    script.write_text("answer = 42\n")
    handle = FakeHandle()
    monkeypatch.setattr(
        exec_module.DatabaseHandle,
        "open",
        staticmethod(lambda _path: handle),
    )

    assert exec_module.main(["database.i64", str(script)]) == 0

    assert handle.calls == [
        {
            "code": "answer = 42\n",
            "operation_label": exec_module._script_operation_label(str(script)),
            "persist_globals": True,
            "filename": str(script),
        }
    ]


def test_script_label_preserves_path_suffix_within_protocol_limit() -> None:
    filename = f"/long/path/{'directory/' * 200}rename_functions.py"

    label = exec_module._script_operation_label(filename)

    assert len(label) == 1024
    assert label.startswith("REPL: script …")
    assert label.endswith("rename_functions.py")
