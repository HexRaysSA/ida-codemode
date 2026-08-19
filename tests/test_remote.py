from __future__ import annotations

import builtins
import io
from collections import namedtuple
from contextlib import redirect_stderr, redirect_stdout
from typing import TYPE_CHECKING, Any, cast

import pytest

from ida_nexus import DatabaseHandle, remote_ida
from ida_nexus._runtime import _execute_user_code
from ida_nexus.models import PythonExecutionResult

if TYPE_CHECKING:
    from ida_domain import Database


class InProcessHandle(DatabaseHandle):
    def __init__(self, database: object) -> None:
        self.database = database
        self.calls: list[dict[str, Any]] = []

    def execute_python(
        self,
        code: str,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ) -> PythonExecutionResult:
        self.calls.append(
            {
                "code": code,
                "timeout": timeout,
                "operation_id": operation_id,
                "persist_globals": persist_globals,
                "filename": filename,
            }
        )
        runtime = {"db": self.database, "ida_domain": object()}
        namespace = {
            "__builtins__": builtins.__dict__,
            "__name__": "__ida_nexus_execute__",
            **runtime,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = _execute_user_code(code, namespace, runtime, filename)
        return {
            "result": result,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
        }


class FakeBytes:
    def get_bytes_at(self, address: int, size: int) -> bytes | None:
        if address == 0 and size == 1:
            return b"\x00"
        return None


class FakeDatabase:
    bytes = FakeBytes()


@remote_ida
def remote_round_trip(
    db: Database,
    payload: dict[str, object],
    pair: tuple[bytes, int],
    *,
    suffix: bytes,
) -> tuple[bytes, dict[str, object], tuple[bytes, int]]:
    print("executed in IDA")
    prefix = db.bytes.get_bytes_at(0, 1) or b""
    return prefix + pair[0] + suffix, payload, pair


@remote_ida
def remote_identity(db: Database, value: object) -> object:
    del db
    return value


@remote_ida
def remote_unsupported_result(db: Database) -> object:
    del db
    return {1, 2}


def test_remote_ida_executes_function_and_preserves_bytes_and_tuples(
    capsys: pytest.CaptureFixture[str],
) -> None:
    handle = InProcessHandle(FakeDatabase())
    payload: dict[str, object] = {
        "items": [b"\x01\xff", ("name", b"")],
        "$bytes": "literal user value",
        "$tuple": [1, 2],
        "$dict": {"nested": b"\x02"},
    }

    result = remote_round_trip(
        handle,
        payload,
        (b"ELF", 7),
        suffix=b"!",
    )

    assert result == (b"\x00ELF!", payload, (b"ELF", 7))
    assert type(result) is tuple
    assert type(result[1]["items"]) is list
    assert capsys.readouterr().out == "executed in IDA\n"
    assert len(handle.calls) == 1
    call = handle.calls[0]
    assert call["persist_globals"] is False
    assert call["timeout"] is None
    assert isinstance(call["filename"], str)
    assert "test_remote.py" in call["filename"]
    assert "@remote_ida" not in call["code"]


def test_remote_ida_round_trips_empty_and_binary_values() -> None:
    handle = InProcessHandle(object())
    value = [b"", bytes(range(256)), (), (b"\x00",)]

    result = remote_identity(handle, value)

    assert result == value
    assert isinstance(result, list)
    assert type(result[2]) is tuple


@pytest.mark.parametrize(
    "value",
    (
        bytearray(b"mutable"),
        memoryview(b"view"),
        {1, 2},
        {1: "non-string key"},
        float("nan"),
        float("inf"),
        namedtuple("Pair", ("left", "right"))(1, 2),
    ),
)
def test_remote_ida_rejects_unsupported_arguments_before_execution(
    value: object,
) -> None:
    handle = InProcessHandle(object())

    with pytest.raises((TypeError, ValueError), match="remote_ida"):
        remote_identity(handle, value)

    assert handle.calls == []


def test_remote_ida_rejects_unsupported_remote_result() -> None:
    handle = InProcessHandle(object())

    with pytest.raises(TypeError, match="remote_ida values"):
        remote_unsupported_result(handle)


def test_remote_ida_requires_a_database_handle() -> None:
    with pytest.raises(TypeError, match="DatabaseHandle"):
        remote_identity(cast(DatabaseHandle, object()), "value")


def test_remote_ida_rejects_async_functions() -> None:
    async def async_function(db: Database) -> None:
        del db

    with pytest.raises(TypeError, match="does not support async functions"):
        remote_ida(async_function)


def test_remote_ida_rejects_closures() -> None:
    captured = "local"

    def closure(db: Database) -> str:
        del db
        return captured

    with pytest.raises(TypeError, match="cannot capture nonlocal values"):
        remote_ida(closure)
