import json
from pathlib import Path

from ida_codemode import serialization
from ida_codemode.serialization import dumps_json


def test_json_safe_result_bypasses_compatibility_walker(monkeypatch) -> None:
    def unexpected_conversion(_value):
        raise AssertionError("JSON-safe result used the compatibility walker")

    monkeypatch.setattr(serialization, "to_jsonable", unexpected_conversion)

    value = {"rows": [{"ea": index, "name": f"sub_{index:x}"} for index in range(100)]}
    assert json.loads(dumps_json(value)) == value


def test_unsupported_values_use_compatibility_conversion() -> None:
    value = {
        "path": Path("database.i64"),
        "addresses": {1, 2},
        "nan": float("nan"),
        None: "unusual key",
    }

    assert json.loads(dumps_json(value)) == {
        "path": "database.i64",
        "addresses": [1, 2],
        "nan": "nan",
        "None": "unusual key",
    }
