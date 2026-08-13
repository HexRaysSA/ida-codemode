import json
from pathlib import Path

import pytest

from ida_codemode.serialization import dumps_json


def test_json_compatible_result_is_encoded_without_conversion() -> None:
    value = {"rows": [{"ea": index, "name": f"sub_{index:x}"} for index in range(100)]}
    assert json.loads(dumps_json(value)) == value


@pytest.mark.parametrize(
    "value",
    (
        {"path": Path("database.i64")},
        {"addresses": {1, 2}},
        {"bytes": b"binary"},
        {"nan": float("nan")},
        {"positive": float("inf")},
    ),
)
def test_non_json_results_are_rejected(value) -> None:
    with pytest.raises((TypeError, ValueError)):
        dumps_json(value)
