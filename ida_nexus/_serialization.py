import json
from typing import Any


def dumps_json(value: Any) -> str:
    """Encode a JSON-compatible value without coercing unsupported objects."""

    return json.dumps(
        value,
        allow_nan=False,
        separators=(",", ":"),
    )
