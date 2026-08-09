import json
import math
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any


def to_jsonable(value: Any) -> Any:
    """Convert a value that the standard JSON encoder rejected.

    Normal Code Mode results bypass this Python walker entirely. It remains as
    a compatibility fallback for IDA objects, sets, non-finite floats, unusual
    dictionary keys, and other values unsupported by ``json.dumps``.
    """

    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        # NaN and infinities are accepted by Python's encoder but are not JSON.
        return value if math.isfinite(value) else repr(value)
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


def dumps_json(value: Any) -> str:
    """Encode JSON-safe values directly, falling back to compatibility conversion."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            default=to_jsonable,
        )
    except (TypeError, ValueError):
        # The default callback handles unsupported values, but the encoder does
        # not invoke it for non-finite floats or unsupported dictionary keys.
        # Preserve the old conversion behavior for those uncommon results.
        return json.dumps(
            to_jsonable(value),
            allow_nan=False,
            separators=(",", ":"),
            default=to_jsonable,
        )
