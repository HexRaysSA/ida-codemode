from __future__ import annotations

import ast
import base64
import binascii
import functools
import inspect
import json
import math
import sys
import textwrap
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Concatenate, ParamSpec, TypeVar, cast, overload

from .errors import CodeModeConnectionError
from .handle import DatabaseHandle

if TYPE_CHECKING:
    from ida_domain import Database

P = ParamSpec("P")
R = TypeVar("R")

_CODEC_VERSION = 1
_BYTES_TAG = "$bytes"
_TUPLE_TAG = "$tuple"
_DICT_TAG = "$dict"
_RESERVED_TAGS = frozenset((_BYTES_TAG, _TUPLE_TAG, _DICT_TAG))

_SUPPORTED_VALUES = (
    "None, bool, int, finite float, str, bytes, list, tuple, and dict[str, value]"
)

_REMOTE_CODEC_SOURCE = """
import base64 as __remote_ida_base64
import math as __remote_ida_math

__remote_ida_reserved_tags = frozenset(("$bytes", "$tuple", "$dict"))


def __remote_ida_decode(value):
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not __remote_ida_math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is list:
        return [__remote_ida_decode(item) for item in value]
    if value_type is not dict:
        raise TypeError(f"invalid remote_ida encoded value: {value_type.__name__}")

    keys = set(value)
    if keys == {"$bytes"}:
        encoded = value["$bytes"]
        if type(encoded) is not str:
            raise TypeError("invalid remote_ida bytes value")
        return __remote_ida_base64.b64decode(encoded, validate=True)
    if keys == {"$tuple"}:
        items = value["$tuple"]
        if type(items) is not list:
            raise TypeError("invalid remote_ida tuple value")
        return tuple(__remote_ida_decode(item) for item in items)
    if keys == {"$dict"}:
        entries = value["$dict"]
        if type(entries) is not list:
            raise TypeError("invalid remote_ida dictionary value")
        decoded = {}
        for entry in entries:
            if type(entry) is not list or len(entry) != 2 or type(entry[0]) is not str:
                raise TypeError("invalid remote_ida dictionary entry")
            key, item = entry
            if key in decoded:
                raise ValueError(f"duplicate remote_ida dictionary key: {key!r}")
            decoded[key] = __remote_ida_decode(item)
        return decoded
    if keys & __remote_ida_reserved_tags:
        raise ValueError("invalid remote_ida tagged value")
    return {key: __remote_ida_decode(item) for key, item in value.items()}


def __remote_ida_encode(value):
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not __remote_ida_math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is bytes:
        return {"$bytes": __remote_ida_base64.b64encode(value).decode("ascii")}
    if value_type is list:
        return [__remote_ida_encode(item) for item in value]
    if value_type is tuple:
        return {"$tuple": [__remote_ida_encode(item) for item in value]}
    if value_type is dict:
        entries = []
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("remote_ida dictionary keys must be strings")
            entries.append((key, __remote_ida_encode(item)))
        if set(value) & __remote_ida_reserved_tags:
            return {"$dict": [[key, item] for key, item in entries]}
        return {key: item for key, item in entries}
    raise TypeError(
        "remote_ida values must be None, bool, int, finite float, str, bytes, "
        f"list, tuple, or dict[str, value]; got {value_type.__name__}"
    )
""".strip()


def _encode_value(value: Any) -> Any:
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is bytes:
        return {_BYTES_TAG: base64.b64encode(value).decode("ascii")}
    if value_type is list:
        return [_encode_value(item) for item in value]
    if value_type is tuple:
        return {_TUPLE_TAG: [_encode_value(item) for item in value]}
    if value_type is dict:
        entries: list[tuple[str, Any]] = []
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("remote_ida dictionary keys must be strings")
            entries.append((key, _encode_value(item)))
        if set(value) & _RESERVED_TAGS:
            return {_DICT_TAG: [[key, item] for key, item in entries]}
        return {key: item for key, item in entries}
    raise TypeError(
        f"remote_ida values must be {_SUPPORTED_VALUES}; got {value_type.__name__}"
    )


def _decode_value(value: Any) -> Any:
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("remote_ida does not support non-finite floats")
        return value
    if value_type is list:
        return [_decode_value(item) for item in value]
    if value_type is not dict:
        raise TypeError(f"invalid remote_ida encoded value: {value_type.__name__}")

    keys = set(value)
    if keys == {_BYTES_TAG}:
        encoded = value[_BYTES_TAG]
        if type(encoded) is not str:
            raise TypeError("invalid remote_ida bytes value")
        try:
            return base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("invalid remote_ida base64 value") from exc
    if keys == {_TUPLE_TAG}:
        items = value[_TUPLE_TAG]
        if type(items) is not list:
            raise TypeError("invalid remote_ida tuple value")
        return tuple(_decode_value(item) for item in items)
    if keys == {_DICT_TAG}:
        entries = value[_DICT_TAG]
        if type(entries) is not list:
            raise TypeError("invalid remote_ida dictionary value")
        decoded: dict[str, Any] = {}
        for entry in entries:
            if type(entry) is not list or len(entry) != 2 or type(entry[0]) is not str:
                raise TypeError("invalid remote_ida dictionary entry")
            key, item = entry
            if key in decoded:
                raise ValueError(f"duplicate remote_ida dictionary key: {key!r}")
            decoded[key] = _decode_value(item)
        return decoded
    if keys & _RESERVED_TAGS:
        raise ValueError("invalid remote_ida tagged value")
    if any(type(key) is not str for key in value):
        raise TypeError("invalid remote_ida dictionary key")
    return {key: _decode_value(item) for key, item in value.items()}


def _extract_function_source(
    function: Callable[..., Any],
    *,
    helper: bool = False,
) -> tuple[str, str, str]:
    role = "helper" if helper else "function"
    if not inspect.isfunction(function):
        raise TypeError(f"@remote_ida {role}s must be plain Python functions")
    if inspect.iscoroutinefunction(function):
        raise TypeError(f"@remote_ida does not support async {role}s")

    if not helper:
        parameters = list(inspect.signature(function).parameters.values())
        if not parameters or parameters[0].name != "db":
            raise TypeError(
                "@remote_ida functions must declare 'db' as their first parameter"
            )
        if parameters[0].kind not in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            raise TypeError("@remote_ida function parameter 'db' must be positional")
    if function.__closure__:
        raise TypeError(f"@remote_ida {role}s cannot capture nonlocal values")

    try:
        lines, first_line = inspect.getsourcelines(function)
    except (OSError, TypeError) as exc:
        raise TypeError(f"@remote_ida could not recover the {role} source") from exc

    source = textwrap.dedent("".join(lines))
    try:
        module = ast.parse(source)
    except SyntaxError as exc:
        raise TypeError(f"@remote_ida could not parse the {role} source") from exc

    definitions = [
        statement
        for statement in module.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if len(definitions) != 1 or definitions[0].name != function.__name__:
        raise TypeError(f"@remote_ida requires one recoverable {role} definition")
    definition = definitions[0]
    if isinstance(definition, ast.AsyncFunctionDef):
        raise TypeError(f"@remote_ida does not support async {role}s")
    if helper and definition.decorator_list:
        raise TypeError("@remote_ida helpers cannot have decorators")
    if not helper and len(definition.decorator_list) > 1:
        raise TypeError("@remote_ida cannot be combined with other decorators")
    if function.__name__ in {"db", "ida_domain"} or function.__name__.startswith(
        "__remote_ida_"
    ):
        raise TypeError(f"@remote_ida {role} name {function.__name__!r} is reserved")
    definition.decorator_list = []
    ast.fix_missing_locations(definition)

    filename = inspect.getsourcefile(function) or function.__code__.co_filename
    return (
        ast.unparse(definition),
        f"{filename}:{first_line} ({function.__qualname__})",
        function.__name__,
    )


def _extract_helper_sources(
    helpers: tuple[Callable[..., Any], ...],
) -> tuple[tuple[str, ...], frozenset[str]]:
    sources: list[str] = []
    names: set[str] = set()
    for helper in helpers:
        source, _, name = _extract_function_source(helper, helper=True)
        if name in names:
            raise TypeError(f"duplicate @remote_ida helper name: {name!r}")
        sources.append(source)
        names.add(name)
    return tuple(sources), frozenset(names)


def _build_remote_code(
    helper_sources: tuple[str, ...],
    function_source: str,
    function_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str:
    payload = {
        "version": _CODEC_VERSION,
        "args": _encode_value(list(args)),
        "kwargs": _encode_value(kwargs),
    }
    payload_json = json.dumps(
        payload,
        allow_nan=False,
        separators=(",", ":"),
    )
    definitions = "\n\n".join((*helper_sources, function_source))
    return f"""from __future__ import annotations
import json as __remote_ida_json

{_REMOTE_CODEC_SOURCE}

{definitions}

__remote_ida_payload = __remote_ida_json.loads({payload_json!r})
if (
    type(__remote_ida_payload) is not dict
    or __remote_ida_payload.get("version") != {_CODEC_VERSION}
):
    raise ValueError("invalid remote_ida payload")
__remote_ida_args = __remote_ida_decode(__remote_ida_payload.get("args"))
__remote_ida_kwargs = __remote_ida_decode(__remote_ida_payload.get("kwargs"))
__remote_ida_result = {function_name}(
    db,
    *__remote_ida_args,
    **__remote_ida_kwargs,
)
{{"version": {_CODEC_VERSION}, "value": __remote_ida_encode(__remote_ida_result)}}
"""


def _decode_result(value: Any) -> Any:
    if (
        type(value) is not dict
        or set(value) != {"version", "value"}
        or type(value["version"]) is not int
        or value["version"] != _CODEC_VERSION
    ):
        raise CodeModeConnectionError("remote_ida returned an invalid encoded result")
    try:
        return _decode_value(value["value"])
    except (TypeError, ValueError) as exc:
        raise CodeModeConnectionError(
            "remote_ida returned an invalid encoded result"
        ) from exc


def _decorate_remote(
    function: Callable[Concatenate[Database, P], R],
    helpers: tuple[Callable[..., Any], ...],
) -> Callable[Concatenate[DatabaseHandle, P], R]:
    function_source, filename, function_name = _extract_function_source(function)
    helper_sources, helper_names = _extract_helper_sources(helpers)
    if function_name in helper_names:
        raise TypeError(f"@remote_ida function and helper share name {function_name!r}")

    @functools.wraps(function)
    def wrapper(
        handle: DatabaseHandle,
        /,
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        if not isinstance(handle, DatabaseHandle):
            raise TypeError(
                "the first argument to a @remote_ida function must be a DatabaseHandle"
            )
        code = _build_remote_code(
            helper_sources,
            function_source,
            function_name,
            args,
            kwargs,
        )
        execution = handle.execute_python(
            code,
            persist_globals=False,
            filename=filename,
        )
        if execution["stdout"]:
            sys.stdout.write(execution["stdout"])
        if execution["stderr"]:
            sys.stderr.write(execution["stderr"])
        return cast(R, _decode_result(execution["result"]))

    return cast(Callable[Concatenate[DatabaseHandle, P], R], wrapper)


@overload
def remote_ida(
    function: Callable[Concatenate[Database, P], R],
    /,
) -> Callable[Concatenate[DatabaseHandle, P], R]: ...


@overload
def remote_ida(
    *,
    helpers: tuple[Callable[..., Any], ...] = (),
) -> Callable[
    [Callable[Concatenate[Database, P], R]],
    Callable[Concatenate[DatabaseHandle, P], R],
]: ...


def remote_ida(
    function: Callable[..., Any] | None = None,
    /,
    *,
    helpers: tuple[Callable[..., Any], ...] = (),
) -> Callable[..., Any]:
    """Run a typed IDA-domain function through a ``DatabaseHandle``."""

    if function is None:
        return lambda selected: _decorate_remote(selected, helpers)
    return _decorate_remote(function, helpers)
