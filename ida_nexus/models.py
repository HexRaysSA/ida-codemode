"""Public result models returned by Nexus database operations."""

from typing import Any, TypeAlias, TypedDict


class PythonExecutionResult(TypedDict):
    result: Any
    stdout: str
    stderr: str


class AnalysisResult(TypedDict):
    status: str
    complete: bool


# IDB change payloads combine common metadata with event-specific fields.
DatabaseChangeEvent: TypeAlias = dict[str, Any]


class SaveResult(TypedDict):
    saved: bool
    idb_path: str


class ShutdownResult(TypedDict):
    shutting_down: bool
    save: bool
