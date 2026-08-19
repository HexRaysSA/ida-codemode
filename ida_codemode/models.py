"""Public result models returned by Code Mode database operations."""

from typing import Any, TypedDict


class PythonExecutionResult(TypedDict):
    result: Any
    stdout: str
    stderr: str


class AnalysisResult(TypedDict):
    status: str
    complete: bool


class DatabaseChangeEvent(TypedDict):
    event_name: str
    timestamp: int
    revision: int
    operation_id: str | None
    operation_label: str | None
    origin_id: str | None


class SaveResult(TypedDict):
    saved: bool
    idb_path: str


class ShutdownResult(TypedDict):
    shutting_down: bool
    save: bool
