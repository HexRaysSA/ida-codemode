"""Public result models returned by Nexus database operations."""

from typing import Any, TypedDict


class PythonExecutionResult(TypedDict):
    result: Any
    stdout: str
    stderr: str


class AnalysisResult(TypedDict):
    status: str
    complete: bool


class SaveResult(TypedDict):
    saved: bool
    idb_path: str


class ShutdownResult(TypedDict):
    shutting_down: bool
    save: bool
