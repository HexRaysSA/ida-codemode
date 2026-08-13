"""Public exception hierarchy for IDA Code Mode clients."""

from typing import Any


class CodeModeError(RuntimeError):
    """Base class for recoverable IDA Code Mode service errors."""


class CodeModeConnectionError(CodeModeError):
    """A Code Mode instance could not be reached or used."""


class DatabaseDisconnectedError(CodeModeConnectionError):
    """A previously attached database instance disconnected permanently."""


class RemoteError(CodeModeError):
    """The Code Mode service rejected an operation with a structured error."""

    def __init__(
        self,
        code: str,
        message: str,
        status: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}


class DatabaseOpenError(CodeModeError):
    """A requested database instance could not be resolved or opened."""


class NoDatabaseInstanceError(DatabaseOpenError):
    """No matching live instance exists and spawning was disabled."""


class DatabaseBusyError(DatabaseOpenError):
    """A matching database is owned by an unusable or conflicting instance."""


class AmbiguousDatabaseError(DatabaseOpenError):
    """More than one live instance matches a requested database."""


class WorkerStartError(DatabaseOpenError):
    """A managed idalib worker failed to become ready."""


class DatabaseSelectionError(CodeModeError):
    """A multi-database manager has no valid selected target."""
