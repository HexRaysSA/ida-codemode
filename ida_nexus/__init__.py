"""Public Python API for authenticated IDA Nexus database sessions."""

from .errors import (
    AmbiguousDatabaseError,
    NexusConnectionError,
    NexusError,
    DatabaseBusyError,
    DatabaseDisconnectedError,
    DatabaseOpenError,
    DatabaseSelectionError,
    NoDatabaseInstanceError,
    RemoteError,
    WorkerStartError,
)
from .handle import DatabaseChangeSubscription, DatabaseHandle
from .instances import (
    DatabaseInstance,
    DiscoveredDatabase,
    InstanceState,
    discover_databases,
    find_database_owner,
    wait_database_released,
)
from .manager import (
    CloseDatabaseResult,
    DatabaseEventCallback,
    DatabaseListing,
    DatabaseManager,
    ListDatabasesResult,
    OpenDatabaseResult,
    SaveDatabaseResult,
    WaitAutoanalysisResult,
)
from .models import (
    AnalysisResult,
    DatabaseChangeEvent,
    PythonExecutionResult,
    SaveResult,
    ShutdownResult,
)
from .options import DatabaseOpenOptions
from .paths import get_state_dir
from .reference import get_ida_domain_version, reference

__all__ = [
    "AmbiguousDatabaseError",
    "AnalysisResult",
    "CloseDatabaseResult",
    "NexusConnectionError",
    "NexusError",
    "DatabaseBusyError",
    "DatabaseChangeEvent",
    "DatabaseChangeSubscription",
    "DatabaseDisconnectedError",
    "DatabaseEventCallback",
    "DatabaseHandle",
    "DatabaseInstance",
    "DatabaseListing",
    "DatabaseManager",
    "DatabaseOpenError",
    "DatabaseOpenOptions",
    "DatabaseSelectionError",
    "DiscoveredDatabase",
    "InstanceState",
    "ListDatabasesResult",
    "NoDatabaseInstanceError",
    "OpenDatabaseResult",
    "PythonExecutionResult",
    "RemoteError",
    "SaveDatabaseResult",
    "SaveResult",
    "ShutdownResult",
    "WaitAutoanalysisResult",
    "WorkerStartError",
    "discover_databases",
    "find_database_owner",
    "get_ida_domain_version",
    "get_state_dir",
    "reference",
    "wait_database_released",
]
