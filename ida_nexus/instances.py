"""Public discovery and lifecycle helpers for Nexus instances."""

import math
import time
from pathlib import Path

from ._registry import (
    REGISTRY_DIR,
    DatabaseInstance,
    DiscoveredDatabase,
    FileLock,
    InstanceState,
    canonical_path,
    idb_key,
    scan_instances,
)
from ._resolver import expected_idb_path
from .errors import AmbiguousDatabaseError


def discover_databases(timeout: float = 1.0) -> list[DiscoveredDatabase]:
    """Discover live database owners and report ready or unavailable state."""
    return scan_instances(timeout=timeout)


def find_database_owner(
    path: str | Path,
    *,
    output_database: str | Path | None = None,
    timeout: float = 1.0,
) -> DatabaseInstance | None:
    """Return the unique live owner of an executable or IDB target, if any.

    A lock-held but temporarily unavailable owner is still returned: ownership
    must not be confused with readiness when a caller is deciding whether it is
    safe to replace files.
    """
    source = canonical_path(path)
    expected = (
        canonical_path(output_database)
        if output_database is not None
        else expected_idb_path(source)
    )
    discovered = discover_databases(timeout)

    matches: list[DatabaseInstance] = []
    if output_database is None and not source.lower().endswith(".i64"):
        source_key = idb_key(source)
        matches.extend(
            item.instance
            for item in discovered
            if item.instance.backend == "gui"
            and item.instance.exe_path
            and idb_key(item.instance.exe_path) == source_key
        )
    if not matches:
        expected_key = idb_key(expected)
        matches.extend(
            item.instance
            for item in discovered
            if item.instance.idb_key == expected_key
        )

    unique = {instance.record_id: instance for instance in matches}
    if len(unique) > 1:
        records = ", ".join(sorted(unique))
        raise AmbiguousDatabaseError(
            f"multiple live instances own {expected}: {records}"
        )
    return next(iter(unique.values()), None)


def wait_database_released(
    instance: DatabaseInstance,
    timeout: float | None = None,
) -> bool:
    """Wait until an instance releases its lifetime lock.

    Returns ``True`` when released and ``False`` on timeout. This observes
    process/database ownership; it does not terminate or release any lease.
    """
    if timeout is not None and (not math.isfinite(timeout) or timeout < 0):
        raise ValueError("timeout must be a finite non-negative number or None")
    deadline = None if timeout is None else time.monotonic() + timeout
    lock_path = REGISTRY_DIR / f"{instance.record_id}.lock"
    while True:
        if not lock_path.exists():
            return True
        lock = FileLock(lock_path)
        try:
            if lock.try_acquire():
                return True
        except OSError:
            pass
        finally:
            lock.close()
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.1, remaining))
        else:
            time.sleep(0.1)


__all__ = [
    "DatabaseInstance",
    "DiscoveredDatabase",
    "InstanceState",
    "discover_databases",
    "find_database_owner",
    "wait_database_released",
]
