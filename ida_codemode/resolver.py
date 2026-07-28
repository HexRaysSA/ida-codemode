from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
import time
from collections.abc import Callable
from pathlib import Path

from .registry import (
    LOG_DIR,
    REGISTRY_DIR,
    SPAWN_DIR,
    DiscoveredInstance,
    FileLock,
    InstanceState,
    RegistryEntry,
    canonical_path,
    ensure_private_directory,
    idb_key,
    scan_instances,
)


class ResolveError(RuntimeError):
    pass


class NoInstance(ResolveError):
    pass


class IdbBusy(ResolveError):
    pass


class AmbiguousInstance(ResolveError):
    pass


class WorkerStartError(ResolveError):
    pass


WorkerSpawner = Callable[[str, str, float], tuple[subprocess.Popen[bytes], Path]]


def expected_idb_path(path: str | os.PathLike[str]) -> str:
    source = canonical_path(path)
    return source if source.lower().endswith(".i64") else source + ".i64"


def _single(
    instances: list[DiscoveredInstance],
    description: str,
) -> DiscoveredInstance | None:
    if not instances:
        return None
    if len(instances) > 1:
        records = ", ".join(item.entry.record_id for item in instances)
        raise AmbiguousInstance(
            f"multiple live instances match {description}: {records}"
        )
    return instances[0]


def _resolve_existing(
    instances: list[DiscoveredInstance],
    source: str,
    expected_idb: str,
) -> RegistryEntry | None:
    if not source.lower().endswith(".i64"):
        gui = _single(
            [
                item
                for item in instances
                if item.entry.backend == "gui" and item.entry.exe_path == source
            ],
            f"executable {source}",
        )
        if gui is not None:
            if gui.state is InstanceState.READY:
                return gui.entry
            raise IdbBusy(
                f"GUI instance {gui.entry.record_id} for {source} is unavailable: "
                f"{gui.detail or 'health probe failed'}"
            )

    owner = _single(
        [item for item in instances if item.entry.idb_path == expected_idb],
        f"IDB {expected_idb}",
    )
    if owner is None:
        return None
    if owner.state is InstanceState.READY:
        return owner.entry
    raise IdbBusy(
        f"instance {owner.entry.record_id} owns {expected_idb} but is unavailable: "
        f"{owner.detail or 'health probe failed'}"
    )


def _find_console_script(name: str) -> str | None:
    """Locate a pip-installed console script for the current interpreter.

    Inside IDA, ``sys.executable`` is the IDA binary, not a Python interpreter,
    so we cannot launch the worker with ``sys.executable -m ...``. The console
    script installed by pip carries the correct interpreter in its shebang (or is
    an ``.exe`` wrapper on Windows), so running it directly always works.

    Only script directories belonging to the current interpreter are searched.
    We never fall back to ``PATH``, which could resolve a same-named script from
    an unrelated environment running a different interpreter.
    """
    dirs: list[str] = []
    scripts_dir = sysconfig.get_path("scripts")
    if scripts_dir:
        dirs.append(scripts_dir)
    for prefix in dict.fromkeys([sys.prefix, sys.base_prefix]):
        dirs.append(os.path.join(prefix, "Scripts" if os.name == "nt" else "bin"))

    exe_names = [f"{name}.exe", name] if os.name == "nt" else [name]
    for directory in dirs:
        for exe in exe_names:
            candidate = os.path.join(directory, exe)
            if os.path.isfile(candidate):
                return candidate
    return None


def spawn_worker(
    source: str,
    expected_idb: str,
    lease_grace: float,
) -> tuple[subprocess.Popen[bytes], Path]:
    suffix = os.urandom(3).hex()
    input_path = expected_idb if os.path.exists(expected_idb) else source
    worker = _find_console_script("ida-codemode-worker")
    if worker is None:
        raise ResolveError(
            "Could not find the 'ida-codemode-worker' console script for this "
            "Python. Ensure the ida-codemode-mcp package is installed."
        )
    command = [
        worker,
        input_path,
        "--managed",
        "--record-suffix",
        suffix,
        "--lease-grace",
        str(lease_grace),
    ]
    if input_path == source and source != expected_idb:
        command.extend(["--output-database", expected_idb])

    process: subprocess.Popen[bytes]
    if os.name == "nt":
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            ),
        )
    else:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            start_new_session=True,
        )
    log_path = ensure_private_directory(LOG_DIR) / f"{process.pid}-{suffix}.log"
    return process, log_path


def _log_tail(path: Path, limit: int = 16 * 1024) -> str:
    try:
        with path.open("rb") as file:
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(max(0, size - limit))
            return file.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _await_ready(
    process: subprocess.Popen[bytes],
    expected_idb: str,
    log_path: Path,
    deadline: float,
    registry_dir: str | os.PathLike[str],
) -> RegistryEntry:
    expected_key = idb_key(expected_idb)
    last_detail: str | None = None
    while True:
        returncode = process.poll()
        if returncode is not None:
            tail = _log_tail(log_path)
            message = f"idalib worker {process.pid} exited with status {returncode}"
            if tail:
                message += f"\n\n{tail}"
            raise WorkerStartError(message)

        now = time.monotonic()
        if now >= deadline:
            tail = _log_tail(log_path)
            message = f"timed out waiting for idalib worker {process.pid}"
            if last_detail:
                message += f": {last_detail}"
            if tail:
                message += f"\n\n{tail}"
            raise WorkerStartError(message)

        for instance in scan_instances(
            registry_dir,
            timeout=min(0.25, max(0.05, deadline - now)),
        ):
            if instance.entry.pid != process.pid:
                continue
            if instance.entry.idb_key != expected_key:
                raise WorkerStartError(
                    f"worker {process.pid} opened {instance.entry.idb_path}, "
                    f"expected {expected_idb}"
                )
            if instance.state is InstanceState.READY:
                return instance.entry
            last_detail = instance.detail
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def resolve_instance(
    path: str | os.PathLike[str],
    *,
    spawn: bool = True,
    timeout: float = 120.0,
    registry_dir: str | os.PathLike[str] = REGISTRY_DIR,
    spawn_dir: str | os.PathLike[str] = SPAWN_DIR,
    lease_grace: float = 20.0,
    spawner: WorkerSpawner = spawn_worker,
) -> RegistryEntry:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    source = canonical_path(path)
    if not os.path.exists(source):
        raise FileNotFoundError(source)
    expected_idb = expected_idb_path(source)
    deadline = time.monotonic() + timeout

    instance = _resolve_existing(scan_instances(registry_dir), source, expected_idb)
    if instance is not None:
        return instance

    spawn_lock = FileLock(
        ensure_private_directory(spawn_dir) / f"{idb_key(expected_idb)}.lock"
    )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"timed out resolving {expected_idb}")
    spawn_lock.acquire(remaining)
    try:
        instance = _resolve_existing(scan_instances(registry_dir), source, expected_idb)
        if instance is not None:
            return instance
        if not spawn:
            raise NoInstance(expected_idb)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out resolving {expected_idb}")
        process, log_path = spawner(source, expected_idb, lease_grace)
        return _await_ready(process, expected_idb, log_path, deadline, registry_dir)
    finally:
        spawn_lock.close()
