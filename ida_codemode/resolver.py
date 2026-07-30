import os
import subprocess
import sys
import sysconfig
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .registry import (
    DEFAULT_TIMEOUT,
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


@dataclass(frozen=True)
class WorkerLaunchOptions:
    """Import options used only when a new idalib worker must be spawned."""

    processor: str | None = None
    loading_address: int | None = None
    file_type: str | None = None
    new_database: bool = False


WorkerSpawner = Callable[
    [str, str, float, WorkerLaunchOptions],
    tuple[subprocess.Popen[bytes], Path],
]


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
    # Match on the case-insensitive identity key, never the real (case-preserving)
    # path string: a GUI instance registered as Foo.exe.i64 must still match a
    # lookup spelled foo.exe.i64 on case-insensitive volumes.
    if not source.lower().endswith(".i64"):
        source_key = idb_key(source)
        gui = _single(
            [
                item
                for item in instances
                if item.entry.backend == "gui"
                and item.entry.exe_path
                and idb_key(item.entry.exe_path) == source_key
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

    expected_key = idb_key(expected_idb)
    owner = _single(
        [item for item in instances if item.entry.idb_key == expected_key],
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
    options: WorkerLaunchOptions | None = None,
) -> tuple[subprocess.Popen[bytes], Path]:
    options = options or WorkerLaunchOptions()
    suffix = os.urandom(3).hex()
    # A fresh database must be created from the original input, never by
    # reopening the old IDB that is about to be replaced.
    input_path = (
        source
        if options.new_database
        else expected_idb if os.path.exists(expected_idb) else source
    )
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
    if options.processor:
        command.extend(["--processor", options.processor])
    if options.loading_address is not None:
        command.extend(["--loading-address", hex(options.loading_address)])
    if options.file_type:
        command.extend(["--file-type", options.file_type])
    if options.new_database:
        command.append("--new-database")

    process: subprocess.Popen[bytes]
    if os.name == "nt":
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
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


def _scan_until(
    registry_dir: str | os.PathLike[str],
    deadline: float,
    *,
    probe_timeout: float = DEFAULT_TIMEOUT,
) -> list[DiscoveredInstance]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("timed out scanning Code Mode instances")
    return scan_instances(
        registry_dir,
        timeout=min(probe_timeout, remaining),
        deadline=deadline,
    )


def _launcher_exit_is_fatal(returncode: int, platform: str) -> bool:
    """Whether a launcher exit proves that no worker child can become ready."""

    return platform != "nt" or returncode != 0


def _await_ready(
    process: subprocess.Popen[bytes],
    expected_idb: str,
    log_path: Path,
    deadline: float,
    registry_dir: str | os.PathLike[str],
) -> RegistryEntry:
    expected_key = idb_key(expected_idb)
    # Windows console-script launchers may keep a wrapper PID while Python runs
    # the worker as a child. The random suffix is passed explicitly to that
    # worker and is therefore the stable launch identity across both processes.
    record_suffix = log_path.stem.rsplit("-", 1)[-1]
    last_detail: str | None = None
    actual_log_path = log_path
    while True:
        now = time.monotonic()
        if now >= deadline:
            tail = _log_tail(actual_log_path)
            message = f"timed out waiting for idalib worker {process.pid}"
            if last_detail:
                message += f": {last_detail}"
            if tail:
                message += f"\n\n{tail}"
            raise WorkerStartError(message)

        try:
            instances = _scan_until(
                registry_dir,
                deadline,
                probe_timeout=0.25,
            )
        except TimeoutError:
            # Let the top of the loop produce the worker-specific timeout with
            # any available startup log and last health detail.
            continue
        matched_record = False
        for instance in instances:
            entry = instance.entry
            launched_by_us = entry.pid == process.pid or entry.record_id.endswith(
                f"-{record_suffix}"
            )
            if not launched_by_us:
                continue
            matched_record = True
            actual_log_path = log_path.with_name(f"{entry.record_id}.log")
            if entry.idb_key != expected_key:
                raise WorkerStartError(
                    f"worker {entry.pid} opened {entry.idb_path}, "
                    f"expected {expected_idb}"
                )
            if instance.state is InstanceState.READY:
                return entry
            last_detail = instance.detail

        returncode = process.poll()
        if returncode is not None and not matched_record:
            matches = list(log_path.parent.glob(f"*-{record_suffix}.log"))
            if matches:
                actual_log_path = max(matches, key=lambda path: path.stat().st_mtime)
            # uv/pip console-script launchers on Windows can exit successfully
            # after starting the real Python worker under a different PID. The
            # suffix remains authoritative, so keep waiting for its record.
            if _launcher_exit_is_fatal(returncode, os.name):
                tail = _log_tail(actual_log_path)
                message = (
                    f"idalib worker launcher {process.pid} exited with status "
                    f"{returncode}"
                )
                if tail:
                    message += f"\n\n{tail}"
                raise WorkerStartError(message)

        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def resolve_instance(
    path: str | os.PathLike[str],
    *,
    spawn: bool = True,
    timeout: float = 120.0,
    registry_dir: str | os.PathLike[str] = REGISTRY_DIR,
    spawn_dir: str | os.PathLike[str] = SPAWN_DIR,
    lease_grace: float = 20.0,
    output_database: str | os.PathLike[str] | None = None,
    processor: str | None = None,
    loading_address: int | None = None,
    file_type: str | None = None,
    new_database: bool = False,
    spawner: WorkerSpawner = spawn_worker,
) -> RegistryEntry:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    source = canonical_path(path)
    expected_idb = (
        canonical_path(output_database)
        if output_database is not None
        else expected_idb_path(source)
    )
    launch_options = WorkerLaunchOptions(
        processor=processor,
        loading_address=loading_address,
        file_type=file_type,
        new_database=new_database,
    )
    deadline = time.monotonic() + timeout

    # Match a live instance before touching the filesystem: a registered
    # instance (e.g. an unsaved GUI database whose .i64 has not been written)
    # is valid even when the path does not exist. An explicit output path is a
    # request for that IDB identity, so do not attach to a GUI that merely has
    # the same input executable open under a different database path.
    instance = _resolve_existing(
        _scan_until(registry_dir, deadline),
        source if output_database is None else expected_idb,
        expected_idb,
    )
    if instance is not None:
        if new_database:
            raise IdbBusy(
                f"cannot create a fresh database while instance "
                f"{instance.record_id} owns {expected_idb}"
            )
        return instance

    spawn_lock = FileLock(
        ensure_private_directory(spawn_dir) / f"{idb_key(expected_idb)}.lock"
    )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"timed out resolving {expected_idb}")
    spawn_lock.acquire(remaining)
    try:
        instance = _resolve_existing(
            _scan_until(registry_dir, deadline),
            source if output_database is None else expected_idb,
            expected_idb,
        )
        if instance is not None:
            if new_database:
                raise IdbBusy(
                    f"cannot create a fresh database while instance "
                    f"{instance.record_id} owns {expected_idb}"
                )
            return instance
        if not spawn:
            raise NoInstance(expected_idb)
        if not os.path.exists(source):
            raise FileNotFoundError(source)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out resolving {expected_idb}")
        process, log_path = spawner(
            source,
            expected_idb,
            lease_grace,
            launch_options,
        )
        return _await_ready(process, expected_idb, log_path, deadline, registry_dir)
    finally:
        spawn_lock.close()
