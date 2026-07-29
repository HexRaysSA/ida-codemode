from __future__ import annotations

import errno
import glob
import hashlib
import json
import os
import socket
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import Any, Literal, Self
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HOST = "127.0.0.1"
STATE_DIR = Path.home() / ".ida-codemode"
REGISTRY_DIR = STATE_DIR / "instances"
SPAWN_DIR = STATE_DIR / "spawn"
LOG_DIR = STATE_DIR / "logs"
PROTOCOL_VERSION = 1
DEFAULT_TIMEOUT = 1.0
BackendName = Literal["gui", "idalib"]


class InstanceState(str, Enum):
    READY = "ready"
    BLOCKED = "blocked"
    DEAD = "dead"


def ensure_private_directory(path: str | os.PathLike[str]) -> Path:
    directory = Path(path)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError:
        if os.name != "nt":
            raise
    return directory


def canonical_path(path: str | os.PathLike[str]) -> str:
    """Resolve a path to its real, absolute form, preserving case.

    This is the *real filesystem path*: it is what we open, create databases at,
    hand to workers, and store/display in registry entries. Case is deliberately
    preserved so an IDB is created exactly as IDA would name it (``Foo.exe.i64``,
    not ``foo.exe.i64``). Case-insensitive identity matching lives entirely in
    ``identity_key`` / ``idb_key`` and never leaks back into a path on disk.
    """
    return os.path.realpath(os.path.abspath(os.path.expanduser(os.fspath(path))))


def identity_key(path: str | os.PathLike[str]) -> str:
    """Fold a real path to a stable identity used for discovery/matching only.

    On case-insensitive volumes (macOS, Windows) two spellings that differ only
    in case name the same file, so they must resolve to one identity. This fold
    is used solely to compare and deduplicate instances; the result is never used
    as a path that touches the filesystem.
    """
    value = canonical_path(path)
    if sys.platform == "win32":
        return os.path.normcase(value)
    if sys.platform == "darwin":
        # normcase() is a no-op in posixpath, while normal macOS volumes are
        # case-insensitive. This intentionally treats case-sensitive APFS the
        # same way so all Code Mode clients calculate one stable identity.
        return value.casefold()
    return value


def idb_key(path: str | os.PathLike[str]) -> str:
    return hashlib.sha256(identity_key(path).encode("utf-8")).hexdigest()[:16]


class FileLock:
    """Small cross-platform exclusive file lock.

    Lock files are deliberately persistent. Deleting a shared synchronization
    file can let contenders lock different inodes during a race.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.file: Any | None = None
        self._locked = False

    def _open(self) -> None:
        if self.file is not None:
            return
        ensure_private_directory(self.path.parent)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        self.file = os.fdopen(fd, "r+b", buffering=0)
        if os.fstat(fd).st_size == 0:
            self.file.write(b"\0")
            self.file.flush()

    def try_acquire(self) -> bool:
        self._open()
        if self._locked:
            return True
        assert self.file is not None
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            busy_errors = {errno.EACCES, errno.EAGAIN}
            if isinstance(exc, BlockingIOError) or exc.errno in busy_errors:
                return False
            raise
        self._locked = True
        return True

    def acquire(self, timeout: float | None = None) -> None:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.try_acquire():
            if deadline is not None and time.monotonic() >= deadline:
                self.close()
                raise TimeoutError(f"timed out acquiring lock {self.path}")
            time.sleep(0.05)

    def release(self) -> None:
        if not self._locked or self.file is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        finally:
            self._locked = False

    def close(self) -> None:
        try:
            self.release()
        finally:
            if self.file is not None:
                self.file.close()
                self.file = None

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


@dataclass(frozen=True)
class InstanceIdentity:
    idb_path: str
    exe_path: str
    backend: BackendName
    managed: bool = False


@dataclass(frozen=True)
class RegistryEntry:
    record_id: str
    backend: BackendName
    pid: int
    port: int
    token: str
    version: int
    idb_path: str
    idb_key: str
    exe_path: str
    managed: bool
    started_at: float

    def health_identity(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("port")
        payload.pop("token")
        return payload


@dataclass(frozen=True)
class DiscoveredInstance:
    entry: RegistryEntry
    state: InstanceState
    detail: str | None = None
    registry_file: str | None = None


_KEEP_ALIVE: list[FileLock] = []


class InstanceRegistration:
    """A published instance whose lock remains held until release()."""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        identity: InstanceIdentity,
        *,
        token: str,
        record_suffix: str | None = None,
    ) -> None:
        self.directory = ensure_private_directory(directory)
        self.identity = identity
        self.token = token
        suffix = record_suffix or os.urandom(3).hex()
        if len(suffix) != 6 or any(c not in "0123456789abcdef" for c in suffix):
            raise ValueError(
                "record suffix must be six lowercase hexadecimal characters"
            )
        self.record_id = f"{os.getpid()}-{suffix}"
        self.lock = FileLock(self.directory / f"{self.record_id}.lock")
        self.lock.acquire(timeout=0)
        _KEEP_ALIVE.append(self.lock)
        self.entry: RegistryEntry | None = None
        self.registry_path: Path | None = None

    def publish(self, port: int) -> RegistryEntry:
        """Atomically publish the instance record with private permissions."""

        if self.entry is not None:
            return self.entry
        if not self.identity.idb_path:
            raise ValueError("an instance cannot register without an IDB path")
        idb_path = canonical_path(self.identity.idb_path)
        exe_path = (
            canonical_path(self.identity.exe_path) if self.identity.exe_path else ""
        )
        entry = RegistryEntry(
            record_id=self.record_id,
            backend=self.identity.backend,
            pid=os.getpid(),
            port=port,
            token=self.token,
            version=PROTOCOL_VERSION,
            idb_path=idb_path,
            idb_key=idb_key(idb_path),
            exe_path=exe_path,
            managed=self.identity.managed,
            started_at=time.time(),
        )
        target = self.directory / f"{self.record_id}.json"
        fd, temporary_name = tempfile.mkstemp(
            dir=self.directory,
            prefix=f".{self.record_id}-",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                if os.name != "nt":
                    raise
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                fd = -1
                json.dump(asdict(entry), file, separators=(",", ":"))
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, target)
        except Exception:
            if fd >= 0:
                os.close(fd)
            temporary.unlink(missing_ok=True)
            raise
        self.entry = entry
        self.registry_path = target
        return entry

    def withdraw(self) -> None:
        path = self.registry_path
        if path is None:
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload.get("token") == self.token:
                path.unlink(missing_ok=True)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            # Shutdown cleanup is best effort. Never unlink a record that
            # could not be authenticated as ours.
            pass
        self.registry_path = None

    def release(self) -> None:
        self.withdraw()
        self.lock.close()
        try:
            _KEEP_ALIVE.remove(self.lock)
        except ValueError:
            pass


def load_registry_entry(path: str | os.PathLike[str]) -> RegistryEntry:
    entry_path = Path(path)
    payload = json.loads(entry_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("registry entry must be a JSON object")
    required = {
        "record_id",
        "backend",
        "pid",
        "port",
        "token",
        "version",
        "idb_path",
        "idb_key",
        "exe_path",
        "managed",
        "started_at",
    }
    if set(payload) != required:
        raise ValueError("registry entry has unexpected fields")
    if payload["record_id"] != entry_path.stem:
        raise ValueError("record ID does not match its filename")
    if payload["backend"] not in ("gui", "idalib"):
        raise ValueError("registry entry has an invalid backend")
    if (
        not isinstance(payload["pid"], int)
        or isinstance(payload["pid"], bool)
        or payload["pid"] <= 0
    ):
        raise ValueError("registry entry has an invalid pid")
    if not payload["record_id"].startswith(f"{payload['pid']}-"):
        raise ValueError("record ID does not match its pid")
    if (
        not isinstance(payload["port"], int)
        or isinstance(payload["port"], bool)
        or not 1 <= payload["port"] <= 65535
    ):
        raise ValueError("registry entry has an invalid port")
    if not isinstance(payload["token"], str) or not payload["token"]:
        raise ValueError("registry entry has an invalid token")
    if not isinstance(payload["version"], int) or isinstance(payload["version"], bool):
        raise TypeError("registry entry has an invalid version")
    for key in ("idb_path", "idb_key", "exe_path"):
        if not isinstance(payload[key], str):
            raise TypeError(f"registry entry has an invalid {key}")
    if payload["idb_key"] != idb_key(payload["idb_path"]):
        raise ValueError("registry entry has an invalid IDB key")
    if not isinstance(payload["managed"], bool):
        raise TypeError("registry entry has an invalid managed flag")
    if isinstance(payload["started_at"], bool) or not isinstance(
        payload["started_at"], (int, float)
    ):
        raise TypeError("registry entry has an invalid start time")
    return RegistryEntry(**payload)


def _is_timeout(error: BaseException) -> bool:
    reason = error.reason if isinstance(error, URLError) else error
    return isinstance(reason, (TimeoutError, socket.timeout))


def probe_health(
    entry: RegistryEntry, timeout: float = DEFAULT_TIMEOUT
) -> tuple[bool, str | None]:
    request = Request(
        f"http://{HOST}:{entry.port}/health",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {entry.token}",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read()
            if response.status != 200:
                return False, f"HTTP {response.status}"
    except HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except (URLError, OSError) as exc:
        return False, "timeout" if _is_timeout(exc) else str(exc)
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False, "health response was not JSON"
    expected = {"status": "ok", **entry.health_identity()}
    if payload != expected:
        return False, "health identity did not match the registry entry"
    return True, None


def _reap_locked_record(path: Path, lock: FileLock) -> None:
    try:
        path.unlink(missing_ok=True)
    finally:
        lock.close()
    try:
        lock.path.unlink(missing_ok=True)
    except OSError:
        pass


def sweep_orphan_locks(directory: str | os.PathLike[str]) -> None:
    root = ensure_private_directory(directory)
    for lock_path in root.glob("*.lock"):
        if (root / f"{lock_path.stem}.json").exists():
            continue
        lock = FileLock(lock_path)
        try:
            if not lock.try_acquire():
                lock.close()
                continue
            lock.close()
            try:
                lock_path.unlink(missing_ok=True)
            except OSError:
                pass
        except OSError:
            lock.close()


def scan_instances(
    registry_dir: str | os.PathLike[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[DiscoveredInstance]:
    """Return live records, reaping only records whose lock is acquirable."""

    directory = ensure_private_directory(
        REGISTRY_DIR if registry_dir is None else registry_dir
    )
    discovered: list[DiscoveredInstance] = []
    for name in sorted(glob.glob(str(directory / "*.json"))):
        path = Path(name)
        lock = FileLock(directory / f"{path.stem}.lock")
        try:
            entry = load_registry_entry(path)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            try:
                if lock.try_acquire():
                    _reap_locked_record(path, lock)
                else:
                    lock.close()
            except OSError:
                lock.close()
            continue

        try:
            if lock.try_acquire():
                _reap_locked_record(path, lock)
                continue
        except OSError as exc:
            lock.close()
            discovered.append(
                DiscoveredInstance(entry, InstanceState.BLOCKED, str(exc), str(path))
            )
            continue
        lock.close()

        valid, detail = probe_health(entry, timeout)
        discovered.append(
            DiscoveredInstance(
                entry,
                InstanceState.READY if valid else InstanceState.BLOCKED,
                detail,
                str(path),
            )
        )
    sweep_orphan_locks(directory)
    return discovered


def discover_instances(
    registry_dir: str | os.PathLike[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compatibility wrapper returning ready and blocked instance dictionaries."""

    ready: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for instance in scan_instances(registry_dir, timeout):
        payload = asdict(instance.entry)
        payload.update(
            registry_file=instance.registry_file,
            availability=instance.state.value,
        )
        if instance.state is InstanceState.READY:
            ready.append(payload)
        else:
            payload["error"] = instance.detail or "instance is unavailable"
            blocked.append(payload)
    return ready, blocked


def read_records(
    registry_dir: str | os.PathLike[str] | None = None,
) -> list[RegistryEntry]:
    """Return published registry records without probing health or acquiring locks.

    Much cheaper than :func:`scan_instances` (no HTTP health probe, no lock
    reaping), but the records are therefore only "potentially live" - a returned
    entry may belong to a process that has since exited. Suitable for a coarse
    "is anything registered for this IDB?" check where an occasional stale match
    is acceptable.
    """
    directory = ensure_private_directory(
        REGISTRY_DIR if registry_dir is None else registry_dir
    )
    records: list[RegistryEntry] = []
    for name in sorted(glob.glob(str(directory / "*.json"))):
        try:
            records.append(load_registry_entry(name))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return records


def find_gui_owner(
    idb_path: str | os.PathLike[str],
    registry_dir: str | os.PathLike[str] | None = None,
) -> RegistryEntry | None:
    """Return a live registered GUI record that owns ``idb_path``, or None.

    Cheaply lists records with :func:`read_records`, then confirms liveness for
    the matching candidate(s) *only* - via each record's lock, the same
    authority :func:`scan_instances` and the resolver use - instead of
    health-probing every instance. A held lock means the owner is running
    (READY or BLOCKED), so a second GUI server would make
    :func:`resolve_instance` raise ``AmbiguousInstance`` and the caller should
    back off and attach instead. An acquirable lock means the record is stale
    and is ignored (unlike a health probe, this never gives a false negative on
    a transient blip, which would otherwise create a persistent duplicate owner).
    """
    directory = ensure_private_directory(
        REGISTRY_DIR if registry_dir is None else registry_dir
    )
    key = idb_key(idb_path)
    for entry in read_records(directory):
        if entry.backend != "gui" or entry.idb_key != key:
            continue
        lock = FileLock(directory / f"{entry.record_id}.lock")
        try:
            acquirable = lock.try_acquire()
        except OSError:
            acquirable = False  # can't probe the lock; assume the owner is live
        finally:
            lock.close()
        if acquirable:
            continue  # stale record: the owning process is gone
        return entry
    return None
