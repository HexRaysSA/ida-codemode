from __future__ import annotations

from dataclasses import asdict, dataclass
import errno
import glob
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


HOST = "127.0.0.1"
REGISTRY_DIRECTORY = "lifecycle-instances"
DEFAULT_TIMEOUT = 2.0
BackendName = Literal["gui", "idalib"]


@dataclass(frozen=True)
class InstanceIdentity:
    idb_path: str
    exe_path: str
    backend: BackendName


@dataclass(frozen=True)
class RegistryEntry:
    port: int
    idb_path: str
    exe_path: str
    token: str
    backend: BackendName


def get_ida_user_dir() -> Path:
    configured = os.environ.get("IDAUSR")
    if configured:
        return Path(configured).expanduser().resolve()
    if sys.platform == "win32":
        return Path(os.environ["APPDATA"]) / "Hex-Rays" / "IDA Pro"
    return Path.home() / ".idapro"


def get_registry_dir(ida_user_dir: str | os.PathLike[str] | None = None) -> Path:
    return (
        Path(ida_user_dir) / REGISTRY_DIRECTORY
        if ida_user_dir
        else get_ida_user_dir() / REGISTRY_DIRECTORY
    )


def publish_entry(
    directory: str | os.PathLike[str],
    entry: RegistryEntry,
    *,
    pid: int | None = None,
) -> Path:
    """Atomically publish an instance registry entry with private permissions."""

    directory_path = Path(directory)
    directory_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        directory_path.chmod(0o700)
    except OSError:
        if os.name != "nt":
            raise

    pid = os.getpid() if pid is None else pid
    target = directory_path / f"{pid}.json"
    fd, temporary_name = tempfile.mkstemp(
        dir=directory_path,
        prefix=f".{pid}-",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    replaced = False
    try:
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            if os.name != "nt":
                raise
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            fd = -1
            json.dump(asdict(entry), file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, target)
        replaced = True
        try:
            target.chmod(0o600)
        except OSError:
            if os.name != "nt":
                raise
    except Exception:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
        if replaced:
            remove_entry(target, entry.token)
        raise
    return target


def remove_entry(path: str | os.PathLike[str] | None, token: str) -> None:
    """Remove an entry only if it still belongs to this server token."""

    if path is None:
        return
    entry_path = Path(path)
    try:
        payload = json.loads(entry_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("token") != token:
            return
        entry_path.unlink()
    except FileNotFoundError:
        pass
    except OSError, UnicodeDecodeError, json.JSONDecodeError:
        # Shutdown cleanup is best effort. Never unlink an entry that could not
        # be authenticated as ours.
        pass


def load_registry_entry(path: str | os.PathLike[str]) -> RegistryEntry:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("registry entry must be a JSON object")
    port = payload.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("registry entry has an invalid port")
    for key in ("idb_path", "exe_path", "token", "backend"):
        if not isinstance(payload.get(key), str):
            raise ValueError(f"registry entry has an invalid {key}")
    if not payload["token"]:
        raise ValueError("registry entry has an empty token")
    if payload["backend"] not in ("gui", "idalib"):
        raise ValueError("registry entry has an invalid backend")
    return RegistryEntry(**payload)


def _is_timeout(error: BaseException) -> bool:
    reason = error.reason if isinstance(error, URLError) else error
    return isinstance(reason, (TimeoutError, socket.timeout))


def _is_connection_refused(error: BaseException) -> bool:
    reason = error.reason if isinstance(error, URLError) else error
    return isinstance(reason, ConnectionRefusedError) or (
        isinstance(reason, OSError) and reason.errno == errno.ECONNREFUSED
    )


def probe_health(
    entry: RegistryEntry,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[str, Any]:
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
            status = response.status
            body = response.read()
    except HTTPError as exc:
        return "mismatch", f"HTTP {exc.code}"
    except (URLError, OSError) as exc:
        if _is_timeout(exc):
            return "timeout", str(exc)
        if _is_connection_refused(exc):
            return "dead", str(exc)
        return "unavailable", str(exc)

    if status != 200:
        return "unavailable", f"HTTP {status}"
    try:
        payload = json.loads(body)
    except UnicodeDecodeError, json.JSONDecodeError:
        return "mismatch", "health response was not JSON"
    expected = asdict(entry)
    expected.pop("port")
    if not isinstance(payload, dict) or any(
        payload.get(key) != value for key, value in expected.items()
    ):
        return "mismatch", "health identity did not match the registry entry"
    return "valid", payload


def discover_instances(
    registry_dir: str | os.PathLike[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Discover valid instances and remove entries proven to be stale."""

    directory = get_registry_dir() if registry_dir is None else Path(registry_dir)
    valid: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []
    for name in sorted(glob.glob(str(directory / "*.json"))):
        path = Path(name)
        try:
            entry = load_registry_entry(path)
        except OSError, ValueError, json.JSONDecodeError:
            try:
                path.unlink()
            except OSError:
                pass
            continue

        state, detail = probe_health(entry, timeout)
        result = asdict(entry)
        result.update(
            pid=path.stem,
            registry_file=str(path),
            availability=state,
        )
        if state == "valid":
            valid.append(result)
        elif state in {"dead", "mismatch"}:
            try:
                path.unlink()
            except OSError:
                pass
        else:
            result["error"] = str(detail)
            unavailable.append(result)
    return valid, unavailable
