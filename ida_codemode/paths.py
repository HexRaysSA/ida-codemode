import os
import sys
import sysconfig
from pathlib import Path


def get_idausr_dir() -> Path:
    """Return IDA's main user directory."""
    idausr = os.environ.get("IDAUSR")
    if idausr:
        first = idausr.split(os.pathsep)[0].strip()
        if first:
            return Path(first).expanduser()

    if os.name == "nt":
        return Path(os.environ["APPDATA"]) / "Hex-Rays" / "IDA Pro"
    return Path.home() / ".idapro"


def get_state_dir() -> Path:
    """Return the directory where IDA Code Mode state is stored."""
    state_dir = os.environ.get("IDA_CODEMODE_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser()
    return get_idausr_dir() / "codemode"


def find_console_script(name: str) -> str | None:
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


STATE_DIR = get_state_dir()
