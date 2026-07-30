import os
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


STATE_DIR = get_state_dir()
