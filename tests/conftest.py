from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

_STATE_DIR = Path(tempfile.mkdtemp(prefix="ida-codemode-tests-"))
os.environ["IDA_CODEMODE_STATE_DIR"] = str(_STATE_DIR)


@pytest.fixture(autouse=True)
def clean_codemode_state() -> Iterator[None]:
    for name in ("instances", "spawn", "logs"):
        shutil.rmtree(_STATE_DIR / name, ignore_errors=True)
    yield
    for name in ("instances", "spawn", "logs"):
        shutil.rmtree(_STATE_DIR / name, ignore_errors=True)


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    del session, exitstatus
    shutil.rmtree(_STATE_DIR, ignore_errors=True)
