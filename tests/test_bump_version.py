from __future__ import annotations

import pytest

from scripts import bump_version


@pytest.mark.parametrize(
    ("current", "requested", "expected"),
    [
        ("0.2.0", "dev", "0.2.1-dev.1"),
        ("0.2.1-dev.1", "dev", "0.2.1-dev.2"),
        ("0.2.1-dev.2", "release-patch", "0.2.1"),
        ("0.2.1", "release-patch", "0.2.2"),
        ("0.2.1-dev.2", "release-minor", "0.3.0"),
        ("0.2.1", "release-major", "1.0.0"),
        ("0.2.0", "2.4.6-dev.3", "2.4.6-dev.3"),
        ("0.2.0", "2.4.6.dev3", "2.4.6-dev.3"),
    ],
)
def test_next_version(current: str, requested: str, expected: str) -> None:
    assert bump_version._next_version(current, requested) == expected


def test_version_declarations_are_in_sync() -> None:
    assert bump_version.main(["--check"]) == 0
