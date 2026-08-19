from __future__ import annotations

from typing import TYPE_CHECKING, assert_type

from ida_codemode import DatabaseHandle, remote_ida

if TYPE_CHECKING:
    from ida_domain import Database


@remote_ida
def read_bytes(db: Database, address: int, size: int) -> bytes:
    return db.bytes.get_bytes_at(address, size) or b""


@remote_ida
def describe_bytes(
    db: Database,
    address: int,
    expected: bytes,
) -> tuple[int, bytes]:
    actual = db.bytes.get_bytes_at(address, len(expected)) or b""
    return address, actual


def check_remote_ida_types(handle: DatabaseHandle) -> None:
    assert_type(read_bytes(handle, 0x401000, 4), bytes)
    assert_type(describe_bytes(handle, 0x401000, b"\x7fELF"), tuple[int, bytes])
