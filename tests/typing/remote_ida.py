from __future__ import annotations

from typing import TYPE_CHECKING, assert_type

from ida_nexus import DatabaseHandle, remote_ida

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


def read_pair(db: Database, address: int) -> tuple[int, bytes]:
    data = db.bytes.get_bytes_at(address, 2) or b""
    return address, data


def keep_bytes(pair: tuple[int, bytes]) -> bytes:
    return pair[1]


@remote_ida(helpers=(keep_bytes, read_pair))
def read_with_helpers(db: Database, address: int) -> bytes:
    return keep_bytes(read_pair(db, address))


def check_remote_ida_types(handle: DatabaseHandle) -> None:
    assert_type(read_bytes(handle, 0x401000, 4), bytes)
    assert_type(describe_bytes(handle, 0x401000, b"\x7fELF"), tuple[int, bytes])
    assert_type(read_with_helpers(handle, 0x401000), bytes)
