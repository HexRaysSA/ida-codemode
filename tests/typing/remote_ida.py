from __future__ import annotations

from typing import TYPE_CHECKING, assert_type

from ida_nexus import (
    DatabaseHandle,
    RemoteExecutor,
    RemoteModule,
    remote_ida,
)

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


@remote_ida(database=False)
def direct_idapython(value: int) -> int:
    return value


@remote_ida()
def implicit_factory(db: Database, value: int) -> int:
    del db
    return value


@remote_ida(database=False)
def preserve_named_database(database: Database, value: int) -> int:
    del database
    return value


@remote_ida(database=True)
def explicit_database(database: Database, value: int) -> int:
    del database
    return value


module = RemoteModule(__file__)


def module_read(db: Database, address: int) -> bytes:
    return db.bytes.get_bytes_at(address, 1) or b""


remote_module_read = module.function(module_read)


def module_read_factory(db: Database, address: int) -> bytes:
    return db.bytes.get_bytes_at(address, 1) or b""


remote_module_read_factory = module.function()(module_read_factory)


def module_read_explicit(database: Database, address: int) -> bytes:
    return database.bytes.get_bytes_at(address, 1) or b""


remote_module_read_explicit = module.function(database=True)(module_read_explicit)


def check_remote_ida_types(
    handle: DatabaseHandle,
    executor: RemoteExecutor,
    database: Database,
) -> None:
    assert_type(read_bytes(handle, 0x401000, 4), bytes)
    assert_type(describe_bytes(handle, 0x401000, b"\x7fELF"), tuple[int, bytes])
    assert_type(read_with_helpers(handle, 0x401000), bytes)
    assert_type(remote_module_read(executor, 0x401000), bytes)
    assert_type(remote_module_read_factory(executor, 0x401000), bytes)
    assert_type(remote_module_read_explicit(executor, 0x401000), bytes)
    assert_type(direct_idapython(executor, 7), int)
    assert_type(implicit_factory(executor, 7), int)
    assert_type(preserve_named_database(executor, database, 7), int)
    assert_type(explicit_database(executor, 7), int)
