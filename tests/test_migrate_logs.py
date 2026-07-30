import json
from pathlib import Path

from migrate_logs import migrate


def _write_transitional_trace(path: Path, server_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "ts": "2026-01-01T00:00:00+00:00",
                "mcp_server_id": server_id,
                "pid": 123,
                "event": "mcp_started",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_migration_sanitizes_transitional_server_id(tmp_path: Path) -> None:
    source = tmp_path / "logs"
    destination = tmp_path / "sessions"
    _write_transitional_trace(source / "mcp" / "trace.jsonl", "../escaped")

    assert migrate(source, destination, dry_run=False) == 0

    assert (destination / "escaped.jsonl").is_file()
    assert not (tmp_path / "escaped.jsonl").exists()


def test_migration_avoids_windows_reserved_filename(tmp_path: Path) -> None:
    source = tmp_path / "logs"
    destination = tmp_path / "sessions"
    _write_transitional_trace(source / "mcp" / "trace.jsonl", "CON")

    assert migrate(source, destination, dry_run=False) == 0

    assert (destination / "session-CON.jsonl").is_file()
