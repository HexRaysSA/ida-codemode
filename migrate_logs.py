"""One-shot migration of pre-0.2 ida-codemode logs into semantic sessions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ida_codemode.paths import STATE_DIR

DEFAULT_SOURCE = STATE_DIR / "logs"
DEFAULT_DESTINATION = STATE_DIR / "sessions"
_AGENT_FIELDS = {
    "claude": "claude_session_path",
    "codex": "codex_session_path",
    "pi": "pi_session_path",
}
_GUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _read_records(path: Path, report: list[str]) -> list[tuple[int, dict[str, Any]]]:
    records: list[tuple[int, dict[str, Any]]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        report.append(f"ERROR {path}: {exc}")
        return records
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            report.append(f"MALFORMED {path}:{line_number}: {exc}")
            continue
        if not isinstance(value, dict):
            report.append(f"MALFORMED {path}:{line_number}: record is not an object")
            continue
        records.append((line_number, value))
    return records


def _session_fields(record: dict[str, Any]) -> dict[str, Any]:
    nested = record.get("session")
    fields = dict(nested) if isinstance(nested, dict) else {}
    codemode_id = record.get("codemode_id")
    if isinstance(codemode_id, str) and codemode_id:
        fields.setdefault("codemode_id", codemode_id)
    for field in _AGENT_FIELDS.values():
        value = record.get(field)
        if isinstance(value, str) and value:
            fields.setdefault(field, value)
    return fields


def _session_key(fields: dict[str, Any], source: Path) -> tuple[str, str]:
    for kind, field in _AGENT_FIELDS.items():
        value = fields.get(field)
        if isinstance(value, str) and value:
            return kind, str(Path(value).expanduser())
    codemode_id = fields.get("codemode_id")
    if isinstance(codemode_id, str) and codemode_id:
        return "codemode", codemode_id
    return "unattributed", str(source.resolve())


def _safe_component(value: str) -> str:
    value = "".join(c if c.isalnum() or c in "-_" else "-" for c in value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value[:64] or "session"


def _session_id(key: tuple[str, str]) -> str:
    kind, value = key
    guid = _GUID_RE.search(value)
    if guid:
        identity = guid.group(0).lower()
    else:
        stem = _safe_component(Path(value).stem if kind in _AGENT_FIELDS else value)
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
        identity = f"{stem}-{digest}"
    return f"migrated-{kind}-{identity}"


def _iso_sort_key(record: dict[str, Any], sequence: int) -> tuple[str, int]:
    value = record.get("ts")
    return (value if isinstance(value, str) else "", sequence)


def _base_record(
    *,
    ts: Any,
    server_id: str,
    pid: int | None,
    event: str,
    session: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": 1,
        "ts": ts if isinstance(ts, str) else datetime.now(UTC).isoformat(),
        "mcp_server_id": server_id,
        "pid": pid,
        "event": event,
        "session": session,
    }


def _legacy_instance_id(path: Path) -> str:
    target, separator, instance_id = path.stem.rpartition("-")
    return instance_id if separator and target else path.stem


def _legacy_target(
    path: Path,
    records: list[tuple[int, dict[str, Any]]],
) -> dict[str, Any]:
    pid: int | None = None
    database_path: str | None = None
    for _line, record in records:
        if record.get("event") == "process_started" and isinstance(
            record.get("pid"), int
        ):
            pid = record["pid"]
        if record.get("event") == "request":
            payload = record.get("payload")
            if isinstance(payload, dict) and payload.get("command") == "open":
                value = payload.get("path")
                if isinstance(value, str):
                    database_path = value
                    break
    return {
        "instance_id": _legacy_instance_id(path),
        "record_id": None,
        "backend": "idalib",
        "pid": pid,
        "idb_path": database_path,
        "exe_path": database_path,
        "managed": True,
    }


def _legacy_tool(command: Any) -> str | None:
    return {
        "open": "open_database",
        "execute": "execute_python",
        "close": "close_database",
    }.get(command)


def _print_unmigrated(
    report: list[str],
    path: Path,
    line_number: int,
    reason: str,
    record: dict[str, Any],
) -> None:
    rendered = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    report.append(f"UNMIGRATED {path}:{line_number} ({reason})\n  {rendered}")


def _print_discarded(
    report: list[str],
    path: Path,
    line_number: int,
    reason: str,
    record: dict[str, Any],
) -> None:
    rendered = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    report.append(f"DISCARDED_RECORD {path}:{line_number} ({reason})\n  {rendered}")


def _translate_legacy(
    paths: list[Path],
    report: list[str],
    *,
    verbose: bool,
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    buckets: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    bucket_sources: dict[tuple[str, str], set[Path]] = defaultdict(set)
    source_closed: dict[Path, bool] = {}
    discarded_output: dict[Path, int] = defaultdict(int)
    sequence = 0

    for path in paths:
        records = _read_records(path, report)
        if not records:
            continue
        defaults: dict[str, Any] = {}
        for _line, record in records:
            defaults.update(_session_fields(record))
        target = _legacy_target(path, records)
        # A bridge PID belongs to the old worker, not to a reconstructable MCP
        # process. It remains in target metadata but is never used as session PID.
        source_closed[path] = any(
            record.get("event") in {"process_exited", "process_already_exited"}
            for _line, record in records
        )
        requests: dict[str, tuple[tuple[str, str], dict[str, Any], str]] = {}
        emitted_open: set[tuple[str, str]] = set()
        handled_responses: set[int] = set()

        responses: dict[str, tuple[int, int, dict[str, Any]]] = {}
        for index, (line_number, record) in enumerate(records):
            if record.get("event") == "response" and isinstance(
                record.get("request_id"), str
            ):
                responses[record["request_id"]] = (index, line_number, record)

        for index, (line_number, record) in enumerate(records):
            event = record.get("event")
            fields = {**defaults, **_session_fields(record)}
            key = _session_key(fields, path)
            server_id = _session_id(key)

            if event == "request":
                payload = record.get("payload")
                if not isinstance(payload, dict):
                    _print_unmigrated(
                        report,
                        path,
                        line_number,
                        "request payload is not an object",
                        record,
                    )
                    continue
                tool = _legacy_tool(payload.get("command"))
                if tool is None:
                    _print_unmigrated(
                        report, path, line_number, "unsupported command", record
                    )
                    continue
                request_id = record.get("request_id")
                if not isinstance(request_id, str) or not request_id:
                    request_id = hashlib.sha256(
                        f"{path}:{line_number}".encode()
                    ).hexdigest()[:24]
                bucket_sources[key].add(path)
                if key not in emitted_open:
                    opened = _base_record(
                        ts=record.get("ts"),
                        server_id=server_id,
                        pid=None,
                        event="database_opened",
                        session=fields,
                    )
                    opened.update(instance_id=target["instance_id"], target=target)
                    buckets[key].append((sequence, opened))
                    sequence += 1
                    emitted_open.add(key)
                arguments = {
                    str(name): value
                    for name, value in payload.items()
                    if name not in {"command", "request_id"}
                }
                call = _base_record(
                    ts=record.get("ts"),
                    server_id=server_id,
                    pid=None,
                    event="tool_call",
                    session=fields,
                )
                call.update(call_id=request_id, tool=tool, input=arguments)
                buckets[key].append((sequence, call))
                sequence += 1
                requests[request_id] = (key, fields, tool)

                response_info = responses.get(request_id)
                if response_info is not None:
                    response_index, _response_line, response = response_info
                    handled_responses.add(response_index)
                    response_payload = response.get("payload")
                    if not isinstance(response_payload, dict):
                        _print_unmigrated(
                            report,
                            path,
                            response_info[1],
                            "response payload is not an object",
                            response,
                        )
                        continue
                    ok = bool(response_payload.get("ok"))
                    translated = _base_record(
                        ts=response.get("ts"),
                        server_id=server_id,
                        pid=None,
                        event="tool_result" if ok else "tool_error",
                        session=fields,
                    )
                    translated.update(call_id=request_id, tool=tool)
                    if ok:
                        translated["output"] = response_payload.get("result")
                    else:
                        translated["error"] = {
                            "type": "LegacyBridgeError",
                            "message": response_payload.get("error", "unknown error"),
                            "traceback": response_payload.get("traceback", ""),
                        }
                    buckets[key].append((sequence, translated))
                    sequence += 1
                continue

            if event == "response":
                if index not in handled_responses:
                    _print_unmigrated(
                        report, path, line_number, "orphan response", record
                    )
                continue

            if event in {"timeout", "request_failed"}:
                request_id = record.get("request_id")
                request = (
                    requests.get(request_id) if isinstance(request_id, str) else None
                )
                if request is None:
                    _print_unmigrated(
                        report, path, line_number, "unattributed failure", record
                    )
                    continue
                request_key, request_fields, tool = request
                failed = _base_record(
                    ts=record.get("ts"),
                    server_id=_session_id(request_key),
                    pid=None,
                    event="tool_error",
                    session=request_fields,
                )
                failed.update(
                    call_id=request_id,
                    tool=tool,
                    error={
                        "type": "LegacyBridgeFailure",
                        "message": event,
                        "details": {
                            name: value
                            for name, value in record.items()
                            if name not in {"ts", "event"}
                        },
                    },
                )
                buckets[request_key].append((sequence, failed))
                sequence += 1
                continue

            if event == "bridge_output":
                discarded_output[path] += 1
                if verbose:
                    _print_discarded(
                        report,
                        path,
                        line_number,
                        "operational bridge output",
                        record,
                    )
                continue
            if event in {
                "instance_started",
                "process_started",
                "process_exited",
                "process_already_exited",
                "process_terminate",
                "process_kill",
            }:
                continue
            _print_unmigrated(report, path, line_number, "unsupported event", record)

    migrated: dict[str, list[dict[str, Any]]] = {}
    for key, sequenced in buckets.items():
        sequenced.sort(key=lambda item: _iso_sort_key(item[1], item[0]))
        records = [record for _sequence, record in sequenced]
        sources = bucket_sources[key]
        if sources and all(source_closed.get(source, False) for source in sources):
            last = records[-1]
            last_session = last.get("session")
            session: dict[str, Any] = (
                {str(name): value for name, value in last_session.items()}
                if isinstance(last_session, dict)
                else {}
            )
            last_pid = last.get("pid")
            records.append(
                _base_record(
                    ts=last.get("ts"),
                    server_id=_session_id(key),
                    pid=last_pid if isinstance(last_pid, int) else None,
                    event="mcp_stopped",
                    session=session,
                )
            )
        migrated[_session_id(key)] = records
    for path, count in sorted(discarded_output.items()):
        report.append(
            f"DISCARDED {path}: {count} operational bridge_output records "
            "(preserved in source log)"
        )
    return migrated, sum(discarded_output.values())


def _write_session(
    destination: Path,
    session_id: str,
    records: list[dict[str, Any]],
    *,
    dry_run: bool,
    report: list[str],
) -> bool:
    content = "".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        for record in records
    )
    path = destination / f"{session_id}.jsonl"
    if path.exists():
        if path.read_text(encoding="utf-8", errors="replace") == content:
            report.append(f"SKIP {path} (already migrated)")
            return False
        report.append(f"ERROR {path} already exists with different content")
        return False
    report.append(
        f"{'WOULD WRITE' if dry_run else 'WRITE'} {path} ({len(records)} records)"
    )
    if dry_run:
        return True
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        destination.chmod(0o700)
    except OSError:
        if os.name != "nt":
            raise
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())
    return True


def migrate(
    source: Path,
    destination: Path,
    *,
    dry_run: bool,
    verbose: bool = False,
) -> int:
    report: list[str] = []
    transitional = sorted((source / "mcp").glob("*.jsonl"))
    legacy = sorted(source.glob("*.jsonl"))
    written = 0

    for path in transitional:
        records = [record for _line, record in _read_records(path, report)]
        if not records:
            continue
        if not all(record.get("schema") == 1 for record in records):
            report.append(f"ERROR {path} is not a schema-1 MCP trace")
            continue
        server_id = records[0].get("mcp_server_id")
        if not isinstance(server_id, str) or not server_id:
            report.append(f"ERROR {path} has no mcp_server_id")
            continue
        written += _write_session(
            destination, server_id, records, dry_run=dry_run, report=report
        )

    migrated, discarded = _translate_legacy(legacy, report, verbose=verbose)
    for session_id, records in sorted(migrated.items()):
        written += _write_session(
            destination, session_id, records, dry_run=dry_run, report=report
        )

    heading = "DRY RUN" if dry_run else "MIGRATION"
    print(f"{heading}: {source} -> {destination}")
    print(
        f"Found {len(transitional)} transitional traces and {len(legacy)} legacy logs"
    )
    for line in report:
        print(line)
    unmigrated = sum(line.startswith("UNMIGRATED ") for line in report)
    malformed = sum(line.startswith("MALFORMED ") for line in report)
    errors = sum(line.startswith("ERROR ") for line in report)
    print(
        f"Summary: {len(migrated) + len(transitional)} sessions, "
        f"{written} {'planned' if dry_run else 'written'}, "
        f"{discarded} operational records discarded, "
        f"{unmigrated} unknown records, {malformed} malformed, {errors} errors"
    )
    return 0 if errors == 0 else 1


def cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every intentionally discarded operational record",
    )
    args = parser.parse_args()
    return migrate(
        args.source.expanduser().resolve(),
        args.destination.expanduser().resolve(),
        dry_run=args.dry_run,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    raise SystemExit(cli())
