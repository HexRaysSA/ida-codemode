"""Web dashboard for ida-codemode bridge sessions.

Serves a local HTTP UI (stdlib only, no extra dependencies) that lists the
JSONL bridge logs in ~/.ida-codemode/logs and renders them as a timeline.
When a bridge log references a Claude Code or Codex session transcript, the
dashboard links to a visual rendering of that transcript as well.

Run with: ida-codemode-dashboard [--host 127.0.0.1] [--port 8736] [--open]
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import threading
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

STATE_DIR = Path.home() / ".ida-codemode"
DEFAULT_LOGS_DIR = STATE_DIR / "logs"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8736

LOGS_DIR = DEFAULT_LOGS_DIR

_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# JSONL helpers
# --------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
    except OSError:
        pass
    return records


def _parse_ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _format_ts(dt: datetime | None, with_date: bool = True) -> str:
    if dt is None:
        return ""
    local = dt.astimezone()
    return local.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs:02d}s"


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _format_tokens(n: int) -> str:
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k"
    return f"{n / 1_000_000:.2f}M"


def _format_cost(cost: float) -> str:
    if cost >= 1:
        return f"${cost:.2f}"
    if cost >= 0.01:
        return f"${cost:.3f}"
    return f"${cost:.4f}"


# Per-1M-token USD pricing (input, output), sourced from the Claude API model
# table. Cache writes bill at 1.25x input, cache reads at 0.10x input.
_MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-fable-5": (10.0, 50.0),
    "claude-mythos-5": (10.0, 50.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-opus-4-7": (5.0, 25.0),
    "claude-opus-4-6": (5.0, 25.0),
    "claude-opus-4-5": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
}


def _model_pricing(model: str) -> tuple[float, float] | None:
    if not model:
        return None
    m = model.lower()
    for key, price in _MODEL_PRICING.items():
        if key in m:
            return price
    if "fable" in m or "mythos" in m:
        return (10.0, 50.0)
    if "haiku" in m:
        return (1.0, 5.0)
    if "sonnet" in m:
        return (3.0, 15.0)
    if "opus" in m:
        return (5.0, 25.0)
    return None


def _cost_for(model: str, usage: dict[str, int]) -> float | None:
    price = _model_pricing(model)
    if price is None:
        return None
    price_in, price_out = price
    return (
        usage.get("input", 0) * price_in
        + usage.get("cache_write", 0) * price_in * 1.25
        + usage.get("cache_read", 0) * price_in * 0.10
        + usage.get("output", 0) * price_out
    ) / 1_000_000


def _blank_totals() -> dict[str, Any]:
    return {
        "input": 0,
        "output": 0,
        "cache_read": 0,
        "cache_write": 0,
        "cost": 0.0,
        "cost_available": False,
        "has_tokens": False,
    }


def _add_usage(totals: dict[str, Any], usage: dict[str, Any]) -> None:
    for key in ("input", "output", "cache_read", "cache_write"):
        totals[key] += usage.get(key, 0)
    totals["has_tokens"] = True
    cost = usage.get("cost")
    if cost is not None:
        totals["cost"] += cost
        totals["cost_available"] = True


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _display_target(name: str) -> str:
    """Collapse a long all-hex target name to prefix…suffix form."""
    if "." in name:
        base, _, ext = name.rpartition(".")
        suffix = f".{ext}"
    else:
        base, suffix = name, ""
    if _HEX_RE.match(base) and len(base) >= 24:
        return f"{base[:8]}…{base[-8:]}{suffix}"
    return name


# --------------------------------------------------------------------------
# Bridge log scanning
# --------------------------------------------------------------------------


@dataclass
class BridgeLogSummary:
    path: Path
    target: str
    instance_id: str
    size: int
    started: datetime | None = None
    last_activity: datetime | None = None
    events: int = 0
    executes: int = 0
    errors: int = 0
    closed: bool = False
    pid: int | None = None
    database_path: str | None = None
    agent_sessions: dict[str, str] = field(default_factory=dict)

    @property
    def status(self) -> str:
        """closed (clean exit), running (pid alive), or killed (no clean exit)."""
        if self.closed:
            return "closed"
        if self.pid is not None and _pid_alive(self.pid):
            return "running"
        return "killed"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _split_log_filename(path: Path) -> tuple[str, str]:
    stem = path.stem
    target, _, instance_id = stem.rpartition("-")
    if not target:
        return stem, ""
    return target, instance_id


def _summarize_bridge_log(path: Path) -> BridgeLogSummary:
    target, instance_id = _split_log_filename(path)
    summary = BridgeLogSummary(
        path=path,
        target=target,
        instance_id=instance_id,
        size=path.stat().st_size,
    )
    records = _read_jsonl(path)
    summary.events = len(records)
    for record in records:
        ts = _parse_ts(record.get("ts"))
        if ts is not None:
            if summary.started is None:
                summary.started = ts
            summary.last_activity = ts

        for kind in ("claude", "codex"):
            session_path = record.get(f"{kind}_session_path")
            if isinstance(session_path, str) and session_path:
                summary.agent_sessions[kind] = session_path

        event = record.get("event")
        payload = record.get("payload")
        if event == "request" and isinstance(payload, dict):
            if payload.get("command") == "execute":
                summary.executes += 1
            elif payload.get("command") == "open":
                db_path = payload.get("path")
                if isinstance(db_path, str):
                    summary.database_path = db_path
        elif event == "response" and isinstance(payload, dict):
            if not payload.get("ok", True):
                summary.errors += 1
        elif event in ("timeout", "request_failed"):
            summary.errors += 1
        elif event == "process_started":
            pid = record.get("pid")
            if isinstance(pid, int):
                summary.pid = pid
        elif event == "process_exited":
            summary.closed = True
    return summary


def _scan_bridge_logs() -> list[BridgeLogSummary]:
    if not LOGS_DIR.is_dir():
        return []
    summaries = [
        _summarize_bridge_log(path) for path in sorted(LOGS_DIR.glob("*.jsonl"))
    ]
    summaries.sort(
        key=lambda s: s.last_activity or datetime.fromtimestamp(0).astimezone(),
        reverse=True,
    )
    return summaries


def _known_agent_sessions() -> dict[str, list[BridgeLogSummary]]:
    """Map agent session paths to the bridge logs that reference them.

    Doubles as the allowlist of transcript files the dashboard may read, so
    arbitrary paths can never be requested over HTTP.
    """
    mapping: dict[str, list[BridgeLogSummary]] = {}
    for summary in _scan_bridge_logs():
        for session_path in summary.agent_sessions.values():
            mapping.setdefault(session_path, []).append(summary)
    return mapping


# --------------------------------------------------------------------------
# HTML rendering primitives
# --------------------------------------------------------------------------

_PAGE_CSS = """
:root {
  --bg: #f6f7f9; --panel: #ffffff; --border: #dde1e6; --text: #1b1f24;
  --muted: #59636e; --accent: #0969da; --user: #ddf4ff; --assistant: #ffffff;
  --code-bg: #f0f2f5; --error: #cf222e; --ok: #1a7f37;
  --kw: #cf222e; --str: #0a3069; --num: #953800; --com: #59636e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8d96a0; --accent: #4493f8; --user: #121d2f; --assistant: #161b22;
    --code-bg: #0d1117; --error: #f85149; --ok: #3fb950;
    --kw: #ff7b72; --str: #a5d6ff; --num: #ffa657; --com: #8d96a0;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 24px 16px 64px; }
header.top {
  background: var(--panel); border-bottom: 1px solid var(--border);
  padding: 12px 16px; display: flex; align-items: baseline; gap: 16px;
}
header.top h1 { font-size: 16px; margin: 0; }
header.top .sub { color: var(--muted); font-size: 12px; }
h2 { font-size: 18px; margin: 24px 0 12px; }
table.sessions { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
table.sessions th, table.sessions td {
  padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border);
  vertical-align: top; }
table.sessions th { font-size: 12px; color: var(--muted); font-weight: 600;
  background: var(--bg); cursor: pointer; user-select: none;
  white-space: nowrap; }
table.sessions th:hover { color: var(--text); }
table.sessions th::after { content: ""; opacity: 0.6; font-size: 10px; }
table.sessions th.sort-asc::after { content: " \\2191"; }
table.sessions th.sort-desc::after { content: " \\2193"; }
table.sessions tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
  font-size: 11px; font-weight: 600; border: 1px solid var(--border); }
.badge.claude { color: #b0530a; border-color: #b0530a55; }
.badge.codex { color: var(--ok); border-color: var(--ok); }
.badge.open { color: var(--ok); border-color: var(--ok); }
.badge.closed { color: var(--muted); }
.badge.killed { color: var(--error); border-color: var(--error); opacity: 0.75; }
.badge.error { color: var(--error); border-color: var(--error); }
.muted { color: var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12px; }
.card { background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; margin: 12px 0; overflow: hidden; }
.card > .head { padding: 8px 12px; display: flex; gap: 10px; align-items: baseline;
  flex-wrap: wrap; border-bottom: 1px solid var(--border); background: var(--bg); }
.card > .head .title { font-weight: 600; }
.card > .head .ts { color: var(--muted); font-size: 12px; margin-left: auto; }
.card > .body { padding: 12px; }
pre { background: var(--code-bg); border: 1px solid var(--border);
  border-radius: 6px; padding: 10px 12px; overflow-x: auto; margin: 8px 0;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12px; line-height: 1.45; white-space: pre; }
code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12px; background: var(--code-bg); padding: 1px 4px;
  border-radius: 4px; }
pre code { background: none; padding: 0; }
.kw { color: var(--kw); } .str { color: var(--str); }
.num { color: var(--num); } .com { color: var(--com); font-style: italic; }
details { margin: 8px 0; }
details > summary { cursor: pointer; color: var(--muted); font-size: 12px;
  user-select: none; }
details[open] > summary { margin-bottom: 4px; }
.msg { border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px;
  margin: 12px 0; background: var(--assistant); }
.msg.user { background: var(--user); }
.msg .who { font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--muted); margin-bottom: 4px;
  display: flex; gap: 8px; align-items: baseline; }
.msg .who .ts { font-weight: 400; text-transform: none; letter-spacing: 0;
  margin-left: auto; }
.msg .text { white-space: pre-wrap; word-break: break-word; }
.toolcall { border-left: 3px solid var(--accent); }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px;
  margin: 8px 0; font-size: 13px; }
.kv .k { color: var(--muted); }
.kv .v { word-break: break-all; }
.bridgeout { color: var(--muted); }
.usage { margin-top: 6px; font-size: 11px; color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; }
.transcript-item { position: relative; padding-left: 16px; margin: 4px 0; }
.transcript-item::before { content: ""; position: absolute; left: 3px;
  top: 6px; bottom: 6px; width: 2px; background: var(--accent);
  opacity: 0.4; border-radius: 2px; }
.transcript-item .msg { margin: 6px 0; }
.transcript-item > details { margin: 6px 0; }
body.hide-transcript .transcript-item { display: none; }
.toolbar { display: flex; gap: 12px; margin: 12px 0; font-size: 13px; }
.toolbar button { background: var(--panel); color: var(--text);
  border: 1px solid var(--border); border-radius: 6px; padding: 4px 10px;
  cursor: pointer; font-size: 12px; }
.empty { text-align: center; padding: 48px; color: var(--muted); }
.crumbs { font-size: 13px; margin-bottom: 8px; color: var(--muted); }
"""

_PAGE_JS = """
function setAllDetails(open) {
  document.querySelectorAll('details').forEach(function (d) { d.open = open; });
}
function sortTable(table, col, th) {
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var dir = th.getAttribute('data-dir') === 'asc' ? 'desc' : 'asc';
  var headers = th.parentNode.children;
  for (var i = 0; i < headers.length; i++) {
    headers[i].removeAttribute('data-dir');
    headers[i].classList.remove('sort-asc', 'sort-desc');
  }
  th.setAttribute('data-dir', dir);
  th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
  var mult = dir === 'asc' ? 1 : -1;
  function key(row) {
    var cell = row.cells[col];
    var v = cell.getAttribute('data-sort');
    return v === null ? cell.textContent.trim() : v;
  }
  rows.sort(function (a, b) {
    var x = key(a), y = key(b);
    if (x === '' && y === '') return 0;
    if (x === '') return 1;   // blanks always sort last
    if (y === '') return -1;
    var nx = parseFloat(x), ny = parseFloat(y);
    if (!isNaN(nx) && !isNaN(ny) && x !== '' && y !== '') return (nx - ny) * mult;
    return x.localeCompare(y) * mult;
  });
  rows.forEach(function (r) { tbody.appendChild(r); });
}
function initSort() {
  document.querySelectorAll('table.sessions thead th').forEach(function (th, i) {
    th.addEventListener('click', function () {
      sortTable(th.closest('table'), i, th);
    });
  });
}
document.addEventListener('DOMContentLoaded', initSort);
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _page(title: str, body: str, subtitle: str = "", standalone: bool = False) -> str:
    heading = "ida-codemode dashboard"
    heading_html = (
        f"<h1>{_e(heading)}</h1>"
        if standalone
        else f'<h1><a href="/">{_e(heading)}</a></h1>'
    )
    sub = subtitle if (subtitle or standalone) else str(LOGS_DIR)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>{_PAGE_CSS}</style>
<script>{_PAGE_JS}</script>
</head>
<body>
<header class="top">
  {heading_html}
  <span class="sub">{_e(sub)}</span>
</header>
<div class="wrap">
{body}
</div>
</body>
</html>"""


_PY_KEYWORDS = (
    "False|None|True|and|as|assert|async|await|break|class|continue|def|del|"
    "elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|"
    "not|or|pass|raise|return|try|while|with|yield|self"
)

_PY_TOKEN_RE = re.compile(
    r"(?P<comment>#[^\n]*)"
    r'|(?P<string>[rbufRBUF]{0,2}("""(?:[^"\\]|\\.|"(?!""))*"""'
    r"|'''(?:[^'\\]|\\.|'(?!''))*'''"
    r'|"(?:[^"\\\n]|\\.)*"'
    r"|'(?:[^'\\\n]|\\.)*'))"
    r"|(?P<number>\b(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+"
    r"|\d[\d_]*(?:\.[\d_]+)?(?:[eE][+-]?\d+)?)\b)"
    rf"|(?P<keyword>\b(?:{_PY_KEYWORDS})\b)"
)

_TOKEN_CLASSES = {"comment": "com", "string": "str", "number": "num", "keyword": "kw"}


def _highlight_python(code: str) -> str:
    parts: list[str] = []
    pos = 0
    for match in _PY_TOKEN_RE.finditer(code):
        parts.append(_e(code[pos : match.start()]))
        css = _TOKEN_CLASSES[match.lastgroup or "keyword"]
        parts.append(f'<span class="{css}">{_e(match.group())}</span>')
        pos = match.end()
    parts.append(_e(code[pos:]))
    return "".join(parts)


def _python_block(code: str) -> str:
    return f"<pre><code>{_highlight_python(code.strip())}</code></pre>"


def _json_block(value: object, collapsed_label: str | None = None) -> str:
    text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    block = f"<pre><code>{_e(text)}</code></pre>"
    if collapsed_label is None:
        return block
    return (
        f"<details><summary>{_e(collapsed_label)} "
        f"({len(text):,} chars)</summary>{block}</details>"
    )


def _text_block(text: str, collapse_over: int = 1500, label: str = "output") -> str:
    block = f"<pre>{_e(text)}</pre>"
    if len(text) <= collapse_over:
        return block
    return (
        f"<details><summary>{_e(label)} ({len(text):,} chars)</summary>"
        f"{block}</details>"
    )


_FENCE_RE = re.compile(r"^```([\w+-]*)\n(.*?)^```\s*$", re.MULTILINE | re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_BOLD_RE = re.compile(r"\*\*([^*\n]+)\*\*")


def _render_markdownish(text: str) -> str:
    """Minimal markdown: fenced code blocks, inline code, and bold."""

    def render_span(span: str) -> str:
        escaped = _e(span)
        escaped = _INLINE_CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
        escaped = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)
        return escaped

    parts: list[str] = []
    pos = 0
    for match in _FENCE_RE.finditer(text):
        parts.append(render_span(text[pos : match.start()]))
        lang, code = match.group(1), match.group(2)
        if lang in ("python", "py"):
            parts.append(_python_block(code))
        else:
            parts.append(f"<pre>{_e(code)}</pre>")
        pos = match.end()
    parts.append(render_span(text[pos:]))
    return f'<div class="text">{"".join(parts)}</div>'


def _agent_link(kind: str, session_path: str, *, link: bool = True) -> str:
    if not link:
        return f'<span class="badge {kind}">{_e(kind)}</span>'
    href = f"/agent?path={quote(session_path)}"
    return f'<a class="badge {kind}" href="{_e(href)}">{_e(kind)}</a>'


_STATUS_CSS = {"running": "open", "closed": "closed", "killed": "killed"}


def _status_badge(summary: BridgeLogSummary) -> str:
    css = _STATUS_CSS.get(summary.status, "closed")
    return f'<span class="badge {css}">{_e(summary.status)}</span>'


# --------------------------------------------------------------------------
# Index page
# --------------------------------------------------------------------------


def render_index() -> str:
    summaries = _scan_bridge_logs()
    if not summaries:
        body = (
            '<div class="empty">No bridge logs found in '
            f"<code>{_e(str(LOGS_DIR))}</code>.<br>"
            "Open a database through the MCP server first.</div>"
        )
        return _page("ida-codemode dashboard", body)

    rows = []
    for s in summaries:
        status = _status_badge(s)
        errors = f'<span class="badge error">{s.errors} err</span>' if s.errors else ""
        totals = _session_usage(s)
        if totals["cost_available"]:
            cost = _format_cost(totals["cost"])
            cost_sort = f"{totals['cost']:.6f}"
        elif totals["has_tokens"]:
            cost = '<span class="muted" title="pricing unavailable for this model">n/a</span>'
            cost_sort = ""
        else:
            cost = '<span class="muted">—</span>'
            cost_sort = ""
        started_sort = s.started.isoformat() if s.started else ""
        activity_sort = s.last_activity.isoformat() if s.last_activity else ""
        log_href = f"/log/{quote(s.path.name)}"
        rows.append(
            "<tr>"
            f'<td data-sort="{_e(s.target.lower())}">'
            f'<a href="{_e(log_href)}" title="{_e(s.target)}">'
            f"<strong>{_e(_display_target(s.target))}</strong></a>"
            f'<div class="mono muted">{_e(s.instance_id)}</div></td>'
            f'<td data-sort="{_e(started_sort)}">{_e(_format_ts(s.started))}</td>'
            f'<td data-sort="{_e(activity_sort)}">{_e(_format_ts(s.last_activity))}</td>'
            f'<td data-sort="{_e(s.status)}">{status} {errors}</td>'
            f'<td class="mono" data-sort="{_e(cost_sort)}">{cost}</td>'
            "</tr>"
        )

    body = f"""
<h2>Bridge sessions <span class="muted">({len(summaries)})</span></h2>
<table class="sessions">
<thead><tr>
  <th>Target</th><th>Started</th><th>Last activity</th><th>Status</th><th>Cost</th>
</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
<p class="muted" style="font-size:12px;margin-top:8px">Click a column header to sort.</p>
"""
    return _page("ida-codemode dashboard", body)


# --------------------------------------------------------------------------
# Bridge log page
# --------------------------------------------------------------------------


def _card(title: str, ts: datetime | None, body: str, extra_head: str = "") -> str:
    ts_html = f'<span class="ts">{_e(_format_ts(ts))}</span>' if ts else ""
    body_html = f'<div class="body">{body}</div>' if body else ""
    return (
        f'<div class="card"><div class="head">'
        f'<span class="title">{title}</span>{extra_head}{ts_html}</div>'
        f"{body_html}</div>"
    )


def _render_request_card(
    request: dict,
    request_ts: datetime | None,
    response: dict | None,
    response_ts: datetime | None,
) -> str:
    payload = request.get("payload") or {}
    command = payload.get("command", "?")

    head_extra = ""
    if request_ts and response_ts:
        seconds = (response_ts - request_ts).total_seconds()
        head_extra = f'<span class="muted">{_e(_format_duration(seconds))}</span>'

    parts: list[str] = []
    if command == "execute":
        code = payload.get("code", "")
        parts.append(_python_block(code))
    elif command == "open":
        options = {
            key: payload[key]
            for key in ("path", "auto_analysis", "new_database", "options")
            if key in payload
        }
        parts.append(_json_block(options))
    elif command not in ("close", "status"):
        parts.append(_json_block(payload, collapsed_label="payload"))

    status_badge = '<span class="badge muted">pending</span>'
    if response is not None:
        response_payload = response.get("payload") or {}
        if response_payload.get("ok"):
            status_badge = '<span class="badge open">ok</span>'
            result = response_payload.get("result")
            if result is not None:
                parts.append(_json_block(result, collapsed_label="result"))
        else:
            status_badge = '<span class="badge error">error</span>'
            error = response_payload.get("error", "unknown error")
            parts.append(
                f'<div class="mono" style="color:var(--error)">{_e(error)}</div>'
            )
            traceback_text = response_payload.get("traceback")
            if traceback_text:
                parts.append(_text_block(str(traceback_text), 200, "traceback"))

    title = f"{_e(command)} {status_badge}"
    return _card(title, request_ts, "".join(parts), head_extra)


def _transcript_window(
    summary: BridgeLogSummary, name: str, session_path: str
) -> tuple[datetime | None, datetime | None]:
    """Time bounds attributing transcript items to this bridge instance.

    A single agent transcript may span several bridge instances. Messages from
    the moment the previous instance ended up to the moment the next instance
    started belong to this one, so the wrap-up after a close and the prompt
    before an open are both captured.
    """
    siblings = _known_agent_sessions().get(session_path, [])
    ordered = sorted(siblings, key=lambda s: s.started or _MIN_DT)
    lower: datetime | None = None
    upper: datetime | None = None
    for index, sibling in enumerate(ordered):
        if sibling.path.name != name:
            continue
        if index > 0:
            lower = ordered[index - 1].last_activity
        if index < len(ordered) - 1:
            upper = ordered[index + 1].started
        break
    return lower, upper


def _in_window(
    ts: datetime | None, lower: datetime | None, upper: datetime | None
) -> bool:
    if ts is None:
        return False
    if lower is not None and ts <= lower:
        return False
    if upper is not None and ts >= upper:
        return False
    return True


def _interleave_transcript(
    summary: BridgeLogSummary,
    name: str,
    add_event: Callable[[datetime | None, str], None],
) -> int:
    """Add linked-transcript conversation items to the timeline, in time order.

    Only user/assistant/thinking items are added; tool calls are skipped because
    the code-mode calls already appear as bridge events. Returns the count added.
    """
    added = 0
    for session_path in summary.agent_sessions.values():
        lower, upper = _transcript_window(summary, name, session_path)
        items, _meta, _kind, _totals = _load_agent_items(session_path)
        for item in items:
            if item.category == "tool" or not _in_window(item.ts, lower, upper):
                continue
            add_event(item.ts, f'<div class="transcript-item">{item.html}</div>')
            added += 1
    return added


def _session_usage(summary: BridgeLogSummary) -> dict[str, Any]:
    """Token/cost totals for one bridge instance, scoped to its time window.

    Claude usage is summed per-message within the window. Codex has only
    whole-session cumulative counts (no per-message data, no cost), so those are
    used as-is when the instance has no windowable per-message usage.
    """
    totals = _blank_totals()
    for session_path in summary.agent_sessions.values():
        lower, upper = _transcript_window(summary, summary.path.name, session_path)
        items, _meta, kind, session_totals = _load_agent_items(session_path)
        windowed = [
            it.usage for it in items if it.usage and _in_window(it.ts, lower, upper)
        ]
        if windowed:
            for usage in windowed:
                _add_usage(totals, usage)
        elif kind == "codex" and session_totals["has_tokens"]:
            _add_usage(totals, session_totals)
    return totals


def _totals_summary_html(totals: dict[str, Any]) -> str:
    parts = [
        f"in {_format_tokens(totals['input'])}",
        f"out {_format_tokens(totals['output'])}",
        f"cached {_format_tokens(totals['cache_read'])}",
    ]
    if totals["cost_available"]:
        parts.append(_format_cost(totals["cost"]))
    else:
        parts.append("cost n/a")
    return " · ".join(_e(p) for p in parts)


def render_bridge_log(name: str, *, export: bool = False) -> str | None:
    """Render a bridge session page.

    With export=True, produce a fully self-contained page: navigation links are
    dropped and server-only controls removed, so the HTML can be saved and
    shared or hosted as a static artifact.
    """
    path = LOGS_DIR / name
    if "/" in name or "\\" in name or not name.endswith(".jsonl"):
        return None
    if not path.is_file():
        return None

    summary = _summarize_bridge_log(path)
    records = _read_jsonl(path)

    responses_by_id: dict[str, tuple[dict, datetime | None]] = {}
    for record in records:
        if record.get("event") == "response":
            request_id = record.get("request_id")
            if isinstance(request_id, str):
                responses_by_id[request_id] = (record, _parse_ts(record.get("ts")))

    # Merged timeline of bridge events and (optionally) interleaved transcript
    # items. Each entry is (sort_ts, insertion_seq, html); a stable sort by
    # (ts, seq) keeps same-timestamp events in discovery order.
    events: list[tuple[datetime, int, str]] = []
    seq = 0

    def add_event(ts: datetime | None, html: str) -> None:
        nonlocal seq
        events.append((ts or _MIN_DT, seq, html))
        seq += 1

    pending_output: list[str] = []
    pending_ts: datetime | None = None

    def flush_output() -> None:
        nonlocal pending_ts
        if not pending_output:
            return
        text = "\n".join(pending_output)
        add_event(
            pending_ts,
            f'<div class="card"><div class="body bridgeout">'
            f"{_text_block(text, 800, 'bridge output')}</div></div>",
        )
        pending_output.clear()
        pending_ts = None

    for record in records:
        event = record.get("event")
        ts = _parse_ts(record.get("ts"))
        if event == "bridge_output":
            if pending_ts is None:
                pending_ts = ts
            pending_output.append(str(record.get("line", "")))
            continue
        flush_output()

        if event == "request":
            request_id = record.get("request_id")
            response, response_ts = responses_by_id.get(request_id, (None, None))
            add_event(ts, _render_request_card(record, ts, response, response_ts))
        elif event == "response":
            continue  # rendered together with its request
        elif event in ("instance_started", "process_started"):
            details = []
            if record.get("pid"):
                details.append(f"pid {record['pid']}")
            label = " · ".join(details)
            add_event(
                ts,
                _card(
                    f"{_e(event)}"
                    + (f' <span class="muted">{_e(label)}</span>' if label else ""),
                    ts,
                    "",
                ),
            )
        elif event in ("timeout", "request_failed"):
            add_event(
                ts,
                _card(
                    f'<span style="color:var(--error)">{_e(event)}</span>',
                    ts,
                    _json_block(
                        {
                            key: value
                            for key, value in record.items()
                            if key not in ("ts", "event")
                        }
                    ),
                ),
            )
        elif isinstance(event, str):
            extra = {
                key: value
                for key, value in record.items()
                if key not in ("ts", "event", "instance_id")
            }
            body = _json_block(extra) if extra else ""
            add_event(ts, _card(_e(event), ts, body))
    flush_output()

    transcript_count = _interleave_transcript(summary, name, add_event)

    events.sort(key=lambda entry: (entry[0], entry[1]))
    timeline_html = "".join(entry[2] for entry in events)

    agents = " ".join(
        _agent_link(kind, session_path, link=not export)
        for kind, session_path in sorted(summary.agent_sessions.items())
    )
    totals = _session_usage(summary)
    meta_rows = [
        ("Database", f'<span class="mono">{_e(summary.database_path or "?")}</span>'),
        ("Instance", f'<span class="mono">{_e(summary.instance_id)}</span>'),
        (
            "Duration",
            _e(
                _format_duration(
                    (summary.last_activity - summary.started).total_seconds()
                )
                if summary.started and summary.last_activity
                else "?"
            ),
        ),
        ("Agent session", agents or '<span class="muted">none recorded</span>'),
    ]
    if totals["has_tokens"]:
        meta_rows.append(("Tokens", _totals_summary_html(totals)))
    if not export:
        # The absolute log path leaks the host filesystem; omit it from exports.
        meta_rows.insert(0, ("Log file", f'<span class="mono">{_e(str(path))}</span>'))
    kv = "".join(
        f'<span class="k">{key}</span><span class="v">{value}</span>'
        for key, value in meta_rows
    )

    controls = [
        '<button onclick="setAllDetails(true)">expand all</button>',
        '<button onclick="setAllDetails(false)">collapse all</button>',
    ]
    if transcript_count:
        controls.append(
            "<button onclick=\"document.body.classList.toggle('hide-transcript')\">"
            f"toggle transcript ({transcript_count})</button>"
        )
    if not export:
        controls.append(
            f'<a href="/export/log/{quote(name)}" style="align-self:center">'
            "export HTML</a>"
        )

    crumbs = (
        ""
        if export
        else f'<div class="crumbs"><a href="/">sessions</a> / {_e(name)}</div>'
    )

    body = f"""
{crumbs}
<h2><span title="{_e(summary.target)}">{_e(_display_target(summary.target))}</span>
<span class="muted mono">{_e(summary.instance_id)}</span>
{_status_badge(summary)}</h2>
<div class="kv">{kv}</div>
<div class="toolbar">
  {"".join(controls)}
</div>
{timeline_html}
"""
    return _page(
        f"{summary.target} — ida-codemode",
        body,
        subtitle=name,
        standalone=export,
    )


# --------------------------------------------------------------------------
# Agent transcript pages (Claude Code + Codex)
# --------------------------------------------------------------------------


def _detect_agent_kind(records: list[dict]) -> str:
    for record in records:
        record_type = record.get("type")
        if record_type in (
            "session_meta",
            "response_item",
            "turn_context",
            "event_msg",
        ):
            return "codex"
        if record_type in ("user", "assistant"):
            return "claude"
    return "unknown"


def _message_bubble(
    who: str, css: str, body: str, ts: datetime | None, tag: str = ""
) -> str:
    ts_html = f'<span class="ts">{_e(_format_ts(ts))}</span>' if ts else ""
    tag_html = f'<span class="badge">{_e(tag)}</span>' if tag else ""
    return (
        f'<div class="msg {css}"><div class="who">{_e(who)}{tag_html}{ts_html}</div>'
        f"{body}</div>"
    )


def _tool_display_name(tool_name: str) -> str:
    """Shorten MCP tool names like mcp__plugin_x_ida__execute to ida · execute."""
    if not tool_name.startswith("mcp__"):
        return tool_name
    parts = tool_name.split("__")
    if len(parts) < 3:
        return tool_name
    server = parts[1].rpartition("_")[2] or parts[1]
    return f"{server} · {parts[-1]}"


def _tool_input_html(tool_name: str, tool_input: object) -> str:
    """Render a tool invocation's input, special-casing code-mode calls."""
    if isinstance(tool_input, dict):
        tool_input = {k: v for k, v in tool_input.items() if k != "_meta"}
        code = tool_input.get("code")
        is_codemode = tool_name.rsplit("__", 1)[-1] in (
            "execute",
            "search",
        ) or tool_name in ("execute", "search")
        if is_codemode and isinstance(code, str):
            rest = {k: v for k, v in tool_input.items() if k != "code"}
            parts = [_python_block(code)]
            if rest:
                parts.append(_json_block(rest, collapsed_label="other arguments"))
            return "".join(parts)
        command = tool_input.get("command")
        if tool_name == "Bash" and isinstance(command, str):
            return f"<pre>{_e(command)}</pre>"
    return _json_block(tool_input, collapsed_label="input")


def _tool_result_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(str(item.get("text", "")))
        return "\n".join(texts)
    if content is None:
        return ""
    return json.dumps(content, indent=2, ensure_ascii=False, default=str)


_SYSTEM_REMINDER_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL)


@dataclass
class TranscriptItem:
    ts: datetime | None
    category: str  # "user" | "assistant" | "thinking" | "tool"
    html: str
    usage: dict[str, Any] | None = None  # attached once per source record


def _usage_line(usage: dict[str, Any]) -> str:
    parts = [
        f"in {_format_tokens(usage.get('input', 0))}",
        f"out {_format_tokens(usage.get('output', 0))}",
    ]
    cached = usage.get("cache_read", 0)
    if cached:
        parts.append(f"cached {_format_tokens(cached)}")
    cost = usage.get("cost")
    if cost is not None:
        parts.append(_format_cost(cost))
    return f'<div class="usage">{" · ".join(_e(p) for p in parts)}</div>'


def _claude_items(records: list[dict]) -> tuple[list[TranscriptItem], dict[str, str]]:
    tool_results: dict[str, object] = {}
    for record in records:
        if record.get("type") != "user":
            continue
        content = record.get("message", {}).get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_result":
                tool_use_id = item.get("tool_use_id")
                if isinstance(tool_use_id, str):
                    tool_results[tool_use_id] = item.get("content")

    meta: dict[str, str] = {}
    items: list[TranscriptItem] = []
    for record in records:
        record_type = record.get("type")
        ts = _parse_ts(record.get("timestamp"))
        sidechain = "sidechain" if record.get("isSidechain") else ""

        if not meta and record_type in ("user", "assistant"):
            for key in ("sessionId", "cwd", "version", "gitBranch"):
                value = record.get(key)
                if value:
                    meta[key] = str(value)

        if record_type == "user":
            content = record.get("message", {}).get("content")
            texts: list[str] = []
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                texts.extend(
                    str(item.get("text", ""))
                    for item in content
                    if isinstance(item, dict) and item.get("type") == "text"
                )
            for raw in texts:
                text = _SYSTEM_REMINDER_RE.sub("", raw).strip()
                if text:
                    items.append(
                        TranscriptItem(
                            ts,
                            "user",
                            _message_bubble(
                                "user", "user", _render_markdownish(text), ts, sidechain
                            ),
                        )
                    )
        elif record_type == "assistant":
            message = record.get("message", {})
            model = str(message.get("model", ""))
            record_items: list[TranscriptItem] = []
            for item in message.get("content") or []:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                if item_type == "text":
                    text = str(item.get("text", "")).strip()
                    if text:
                        record_items.append(
                            TranscriptItem(
                                ts,
                                "assistant",
                                _message_bubble(
                                    model or "assistant",
                                    "assistant",
                                    _render_markdownish(text),
                                    ts,
                                    sidechain,
                                ),
                            )
                        )
                elif item_type == "thinking":
                    thinking = str(item.get("thinking", "")).strip()
                    if thinking:
                        record_items.append(
                            TranscriptItem(
                                ts,
                                "thinking",
                                f"<details><summary>thinking</summary>"
                                f'<div class="msg"><div class="text">{_e(thinking)}'
                                f"</div></div></details>",
                            )
                        )
                elif item_type == "tool_use":
                    tool_name = str(item.get("name", "tool"))
                    body_parts = [_tool_input_html(tool_name, item.get("input"))]
                    tool_use_id = item.get("id")
                    if tool_use_id in tool_results:
                        result_text = _tool_result_text(tool_results[tool_use_id])
                        if result_text.strip():
                            body_parts.append(_text_block(result_text, 700, "result"))
                    record_items.append(
                        TranscriptItem(
                            ts,
                            "tool",
                            _message_bubble(
                                _tool_display_name(tool_name),
                                "toolcall",
                                "".join(body_parts),
                                ts,
                                sidechain,
                            ),
                        )
                    )
            usage = _claude_usage(message.get("usage"), model)
            if usage and record_items:
                # Attribute the record's usage to its first rendered item so it
                # is counted once, and show it inline.
                record_items[0].usage = usage
                record_items[0].html += _usage_line(usage)
            items.extend(record_items)
    return items, meta


def _claude_usage(raw: object, model: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    usage = {
        "input": int(raw.get("input_tokens", 0) or 0),
        "output": int(raw.get("output_tokens", 0) or 0),
        "cache_read": int(raw.get("cache_read_input_tokens", 0) or 0),
        "cache_write": int(raw.get("cache_creation_input_tokens", 0) or 0),
        "model": model,
    }
    if not any(usage[k] for k in ("input", "output", "cache_read", "cache_write")):
        return None
    usage["cost"] = _cost_for(model, usage)
    return usage


def _codex_items(records: list[dict]) -> tuple[list[TranscriptItem], dict[str, str]]:
    call_outputs: dict[str, str] = {}
    for record in records:
        if record.get("type") != "response_item":
            continue
        payload = record.get("payload") or {}
        if payload.get("type") == "function_call_output":
            call_id = payload.get("call_id")
            if isinstance(call_id, str):
                call_outputs[call_id] = str(payload.get("output", ""))

    meta: dict[str, str] = {}
    items: list[TranscriptItem] = []
    seen_call_ids: set[str] = set()

    for record in records:
        record_type = record.get("type")
        ts = _parse_ts(record.get("timestamp"))
        payload = record.get("payload") or {}

        if record_type == "session_meta":
            for key in ("session_id", "cwd", "cli_version", "model_provider"):
                value = payload.get(key)
                if value:
                    meta[key] = str(value)
        elif record_type == "event_msg":
            event_type = payload.get("type")
            if event_type == "user_message":
                message = str(payload.get("message", "")).strip()
                if message:
                    items.append(
                        TranscriptItem(
                            ts,
                            "user",
                            _message_bubble(
                                "user", "user", _render_markdownish(message), ts
                            ),
                        )
                    )
            elif event_type == "agent_message":
                message = str(payload.get("message", "")).strip()
                if message:
                    items.append(
                        TranscriptItem(
                            ts,
                            "assistant",
                            _message_bubble(
                                "codex", "assistant", _render_markdownish(message), ts
                            ),
                        )
                    )
            elif event_type == "agent_reasoning":
                text = str(payload.get("text", "")).strip()
                if text:
                    items.append(
                        TranscriptItem(
                            ts,
                            "thinking",
                            f"<details><summary>reasoning</summary>"
                            f'<div class="msg"><div class="text">{_e(text)}</div>'
                            f"</div></details>",
                        )
                    )
            elif event_type == "mcp_tool_call_end":
                call_id = payload.get("call_id")
                if isinstance(call_id, str) and call_id in seen_call_ids:
                    continue
                invocation = payload.get("invocation") or {}
                tool_name = (
                    f"{invocation.get('server', '?')}.{invocation.get('tool', '?')}"
                )
                body_parts = [
                    _tool_input_html(
                        str(invocation.get("tool", "")),
                        invocation.get("arguments"),
                    )
                ]
                result = payload.get("result")
                if isinstance(result, dict):
                    ok_content = result.get("Ok")
                    if isinstance(ok_content, dict):
                        result_text = _tool_result_text(ok_content.get("content"))
                        if result_text.strip():
                            body_parts.append(_text_block(result_text, 700, "result"))
                    elif "Err" in result:
                        body_parts.append(_text_block(str(result["Err"]), 700, "error"))
                if isinstance(call_id, str):
                    seen_call_ids.add(call_id)
                items.append(
                    TranscriptItem(
                        ts,
                        "tool",
                        _message_bubble(tool_name, "toolcall", "".join(body_parts), ts),
                    )
                )
        elif record_type == "response_item":
            item_type = payload.get("type")
            if item_type == "function_call":
                call_id = payload.get("call_id")
                if isinstance(call_id, str):
                    if call_id in seen_call_ids:
                        continue
                    seen_call_ids.add(call_id)
                tool_name = str(payload.get("name", "tool"))
                try:
                    arguments = json.loads(payload.get("arguments", "{}"))
                except json.JSONDecodeError, TypeError:
                    arguments = payload.get("arguments")
                body_parts = [_tool_input_html(tool_name, arguments)]
                if isinstance(call_id, str) and call_id in call_outputs:
                    output = call_outputs[call_id]
                    if output.strip():
                        body_parts.append(_text_block(output, 700, "output"))
                items.append(
                    TranscriptItem(
                        ts,
                        "tool",
                        _message_bubble(tool_name, "toolcall", "".join(body_parts), ts),
                    )
                )
    return items, meta


def _codex_session_totals(records: list[dict]) -> dict[str, Any]:
    """Whole-session token totals from the last Codex token_count event.

    Codex records cumulative usage per turn rather than per message, so these
    totals cannot be scoped to a bridge instance's time window. OpenAI pricing
    is not tracked, so cost is left unavailable.
    """
    totals = _blank_totals()
    totals["cost"] = None  # OpenAI pricing not tracked; keep cost unavailable
    latest: dict[str, Any] | None = None
    for record in records:
        if record.get("type") != "event_msg":
            continue
        payload = record.get("payload") or {}
        if payload.get("type") == "token_count":
            info = payload.get("info") or {}
            usage = info.get("total_token_usage")
            if isinstance(usage, dict):
                latest = usage
    if latest:
        totals["input"] = int(latest.get("input_tokens", 0) or 0)
        totals["output"] = int(latest.get("output_tokens", 0) or 0)
        totals["cache_read"] = int(latest.get("cached_input_tokens", 0) or 0)
        totals["has_tokens"] = any(totals[k] for k in ("input", "output", "cache_read"))
    return totals


_AGENT_ITEMS_CACHE: dict[str, tuple[Any, ...]] = {}


def _load_agent_items(
    session_path: str,
) -> tuple[list[TranscriptItem], dict[str, str], str, dict[str, Any]]:
    """Return (items, meta, kind, totals) for a transcript file, or empties.

    Results are cached per (path, mtime, size) so the index — which loads the
    same shared transcript for many sessions — parses each file only once.
    """
    path = Path(session_path)
    if not path.is_file():
        return [], {}, "unknown", _blank_totals()

    try:
        stat = path.stat()
        cache_key = f"{session_path}:{stat.st_mtime_ns}:{stat.st_size}"
    except OSError:
        cache_key = None

    if cache_key is not None and cache_key in _AGENT_ITEMS_CACHE:
        return _AGENT_ITEMS_CACHE[cache_key]

    records = _read_jsonl(path)
    kind = _detect_agent_kind(records)
    if kind == "codex":
        items, meta = _codex_items(records)
        totals = _codex_session_totals(records)
    else:
        items, meta = _claude_items(records)
        totals = _blank_totals()
        for item in items:
            if item.usage:
                _add_usage(totals, item.usage)

    result = (items, meta, kind, totals)
    if cache_key is not None:
        _AGENT_ITEMS_CACHE[cache_key] = result
    return result


def render_agent_session(session_path: str) -> str | None:
    known = _known_agent_sessions()
    if session_path not in known:
        return None
    path = Path(session_path)
    if not path.is_file():
        body = (
            '<div class="empty">Transcript no longer exists:<br>'
            f"<code>{_e(session_path)}</code></div>"
        )
        return _page("missing transcript — ida-codemode", body)

    items, meta, kind, totals = _load_agent_items(session_path)
    transcript_html = "".join(item.html for item in items)

    related = "".join(
        f'<a href="/log/{quote(s.path.name)}">{_e(_display_target(s.target))} '
        f'<span class="mono muted">{_e(s.instance_id)}</span></a><br>'
        for s in known[session_path]
    )
    meta_rows = [("Transcript", f'<span class="mono">{_e(session_path)}</span>')]
    meta_rows += [(key, _e(value)) for key, value in meta.items()]
    if totals["has_tokens"]:
        meta_rows.append(("Tokens", _totals_summary_html(totals)))
    meta_rows.append(("Bridge logs", related or "—"))
    kv = "".join(
        f'<span class="k">{key}</span><span class="v">{value}</span>'
        for key, value in meta_rows
    )

    if not transcript_html:
        transcript_html = '<div class="empty">No renderable messages found.</div>'

    body = f"""
<div class="crumbs"><a href="/">sessions</a> / {_e(kind)} transcript</div>
<h2><span class="badge {_e(kind)}">{_e(kind)}</span> {_e(path.name)}</h2>
<div class="kv">{kv}</div>
<div class="toolbar">
  <button onclick="setAllDetails(true)">expand all</button>
  <button onclick="setAllDetails(false)">collapse all</button>
</div>
{transcript_html}
"""
    return _page(f"{path.name} — ida-codemode", body, subtitle=f"{kind} session")


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ida-codemode-dashboard"

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep the console quiet

    def _send_html(self, content: str, status: int = 200) -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_download(self, content: str, filename: str) -> None:
        data = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _not_found(self) -> None:
        self._send_html(
            _page("not found — ida-codemode", '<div class="empty">Not found.</div>'),
            status=404,
        )

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        url = urlparse(self.path)
        route = url.path

        try:
            if route == "/":
                self._send_html(render_index())
            elif route.startswith("/log/"):
                page = render_bridge_log(route[len("/log/") :])
                self._send_html(page) if page else self._not_found()
            elif route.startswith("/export/log/"):
                name = route[len("/export/log/") :]
                page = render_bridge_log(name, export=True)
                if page:
                    self._send_download(page, f"{Path(name).stem}.html")
                else:
                    self._not_found()
            elif route == "/agent":
                params = parse_qs(url.query)
                session_path = (params.get("path") or [""])[0]
                page = render_agent_session(session_path)
                self._send_html(page) if page else self._not_found()
            else:
                self._not_found()
        except BrokenPipeError:
            pass
        except Exception as exc:  # pragma: no cover - defensive
            self._send_html(
                _page(
                    "error — ida-codemode",
                    f'<div class="empty">Internal error: {_e(exc)}</div>',
                ),
                status=500,
            )


def serve(host: str, port: int, open_browser: bool = False) -> None:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    url = f"http://{host}:{port}/"
    print(f"ida-codemode dashboard: {url}")
    print(f"logs directory: {LOGS_DIR}")
    if open_browser:
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()


def cli() -> int:
    global LOGS_DIR
    parser = argparse.ArgumentParser(
        prog="ida-codemode-dashboard",
        description="Web dashboard for ida-codemode bridge sessions",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port")
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=DEFAULT_LOGS_DIR,
        help="Directory containing bridge JSONL logs",
    )
    parser.add_argument(
        "--open", action="store_true", help="Open the dashboard in a browser"
    )
    args = parser.parse_args()

    LOGS_DIR = args.logs_dir.expanduser().resolve()
    serve(args.host, args.port, open_browser=args.open)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
