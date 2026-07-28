# Contributing

## Development checkout

```bash
uv sync
uv run ida-codemode-mcp
```

The MCP server uses stdio by default. A local HTTP transport is also available:

```bash
uv run ida-codemode-mcp --transport http://127.0.0.1:5001
```

To manually play with the MCP, use the inspector:

```bash
npx -y @modelcontextprotocol/inspector
```

## Develop the Claude plugin locally

The plugin registers the MCP server as `ida`, so Claude Code tool names are shorter, e.g. `mcp__plugin_ida-codemode-mcp_ida__open_database`. The first invocation of any matching `mcp__(.*[_:])?ida__.*` tool will trigger `uv` to install the server (cached after that) and fire the `PreToolUse` hook that injects the Claude session id for log correlation.

Clone the repo and launch Claude Code pointing at the checkout:

```bash
git clone https://github.com/HexRaysSA/ida-codemode-mcp
claude --plugin-dir ./ida-codemode-mcp
```

After editing `plugin.json`, hooks, or the Python source, run `/reload-plugins` inside Claude Code to pick up the changes without restarting. The manifest runs the MCP via `uv run --project ${CLAUDE_PLUGIN_ROOT} ...`, so local Python edits are reflected immediately - no rebuild step.

## Opening databases

Given an executable path, Code Mode normally uses `<executable>.i64`. Given an
existing `.i64`, it uses that database directly.

```json
{
  "path": "/path/to/sample.exe",
  "set_current": true
}
```

Resolution proceeds as follows:

1. Use a registered GUI whose executable path matches.
2. Otherwise use the unique owner of the expected IDB.
3. Otherwise serialize creation and start a managed idalib worker.

All conceptual database access is read/write. Use `save_database` when an
explicit save is required.

## Executing Code Mode Python

`execute_python` accepts ordinary Python with the current ida-domain `Database`
available globally as `db` and the imported package as `ida_domain`. A single
or trailing expression becomes the result:

```python
functions = list(db.functions)
{"count": len(functions), "first": functions[0].name}
```

Function-style code remains available and receives `db` by name:

```python
def run(db):
    return {
        "minimum_ea": db.minimum_ea,
        "maximum_ea": db.maximum_ea,
    }
```

Use `reference` before execution instead of guessing ida-domain API shapes.

## Shared clients and lifecycle

Each open MCP handle maintains an authenticated SSE lease. Multiple agents and
MCP servers may open the same database and resolve to the same GUI or idalib
instance.

Closing a handle releases only that lease. Managed idalib workers wait through
a short grace period after the final lease, stop accepting work, save and close
the IDB on the idalib main thread, and exit. Crashed clients are detected by
SSE heartbeats. Hard-killed workers are detected by lifetime file locks and
reaped on the next scan.

There are no client process refcounts and no remote database-close endpoint.

## Local state

```text
~/.ida-codemode/
  instances/<record-id>.json
  instances/<record-id>.lock
  spawn/<idb-key>.lock
  logs/<record-id>.log
  sessions/<session-id>.jsonl
```

- `instances/` is the live discovery registry.
- `spawn/` serializes idalib worker creation.
- `logs/` contains IDA/worker operational output.
- `sessions/` contains semantic MCP and agent traces.

Registry tokens and records are private to the local user. HTTP endpoints bind
to `127.0.0.1`, require bearer authentication, validate `Host`, reject browser
origins, and enforce bounded request decoding.

## Semantic session traces

Every MCP process writes one schema-1 JSONL trace:

```text
~/.ida-codemode/sessions/<mcp-server-id>.jsonl
```

The trace contains:

- every MCP tool call, result, error, and duration;
- complete `reference` queries and results;
- executed Python and returned values;
- database open, reuse, disconnection, save, and release events;
- GUI or idalib record identity and worker log path;
- Claude, Codex, Pi, and `IDA_CODEMODE_ID` session metadata.

Tool calls and results are paired by `call_id`. Shared worker operational logs
are linked through `record_id`.

Claude and Codex use the bundled `PreToolUse` hook to inject transcript paths as
hidden `_meta` values. The MCP server removes `_meta` from public arguments and
records it under the semantic session context. Pi session metadata is handled
the same way.

## Dashboard

Run the stdlib-only local dashboard with:

```bash
uv run ida-codemode-dashboard --open
uv run ida-codemode-dashboard --port 9000 \
  --sessions-dir ~/.ida-codemode/sessions
```

The dashboard provides:

- a newest-first session index (startup/shutdown and internal lifecycle-only
  traces without MCP tool or linked-agent activity are hidden);
- running, closed, or killed status;
- all GUI and idalib targets used in one session;
- paired tool-call timelines with highlighted Python code;
- logged reference output and structured errors;
- interleaved Claude, Codex, or Pi transcript activity;
- token and estimated cost summaries where available;
- self-contained HTML export.

Only transcript paths referenced by semantic sessions may be served.

## Migrating pre-0.2 logs

The one-shot migration utility intentionally remains a project-root Python
script rather than an installed command:

```bash
uv run python migrate_logs.py --dry-run
uv run python migrate_logs.py --dry-run --verbose  # print every discarded record
uv run python migrate_logs.py
```

It reads legacy logs from `~/.ida-codemode/logs`, reconstructs sessions using
per-request agent transcript paths or GUIDs, and writes the 0.2 schema under
`~/.ida-codemode/sessions`.

Migration never modifies source logs. Known `bridge_output` records are
operational noise, so the default output reports a count per source file while
leaving the originals intact. `--verbose` prints every discarded record.
Unknown, malformed, and unattributable records are always printed with their
source file and line number rather than entering the permanent dashboard
schema.

## Live endpoint check

The idalib worker is an internal implementation detail started by the resolver.
For diagnostics, the live HTTP smoke test accepts an endpoint and discovers its
token from the private registry:

```bash
uv run python tests/test_live.py http://127.0.0.1:PORT --save
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for lifecycle invariants, state
transitions, failure handling, and trace design.
