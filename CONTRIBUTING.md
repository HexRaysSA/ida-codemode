# Contributing

## MCP tools

- `reference(query)` - search the installed ida-domain API reference.
- `open_database(path, set_current=True)` - attach to a GUI database or shared idalib worker.
- `execute_python(code, instance_id=None)` - wait for initial autoanalysis on the first execution for an attached database, then run Python with the IDA runtime preloaded and return its result, stdout, and stderr.
- `list_databases()` - discover all registered GUI and idalib instances and identify this MCP server's active handles.
- `save_database(instance_id=None)` - explicitly save a database.
- `close_database(instance_id=None)` - release this MCP server's handle and lease.

The intended flow is `open_database` → `reference` → `execute_python`.
Inside `execute_python`, `db` is the current `ida-domain` `Database`; both
`db` and `ida_domain` are available globally. Ordinary Python statements are
accepted, a single or trailing expression becomes the result, and
`def run(db): ...` remains
available for function-style code.

`close_database` is not a global shutdown operation. Other agents continue to
use the same instance. A managed idalib worker cancels orphaned execution, saves,
and exits after its final lease disappears; GUI databases are never closed by
MCP lifecycle management. Low-level `DatabaseManager` users can set
`keepalive=30` (or another bounded duration) to retain an idle worker for reuse.

## Development checkout

```bash
uv sync
uv run ida-codemode-mcp
```

The MCP server uses stdio by default. A local HTTP transport is also available:

```bash
uv run ida-codemode-mcp --transport http://127.0.0.1:5001 --agent inspector
```

To manually play with the MCP, use the inspector:

```bash
npx -y @modelcontextprotocol/inspector
```

## Develop the Claude plugin locally

The plugin registers the MCP server as `ida`, so Claude Code tool names are shorter, e.g. `mcp__plugin_ida__open_database`. The first invocation of any matching `mcp__(.*[_:])?ida__.*` tool will trigger `uv` to install the server (cached after that) and fire the `PreToolUse` hook that injects the Claude session id for log correlation.

Clone the repo and launch Claude Code pointing at the checkout:

```bash
git clone https://github.com/HexRaysSA/ida-codemode
claude --plugin-dir ./ida-codemode
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

Use `reference` before execution instead of guessing ida-domain API shapes. The
MCP execution first issues a separate initial-autoanalysis wait for each
attached database. The upstream `/execute_python` route and client method do not
wait implicitly, so the script retains its full execution timeout.

## Shared clients and lifecycle

Each open MCP handle maintains an authenticated SSE lease. Multiple agents and
MCP servers may open the same database and resolve to the same GUI or idalib
instance.

Closing a handle releases only that lease. After the final lease, managed
idalib workers cancel orphaned work, save and close the IDB on the idalib main
thread, and exit immediately unless that lease requested a bounded keepalive.
The fixed grace period applies only before the first lease. Crashed clients are
detected by SSE heartbeats. Hard-killed workers are detected by lifetime file
locks and reaped on the next scan.

There are no client process refcounts and no remote database-close endpoint;
the lease-scoped release route cannot close another client's lease.

## Local state

```text
<IDAUSR>/codemode/
  instances/<record-id>.json
  instances/<record-id>.lock
  spawn/<idb-key>.lock
  logs/<record-id>.log
  sessions/<session-id>.jsonl
```

`<IDAUSR>` is the first directory in the `IDAUSR` environment variable. When
unset, IDA's platform default is used (`~/.idapro` on Unix-like systems or
`%APPDATA%/Hex-Rays/IDA Pro` on Windows).

- `instances/` is the live discovery registry.
- `spawn/` serializes idalib worker creation.
- `logs/` contains IDA/worker operational output.
- `sessions/` contains semantic MCP and agent traces, including the configured
  agent name and MCP initialize client information/metadata.

Registry tokens and records are private to the local user. HTTP endpoints bind
to `127.0.0.1`, require bearer authentication, validate `Host`, reject browser
origins, and enforce bounded request decoding.

## Semantic session traces

Every MCP process writes one schema-1 JSONL trace:

```text
<IDAUSR>/codemode/sessions/<mcp-server-id>.jsonl
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
  --sessions-dir "$IDAUSR/codemode/sessions"
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

It reads legacy logs from `<IDAUSR>/codemode/logs`, reconstructs sessions using
per-request agent transcript paths or GUIDs, and writes the 0.2 schema under
`<IDAUSR>/codemode/sessions`.

Migration never modifies source logs. Known `bridge_output` records are
operational noise, so the default output reports a count per source file while
leaving the originals intact. `--verbose` prints every discarded record.
Unknown, malformed, and unattributable records are always printed with their
source file and line number rather than entering the permanent dashboard
schema.

## Running a worker directly

The resolver normally starts idalib workers on demand, but the worker is also
exposed as a console script for reuse and diagnostics. To verify that idalib
initializes without opening a database:

```bash
uv run ida-codemode-worker --probe
```

To open one executable or IDB in idalib and serve the same authenticated
loopback HTTP API:

```bash
uv run ida-codemode-worker /path/to/target.elf
```

It registers in the private registry just like a resolver-spawned worker, so
`open_database()` and the live endpoint check below discover it automatically.
Omit `--managed` (as above) to keep the worker running until interrupted; the
resolver passes `--managed` so workers exit after their final lease is released.

## Live endpoint check

For diagnostics, the live HTTP smoke test accepts an endpoint and discovers its
token from the private registry:

```bash
uv run python tests/test_live.py http://127.0.0.1:PORT --save
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for lifecycle invariants, state
transitions, failure handling, and trace design.
