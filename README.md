# ida-codemode-mcp

A Code Mode MCP server for the `ida-domain` API.

It uses a centralized bridge architecture:

- `search(code)` — search a generated API spec built from the active `ida-domain` checkout/package
- `open_database(...)` — spawn a long-lived idalib bridge instance for a local target
- `execute(code)` — run Python against an already-open `db` with `ida-domain` preloaded
- `list_databases()` — inspect active bridge instances and their JSONL log paths
- `close_database(...)` — close a bridge instance

## Install as a Claude Code plugin

Prerequisites: [uv](https://docs.astral.sh/uv/) on `PATH`, and an IDA Pro installation that `ida-domain` / `idalib` can find.

To install:

```bash
claude plugin marketplace add HexRaysSA/ida-claude-plugins
claude plugin install ida-codemode-mcp@ida-claude-plugins
```

The plugin registers the MCP server as `ida`, so Claude Code tool names are shorter, e.g. `mcp__plugin_ida-codemode-mcp_ida__open_database`. The first invocation of any matching `mcp__(.*[_:])?ida__.*` tool will trigger `uvx` to install the server (cached after that) and fire the `PreToolUse` hook that records the Claude session id for log correlation.

## Develop the plugin locally

Clone the repo and launch Claude Code pointing at the checkout:

```bash
git clone https://github.com/HexRaysSA/ida-codemode-mcp
claude --plugin-dir ./ida-codemode-mcp
```

After editing `plugin.json`, hooks, or the Python source, run `/reload-plugins` inside Claude Code to pick up the changes without restarting. The manifest runs the MCP via `uv run --project ${CLAUDE_PLUGIN_ROOT} ...`, so local Python edits are reflected immediately — no rebuild step.

## Run the MCP server standalone

```bash
uv sync
uv run ida-codemode-mcp mcp                              # stdio (default)
uv run ida-codemode-mcp mcp --transport http://127.0.0.1:5001
```

`ida-domain` is pulled directly from git (see `[tool.uv.sources]` in `pyproject.toml`). The wheel ships `docs/` and `examples/` inside the package as `ida_domain/_docs/` and `ida_domain/_examples/`, which the `search()` tool inspects via `importlib.util.find_spec`.

## Architecture

`open_database()` starts a dedicated subprocess that opens the requested target through `ida-domain`/idalib and keeps the database alive.

`execute()` sends Python code to that live bridge instance, where the runtime already has:

- `db`
- `ida_domain`
- `Database`
- `IdaCommandOptions`
- `database_path`
- `database_options`
- `json`
- `to_jsonable()`

That means the agent can open once and then focus subsequent `execute()` calls purely on analysis tasks.

## JSONL logs

Each opened database instance gets a live JSONL log file under:

```text
~/.ida-codemode/logs/
```

`open_database()`, `execute()`, `list_databases()`, and `close_database()` return the `log_path` for the relevant instance. You can tail it while the agent runs:

```bash
tail -f ~/.ida-codemode/logs/<database-name>-<instance-id>.jsonl
```

The log captures bridge lifecycle events, raw bridge output, and every request/response payload sent between the MCP server and the live IDA bridge instance.

When run via the Claude Code plugin, each record is also stamped with `claude_session_id` and `claude_transcript_path` so the JSONL logs can be cross-referenced with the corresponding Claude Code session transcript under `~/.claude/projects/`. The mapping is established by the `PreToolUse` hook (`ida-codemode-mcp report-session`), which writes `~/.ida-codemode/sessions/<claude-pid>.json`; the MCP server reads that file on first JSONL write.

## Shutdown behavior

The MCP supervisor installs `SIGINT`/`SIGTERM` handlers and an `atexit` shutdown hook. On Claude Code exit, stdio EOF, or process termination, it asks each live bridge worker to close its database before terminating the worker process. Bridge workers also install their own `SIGINT`/`SIGTERM` handlers so a directly signaled worker closes the active database before exiting.

## Typical flow

1. Search the API surface if needed.
2. Open a local target.
3. Run one or more `execute()` calls against the live `db`.
4. Close the instance when finished.

## Examples

Search the generated ida-domain spec:

```python
lambda entries: [
    {
        "qualname": entry["qualname"],
        "signature": entry.get("signature"),
        "summary": entry.get("summary"),
    }
    for entry in entries
    if entry["kind"] in {"function", "method"}
    and "Database.open" in entry["qualname"]
]
```

Open a database:

```json
{
  "path": "/path/to/binary-or-idb",
  "auto_analysis": true,
  "save_on_close": false,
  "set_current": true
}
```

The response includes an `instance_id` and `log_path`.

Execute against the live `db`:

```python
def run(db, to_jsonable):
    result = []
    for index, func in enumerate(db.functions):
        if index >= 10:
            break
        result.append({
            "name": db.functions.get_name(func),
            "start_ea": hex(func.start_ea),
            "end_ea": hex(func.end_ea),
        })
    return to_jsonable({
        "path": db.path,
        "functions": result,
    })
```

Close the current database:

```json
{
  "save": false
}
```