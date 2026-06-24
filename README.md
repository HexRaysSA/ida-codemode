# ida-codemode-mcp

A [Code Mode](https://blog.cloudflare.com/code-mode/) MCP server for the [IDA Domain API](https://github.com/HexRaysSA/ida-domain).

It uses a centralized bridge architecture:

- `search(code)` — search a generated API spec built from the `ida-domain` package
- `open_database(...)` — spawn a long-lived idalib bridge instance for a local target
- `execute(code)` — run Python against an already-open `db` with `ida-domain` preloaded
- `list_databases()` — inspect active bridge instances and their JSONL log paths
- `close_database(...)` — close a bridge instance

## Prerequisites

- [uv](https://docs.astral.sh/uv/) on `PATH`
- IDA with [idalib](https://docs.hex-rays.com/core/idalib/overview) configured

## Install as a Claude Code plugin

```bash
claude plugin marketplace add HexRaysSA/claude-marketplace
claude plugin install ida-codemode-mcp@HexRaysSA
```

## Install as a Codex plugin

```bash
codex plugin marketplace add HexRaysSA/codex-marketplace
codex plugin add ida-codemode-mcp@HexRaysSA
```

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

When run via the Claude Code plugin, each tool call is stamped with `claude_session_path` so the JSONL logs can be cross-referenced with the corresponding Claude Code session transcript under `~/.claude/projects/`. The mapping is injected by the `PreToolUse` hook (`ida-codemode-mcp report-session claude`) as a hidden `_meta.claude_session_path` field in the tool input.

When run via the Codex plugin, the bundled `.codex-plugin/hooks.json` uses the same `PreToolUse` flow through `ida-codemode-mcp report-session codex` to stamp IDA MCP tool calls with `codex_session_path`. Codex requires users to review and trust plugin-bundled hooks before they run; open `/hooks` after installing or updating the plugin if Codex reports that hooks need review. The MCP server strips `_meta` before dispatching the tool call, so this field is not part of the public tool schema.

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
  "set_current": true
}
```

The response includes an `instance_id` and `log_path`. The database is always
persisted to disk when the instance is closed.

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

Close the current database (changes are always saved to disk):

```json
{
  "instance_id": "abc123"
}
```
