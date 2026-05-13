# ida-codemode-mcp

A Code Mode MCP server for the `ida-domain` API.

It uses a centralized bridge architecture:

- `search(code)` — search a generated API spec built from the vendored `ida-domain` checkout
- `open_database(...)` — spawn a long-lived idalib bridge instance for a local target
- `execute(code)` — run Python against an already-open `db` with `ida-domain` preloaded
- `list_databases()` — inspect active bridge instances and their JSONL log paths
- `close_database(...)` — close a bridge instance

## Setup

```bash
uv sync
```

`ida-domain` is pulled directly from git (see `[tool.uv.sources]` in `pyproject.toml`). The wheel ships `docs/` and `examples/` inside the package as `ida_domain/_docs/` and `ida_domain/_examples/`, which the `search()` tool inspects via `importlib.util.find_spec`.

## Run

HTTP transport:

```bash
uv run python main.py --transport http://127.0.0.1:5001
```

stdio transport:

```bash
uv run python main.py --transport stdio
```

## Architecture

`open_database()` starts a dedicated subprocess that opens the requested target through the vendored `ida-domain`/idalib and keeps the database alive.

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
.ida-codemode/logs/
```

`open_database()`, `execute()`, `list_databases()`, and `close_database()` return the `log_path` for the relevant instance. You can tail it while the agent runs:

```bash
tail -f .ida-codemode/logs/<database-name>-<instance-id>.jsonl
```

The log captures bridge lifecycle events, raw bridge output, and every request/response payload sent between the MCP server and the live IDA bridge instance.

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