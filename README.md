# ida-codemode-mcp

A [Code Mode](https://blog.cloudflare.com/code-mode/) MCP server for the [IDA Domain API](https://github.com/HexRaysSA/ida-domain).

It uses a centralized bridge architecture:

- `reference(query)` — look up the active `ida-domain` API reference as plain text
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

## Install as a Pi package

```bash
pi install git:github.com/HexRaysSA/ida-codemode-mcp
```

## Run the MCP server standalone

```bash
uv sync
uv run ida-codemode-mcp mcp                              # stdio (default)
uv run ida-codemode-mcp mcp --transport http://127.0.0.1:5001
```

`ida-domain` is pulled directly from git (see `[tool.uv.sources]` in `pyproject.toml`). The wheel ships `docs/` and `examples/` inside the package as `ida_domain/_docs/` and `ida_domain/_examples/`, which the `reference()` tool indexes via `importlib.util.find_spec`.

## IDA plugin and standalone worker

The repository also includes an authenticated local HTTP runtime for IDA 9.4+.
It is currently independent of the existing MCP bridge layer:

- `ida_codemode_plugin.py` exposes the API from an existing IDA GUI session.
- `ida-codemode-worker` opens one target with idalib and exposes the same API.

Both entry points use `ida-domain` directly from Git: the worker resolves the
branch configured under `[tool.uv.sources]` in `pyproject.toml`, and the IDA
plugin manifest declares the matching direct Git dependency.

Install the GUI plugin from the checkout:

```bash
hcli plugin lint .
hcli plugin install --editable .
```

Run a standalone idalib worker:

```bash
uv sync
uv run ida-codemode-worker /path/to/executable
```

Useful worker options include `--new-database`, `--output-database`,
`--processor`, and `--log-file`. Both backends publish their loopback endpoint,
bearer token, target paths, and backend kind under:

```text
~/.ida-codemode/instances/<pid>.json
```

Every request requires `Authorization: Bearer <registry token>`. The API exposes
`/health`, `/poll_autoanalysis`, `/wait_autoanalysis`, `/execute_python`,
`/save_database`, and `/close_database`. GUI sessions reject close requests
because the user owns their database.

A live endpoint can be smoke-tested with:

```bash
uv run python examples/test_live.py http://127.0.0.1:<port>
```

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

The log captures bridge lifecycle events, raw bridge output, and every request/response payload sent between the MCP server and the live IDA bridge instance. Set `IDA_CODEMODE_ID` to a benchmark/test run identifier to stamp bridge logs with `codemode_id`; the Claude, Codex, and Pi integrations pass this environment variable through to the MCP server. The dashboard uses matching IDs as an explicit grouping boundary even when no agent transcript is available.

When run via the Claude Code plugin, each tool call is stamped with `claude_session_path` so the JSONL logs can be cross-referenced with the corresponding Claude Code session transcript under `~/.claude/projects/`. The mapping is injected by the `PreToolUse` hook (`ida-codemode-mcp report-session claude`) as a hidden `_meta.claude_session_path` field in the tool input.

When run via the Codex plugin, the bundled `.codex-plugin/hooks.json` uses the same `PreToolUse` flow through `ida-codemode-mcp report-session codex` to stamp IDA MCP tool calls with `codex_session_path`. Codex requires users to review and trust plugin-bundled hooks before they run; open `/hooks` after installing or updating the plugin if Codex reports that hooks need review. The MCP server strips `_meta` before dispatching the tool call, so this field is not part of the public tool schema.

When run through the Pi extension, each MCP `tools/call` request includes the current `pi_session_path` in the protocol-level `_meta` object. The server reads it through `mcp.context.meta`, so Pi does not need an external hook or hidden tool argument. Pi sessions created with `--no-session` have no transcript path and are intentionally left unstamped. The Pi TUI renders tool arguments and syntax-highlights the Python passed to `ida_execute()`; snippets longer than 10 lines can be expanded with Pi's tool-expansion keybinding.

## Dashboard

A local web dashboard (stdlib only, independent of the MCP server) renders the JSONL logs visually:

```bash
uv run ida-codemode-dashboard --open           # http://127.0.0.1:8736/
uv run ida-codemode-dashboard --port 9000 --logs-dir ~/.ida-codemode/logs
```

It shows:

- an analysis-work index ordered by start time with the newest first. Matching `IDA_CODEMODE_ID` values explicitly group benchmark/test logs; otherwise shared agent sessions connect related binary logs. A binary log with no agent session or one unshared agent session stays flat, while a log spanning multiple agent sessions gets a combined view. The top-level link opens the complete merged timeline and each binary remains directly linked to its own log page. Columns are sortable and show status (`running`, `closed`, or `killed` based on a clean-close event and PID liveness), errors, and estimated model cost. Long all-hex target names are collapsed to `prefix…suffix`.
- a per-session timeline pairing each request with its response — `execute()` code is syntax-highlighted, results and bridge output are collapsible. When the session is linked to an agent transcript, the agent's user prompts, messages, reasoning, and non-IDA tool calls are interleaved into the timeline at their real timestamps (marked with a left accent rail), so you can read what the agent was thinking and doing around each IDA call. IDA transcript calls are omitted there because the corresponding bridge request cards already show them. Pi's active session branch is followed so abandoned branches are not mixed into the timeline. Each agent turn shows its tokens in/out/cached and cost inline, and the session header sums them. A "toggle transcript" button hides/shows them. A transcript shared by several bridge instances is sliced by time so each instance shows only its own conversation.
- cost is computed from Claude transcripts using current per-model pricing (input, output, cache-write at 1.25×, cache-read at 0.10×); Pi uses the per-message cost recorded in its transcript. Codex sessions show token totals but no cost (OpenAI pricing isn't tracked).
- a standalone rendering of the linked Claude Code, Codex, or Pi transcript (user/assistant messages, thinking, tool calls with their results), when the session was stamped via the plugin hooks

### Sharing a session

Each session page has an **export HTML** button that downloads a single self-contained `.html` file (all CSS/JS inlined, no external requests, navigation links and the host log path stripped). You can open it directly, email it, or host it as a static artifact to share a session with someone who doesn't have the logs. The interleaved agent transcript is included, and the interactive controls (expand/collapse, toggle transcript) still work offline.

For safety, the dashboard binds to `127.0.0.1` by default and only serves transcript files that are actually referenced by a bridge log — arbitrary paths are rejected.

## Shutdown behavior

The MCP supervisor installs `SIGINT`/`SIGTERM` handlers and an `atexit` shutdown hook. On Claude Code exit, stdio EOF, or process termination, it asks each live bridge worker to close its database before terminating the worker process. Bridge workers also install their own `SIGINT`/`SIGTERM` handlers so a directly signaled worker closes the active database before exiting.

## Typical flow

1. Use the IDA reference to look up the API needed for the task.
2. Open a local target.
3. Run one or more `execute()` calls against the live `db`.
4. Close the instance when finished.

## Examples

Look up the ida-domain API reference:

```json
{
  "query": "list functions and retrieve their names and addresses"
}
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
        result.append(
            {
                "name": db.functions.get_name(func),
                "start_ea": hex(func.start_ea),
                "end_ea": hex(func.end_ea),
            }
        )
    return to_jsonable(
        {
            "path": db.path,
            "functions": result,
        }
    )
```

Close the current database (changes are always saved to disk):

```json
{
  "instance_id": "abc123"
}
```

## Testing

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.
