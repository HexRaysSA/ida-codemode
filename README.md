# ida-codemode-mcp

IDA Code Mode gives agents a compact Python execution surface over the
[`ida-domain`](https://github.com/HexRaysSA/ida-domain) API. It will
discover and share databases already open in the IDA GUI, and starts
managed idalib workers only when no suitable instance exists.

## MCP tools

- `reference(query)` - search the installed ida-domain API reference.
- `open_database(path, set_current=True)` - attach to a GUI database or shared idalib worker.
- `execute_python(code, instance_id=None)` - run Python with the IDA runtime preloaded and return its result, stdout, and stderr.
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
use the same instance. A managed idalib worker saves and exits after its final
lease disappears; GUI databases are never closed by MCP lifecycle management.

## Installation

### Requirements

- [uv](https://github.com/astral-sh/uv)
- IDA 9.4 or higher (Python 3.11+) with [idalib](https://docs.hex-rays.com/core/idalib/overview) configured
- MCP Client

### Claude Code

```bash
claude plugin marketplace add HexRaysSA/claude-marketplace
claude plugin install ida-codemode-mcp@HexRaysSA
```

### Codex

```bash
codex plugin marketplace add HexRaysSA/codex-marketplace
codex plugin add ida-codemode-mcp@HexRaysSA
```

### Pi

```bash
pi install git:github.com/HexRaysSA/ida-codemode-mcp
```

### IDA GUI

To (optionally) support using IDA GUI instances from the MCP:

```bash
hcli plugin install https://github.com/HexRaysSA/ida-codemode-mcp
```

### Other agents

Configure a regular stdio MCP server in your `mcp.json`:

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/HexRaysSA/ida-codemode-mcp",
        "ida-codemode-mcp",
        "--agent",
        "my-agent"
      ]
    }
  }
}
```
