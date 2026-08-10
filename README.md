# ida-codemode

⚠️ Experimental prerelease ⚠️

IDA Code Mode gives agents a compact Python execution surface over the
[`ida-domain`](https://github.com/HexRaysSA/ida-domain) API. It will
discover and share databases already open in the IDA GUI, and starts
managed idalib workers only when no suitable instance exists.

The MCP adapter explicitly runs `execute_python` as a lease-scoped REPL: imports,
variables, and function definitions persist between its calls through the same
database handle. The low-level API remains stateless by default and opts in with
`persist_globals=True`; a stateless call discards any namespace previously
retained by that handle. Separate handles receive isolated namespaces, and
closing a handle releases its namespace and retained IDA objects.

## Installation

### Requirements

- Installed in your PATH
  - [Git](https://git-scm.com/)
  - [uv](https://github.com/astral-sh/uv)
- IDA 9.4 or higher with Python 3.11+

### [Claude Code](https://claude.com/product/claude-code)

```bash
claude plugin marketplace add HexRaysSA/claude-marketplace
claude plugin install ida-mcp@HexRaysSA
```

### [Codex CLI](https://learn.chatgpt.com/docs/codex/cli)

```bash
codex plugin marketplace add HexRaysSA/codex-marketplace
codex plugin add ida-mcp@HexRaysSA
```

### [Pi](https://pi.dev/)

```bash
pi install git:github.com/HexRaysSA/ida-codemode
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
        "ida-codemode@latest",
        "ida-codemode-mcp",
        "--agent",
        "my-agent",
        "--install-plugin"
      ]
    }
  }
}
```

`uvx` resolves the latest stable `ida-codemode` release from PyPI, so this
configuration does not need to be updated for each release. Pre-release
dependency resolution is currently required because `ida-domain` is published
as a development release.
