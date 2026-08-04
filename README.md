# ida-codemode

⚠️ Experimental prerelease ⚠️

IDA Code Mode gives agents a compact Python execution surface over the
[`ida-domain`](https://github.com/HexRaysSA/ida-domain) API. It will
discover and share databases already open in the IDA GUI, and starts
managed idalib workers only when no suitable instance exists.

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

### IDA GUI

To (optionally) support using IDA GUI instances from the MCP, install
[hcli](https://hcli.docs.hex-rays.com/) in your PATH and run:

```bash
hcli plugin install https://github.com/HexRaysSA/ida-codemode/archive/refs/heads/main.zip
```

Agent integrations attempt this plugin installation in the background after
MCP starts. If it fails, the MCP remains available for idalib databases.

### Other agents

Configure a regular stdio MCP server in your `mcp.json`:

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/HexRaysSA/ida-codemode",
        "ida-codemode-mcp",
        "--agent",
        "my-agent",
        "--install-plugin"
      ]
    }
  }
}
```
