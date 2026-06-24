# Contributing

The plugin registers the MCP server as `ida`, so Claude Code tool names are shorter, e.g. `mcp__plugin_ida-codemode-mcp_ida__open_database`. The first invocation of any matching `mcp__(.*[_:])?ida__.*` tool will trigger `uv` to install the server (cached after that) and fire the `PreToolUse` hook that injects the Claude session id for log correlation.

## Develop the Cluade plugin locally

Clone the repo and launch Claude Code pointing at the checkout:

```bash
git clone https://github.com/HexRaysSA/ida-codemode-mcp
claude --plugin-dir ./ida-codemode-mcp
```

After editing `plugin.json`, hooks, or the Python source, run `/reload-plugins` inside Claude Code to pick up the changes without restarting. The manifest runs the MCP via `uv run --project ${CLAUDE_PLUGIN_ROOT} ...`, so local Python edits are reflected immediately — no rebuild step.