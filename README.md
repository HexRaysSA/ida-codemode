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
- IDA 9.4 or higher with idalib and Python 3.11+
- Other IDA MCP servers must be disabled to reduce agent confusion

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

### [oh-my-pi](https://github.com/can1357/oh-my-pi)

```bash
omp plugin install github:HexRaysSA/ida-codemode
```

### IDA GUI Support

To support IDA GUI instances when using ida-codemode, install the plugin:

```bash
uvx ida-hcli plugin install ida-codemode
# or if you have hcli installed:
hcli plugin install ida-codemode
```

### Other agents

Configure a regular stdio MCP server in your MCP JSON configuration:

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": [
        "--with=ida-hcli",
        "ida-codemode",
        "mcp",
        "--agent=my-agent"
      ]
    }
  }
}
```

`uvx` resolves the latest stable `ida-codemode` release from PyPI, so this
configuration does not need to be updated for each release. Pre-release
dependency resolution is currently required because `ida-domain` is published
as a development release.

`--agent=my-agent` is a human-chosen label (like `claude-code`, `cursor`,
`my-custom-agent`, etc.) used to differentiate sessions in a metrics dashboard.

We tested the following clients, but any MCP client should work similarly:

- [Antigravity](https://coder.google.com/)
- [LM Studio](https://lmstudio.ai/)

## Usage

Start your agent harness and ask it something like:

> Reverse /path/to/sample.elf for me

To test the GUI integration, open something in IDA and ask your harness:

> What do I have open in the IDA GUI?

## Command line

The package installs one `ida-codemode` command with subcommands:

```bash
# MCP server (stdio/http)
ida-codemode mcp --agent=my-agent

# Inspect MCP session logs
ida-codemode dashboard --open

# Export MCP session logs to ZIP
ida-codemode logs

# IDA Domain API reference
ida-codemode reference "decompile function"

# Execute Python against an IDB (command, script, repl)
ida-codemode exec tests/crackme03/elf -c 'db.functions.get_all()'
```

`exec` labels resulting database events by input mode: `REPL: interactive` for
a terminal session, `REPL: stdin` for piped input, `REPL: command` for `-c`,
and `REPL: script <absolute path>` for a script file. These labels are restored
between executions like every other `execute_python()` provenance label.

Run `ida-codemode COMMAND --help` for command-specific options.

## Python Package (Developers)

You can build on `ida-codemode` as a library and reuse the database management
functionality. Doing so will transparently allow other `ida-codemode` users
to use IDBs concurrently and work together.

### Example scenarios

Below are a few scenarios enabled by the `ida-codemode` library:

- You have an executable open in the IDA GUI and would like to use the MCP without closing IDA.
- Your main agent spawns 5 subagents to work on different parts of the IDB concurrently.
- A headless database is created by the MCP, you want to access it with a CLI tool.
- You develop a web application to look at all the open IDA databases at once.

### API

`DatabaseHandle` is the primary API. One handle owns one lease on an exact GUI
or idalib database; closing it releases only that lease.

```python
from ida_codemode import DatabaseHandle, DatabaseOpenOptions

options = DatabaseOpenOptions(
    startup_timeout=300,
    processor="arm",
    image_base=0x08000000,
)
with DatabaseHandle.open("firmware.bin", options=options) as handle:
    handle.wait_autoanalysis()
    execution = handle.execute_python(
        "len(list(db.functions.get_all()))",
        timeout=60,
    )
    print(execution["result"])
```

IDA import settings in `DatabaseOpenOptions` apply only when Code Mode imports a
new source file. They do not reconfigure a reused GUI, worker, or existing IDB.
`execute_python()` is stateless by default; pass `persist_globals=True` to keep
a lease-scoped Python namespace between calls.

Database changes are available as a closeable, blocking iterator. Each item is
one structured IDB hook event with a monotonically increasing `revision`, a
nanosecond Unix `timestamp`, the `operation_id` and optional untrusted
`operation_label` active when IDA emitted it, and a nullable opaque `origin_id`.
The origin is derived from the producing handle's private lease without exposing
that control-capable lease ID. The GUI plugin labels events outside an
`execute_python()` operation as `IDA GUI`; its background analysis and direct UI
actions share that source:

```python
with handle.subscribe_idb_events() as events:
    for event in events:
        print(
            event["event_name"],
            event["revision"],
            event["operation_id"],
            event["operation_label"],
            handle.owns_event(event),
        )
```

`handle.owns_event(event)` identifies changes made through that handle without
requiring the consumer to generate or retain operation IDs. `operation_id`
remains available when correlation with one specific execution is useful.

Each subscriber buffers at most 4096 events. A subscriber that falls behind is
disconnected rather than receiving an incomplete history. The subscription can
be opened before autoanalysis completes; hooks are installed after initial
autoanalysis and removed when the final subscriber disconnects.

`@remote_ida` turns a typed IDA-domain function into a synchronous function
whose first argument is a `DatabaseHandle`. Keep the `Database` import
type-only so importing an application does not initialize idalib:

```python
from __future__ import annotations

from typing import TYPE_CHECKING

from ida_codemode import DatabaseHandle, remote_ida

if TYPE_CHECKING:
    from ida_domain import Database


@remote_ida
def read_bytes(db: Database, address: int, size: int) -> bytes:
    return db.bytes.get_bytes_at(address, size) or b""


with DatabaseHandle.open("firmware.bin") as handle:
    header = read_bytes(handle, 0x401000, 16)
```

The function body is type-checked against `ida_domain.Database`, while callers
are type-checked against `DatabaseHandle`. Remote functions must be ordinary
source-backed `def` functions without closures or additional decorators.
Imports used by the body belong inside the function. Arguments and return
values may contain `None`, booleans, integers, finite floats, strings, bytes,
lists, tuples, and string-keyed dictionaries recursively.

Reusable plain functions can be bundled explicitly. They are type-checked with
their normal signatures and execute in the same remote namespace:

```python
def read_exact(db: Database, address: int, size: int) -> bytes:
    data = db.bytes.get_bytes_at(address, size)
    if data is None:
        raise ValueError("unreadable address")
    return data


@remote_ida(helpers=(read_exact,))
def read_magic(db: Database, address: int) -> bytes:
    return read_exact(db, address, 4)
```

Helpers must also be synchronous, source-backed functions without decorators or
closures. List every helper used by the remote function, including helpers used
by other helpers.

Discovery returns public instance descriptors that support exact attachment:

```python
from ida_codemode import DatabaseHandle, InstanceState, discover_databases

ready = [
    item.instance for item in discover_databases() if item.state is InstanceState.READY
]
with DatabaseHandle.attach(ready[0]) as handle:
    print(handle.instance.record_id, handle.instance.idb_path)
```

`find_database_owner()` and `wait_database_released()` support clients that must
safely replace an executable or IDB. `DatabaseManager` is the secondary API for
MCP-style adapters that manage several handles and a current target. All
supported Python names are exported directly from `ida_codemode`; underscore
modules and non-exported implementation modules are private.
See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for more details.
