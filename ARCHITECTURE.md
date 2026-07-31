# ida-codemode architecture

ida-codemode uses discoverable, shared IDA instances. Each GUI database or
idalib worker exposes the same authenticated loopback HTTP service. MCP servers
attach through client leases rather than owning or terminating IDA processes
directly.

The main data path is:

```text
Claude/Codex MCP config ─┐
Pi extension ────────────┴─> ZeroMCP adapter -> DatabaseManager -> DatabaseHandle
                                                                  │
                                      private registry <──────────┤
                                                                  ├─ SSE lease
                                                                  └─ HTTP RPC
                                                                         │
                                                GUI plugin or idalib worker
                                                                         │
                                                              IDARuntime -> IDA
```

The filesystem registry provides discovery and process liveness; the SSE
connection expresses one client's interest in an already-running database.

## Components

| Component | Responsibility |
|---|---|
| `ida_codemode_plugin.py` | Starts the Code Mode service inside interactive IDA, prevents duplicate GUI registration, and detaches without closing the GUI database. |
| `ida_codemode/worker.py` | Opens an executable or IDB with idalib, starts the service, and closes/saves the database when its lifecycle ends. Resolver-spawned workers are managed; directly launched workers are unmanaged unless `--managed` is passed. |
| `ida_codemode/http.py` | Loopback HTTP/1.1 listener, bearer/host/browser checks, bounded framing and decompression, and streamed responses. |
| `ida_codemode/server.py` | Code Mode routes, instance publication, SSE lease/request accounting, and managed idle shutdown. |
| `ida_codemode/registry.py` | Canonical identity, cross-platform file locks, atomic records, health classification, and stale-record cleanup. |
| `ida_codemode/resolver.py` | GUI discovery, expected-IDB resolution, serialized worker spawning, import options, and startup diagnostics. |
| `ida_codemode/client.py` | `DatabaseHandle`, SSE lease monitoring, reusable HTTP RPC connection, disconnection detection, execution, analysis waiting, and saving. |
| `ida_codemode/database.py` | Protocol-agnostic database attachment, local selection, per-handle operation serialization, lease cleanup, and lifecycle events. |
| `ida_codemode/runtime.py` | Serializes IDA operations onto IDA's main thread and provides the Code Mode Python runtime. |
| `ida_codemode/reference.py` | Builds and searches an AST-based reference from the installed ida-domain package and examples without importing ida-domain in the MCP process. |
| `ida_codemode/paths.py` | Resolves the shared state root from the environment and IDA defaults. |
| `ida_codemode_mcp.py` | ZeroMCP tools/transports, error mapping, startup attachment, agent metadata, and semantic session tracing. |
| `ida-codemode.ts` | Pi extension that starts the stdio MCP child, mirrors its tools with `ida_` names, attaches Pi transcript metadata, and applies Pi output truncation. |
| `ida_codemode_dashboard.py` | Renders semantic session traces and linked Claude, Codex, or Pi transcripts. |
| `migrate_logs.py` | One-shot conversion of pre-0.2 operational/bridge logs into schema-1 semantic sessions. |

## State layout

```text
<state-dir>/
  instances/<record-id>.json       published instance metadata
  instances/<record-id>.lock       held for the instance lifetime
  spawn/<idb-key>.lock             serializes worker creation
  logs/<record-id>.log             idalib worker stdout/stderr
  sessions/<mcp-server-id>.jsonl   semantic MCP/agent trace
```

`<state-dir>` is `IDA_CODEMODE_STATE_DIR` when that variable is set. Otherwise
it is `<IDAUSR>/codemode`, where `<IDAUSR>` is the first directory in the
`IDAUSR` environment variable. When `IDAUSR` is unset, IDA's platform default
is used (`~/.idapro` on Unix-like systems or `%APPDATA%/Hex-Rays/IDA Pro` on
Windows).

`record-id` is `<pid>-<six random hex digits>`. The random suffix prevents a
stale Windows lock filename from colliding with a new process after PID reuse
and also correlates a Windows console launcher with its Python child.

The registry record contains the backend (`gui` or `idalib`), PID, endpoint,
authentication token, protocol version, canonical executable and IDB paths,
IDB key, managed flag, and start time. Registry and session directories are
private to the user; records, traces, and worker logs are created with private
permissions.

## Database identity

Real paths stored in records preserve their filesystem spelling. Matching and
spawn serialization use a separate comparison identity:

```python
sha256(identity_key(path).encode("utf-8")).hexdigest()[:16]
```

`identity_key()` expands, absolutizes, and resolves the path. Windows then uses
platform case normalization, while macOS case-folds the value so clients on the
usual case-insensitive volumes agree on one identity. Other platforms preserve
case.

Given an executable, the expected database path is `<executable>.i64`. Given a
path ending in `.i64`, that path is already the database identity.

The executable path remains independently useful: a GUI may have saved its IDB
somewhere unusual. Resolution therefore checks a GUI whose input executable
matches before falling back to the expected IDB path.

## Registration and liveness

Registration order is an invariant:

1. Create and exclusively lock `instances/<record-id>.lock`.
2. Bind and start the HTTP service on `127.0.0.1:0`.
3. Atomically publish `instances/<record-id>.json`.

Managed idle shutdown begins only after the grace period has elapsed with no
leases or active API requests. The watchdog marks the service as draining,
withdraws the JSON record, closes lease streams and the listener, and asks the
idalib main loop to stop. The worker then saves/closes the IDB and releases the
lifetime lock. A plugin unload or process signal also withdraws the record and
stops the listener; its lifecycle owner still detaches/closes the database
before releasing that lock.

The JSON file is discovery metadata; the kernel lock is the liveness authority.
Conceptually, a scanner classifies a parseable record as:

- `READY`: lifetime lock is held and authenticated health identity matches.
- `BLOCKED`: lifetime lock is held but health is unavailable or does not match
  the published record.
- `DEAD`: lifetime lock is acquirable; the scanner reaps it instead of returning it.

Only `DEAD` records may be removed. Timeouts, authentication mismatches, and
malformed health responses never justify spawning over a lock-held instance.
The protocol version participates in the health identity but is not separately
negotiated. A malformed registry record is likewise removed only when its
corresponding lock is acquirable.

A hard-killed process leaves files behind, but the kernel releases its lock.
Any scanner may then reap the JSON and lock files idempotently. Acquirable
orphan instance locks are swept opportunistically. Spawn lock files remain on
disk permanently to avoid split-inode locking races.

## Resolution and worker spawning

`DatabaseHandle.open(path)` performs the following:

1. Canonicalize the requested executable or IDB and scan the registry before
   requiring the path to exist. This permits attachment to an unsaved GUI IDB.
2. For an executable request, find a GUI instance matching its input path.
3. Otherwise find the unique owner of the expected IDB.
4. Return a `READY` owner or report a lock-held `BLOCKED` owner.
5. Acquire `spawn/<idb-key>.lock` and repeat the scan.
6. If still absent, validate the source path and start the
   `ida-codemode-worker` console script as a hidden, detached managed worker.
7. Wait for a record with the expected IDB key and launch identity. Normally the
   PID is sufficient; on Windows the console launcher can hand off to a Python
   child, so the random record suffix is authoritative across both processes.

The low-level handle/resolver also accepts an explicit output database,
processor, loading address, file type, and fresh-database flag. An explicit
output database resolves by that IDB identity rather than attaching to a GUI
that merely has the same executable open. A fresh-database request never
reuses a live owner. These import controls are currently low-level/worker APIs,
not arguments of the six-tool MCP surface.

The spawn lock is held until the child becomes ready or fails. Startup waiting
checks `Popen.poll()` without mistaking a successful Windows launcher handoff
for worker exit, and includes the tail of `logs/<record-id>.log` when startup
fails, so import, licensing, and IDA load failures are reported directly. If a
managed worker crosses its zero-lease shutdown boundary between resolution and
the SSE handshake, `DatabaseHandle.open()` resolves once more before failing.

IDA itself remains the final protection against an unregistered IDA process or
a race with an independently opened GUI.

## HTTP and IDA execution

Each per-database Code Mode service is bound to loopback, requires the bearer
token from the private registry record, validates `Host`, and rejects
browser-originated requests. Request framing and content encoding are strict,
and both encoded and decompressed body sizes are bounded.

Important routes are:

| Route | Purpose |
|---|---|
| `GET /health` | Authenticated record identity and liveness probe. |
| `GET /health?sse=1` | Persistent client lease with periodic heartbeat. |
| `POST /execute_python` | Execute Code Mode Python against the open database. |
| `POST /save_database` | Explicitly save a GUI or idalib database. |
| `GET /poll_autoanalysis` | Observe initial IDA autoanalysis. |
| `GET` or `POST /wait_autoanalysis` | Wait for autoanalysis; POST accepts a timeout. |

There is no remote database-close route. Closing a client handle releases only
that client's lease. A handle uses a separate reusable HTTP/1.1 connection for
RPCs and proactively replaces it before the server's idle timeout. A failed
POST is never retried because its execution status may be ambiguous.

These guarantees apply to the per-database API. The optional ZeroMCP HTTP
transport and dashboard have no built-in authentication; both default to local
usage and warn when explicitly bound beyond loopback. Stdio is the normal MCP
transport.

`IDARuntime` serializes operations and dispatches them through
`ida_kernwin.execute_sync`. The current ida-domain `Database` is available
globally as `db`, alongside the imported `ida_domain` package. Ordinary
statements execute once, and a single or trailing expression becomes the
result. As an alternative, code without a trailing
expression may define `run(db)`, `execute(db)`, or `main(db)` for automatic
invocation. Timeout tracing and IDA cancellation prevent one timed-out request
from poisoning the next operation.

## Shared leases and managed shutdown

Each `DatabaseHandle` owns one authenticated SSE lease connection in addition
to its on-demand RPC connection. Multiple handles, MCP servers, and agents may
share the same instance. Closing one handle closes only its own connections.

The server emits heartbeat comments so crashed clients are detected when the
next write fails. A short grace period protects the race between worker
publication and the first lease and allows an orderly final client release.

A managed idalib worker exits only when:

- no SSE leases remain;
- no operation is active; and
- the zero-lease grace period has elapsed.

A new lease cancels pending shutdown. The worker then withdraws its registry
record, stops serving, returns to the idalib main thread, saves/closes the IDB,
and exits. GUI instances are unmanaged and ignore a zero lease count.

Worker lifetime follows the explicit SSE lease, not the incidental lifetime of
a reusable RPC socket or a fragile client-maintained process refcount. Client
crashes and `kill -9` are handled by socket and kernel-lock cleanup.

## MCP model

The MCP server keeps MCP-local opaque `instance_id` values mapped to
`DatabaseHandle` objects. Reopening the same registry record within one MCP
server reuses the existing local session and retains only one lease. Separate
MCP servers retain independent leases. Registry discovery lets
`list_databases()` also report GUI and idalib instances that this MCP server
has not yet attached to; local handles are annotated with their `instance_id`
and current-target state. If a lease connection dies, its MCP-local
`instance_id` is invalidated immediately. Code Mode never silently reconnects
or replaces the database; the agent must discover and open it again.

Tools are:

| Tool | Behavior |
|---|---|
| `reference(query)` | Search the installed ida-domain API reference. |
| `open_database(path, set_current=True)` | Attach to a GUI or shared managed worker. |
| `execute_python(code, instance_id=None)` | Execute Python against the selected handle. |
| `list_databases()` | Discover registered instances and identify this MCP server's handles. |
| `save_database(instance_id=None)` | Explicitly save the selected database. |
| `close_database(instance_id=None)` | Release this MCP server's handle; it is not a global close. |

`--database` schedules a startup attachment without blocking MCP
initialization; an operation that needs the current target waits for that
startup attempt. The server normally runs over stdio, with an opt-in ZeroMCP
HTTP transport. The Pi extension is an MCP client adapter rather than a second
implementation of these tools.

On stdio EOF, SIGINT, SIGTERM, or normal interpreter exit, the MCP server
releases all handles. Other agents continue uninterrupted. If the released
lease was the last lease on a managed worker, that worker performs its own
shutdown.

## Semantic sessions and agent metadata

The MCP server writes one session-oriented JSONL trace to:

```text
<state-dir>/sessions/<mcp-server-id>.jsonl
```

Every record includes schema version, timestamp, MCP server ID, MCP PID, and an
event. `mcp_started` records the optional `--agent` label, while
`mcp_initialized` records the MCP client's `clientInfo` and `_meta`. Tool
activity is represented by `tool_call`, `tool_result`, and `tool_error`, paired
by `call_id`. Database binding events contain MCP-local and registry identity,
including the worker operational log path.

The Claude and Codex `PreToolUse` hooks and the Pi extension attach transcript
paths as hidden `_meta` fields. The MCP adapter promotes those fields into
request metadata and removes them from public tool arguments. Each tool event
records the applicable `codemode_id` and agent transcript path under `session`.
This supports one MCP process serving multiple agent sessions and several
agents sharing one IDA worker.

Semantic tracing remains at the MCP layer because only that layer can observe
`reference`, list operations, resolution failures, and agent metadata. Worker
logs are operational and correlate through `record_id` and timestamps.

The dashboard reads the semantic session schema. It pairs calls and results,
renders executed Python and reference output, lists all database targets and
best-effort transcript model names, and interleaves non-IDA activity from
referenced agent transcripts. It can also auto-detect the benchmark run layout,
select Pi's active transcript branch, summarize available token/cost data, and
export a self-contained session page. Its `/agent` route serves only transcript
paths referenced by discoverable semantic sessions.

## Legacy migration

`migrate_logs.py` reads transitional schema-1 traces from `logs/mcp/` and older
bridge JSONL files from `logs/`, then writes normalized session files under
`sessions/`. It never modifies source logs, sanitizes destination names, and
reports malformed, unknown, or unattributable records instead of silently
placing them in the permanent schema. Known `bridge_output` noise is counted
and intentionally discarded from migrated sessions.

## Failure behavior

| Failure | Result |
|---|---|
| MCP/client exits cleanly | Its leases close; other clients continue. |
| MCP/client is killed | Kernel closes sockets; heartbeat observes the loss. |
| Managed worker is killed | Lifetime lock releases; stale metadata is reaped on scan. |
| Health times out | Instance is `BLOCKED`; no replacement is spawned. |
| Worker exits during startup | Resolver raises with process status and log tail. |
| Worker begins idle shutdown before the first lease | The handle resolves and attempts attachment once more. |
| GUI or worker disappears after opening | Its `instance_id` is invalidated; the next operation tells the agent to list and open again. |
| RPC connection fails during a POST | The connection is discarded, but the operation is not retried because it may already have executed. |
| Response contains an IDA error | Structured code, status, details, and traceback reach MCP tracing. |

The architecture deliberately favors harmless stale files and reloadable
workers over cross-client shutdown authority or ownership bookkeeping.
