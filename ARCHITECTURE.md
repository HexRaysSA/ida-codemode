# ida-codemode architecture

ida-codemode uses discoverable, shared IDA instances. A GUI database and an
idalib worker expose the same authenticated loopback HTTP service. MCP servers
attach through client leases rather than owning or terminating IDA processes
directly.

## Components

| Component | Responsibility |
|---|---|
| `ida_codemode_plugin.py` | Starts the Code Mode service inside interactive IDA and registers the open GUI database. |
| `ida_codemode/worker.py` | Opens an executable or IDB with idalib, starts the service, and closes/saves the database when its managed lifecycle ends. |
| `ida_codemode/server.py` | Authenticated HTTP API, instance publication, SSE leases, request draining, and managed shutdown. |
| `ida_codemode/registry.py` | Canonical identity, cross-platform file locks, atomic records, health classification, and stale-record cleanup. |
| `ida_codemode/resolver.py` | GUI discovery, expected-IDB resolution, serialized worker spawning, and startup diagnostics. |
| `ida_codemode/client.py` | `DatabaseHandle`, SSE lease maintenance, execution, saving, and transparent rebinding after worker replacement. |
| `ida_codemode/runtime.py` | Serializes IDA operations onto IDA's main thread and provides the Code Mode Python runtime. |
| `ida_codemode_mcp.py` | MCP tools, MCP-local database selection, agent metadata, and semantic session tracing. |
| `ida_codemode_dashboard.py` | Renders semantic session traces and linked Claude, Codex, or Pi transcripts. |

## State layout

```text
~/.ida-codemode/
  instances/<record-id>.json       published instance metadata
  instances/<record-id>.lock       held for the instance lifetime
  spawn/<idb-key>.lock             serializes worker creation
  logs/<record-id>.log             IDA/worker operational output
  sessions/<session-id>.jsonl      semantic MCP/agent trace
```

`record-id` is `<pid>-<six random hex digits>`. The random suffix prevents a
stale Windows lock filename from colliding with a new process after PID reuse.

The registry record contains the backend (`gui` or `idalib`), PID, endpoint,
authentication token, protocol version, canonical executable and IDB paths,
IDB key, managed flag, and start time. Registry and session directories are
private to the user; record files are created with private permissions.

## Database identity

The identity used for IDB ownership and spawn serialization is:

```python
sha256(canonical_real_path.encode()).hexdigest()[:16]
```

Windows paths use platform case normalization. macOS paths are case-folded so
clients on the usual case-insensitive volumes agree on one identity.

Given an executable, the expected database path is `<executable>.i64`. Given an
existing `.i64`, that path is already the database identity.

The executable path remains independently useful: a GUI may have saved its IDB
somewhere unusual. Resolution therefore checks a GUI whose input executable
matches before falling back to the expected IDB path.

## Registration and liveness

Registration order is an invariant:

1. Create and exclusively lock `instances/<record-id>.lock`.
2. Bind the HTTP service to `127.0.0.1:0`.
3. Atomically publish `instances/<record-id>.json`.

Shutdown reverses external visibility:

1. Mark the service as draining.
2. Remove the JSON record.
3. Stop accepting work and drain active requests.
4. Close/save the IDB where appropriate.
5. Exit or unload, releasing the lifetime lock only after the IDB is no longer owned.

The JSON file is discovery metadata; the kernel lock is the liveness authority.
A scanner classifies a record as:

- `READY`: lifetime lock is held and authenticated health identity matches.
- `BLOCKED`: lifetime lock is held but health is unavailable or incompatible.
- `DEAD`: lifetime lock is acquirable.

Only `DEAD` records may be removed. Timeouts, authentication mismatches, old
versions, and malformed health responses never justify spawning over a
lock-held instance.

A hard-killed process leaves files behind, but the kernel releases its lock.
Any scanner may then reap the JSON and lock files idempotently. Acquirable
orphan instance locks are swept opportunistically. Spawn lock files remain on
disk permanently to avoid split-inode locking races.

## Resolution and worker spawning

`DatabaseHandle.open(path)` performs the following:

1. Canonicalize and validate the requested executable or IDB.
2. Find a GUI instance matching the executable path.
3. Otherwise find the unique owner of the expected IDB.
4. Return a `READY` owner or report a lock-held `BLOCKED` owner.
5. Acquire `spawn/<idb-key>.lock` and repeat the scan.
6. If still absent, start `python -m ida_codemode.worker` as a detached managed worker.
7. Wait for a record with both the child PID and expected IDB key.

The spawn lock is held until the child becomes ready or fails. Startup waiting
checks `Popen.poll()` and includes the tail of `logs/<record-id>.log` when the
child exits, so import, licensing, and IDA load failures are reported directly.

IDA itself remains the final protection against an unregistered IDA process or
a race with an independently opened GUI.

## HTTP and IDA execution

Every request is bound to loopback, requires the bearer token from the private
registry record, validates `Host`, and rejects browser-originated requests.
Request framing, compression, and decompressed body size are bounded.

Important routes are:

| Route | Purpose |
|---|---|
| `GET /health` | Authenticated record identity and liveness probe. |
| `GET /health?sse=1` | Persistent client lease with periodic heartbeat. |
| `POST /execute_python` | Execute Code Mode Python against the open database. |
| `POST /save_database` | Explicitly save a GUI or idalib database. |
| `/poll_autoanalysis`, `/wait_autoanalysis` | Observe or wait for IDA autoanalysis. |

There is no remote database-close route. Closing a client handle releases only
that client's lease.

`IDARuntime` serializes operations and dispatches them through
`ida_kernwin.execute_sync`. The execution runtime exposes:

- `db`
- `ida_domain`
- `Database`
- `IdaCommandOptions`
- `database_path`
- `database_options`
- `json`
- `to_jsonable`

User code may be a callable expression or define `run`, `execute`, or `main`.
Timeout tracing and IDA cancellation prevent one timed-out request from
poisoning the next operation.

## Shared leases and managed shutdown

Each `DatabaseHandle` owns one authenticated SSE connection. Multiple handles,
MCP servers, and agents may share the same instance. Closing one handle closes
only that connection.

The server emits heartbeat comments so crashed clients are detected when the
next write fails. A short grace period protects reconnects and the race between
worker publication and the first lease.

A managed idalib worker exits only when:

- no SSE leases remain;
- no operation is active; and
- the zero-lease grace period has elapsed.

A new lease cancels pending shutdown. The worker then withdraws its registry
record, stops serving, returns to the idalib main thread, saves/closes the IDB,
and exits. GUI instances are unmanaged and ignore a zero lease count.

This is logical client interest rather than HTTP connection reuse or a fragile
client-maintained process refcount. Client crashes and `kill -9` are handled by
socket and kernel-lock cleanup.

## MCP model

The MCP server keeps MCP-local opaque `instance_id` values mapped to
`DatabaseHandle` objects. Reopening the same registry record within one MCP
server reuses the existing local session and retains only one lease. Separate
MCP servers retain independent leases.

Tools are:

| Tool | Behavior |
|---|---|
| `reference(query)` | Search the installed ida-domain API reference. |
| `open_database(path, set_current=True)` | Attach to a GUI or shared managed worker. |
| `execute(code, instance_id=None)` | Execute against the selected handle. |
| `list_databases()` | List this MCP server's handles. |
| `save_database(instance_id=None)` | Explicitly save the selected database. |
| `close_database(instance_id=None)` | Release this MCP server's handle; it is not a global close. |

On stdio EOF, SIGINT, SIGTERM, or normal interpreter exit, the MCP server
releases all handles. Other agents continue uninterrupted. If the released
lease was the last lease on a managed worker, that worker performs its own
shutdown.

## Semantic sessions and agent metadata

The MCP server writes one session-oriented JSONL trace to:

```text
~/.ida-codemode/sessions/<mcp-server-id>.jsonl
```

Every record includes schema version, timestamp, MCP server ID, MCP PID, and an
event. Tool activity is represented by `tool_call`, `tool_result`, and
`tool_error`, paired by `call_id`. Database binding events contain MCP-local and
registry identity, including the worker operational log path.

Claude, Codex, and Pi hooks promote hidden `_meta` fields into MCP request
metadata. Each tool event records the applicable `codemode_id` and agent
transcript path under `session`. This supports one MCP process serving multiple
agent sessions and several agents sharing one IDA worker.

Semantic tracing remains at the MCP layer because only that layer can observe
`reference`, list operations, resolution failures, and agent metadata. Worker
logs are operational and correlate through `record_id` and timestamps.

The dashboard reads the semantic session schema. It pairs calls and results,
renders execute code and reference output, lists all database targets in a
session, and interleaves non-IDA activity from referenced agent transcripts.

## Failure behavior

| Failure | Result |
|---|---|
| MCP/client exits cleanly | Its leases close; other clients continue. |
| MCP/client is killed | Kernel closes sockets; heartbeat observes the loss. |
| Managed worker is killed | Lifetime lock releases; stale metadata is reaped on scan. |
| Health times out | Instance is `BLOCKED`; no replacement is spawned. |
| Worker exits during startup | Resolver raises with process status and log tail. |
| Worker disappears after opening | The handle's lease monitor resolves and attaches to a replacement. |
| Response contains an IDA error | Structured code, status, details, and traceback reach MCP tracing. |

The architecture deliberately favors harmless stale files and reloadable
workers over cross-client shutdown authority or ownership bookkeeping.
