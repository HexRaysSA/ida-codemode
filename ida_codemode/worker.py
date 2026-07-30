from __future__ import annotations

import argparse
import importlib
import os
import signal
import sys
from pathlib import Path
from typing import Any

from .registry import LOG_DIR, REGISTRY_DIR, InstanceIdentity, ensure_private_directory
from .runtime import AnalysisState, IDARuntime, create_autoanalysis_hook
from .server import DEFAULT_LEASE_GRACE_SECONDS, CodeModeHTTPServer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ida-codemode-worker",
        description="Open one executable in idalib and expose the IDA Code Mode API",
    )
    parser.add_argument(
        "input", nargs="?", type=Path, help="Executable or existing IDB to open"
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Initialize idalib without opening a database, then exit",
    )
    parser.add_argument(
        "--new-database",
        action="store_true",
        help="Discard an existing database and create a new one",
    )
    parser.add_argument(
        "--output-database",
        type=Path,
        help="Write a newly-created database to this path",
    )
    parser.add_argument("--processor", help="IDA processor module name")
    parser.add_argument("--log-file", type=Path, help="IDA kernel log file")
    parser.add_argument(
        "--managed",
        action="store_true",
        help="Exit after the last Code Mode client lease is released",
    )
    parser.add_argument(
        "--record-suffix",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--lease-grace",
        type=float,
        default=DEFAULT_LEASE_GRACE_SECONDS,
        help=argparse.SUPPRESS,
    )
    return parser


def probe() -> None:
    """Initialize idalib without opening a database."""
    importlib.import_module("ida_domain")


def _redirect_output(record_id: str) -> Path:
    directory = ensure_private_directory(LOG_DIR)
    path = directory / f"{record_id}.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    if fd not in (1, 2):
        os.close(fd)
    # Re-wrap after dup2 so Python buffering does not hide startup failures.
    sys.stdout = os.fdopen(1, "w", buffering=1, closefd=False)
    sys.stderr = os.fdopen(2, "w", buffering=1, closefd=False)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.probe:
        if args.input is not None:
            parser.error("input cannot be used with --probe")
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 -- idalib may raise arbitrary errors
            print(
                f"[ida-codemode] idalib initialization failed: {exc}", file=sys.stderr
            )
            return 1
        return 0
    if args.input is None:
        parser.error("the following arguments are required: input")

    suffix = args.record_suffix or os.urandom(3).hex()
    if len(suffix) != 6 or any(c not in "0123456789abcdef" for c in suffix):
        print("[ida-codemode] invalid record suffix", file=sys.stderr)
        return 2
    record_id = f"{os.getpid()}-{suffix}"
    _redirect_output(record_id)

    if args.lease_grace < 0:
        print("[ida-codemode] lease grace must not be negative", file=sys.stderr)
        return 2
    try:
        input_path = args.input.expanduser().resolve(strict=True)
    except FileNotFoundError:
        print(f"[ida-codemode] input does not exist: {args.input}", file=sys.stderr)
        return 2

    # Import ida-domain only after the process-specific log is installed. In
    # library mode it loads idapro first, which makes the IDAPython modules
    # available and records initialization failures in the worker log.
    probe()

    import ida_auto
    import ida_kernwin
    import ida_loader
    import ida_nalt
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    # serve()/stop_serving() are available in IDA 9.4+, but older idapro
    # stubs from the pinned ida-domain Git branch do not declare them.
    kernwin: Any = ida_kernwin

    analysis_state = AnalysisState()
    analysis_hook: Any = create_autoanalysis_hook(analysis_state)
    analysis_hook.hook()
    database: Any | None = None
    runtime: IDARuntime | None = None
    server: CodeModeHTTPServer | None = None
    stop_signal: int | None = None

    def request_stop(signum: int, frame: Any) -> None:
        nonlocal stop_signal
        stop_signal = signum
        kernwin.stop_serving()

    previous_handlers: dict[int, Any] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)

    try:
        options = IdaCommandOptions(
            auto_analysis=False,
            new_database=args.new_database,
            output_database=(
                str(args.output_database.expanduser().resolve())
                if args.output_database
                else None
            ),
            processor=args.processor,
            log_file=(
                str(args.log_file.expanduser().resolve()) if args.log_file else None
            ),
        )
        database = Database.open(
            str(input_path),
            args=options,
            save_on_close=True,
        )
        if ida_auto.auto_is_ok():
            analysis_state.mark_complete()

        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
        exe_path = ida_nalt.get_input_file_path() or str(input_path)
        idb_path = str(Path(idb_path).resolve()) if idb_path else ""
        exe_path = str(Path(exe_path).resolve()) if exe_path else ""
        identity = InstanceIdentity(
            idb_path=idb_path,
            exe_path=exe_path,
            backend="idalib",
            managed=args.managed,
        )
        runtime = IDARuntime(
            backend="idalib",
            database=database,
            analysis_state=analysis_state,
        )
        server = CodeModeHTTPServer(
            runtime,
            identity,
            analysis_state,
            REGISTRY_DIR,
            record_suffix=suffix,
            lease_grace=args.lease_grace,
            on_shutdown=kernwin.stop_serving,
        )
        server.start()
        print(f"[ida-codemode] {server.url}", flush=True)

        # In IDA 9.4+, serve() dispatches execute_sync requests from HTTP
        # threads until managed lease shutdown or a signal calls
        # stop_serving(). A signal received during database startup must not be
        # lost before the serve loop begins.
        if stop_signal is None:
            kernwin.serve()
        return 128 + stop_signal if stop_signal is not None else 0
    except Exception as exc:  # noqa: BLE001 -- IDA initialization is third-party code
        print(f"[ida-codemode] {exc}", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.stop()
        if (
            database is not None
            and runtime is not None
            and runtime.database is not None
        ):
            try:
                # We are back on the idalib main thread after serve().
                database.close(save=True)
                runtime.database = None
            except Exception as exc:  # noqa: BLE001 -- SWIG may raise arbitrary errors
                print(
                    f"[ida-codemode] failed to close database: {exc}",
                    file=sys.stderr,
                )
        elif database is not None and runtime is None:
            try:
                database.close(save=True)
            except Exception as exc:  # noqa: BLE001 -- best-effort startup cleanup
                print(
                    f"[ida-codemode] failed to close database: {exc}",
                    file=sys.stderr,
                )
        # The lifetime lock is deliberately released only after the IDB close.
        if server is not None:
            server.release_registration()
        try:
            analysis_hook.unhook()
        except Exception as exc:  # noqa: BLE001 -- best-effort SWIG hook cleanup
            print(
                f"[ida-codemode] failed to remove analysis hook: {exc}", file=sys.stderr
            )
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


if __name__ == "__main__":
    raise SystemExit(main())
