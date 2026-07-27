from __future__ import annotations

import argparse
from pathlib import Path
import signal
import sys
from typing import Any

from ida_domain import Database
from ida_domain.database import IdaCommandOptions

from .registry import InstanceIdentity, get_registry_dir
from .runtime import IDARuntime, AnalysisState, create_autoanalysis_hook
from .server import CodeModeHTTPServer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Open one executable in idalib and expose the IDA Code Mode API"
    )
    parser.add_argument("input", type=Path, help="Executable or existing IDB to open")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        input_path = args.input.expanduser().resolve(strict=True)
    except FileNotFoundError:
        print(
            f"ida-codemode-worker: input does not exist: {args.input}", file=sys.stderr
        )
        return 2

    import ida_auto
    import ida_diskio
    import ida_kernwin
    import ida_loader
    import ida_nalt

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
        )
        database_options = {
            "backend": "idalib",
            "input_path": str(input_path),
            "new_database": args.new_database,
            "output_database": str(args.output_database)
            if args.output_database
            else None,
            "processor": args.processor,
            "auto_analysis": False,
            "save_on_close": True,
        }
        runtime = IDARuntime(
            backend="idalib",
            database=database,
            analysis_state=analysis_state,
            database_path=idb_path,
            database_options=database_options,
        )
        server = CodeModeHTTPServer(
            runtime,
            identity,
            analysis_state,
            get_registry_dir(ida_diskio.get_user_idadir()),
            on_shutdown=kernwin.stop_serving,
        )
        server.start()
        print(f"[ida-codemode] {server.url}", flush=True)

        # In IDA 9.4+, serve() dispatches execute_sync requests from HTTP
        # threads until /close_database or a signal calls stop_serving(). A
        # signal received during database startup must not be lost before the
        # serve loop begins.
        if stop_signal is None:
            kernwin.serve()
        return 128 + stop_signal if stop_signal is not None else 0
    except Exception as exc:
        print(f"ida-codemode-worker: {exc}", file=sys.stderr)
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
            except Exception as exc:
                print(
                    f"ida-codemode-worker: failed to close database: {exc}",
                    file=sys.stderr,
                )
        elif database is not None and runtime is None:
            try:
                database.close(save=True)
            except Exception:
                pass
        try:
            analysis_hook.unhook()
        except Exception:
            pass
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


if __name__ == "__main__":
    raise SystemExit(main())
