import argparse
import codeop
import json
import os
import sys

from ida_codemode import CodeModeError, DatabaseHandle, RemoteError

try:
    import readline  # noqa: F401  -- enables line editing in input()
except ImportError:
    pass


def exec(handle: DatabaseHandle, code: str, filename: str, json_mode: bool) -> bool:
    try:
        result = handle.execute_python(code, persist_globals=True, filename=filename)
    except RemoteError as e:
        if stdout := e.details.get("stdout"):
            sys.stdout.write(stdout)
            sys.stdout.flush()

        if stderr := e.details.get("stderr"):
            sys.stderr.write(stderr)
            sys.stderr.flush()

        if "exit_code" in e.details:
            raise SystemExit(e.details["exit_code"])

        if traceback := e.details.get("traceback"):
            print(traceback, file=sys.stderr)
        else:
            print(f"{type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return False
    except CodeModeError as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return False

    if stdout := result["stdout"]:
        stream = sys.stderr if json_mode else sys.stdout
        stream.write(stdout)
        stream.flush()

    if stderr := result["stderr"]:
        sys.stderr.write(stderr)
        sys.stderr.flush()

    obj = result["result"]
    if json_mode:
        print(json.dumps(obj))
    elif obj is not None:
        print(repr(obj))
    return True


def repl(handle: DatabaseHandle):
    compiler, buf = codeop.CommandCompiler(), []
    interactive = sys.stdin.isatty()
    while True:
        try:
            prompt = ("... " if buf else ">>> ") if interactive else ""
            buf.append(input(prompt))
        except (EOFError, KeyboardInterrupt):
            if interactive:
                print()
            return
        try:
            if compiler("\n".join(buf), "<repl>", "single") is None:
                continue  # incomplete block
        except SyntaxError as e:
            print(f"{type(e).__name__}: {e}", file=sys.stderr)
            buf.clear()
            continue
        code, buf = "\n".join(buf), []
        if code:
            exec(handle, code, "<stdin>", json_mode=False)


def main():
    parser = argparse.ArgumentParser(
        description="Execute Python script or command in the context of an IDA database."
    )
    parser.add_argument(
        "path",
        help="Path to the IDB/executable to run script against.",
    )
    parser.add_argument(
        "script",
        help="Path to the Python script to run, or a Python snippet in quotes.",
        nargs="?",
    )
    parser.add_argument(
        "-c",
        metavar="cmd",
        help="Python command to execute in the context of the database.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output only JSON to stdout."
    )
    args = parser.parse_args()

    with DatabaseHandle.open(args.path) as handle:
        if args.c:
            code = args.c
            filename = "<string>"
        elif args.script:
            filename = os.path.abspath(args.script)
            with open(filename, "r") as f:
                code = f.read()
        else:
            return repl(handle)

        if not exec(handle, code, filename, args.json):
            sys.exit(1)


if __name__ == "__main__":
    main()
