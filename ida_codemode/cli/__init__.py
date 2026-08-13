"""Command-line interface for ida-codemode."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

_COMMAND_HELP = {
    "mcp": "run the MCP server",
    "dashboard": "browse semantic session traces",
    "exec": "execute Python against an IDA database",
    "logs": "create a portable session log archive",
}

_COMMAND_HIDDEN = (
    "worker",
    "benchmark",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ida-codemode",
        description="IDA Code Mode command-line tools",
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, help_text in _COMMAND_HELP.items():
        commands.add_parser(name, add_help=False, help=help_text)
    return parser


def _command(name: str) -> Callable[[list[str] | None], int]:
    # Imports are intentionally lazy so lightweight commands do not initialize
    # the MCP server, dashboard, or idalib-facing modules unnecessarily.
    if name == "mcp":
        from .mcp import cli

        return cli
    if name == "dashboard":
        from .dashboard import cli

        return cli
    if name == "exec":
        from .exec import main

        return main
    if name == "logs":
        from .logs import main

        return main
    if name == "benchmark":
        from .benchmark import main

        return main
    if name == "worker":
        from .worker import main

        return main
    raise KeyError(name)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if not arguments:
        parser.print_help()
        return 0
    if arguments[0] in {"-h", "--help"}:
        parser.print_help()
        return 0

    command = arguments.pop(0)
    if command not in _COMMAND_HELP and command not in _COMMAND_HIDDEN:
        parser.error(f"argument COMMAND: invalid choice: {command!r}")
    return _command(command)(arguments)
