#!/usr/bin/env python3
"""Check that wheel console-script targets are present in the wheel."""

from __future__ import annotations

import configparser
import sys
import zipfile
from pathlib import Path


def check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())
        entry_points = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(entry_points) != 1:
            raise RuntimeError(
                f"{path}: expected one entry_points.txt, found {len(entry_points)}"
            )

        config = configparser.ConfigParser()
        config.read_string(wheel.read(entry_points[0]).decode("utf-8"))
        for script, target in config.items("console_scripts", raw=True):
            module = target.partition(":")[0].strip()
            module_path = module.replace(".", "/")
            candidates = {f"{module_path}.py", f"{module_path}/__init__.py"}
            if names.isdisjoint(candidates):
                raise RuntimeError(
                    f"{path}: console script {script!r} targets missing module "
                    f"{module!r}"
                )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} WHEEL [WHEEL ...]")
    for argument in sys.argv[1:]:
        check_wheel(Path(argument))
