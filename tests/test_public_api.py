import importlib.util
import tomllib
from pathlib import Path

import ida_codemode


def test_public_api_is_explicit_and_importable() -> None:
    assert ida_codemode.__all__ == sorted(ida_codemode.__all__)
    assert len(ida_codemode.__all__) == len(set(ida_codemode.__all__))
    for name in ida_codemode.__all__:
        assert getattr(ida_codemode, name) is not None


def test_wheel_includes_every_console_script_module() -> None:
    project_root = Path(__file__).parents[1]
    with (project_root / "pyproject.toml").open("rb") as file:
        config = tomllib.load(file)

    scripts = config["project"]["scripts"]
    assert scripts == {"ida-codemode": "ida_codemode.cli:main"}

    included = set(config["tool"]["hatch"]["build"]["targets"]["wheel"]["only-include"])
    for script, target in scripts.items():
        module = target.partition(":")[0]
        root_module = module.partition(".")[0]
        assert root_module in included or f"{root_module}.py" in included, (
            f"wheel omits module {module!r} required by console script {script!r}"
        )


def test_removed_public_looking_implementation_modules_are_gone() -> None:
    for module in (
        "ida_codemode_dashboard",
        "ida_codemode_exec",
        "ida_codemode_mcp",
        "ida_codemode.client",
        "ida_codemode.database",
        "ida_codemode.http",
        "ida_codemode.registry",
        "ida_codemode.resolver",
        "ida_codemode.runtime",
        "ida_codemode.serialization",
        "ida_codemode.server",
    ):
        assert importlib.util.find_spec(module) is None
