import importlib.util

import ida_codemode


def test_public_api_is_explicit_and_importable() -> None:
    assert ida_codemode.__all__ == sorted(ida_codemode.__all__)
    assert len(ida_codemode.__all__) == len(set(ida_codemode.__all__))
    for name in ida_codemode.__all__:
        assert getattr(ida_codemode, name) is not None


def test_removed_public_looking_implementation_modules_are_gone() -> None:
    for module in (
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
