"""Minimal pytest-fixture-compatible test runner.

This sandbox has no network access, so real `pytest` cannot be installed
here. This script supports just enough of pytest's fixture mechanism
(`tmp_path`, `capsys`) to execute this repository's test suite and verify
it passes. Real usage (CI / local dev) should use actual pytest, declared
in pyproject.toml's `[project.optional-dependencies].dev`.
"""
from __future__ import annotations

import contextlib
import importlib
import io
import os
import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class _CapsysResult:
    def __init__(self, out, err):
        self.out = out
        self.err = err


class _Capsys:
    def __init__(self):
        self._out = io.StringIO()
        self._err = io.StringIO()
        self._ctx = None

    def __enter__(self):
        self._ctx = contextlib.redirect_stdout(self._out)
        self._ctx.__enter__()
        return self

    def __exit__(self, *a):
        self._ctx.__exit__(*a)

    def readouterr(self):
        out = self._out.getvalue()
        err = self._err.getvalue()
        self._out.truncate(0)
        self._out.seek(0)
        return _CapsysResult(out, err)


def _install_pytest_stub():
    """Install a minimal stand-in for `pytest` (only `pytest.raises`) since
    real pytest cannot be installed in this offline sandbox. Real
    environments should use actual pytest, not this stub.
    """
    if "pytest" in sys.modules:
        return
    import types

    stub = types.ModuleType("pytest")
    stub.raises = _raises
    sys.modules["pytest"] = stub


@contextlib.contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    else:
        raise AssertionError(f"Expected {exc_type} to be raised")


def run_module(modname: str) -> tuple[int, int, list]:
    mod = importlib.import_module(modname)
    passed = 0
    failed = 0
    failures = []
    for name in dir(mod):
        if not name.startswith("test_"):
            continue
        fn = getattr(mod, name)
        if not callable(fn):
            continue
        params = fn.__code__.co_varnames[: fn.__code__.co_argcount]
        kwargs = {}
        tmp_dir_ctx = None
        capsys = None
        try:
            if "tmp_path" in params:
                tmp_dir_ctx = tempfile.TemporaryDirectory()
                kwargs["tmp_path"] = pathlib.Path(tmp_dir_ctx.name)
            if "capsys" in params:
                capsys = _Capsys()
                capsys.__enter__()
                kwargs["capsys"] = capsys
            fn(**kwargs)
            passed += 1
        except Exception:
            failed += 1
            failures.append((f"{modname}.{name}", traceback.format_exc()))
        finally:
            if capsys is not None:
                capsys.__exit__(None, None, None)
            if tmp_dir_ctx is not None:
                tmp_dir_ctx.cleanup()
    return passed, failed, failures


def main():
    _install_pytest_stub()
    modules = [
        "tests.test_discovery",
        "tests.test_parsers",
        "tests.test_capabilities",
        "tests.test_permissions",
        "tests.test_attack_paths",
        "tests.test_diff",
        "tests.test_scoring",
        "tests.test_outputs",
        "tests.test_cli",
    ]
    total_passed = 0
    total_failed = 0
    all_failures = []
    for modname in modules:
        passed, failed, failures = run_module(modname)
        total_passed += passed
        total_failed += failed
        all_failures.extend(failures)
        print(f"{modname}: {passed} passed, {failed} failed")

    print()
    print(f"TOTAL: {total_passed} passed, {total_failed} failed")
    for name, tb in all_failures:
        print(f"\n--- FAILURE: {name} ---")
        print(tb)

    sys.exit(1 if total_failed else 0)


if __name__ == "__main__":
    main()
