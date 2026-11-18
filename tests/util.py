"""Shared test helpers: isolated FINDINFO_HOME + per-test task/core reload.

Every test module MUST import this module FIRST (before lib.*) so that the
temp-home environment is in place when lib.core resolves its paths at import
time. Tests that need a specific task call fresh_core() to get a reloaded
core module bound to that task's database.
"""
from __future__ import annotations

import importlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_HOMES: list[str] = []


def _new_home() -> str:
    home = tempfile.mkdtemp(prefix="findinfo-test-")
    _HOMES.append(home)
    return home


# module import default: an isolated home, no task
os.environ["FINDINFO_HOME"] = _new_home()
os.environ.pop("FINDINFO_TASK", None)


def fresh_core(task: str | None = None):
    """Reload lib.core under a NEW temp home (optionally with a task name).

    Returns the reloaded module. Callers that also use lib.tools must reload
    tools afterwards so its `from . import core` binding stays current.
    """
    os.environ["FINDINFO_HOME"] = _new_home()
    if task:
        os.environ["FINDINFO_TASK"] = task
    else:
        os.environ.pop("FINDINFO_TASK", None)
    import lib.core as core
    importlib.reload(core)
    return core


def fresh_tools(core_mod):
    """Reload lib.tools bound to the given (already reloaded) core module."""
    import lib.tools as tools
    importlib.reload(tools)
    return tools


def import_findinfo():
    """Import findinfo.py as a module (env already set by fresh_core)."""
    spec = importlib.util.spec_from_file_location(
        "findinfo_main", ROOT / "findinfo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cleanup() -> None:
    for home in _HOMES:
        shutil.rmtree(home, ignore_errors=True)
    _HOMES.clear()
