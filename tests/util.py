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
    pin_environment()
    return tools


def pin_dns_environment(fake_ip: bool = False) -> None:
    """Pin the resolver verdict AND the config switch for the whole process.

    Same contract as pin_environment, plus core.CFG["dns"]["fake_ip"] so a
    config file on the host cannot turn the DoH path on behind a test's back
    (a test that exercises DoH pins it on and injects a doh_client).
    """
    import lib.doh as doh
    doh.reset_environment_cache()
    doh._ENV_CACHE["value"] = {
        "fake_ip_dns": bool(fake_ip), "probe": "", "answers": [],
        "reason": "pinned by tests.util"}
    import lib.core as core
    core.CFG["dns"] = dict(core.CFG.get("dns") or {})
    core.CFG["dns"]["fake_ip"] = "on" if fake_ip else "off"


def unpin_dns_environment() -> None:
    """Forget the pinned verdict (a test that wants the real detection)."""
    import lib.doh as doh
    doh.reset_environment_cache()
    import lib.core as core
    core.CFG["dns"] = dict(core.CFG.get("dns") or {})
    core.CFG["dns"]["fake_ip"] = "auto"


def pin_environment(fake_ip_dns: bool = False):
    """Pin the fake-IP environment probe so tests never depend on the network.

    `lib.doh` asks the OS resolver whether a name that cannot exist comes back
    with a 198.18.0.0/15 address, and moves the whole DNS stage to DoH when it
    does. On a developer machine behind Clash/TUN that answer is "yes", so the
    same test took the DoH path, reached for the public resolver and asserted
    against live answers -- it failed on that machine and passed on CI. A test
    that pins resolver behaviour must not inherit the host's tunnel.

    Pass `fake_ip_dns=True` in the tests that exercise the fake-IP path.
    """
    import lib.doh as doh
    block = doh.detect_environment(fake_ip_dns)
    doh._ENV_CACHE["value"] = block
    return block


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
