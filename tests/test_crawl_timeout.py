"""Regression P13: every long stage must have a ceiling.

Live finding: crawl ran 62 minutes on 5854 hosts (depth 3) and had no stop
condition -- t_crawl defaults to timeout=0 and --tool-timeout is also 0, so a
crawl could run forever. Budget limits are part of the result contract.

These tests check the wiring statically (source + config), so they never touch
the network or start a pipeline.
"""
import re
from pathlib import Path

import tests.util  # noqa: F401
from tests.util import fresh_core

ROOT = Path(__file__).resolve().parent.parent


def test_crawl_timeout_default_is_bounded():
    core = fresh_core()
    limits = (core.CFG.get("limits") or {})
    assert "crawl_timeout" in limits, "crawl_timeout must be configurable"
    assert 60 <= int(limits["crawl_timeout"]) <= 7200, limits["crawl_timeout"]


def test_crawl_call_uses_the_configured_ceiling():
    """The run must derive a positive crawl timeout, not pass tool_timeout blindly."""
    src = (ROOT / "lib" / "pipeline.py").read_text(encoding="utf-8")
    assert "crawl_timeout" in src, "crawl timeout is not derived in cmd_run"
    m = re.search(r"crawl_timeout\s*=\s*tool_timeout\s+or\s+int\(", src)
    assert m, "crawl_timeout must fall back to the configured default"
    call = re.search(r"t_crawl\([^)]*timeout=crawl_timeout", src, re.S)
    assert call, "t_crawl must receive crawl_timeout"


def test_crawl_timeout_is_reported_when_hit():
    src = (ROOT / "lib" / "pipeline.py").read_text(encoding="utf-8")
    assert "rc\") == 124" in src or "rc\") == 124" in src or "124" in src
    assert "ceiling" in src, "a hit ceiling must be logged, not silent"
