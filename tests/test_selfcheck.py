"""Regression: B 环境自检 — distinguish required vs optional capabilities.

The requirement: an unavailable OPTIONAL source is recorded as a coverage gap
and the run continues; an unavailable REQUIRED tool is reported as blocking a
stage while keeping whatever was already collected. These tests pin that split
without touching the network.
"""
import argparse
import io
import json
import unittest.mock as mock
from contextlib import redirect_stdout

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools, import_findinfo


def _args(**over):
    base = dict(
        task="", name="", domain=["example.com"], active=False, ports=False,
        vhost=False, crawl=False, brute=False, brute_wordlist="", brute_bandwidth="3m",
        depth=3, invest=51, deep=2, engines="fofa,quake,hunter,shodan,censys",
        no_icp=True, no_onepass=True, top_ports=1000, max_seed=5,
        max_vhost_ips=10, force_stage=False, background=False, resume="",
        rounds=1, time_budget=0.0, task_timeout=0.0, tool_timeout=0,
        entity_timeout=1200)
    base.update(over)
    return argparse.Namespace(**base)


def _quiet(**over):
    base = {
        "t_certs": lambda s, d, timeout=0: {"count": 0, "ok": True},
        "t_subs": lambda s, d, engines="", timeout=0: {"count": 0, "ok": True},
        "t_dns": lambda s, d, timeout=0: {"count": 0, "ok": True, "rc": 0,
                                         "domains": [], "wildcard": []},
    }
    base.update(over)
    return base


def _run(fi, args, fakes):
    buf = io.StringIO()
    patches = [mock.patch.object(fi.tools, k, side_effect=v) for k, v in fakes.items()]
    for p in patches:
        p.start()
    try:
        with redirect_stdout(buf):
            rc = fi.cmd_run(args)
        return rc, buf.getvalue()
    finally:
        for p in reversed(patches):
            p.stop()


def _summary(core):
    rd = sorted(core.RUNS_DIR.glob("*"), key=lambda p: p.stat().st_mtime)[-1]
    return json.loads((rd / "summary.jsonl").read_text(encoding="utf-8").splitlines()[-1])


def test_missing_optional_engine_key_is_a_gap_not_a_failure():
    """No quake/hunter key: run completes, the gap is recorded."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    with mock.patch.object(core, "api_key", return_value=""), \
         mock.patch.object(core, "api_base", return_value=""):
        rc, _ = _run(fi, _args(engines="fofa,quake"), _quiet())
    assert rc == 0, "a missing optional key must not fail the run"
    s = _summary(core)
    gap = s["coverage"]["unavailable"]
    assert "quake" in gap["engines_without_key"]
    assert gap["blocking"] is False
    assert s["result"]["status"] == "complete"


def test_missing_required_tool_blocks_but_keeps_results():
    """A missing blocking tool is reported, prior collections survive."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    # dns is the only blocking tool; make it fail as if the binary were gone
    def dns_missing(store, domains, timeout=0):
        return {"count": 0, "ok": False, "rc": 127, "error": "dnsx not found",
                "domains": [], "wildcard": []}
    rc, _ = _run(fi, _args(), _quiet(t_dns=dns_missing))
    s = _summary(core)
    failed = {f["stage"] for f in s["coverage"]["failed_stages"]}
    assert "dns" in failed, s["coverage"]["failed_stages"]
    assert s["result"]["status"] in ("partial", "failed")
    assert rc in (1, 5), rc
    # whatever earlier stages collected must still be in the summary
    assert "certs" in s["coverage"]["done_stages"]


def test_retry_helper_gives_up_after_attempts():
    """A source that is really down must not eat the whole budget."""
    core = fresh_core()
    calls = {"n": 0}

    def always_none():
        calls["n"] += 1
        return None

    with mock.patch.object(core.time, "sleep", lambda *_: None):
        out = core.fetch_with_retry(always_none, attempts=3, backoff=0.01)
    assert out is None, "exhausted retries must yield None, not a fake empty result"
    assert calls["n"] == 3, "must attempt exactly 3 times, got %d" % calls["n"]


def test_retry_helper_returns_first_success():
    core = fresh_core()
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        return None if calls["n"] < 2 else {"ok": True, "count": 5}

    with mock.patch.object(core.time, "sleep", lambda *_: None):
        out = core.fetch_with_retry(flaky, attempts=3, backoff=0.01)
    assert out == {"ok": True, "count": 5}
    assert calls["n"] == 2, "must stop at the first success"


def test_retry_helper_survives_an_exception():
    core = fresh_core()
    calls = {"n": 0}

    def boom_then_ok():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("connection reset")
        return "recovered"

    with mock.patch.object(core.time, "sleep", lambda *_: None):
        out = core.fetch_with_retry(boom_then_ok, attempts=3, backoff=0.01)
    assert out == "recovered"

