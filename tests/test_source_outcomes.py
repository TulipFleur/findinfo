"""Acceptance: transient-failure handling (retries, gaps, quota, wildcard).

The workflow rules that live at the source layer rather than the run layer:
- a transient source error is retried a bounded number of times,
- a source without a key is "unavailable", never "found nothing",
- a quota-exhausted source says so,
- wildcard (fake) answers never become trusted assets but are reported.
"""
import unittest.mock as mock

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools


def test_retry_recovers_transient_failure():
    core = fresh_core()
    calls = {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        return None if calls["n"] < 3 else {"ok": True}

    with mock.patch.object(core.time, "sleep", lambda *_: None):
        out = core.fetch_with_retry(flaky, attempts=3, backoff=0.01)
    assert out == {"ok": True}
    assert calls["n"] == 3, "must retry until the source answers"


def test_retry_budget_is_bounded():
    core = fresh_core()
    calls = {"n": 0}

    def always_none(*a, **kw):
        calls["n"] += 1
        return None

    with mock.patch.object(core.time, "sleep", lambda *_: None):
        out = core.fetch_with_retry(always_none, attempts=3, backoff=0.01)
    assert out is None
    assert calls["n"] == 3, "a dead source must stop after the budget"


def test_retry_survives_exceptions():
    core = fresh_core()
    calls = {"n": 0}

    def boom_then_ok(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("tunnel dropped")
        return ["data"]

    with mock.patch.object(core.time, "sleep", lambda *_: None):
        out = core.fetch_with_retry(boom_then_ok, attempts=2, backoff=0.01)
    assert out == ["data"]


def test_certs_reports_unreachable_after_retries():
    """Both CT mirrors down => ok=False (failure), NOT an empty result."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    core.CACHE = core.Cache(core.CACHE_DIR / "isolated-retry")
    with mock.patch.object(core, "curl_json", return_value=None), \
         mock.patch.object(core.time, "sleep", lambda *_: None):
        r = tools.t_certs(store, "down.example.net")
    assert r["ok"] is False
    assert r["count"] == 0
    store.close()


def test_engine_without_key_is_unavailable_not_empty():
    """A mapping engine with no key must be reported unavailable."""
    core = fresh_core()
    from tests.util import import_findinfo
    fi = import_findinfo()
    import argparse
    args = argparse.Namespace(engines="fofa,quake", active=False, ports=False,
                              vhost=False, crawl=False, brute=False,
                              no_onepass=True)
    with mock.patch.object(core, "api_key", return_value=""), \
         mock.patch.object(core, "api_base", return_value=""):
        gap = fi._coverage_unavailable(args, False)
    assert "quake" in gap["engines_without_key"]
    assert "fofa" in gap["engines_without_key"]
    assert gap["blocking"] is False, "missing optional keys must not block the run"


def test_missing_required_tool_is_blocking():
    core = fresh_core()
    from tests.util import import_findinfo
    fi = import_findinfo()
    import argparse
    args = argparse.Namespace(engines="fofa", active=False, ports=False,
                              vhost=False, crawl=False, brute=False,
                              no_onepass=True)
    with mock.patch.object(core, "has_tool", return_value=False):
        gap = fi._coverage_unavailable(args, False)
    assert gap["blocking"] is True
    assert "dnsx" in gap["missing_tools"]


def test_wildcard_answers_are_filtered_and_reported():
    """Wildcard zone answers are reported, and never stored as assets."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    import json

    def fake_run(cmd, timeout=300, input_text=None, cwd=None, env=None):
        # the probe name travels on stdin, not in argv
        if any("wildcard-probe" in str(c) for c in cmd) or \
                "wildcard-probe" in (input_text or ""):
            return 0, json.dumps({"host": "findinfo-wildcard-probe-9f3a.w.example.com",
                                  "a": ["9.9.9.9"]}), ""
        return 0, "", ""

    def fake_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        if on_line:
            on_line(json.dumps({"host": "ghost.w.example.com", "a": ["9.9.9.9"]}))
            on_line(json.dumps({"host": "real.other.com", "a": ["1.2.3.4"]}))
        return 0, 2, ""

    with mock.patch.object(core, "run", fake_run), \
         mock.patch.object(core, "run_stream", fake_stream):
        r = tools.t_dns(store, ["ghost.w.example.com", "real.other.com"])
    stored = {a["canonical"] for a in store.get_assets(kind="domain")}
    assert "ghost.w.example.com" not in stored, "wildcard answer is not an asset"
    assert "real.other.com" in stored
    assert r["wildcard"], "the affected zone must be reported, not silently dropped"
    store.close()


def test_quota_exhausted_is_not_reported_as_empty():
    """An exhausted budget must be a coverage gap, not "no assets found".

    The FOFA relay is a PAID mapping backend, so this now belongs to the
    mapping dispatch (subs is passive): a quota error on the wire is recorded
    as ST_QUOTA on the task ledger, and a later run refuses to treat it as an
    answered question.
    """
    from lib import mapdispatch, mapping, metered
    core = fresh_core()
    store = core.Store()
    try:
        mapping.ensure_schema(store)
        core.CFG.setdefault("apis", {}).setdefault("fofa", {})["key"] = "test-k"
        core.CFG["apis"]["fofa"]["email"] = "probe@example.com"
        orig = core.run

        def quota_run(cmd, **kw):
            return 0, "", "quota exhausted for this AK"

        core.run = quota_run
        try:
            r = mapdispatch.ask(store, "RUNQ", "fofa", "domain", "example.com")
        finally:
            core.run = orig
        assert r["status"] == metered.ST_QUOTA, r
        assert r["rows"] == 0, r
        q = mapping.question("fofa", "domain", "example.com",
                             core.uncover_query("domain", "fofa", "example.com"))
        assert mapping.lookup(store, q)["status"] == metered.ST_QUOTA, (
            "an exhausted quota must be recorded as quota, not as empty")
        cov = mapping.coverage(store)
        assert cov["by_engine"]["fofa"]["quota"] == 1, cov
    finally:
        store.close()
def test_quota_flag_reaches_coverage_unavailable():
    """Exercises the real fold used by the pipeline (no network involved)."""
    fin = __import__("findinfo", fromlist=["findinfo"])
    base = {"missing_tools": [], "blocking_tools": [],
            "engines_without_key": [], "blocking": False, "note": ""}
    stages = [{"stage": "subs", "elapsed": 0.1, "found": 0,
               "quota_exhausted": True}]
    out = fin._fold_runtime_unavailable(base, stages)
    assert out["quota_exhausted"] == ["subs"], out
    assert "quota" in out["note"].lower(), out
    # no flag -> the block is returned unchanged
    assert fin._fold_runtime_unavailable(base, [{"stage": "subs"}]) == base
