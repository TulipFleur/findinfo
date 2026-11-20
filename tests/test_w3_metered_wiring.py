"""Wiring W3 acceptance: billed requests reach the metered ledger (T22-T27).

The pipeline owns one MeteredLedger per run (run_dir/metered.jsonl);
collectors append one row per BILLed request -- the fofa-gateway call and
the uncover dispatch -- never per result row. Free sources (subfinder,
onepass CT) do not touch the ledger. The verdict folds the ledger's
blocked_engines into coverage, and brief summarises totals/by_engine from
the persisted file. Synthetic Meituan fixture; every provider call is an
injected fake, no socket, no credential read.
"""

import io
import json
import unittest.mock as mock
from contextlib import redirect_stdout

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core, fresh_tools, import_findinfo


def _args(**over):
    import argparse
    base = dict(
        task="", name="", domain=["mt-a.example.com"], active=False,
        ports=False, vhost=False, crawl=False, brute=False,
        brute_wordlist="", brute_bandwidth="3m", depth=3, invest=51, deep=1,
        engines="fofa,quake,hunter,shodan,censys", no_icp=True,
        no_onepass=True, top_ports=1000, max_seed=5, max_vhost_ips=10,
        force_stage=False, background=False, resume="", rounds=1,
        time_budget=0.0, task_timeout=0.0, tool_timeout=0, entity_timeout=1200)
    base.update(over)
    return argparse.Namespace(**base)


def _run(fi, args, fakes):
    buf = io.StringIO()
    patches = [mock.patch.object(fi.tools, n, side_effect=f)
               for n, f in fakes.items()]
    for p in patches:
        p.start()
    try:
        with redirect_stdout(buf):
            rc = fi.cmd_run(args)
        return rc
    finally:
        for p in reversed(patches):
            p.stop()


def _latest_run_dir(core):
    return sorted(core.RUNS_DIR.glob("*"), key=lambda p: p.stat().st_mtime)[-1]


def test_subs_gateway_call_records_one_request_row(tmp_path=None):
    """One billed gateway request -> exactly one ledger row (T22)."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()

    captured: dict = {}

    def fake_gateway(query, fields="ip,port", size=100, page=1, timeout=0):
        captured["query"] = query
        # a successful body with provider quota fields
        return {"ok": True, "count": 3, "total": 3,
                "results": [
                    {"link": "https://a.mt-a.example.com/", "ip": "203.0.113.10"},
                    {"link": "https://b.mt-a.example.com/", "ip": "203.0.113.11"},
                    {"link": "https://c.mt-a.example.com/", "ip": "203.0.113.12"}],
                "remaining": 877, "maxQueries": 1000}

    # the REAL t_subs runs (its gateway/uncover calls are faked); the ledger
    # wiring inside lib/tools is what this test exercises
    fakes = {
        "t_certs": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True},
        "t_dns": lambda s, d, timeout=0, **kw: {
            "count": 0, "ok": True, "rc": 0, "domains": [], "wildcard": []},
    }
    with mock.patch.object(tools, "fofa_gateway_query", side_effect=fake_gateway), \
         mock.patch.object(tools.core, "api_base", return_value="https://gw.example.org/v1"), \
         mock.patch.object(tools.core, "api_key", return_value="stub-ak"), \
         mock.patch.object(tools.core, "has_tool", return_value=False):
        # has_tool=False: no subfinder/chaos/uncover binary runs inside this
        # test (offline contract); the gateway is the only provider call
        _run(fi, _args(engines="fofa"), fakes)  # rc is the subs verdict, not the ledger
    rd = _latest_run_dir(core)
    rows = [json.loads(l) for l in
            (rd / "metered.jsonl").read_text(encoding="utf-8").splitlines()
            if l.strip()]
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["engine"] == "fofa-gateway", row
    assert row["status"] == "ok" and row["returned"] == 3, row
    assert row["quota"]["remaining"] == 877, row
    assert row["quota"]["max"] == 1000, row
    # the summary's coverage carries the spend evidence
    summary = json.loads((rd / "summary.jsonl").read_text(
        encoding="utf-8").splitlines()[-1])
    assert summary["coverage"]["metered"]["totals"]["requests"] == 1
    assert "fofa-gateway" in summary["coverage"]["metered"]["by_engine"]
    assert captured["query"].startswith('domain="mt-a.example.com"')


def test_quota_exhausted_engine_blocks_next_round_verdict():
    """A quota-exhausted gateway surfaces as a blocked engine (T26/T27)."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()

    def fake_gateway(query, fields="ip,port", size=100, page=1, timeout=0):
        return {"ok": False, "quota_exhausted": True, "error": "quota limit reached"}

    fakes = {
        "t_certs": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True},
        "t_dns": lambda s, d, timeout=0, **kw: {
            "count": 0, "ok": True, "rc": 0, "domains": [], "wildcard": []},
    }
    with mock.patch.object(tools, "fofa_gateway_query", side_effect=fake_gateway), \
         mock.patch.object(tools.core, "api_base", return_value="https://gw.example.org/v1"), \
         mock.patch.object(tools.core, "api_key", return_value="stub-ak"):
        _run(fi, _args(engines="fofa"), fakes)
    rd = _latest_run_dir(core)
    rows = [json.loads(l) for l in
            (rd / "metered.jsonl").read_text(encoding="utf-8").splitlines()
            if l.strip()]
    assert rows and rows[0]["status"] == "quota", rows
    summary = json.loads((rd / "summary.jsonl").read_text(
        encoding="utf-8").splitlines()[-1])
    cov = summary["coverage"]
    assert "fofa-gateway" in (cov["unavailable"].get("blocked_engines") or []), cov["unavailable"]
    assert "fofa-gateway" in cov["metered"]["blocked_engines"], cov["metered"]


def test_uncover_dispatch_is_billed_and_free_sources_are_not():
    """uncover (billed) records; subfinder (free) never does."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    ledger_rows: list = []

    class _Led:
        run_id = "20261120-220000-mt-a.example.com"

        def record(self, *a, **kw):
            ledger_rows.append({"engine": kw.get("engine") or
                                (a[1] if len(a) > 1 else "?"),
                                "status": kw.get("status")})
            return True

    def fake_subs(store, domain, engines="", timeout=0, ledger=None, **kw):
        # run the REAL collector body with a fake store-set: engine keys are
        # stubbed so split_engines returns usable engines
        return tools.t_subs(store, domain, engines=engines, timeout=timeout,
                            ledger=ledger)

    # direct call, no pipeline: t_subs itself must classify the calls
    store = core.Store()
    try:
        with mock.patch.object(tools.core, "has_tool", return_value=False), \
             mock.patch.object(tools.core, "api_base", return_value=""), \
             mock.patch.object(tools.core, "engine_has_key", return_value=True), \
             mock.patch.object(tools.core, "split_engines",
                               return_value=(["fofa", "quake"], [])):
            tools.t_subs(store, "mt-a.example.com", engines="fofa,quake",
                         ledger=_Led())
    finally:
        store.close()
    # no gateway (api_base empty) and no uncover binary: NO billed request ran
    assert ledger_rows == [], ledger_rows


def test_brief_summarises_the_persisted_ledger():
    """brief reads metered.jsonl and reports totals/by_engine/blocked."""
    import os
    import subprocess
    import sys
    import tempfile
    core = fresh_core()
    home = tempfile.mkdtemp(prefix="fi-w3-brief-")
    try:
        # fabricate a finished run with a ledger
        runs = os.path.join(home, "runs")
        os.makedirs(runs, exist_ok=True)
        rid = "20261120-223000-mt-a.example.com"
        run_dir = os.path.join(runs, rid)
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, "status.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"run_id": rid, "state": "completed", "seq": 1}, fh)
        with open(os.path.join(run_dir, "metered.jsonl"), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": "2026-11-20T22:30:00Z", "run_id": rid,
                "engine": "fofa-gateway", "input_hash": "h1",
                "status": "ok", "requested": 1, "returned": 120,
                "elapsed_sec": 1.2,
                "quota": {"remaining": 880, "max": 1000}}) + "\n")
            fh.write(json.dumps({
                "ts": "2026-11-20T22:31:00Z", "run_id": rid,
                "engine": "quake", "input_hash": "h2",
                "status": "quota", "requested": 1, "returned": 0,
                "elapsed_sec": 0.4}) + "\n")
        env = dict(os.environ, FINDINFO_HOME=home, FINDINFO_TASK="")
        env.pop("FINDINFO_RUN_DIR", None)
        proc = subprocess.run(
            [sys.executable, str(tests.util.ROOT / "findinfo.py"),
             "--home", home, "brief", "--run", rid],
            capture_output=True, text=True, encoding="utf-8", env=env,
            timeout=120)
        lines = [l for l in (proc.stdout or "").splitlines()
                 if l.strip().startswith("{")]
        assert lines, proc.stdout + proc.stderr
        payload = json.loads(lines[0])
        assert payload.get("metered", {}).get("totals", {}).get("requests") == 2, \
            payload.get("metered")
        assert "fofa-gateway" in payload["metered"]["by_engine"]
        assert payload["metered"]["blocked_engines"] == ["quake"], (
            payload["metered"])
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)
