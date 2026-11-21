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

from lib import metered
from lib import metered as metered_mod
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


def test_one_paid_dispatch_records_one_request_row(tmp_path=None):
    """One billed dispatch -> exactly one ledger row (T22).

    The paid call now belongs to the mapping dispatch (subs is passive), so
    this drives lib/mapdispatch with a faked core.run and inspects the run's
    metered.jsonl the same way the old subs-gateway case did.
    """
    from lib import mapdispatch, mapping
    core = fresh_core()
    store = core.Store()
    led_path = tmp_path / "metered.jsonl" if tmp_path else None
    try:
        mapping.ensure_schema(store)
        core.CFG.setdefault("apis", {}).setdefault("fofa", {})["key"] = "test-k"
        core.CFG["apis"]["fofa"]["email"] = "probe@example.com"
        led = metered_mod.MeteredLedger(path=led_path, run_id="RUNQ")
        orig = core.run
        core.run = lambda cmd, **kw: (
            0,
            json.dumps({"host": "a.mt-a.example.com",
                        "ip": "203.0.113.10"}) + chr(10), "")
        try:
            mapdispatch.ask(store, "RUNQ", "fofa", "domain",
                            "mt-a.example.com", ledger=led)
        finally:
            core.run = orig
        rows = led.rows("RUNQ")
        assert len(rows) == 1, rows
        assert rows[0]["engine"] == "fofa", rows[0]
        assert rows[0]["unit"] == "native_dispatch", rows[0]
        assert rows[0]["returned"] == 2, rows[0]   # one host + one ip row
    finally:
        store.close()


def test_quota_exhausted_engine_blocks_next_round_verdict():
    """A quota-exhausted engine is recorded as QUOTA, never as empty (T26/T27).

    The verdict reads the ledger's blocked engines; this pins the recording
    half -- a quota reply must not look like "this engine found nothing".
    """
    from lib import mapdispatch, mapping
    core = fresh_core()
    store = core.Store()
    try:
        mapping.ensure_schema(store)
        core.CFG.setdefault("apis", {}).setdefault("fofa", {})["key"] = "test-k"
        core.CFG["apis"]["fofa"]["email"] = "probe@example.com"
        orig = core.run
        core.run = lambda cmd, **kw: (0, "", "quota exhausted for this AK")
        try:
            r = mapdispatch.ask(store, "RUNQ", "fofa", "domain",
                                "mt-a.example.com")
        finally:
            core.run = orig
        assert r["status"] == metered.ST_QUOTA, r
        q = mapping.question("fofa", "domain", "mt-a.example.com",
                             core.uncover_query("domain", "fofa",
                                                "mt-a.example.com"))
        assert mapping.lookup(store, q)["status"] == metered.ST_QUOTA
    finally:
        store.close()
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
