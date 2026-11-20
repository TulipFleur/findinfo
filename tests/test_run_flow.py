"""Acceptance: the collection loop advances on real results (simulated tools).

Each test patches lib.tools collectors -- the same seam the existing stage tests
use -- so orchestration, checkpoints, result/coverage reporting, reflow rounds
and the exit code are exercised with no target and no API call.
"""
import argparse
import io
import os
import json
import unittest.mock as mock
from contextlib import redirect_stdout

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo


def _args(**over):
    base = dict(
        task="", name="", domain=["example.com"], active=False, ports=False,
        vhost=False, crawl=False, brute=False, brute_wordlist="", brute_bandwidth="3m",
        depth=3, invest=51, deep=2, engines="fofa,quake,hunter,shodan,censys",
        no_icp=True, no_onepass=True, top_ports=1000, max_seed=5,
        max_vhost_ips=10, force_stage=False, background=False, resume="",
        rounds=1, time_budget=0.0, task_timeout=0.0, tool_timeout=0)
    base.update(over)
    return argparse.Namespace(**base)


def _seed_resolved(core, *domains):
    """Put resolved hosts in the store so the probe stage has a work set."""
    store = core.Store()
    try:
        for d in domains:
            store.upsert_asset("domain", d, source="dnsx", confidence=0.8)
    finally:
        store.close()


def _run_quiet(fi, args, fakes):
    """Run cmd_run with patched collectors, swallowing the stdout summary."""
    buf = io.StringIO()
    patches = [mock.patch.object(fi.tools, name, side_effect=fn)
               for name, fn in fakes.items()]
    for p in patches:
        p.start()
    try:
        with redirect_stdout(buf):
            rc = fi.cmd_run(args)
        payload = None
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip().startswith("{")]
        if lines:
            payload = json.loads(lines[-1])
        return rc, payload
    finally:
        for p in reversed(patches):
            p.stop()


def _latest_summary(core):
    rd = sorted(core.RUNS_DIR.glob("*"), key=lambda p: p.stat().st_mtime)[-1]
    return rd, json.loads((rd / "summary.jsonl").read_text(encoding="utf-8").splitlines()[-1])


def _quiet(**fakes):
    """Collectors that answer instantly with empty success."""
    base = {
        "t_certs": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True},
        "t_subs": lambda s, d, engines="", timeout=0, **kw: {"count": 0, "ok": True},
        "t_dns": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True, "rc": 0,
                                         "domains": [], "wildcard": []},
    }
    base.update(fakes)
    return base


def test_first_pass_completes_and_reports_result():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    rc, payload = _run_quiet(fi, _args(), _quiet())
    assert rc == 0
    rd, summary = _latest_summary(core)
    assert summary["result"]["status"] == "complete"
    assert summary["coverage"]["complete"] is True
    assert "dns" in summary["coverage"]["done_stages"]
    assert summary["coverage"]["failed_stages"] == []
    assert summary["rounds"][0]["stop"] in ("no_new_assets", "single_round")
    st = json.loads((rd / "status.json").read_text(encoding="utf-8"))
    assert st["state"] == "completed"
    assert st["result"]["status"] == "complete"
    assert st["stage_index"] >= 1 and st["stage_total"] >= 1
    assert payload["result"]["run_id"] == rd.name


def test_partial_stage_reports_gap_and_exit_5():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    rc, _ = _run_quiet(fi, _args(), _quiet(
        t_certs=lambda s, d, timeout=0, **kw: {"count": 0, "ok": False, "rc": 124}))
    assert rc == 5, "finished with a failed stage must not exit 0"
    rd, summary = _latest_summary(core)
    assert summary["result"]["status"] == "partial"
    assert summary["result"]["reason"] == "stage_failed"
    failed = {f["stage"] for f in summary["coverage"]["failed_stages"]}
    assert "certs" in failed
    assert failed.isdisjoint(set(summary["coverage"]["done_stages"]))
    steps = {r[0]: r[1] for r in core.Store().conn.execute("SELECT step,status FROM steps")}
    assert steps.get("certs") != "done", "failed stage must not be checkpointed done"


def test_empty_result_is_valid_not_failure():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    rc, _ = _run_quiet(fi, _args(), _quiet())
    assert rc == 0
    _, summary = _latest_summary(core)
    assert summary["result"]["status"] == "complete"
    assert summary["coverage"]["failed_stages"] == []


def test_missing_engine_key_is_coverage_gap():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    with mock.patch.object(core, "api_key", return_value=""), \
         mock.patch.object(core, "api_base", return_value=""):
        rc, _ = _run_quiet(fi, _args(engines="fofa,quake"), _quiet())
    assert rc == 0, "a missing optional key must not fail the run"
    _, summary = _latest_summary(core)
    gap = summary["coverage"]["unavailable"]
    assert "quake" in gap["engines_without_key"]
    assert gap["blocking"] is False


def test_rounds_stop_when_no_new_asset():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    calls = {"dns": 0}

    def fake_dns(store, domains, timeout=0, **kw):
        calls["dns"] += 1
        for d in domains:
            store.upsert_asset("domain", d, source="dnsx", confidence=0.8)
        return {"count": len(domains), "ok": True, "rc": 0, "domains": [], "wildcard": []}

    rc, _ = _run_quiet(fi, _args(rounds=3), _quiet(t_dns=fake_dns))
    assert rc == 0
    _, summary = _latest_summary(core)
    assert len(summary["rounds"]) == 1
    assert summary["rounds"][0]["stop"] == "no_new_assets"
    assert calls["dns"] == 1


def test_rounds_repeat_while_new_assets_appear():
    """A round that discovers new in-scope hosts must trigger another round."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    _seed_resolved(core, "a.example.com")     # a host to verify in round 1
    state = {"round": 0, "dns": 0}

    def fake_probe(store, hosts, timeout=0, **kw):
        state["round"] += 1
        store.upsert_asset("domain", "n%d.example.com" % state["round"],
                           source="httpx", confidence=0.9)
        return {"count": len(hosts), "ok": True, "rc": 0, "truncated": False}

    def fake_dns(store, domains, timeout=0, **kw):
        state["dns"] += 1
        for d in domains:
            store.upsert_asset("domain", d, source="dnsx", confidence=0.8)
        return {"count": len(domains), "ok": True, "rc": 0, "domains": [], "wildcard": []}

    rc, _ = _run_quiet(fi, _args(active=True, rounds=3), _quiet(
        t_dns=fake_dns, t_httpx=fake_probe,
        t_ipagg=lambda s, **kw: {"candidates": [], "count_candidates": 0}))
    _, summary = _latest_summary(core)
    assert len(summary["rounds"]) >= 2, summary["rounds"]
    assert summary["rounds"][0]["new_domains"] >= 1
    stop = summary["rounds"][-1]["stop"]
    assert stop in ("no_new_assets", "max_rounds"), stop
    assert state["dns"] >= 2, "each round re-resolves the grown work set"
    if stop == "max_rounds":
        assert summary["result"]["status"] == "partial"
        assert summary["result"]["reason"] == "round_budget_exhausted"
        assert rc == 5
    else:
        assert summary["result"]["status"] == "complete"
        assert rc == 0


def test_time_budget_stops_rounds_and_marks_partial():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    _seed_resolved(core, "a.example.com")
    state = {"n": 0}

    def fake_probe(store, hosts, timeout=0, **kw):
        state["n"] += 1
        store.upsert_asset("domain", "b%d.example.com" % state["n"],
                           source="httpx", confidence=0.9)
        return {"count": len(hosts), "ok": True, "rc": 0}

    def fake_dns(store, domains, timeout=0, **kw):
        for d in domains:
            store.upsert_asset("domain", d, source="dnsx", confidence=0.8)
        return {"count": len(domains), "ok": True, "rc": 0, "domains": [], "wildcard": []}

    rc, _ = _run_quiet(fi, _args(active=True, rounds=5, time_budget=0.001), _quiet(
        t_dns=fake_dns, t_httpx=fake_probe,
        t_ipagg=lambda s, **kw: {"candidates": [], "count_candidates": 0}))
    _, summary = _latest_summary(core)
    assert summary["coverage"]["stop_reason"] == "time_budget"
    assert summary["result"]["status"] == "partial"
    assert rc == 5


def test_background_launch_reuses_inflight_job():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    import lib.jobs as jobs_mod
    launched = {}

    def fake_spawn(rd):
        launched["rd"] = rd
        return 4242

    with mock.patch.object(jobs_mod, "spawn", side_effect=fake_spawn):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = fi.cmd_run(_args(background=True))
        first = json.loads(buf.getvalue().strip().splitlines()[-1])
        assert rc == 0 and first["started"] is True
        assert first["run_id"] and first["state_path"] and first["result_path"]
        assert first["pid"] == 4242
        assert first["planned_stages"], "the plan is published before the worker runs"
        # a live in-flight worker: use this process's pid, which is certainly alive
        import os as _os
        jobs_mod.update_state(launched["rd"], state="running", pid=_os.getpid())
        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            fi.cmd_run(_args(background=True))
        second = json.loads(buf2.getvalue().strip().splitlines()[-1])
        assert second["reused"] is True
        assert second["run_id"] == first["run_id"]


def test_launch_response_lost_still_does_not_duplicate():
    """Requirement 8.3: a lost launch reply must not create a second run."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    import lib.jobs as jobs_mod
    spawned = []

    def fake_spawn(rd):
        # no real child: this test is about the dedupe decision, not the worker
        spawned.append(rd)
        return 4242

    with mock.patch.object(jobs_mod, "spawn", side_effect=fake_spawn):
        buf = io.StringIO()
        with redirect_stdout(buf):
            fi.cmd_run(_args(background=True))
        first = json.loads(buf.getvalue().strip().splitlines()[-1])
        assert first["started"] is True and first["reused"] is False
        # the caller never saw that reply; the job is in flight and alive
        jobs_mod.update_state(spawned[0], state="running", pid=os.getpid())
        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            fi.cmd_run(_args(background=True))
        second = json.loads(buf2.getvalue().strip().splitlines()[-1])
    assert second["reused"] is True, (
        "a lost launch response created a duplicate collection: " + json.dumps(second))
    assert second["run_id"] == first["run_id"]
    assert len(spawned) == 1, "only one worker may start for one in-flight job"


def test_foreground_status_write_carries_scope():
    """Section 7: scope must be recoverable from state, not from memory."""
    core = fresh_core()
    fi = import_findinfo()
    import lib.jobs as jobs_mod
    rd = core.new_run_dir("scope-check")
    # exercise the exact writer the foreground path uses
    fi._write_status(rd, stage="prepare", state="running", stage_state="running",
                     target="example.com", run_id=rd.name, active=False,
                     scope=core.canon_scope(["example.com"]),
                     planned_stages=["dns"], stage_index=0, stage_total=1,
                     started_ts=jobs_mod.now_ts(), rounds=1,
                     budget={"rounds": 1, "time_budget_sec": 0})
    st = jobs_mod.read_state(rd)
    assert st.get("scope") == ["example.com"], (
        "status.json lost the scope, so a fresh session cannot tell what was "
        "collected: " + repr(st.get("scope")))
    assert st.get("target") == "example.com"


def test_failed_source_keeps_other_sources_assets():
    """Req 5.2: after retries are exhausted, other sources' results must stay."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()

    def certs_down(store, d, timeout=0):
        return {"count": 0, "ok": False, "rc": 124}

    def subs_finds_three(store, d, engines="", timeout=0):
        for h in ("a.example.com", "b.example.com", "c.example.com"):
            store.upsert_asset("domain", h, source="subfinder", confidence=0.8)
        return {"domain": d, "count": 3, "domains": []}

    rc, _ = _run_quiet(fi, _args(), _quiet(t_certs=certs_down, t_subs=subs_finds_three))
    rd, summary = _latest_summary(core)
    assert rc == 5, "a failed stage makes the run partial, not complete"
    assert summary["result"]["status"] == "partial"
    # the failed source is reported as a gap ...
    assert "certs" in {f["stage"] for f in summary["coverage"]["failed_stages"]}
    # ... while the healthy source's assets survive in the store
    names = {a["canonical"] for a in core.Store().get_assets(kind="domain", min_conf=0.7)}
    for h in ("a.example.com", "b.example.com", "c.example.com"):
        assert h in names, "one failed source dropped another source's results: " + h
