"""Acceptance #5: resume after failure retries only the failed stage.

Covers the "失败续跑" rule at the pipeline level: a stage that failed leaves no
done-checkpoint, so the next pass re-runs it, while stages that already
succeeded are skipped (their work set is rebuilt from the scoped store).
"""
import argparse
import io
import json
import unittest.mock as mock
from contextlib import redirect_stdout

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools, import_findinfo


def _args():
    return argparse.Namespace(
        task="", name="", domain=["example.com"], active=False, ports=False,
        vhost=False, crawl=False, brute=False, brute_wordlist="", brute_bandwidth="3m",
        depth=3, invest=51, deep=2, engines="fofa",
        no_icp=True, no_onepass=True, top_ports=1000, max_seed=5,
        max_vhost_ips=10, force_stage=False, background=False, resume="",
        rounds=1, time_budget=0.0, task_timeout=0.0, tool_timeout=0)


def _stage_status(core):
    return {r[0]: r[1] for r in core.Store().conn.execute("SELECT step,status FROM steps")}


def test_failed_stage_retried_succeeded_stage_skipped():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    seen = {"subs": 0, "dns": 0, "certs": 0}

    def flaky_certs(store, domain, timeout=0):
        seen["certs"] += 1
        if seen["certs"] == 1:
            return {"count": 0, "ok": False, "rc": 28}      # timeout on pass 1
        store.upsert_asset("domain", "api." + domain, source="crt.sh", confidence=0.5)
        return {"count": 1, "ok": True, "upstream": "crt.sh"}

    def fake_subs(store, domain, engines="", timeout=0):
        seen["subs"] += 1
        return {"count": 0, "ok": True}

    def fake_dns(store, domains, timeout=0):
        seen["dns"] += 1
        for d in domains:
            store.upsert_asset("domain", d, source="dnsx", confidence=0.8)
        return {"count": len(domains), "ok": True, "rc": 0, "domains": [], "wildcard": []}

    fakes = {"t_certs": flaky_certs, "t_subs": fake_subs, "t_dns": fake_dns}
    patches = [mock.patch.object(tools, n, side_effect=f) for n, f in fakes.items()]
    for p in patches:
        p.start()
    try:
        with redirect_stdout(io.StringIO()):
            rc1 = fi.cmd_run(_args())
        assert rc1 == 5, "first pass finishes with a failed stage -> exit 5"
        steps1 = _stage_status(core)
        assert steps1.get("certs") == "failed"
        # a failed stage must not be recorded as done, otherwise the retry is lost
        assert steps1.get("certs") != "done"
        assert steps1.get("subs") == "done" and steps1.get("dns") == "done"

        with redirect_stdout(io.StringIO()):
            rc2 = fi.cmd_run(_args())
        steps2 = _stage_status(core)
        assert steps2.get("certs") == "done", "the retry must actually run certs"
        assert seen["certs"] == 2
        # stages whose inputs did not change are skipped from the checkpoint...
        assert seen["subs"] == 1, "completed subs stage must be skipped on re-run"
        # ...while dns re-runs because its input set CHANGED (the retried certs
        # stage added a host), which is the correct behaviour, not a redo
        assert seen["dns"] == 2, "dns must re-run on the grown work set"
        hosts = {a["canonical"] for a in core.Store().get_assets(kind="domain")}
        assert "api.example.com" in hosts, "the retry's new host must be resolved"
        assert rc2 == 0, "after the retry the run is complete"
    finally:
        for p in reversed(patches):
            p.stop()


def test_rerun_after_failure_keeps_previous_assets():
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    calls = {"n": 0}

    def certs(store, domain, timeout=0):
        calls["n"] += 1
        store.upsert_asset("domain", "h%d.%s" % (calls["n"], domain),
                           source="crt.sh", confidence=0.5)
        if calls["n"] == 1:
            return {"count": 1, "ok": False, "rc": 124}
        return {"count": 1, "ok": True}

    patches = [
        mock.patch.object(tools, "t_certs", side_effect=certs),
        mock.patch.object(tools, "t_subs", return_value={"count": 0, "ok": True}),
        mock.patch.object(tools, "t_dns", side_effect=lambda s, d, timeout=0: {
            "count": 0, "ok": True, "rc": 0, "domains": [], "wildcard": []}),
    ]
    for p in patches:
        p.start()
    try:
        with redirect_stdout(io.StringIO()):
            fi.cmd_run(_args())            # pass 1: certs partially fails
        with redirect_stdout(io.StringIO()):
            fi.cmd_run(_args())            # pass 2: retry succeeds
    finally:
        for p in reversed(patches):
            p.stop()
    stored = {a["canonical"] for a in core.Store().get_assets(kind="domain")}
    assert "h1.example.com" in stored, "partial output of a failed stage is kept"
    assert "h2.example.com" in stored, "the retry adds its own output"
