"""P2 acceptance: checkpoint resume, failure propagation, full work sets.

- Passive run then --active: the dns checkpoint resumes from the scoped store
  and the active probe stage executes on the FULL set.
- A stage whose tool failed (rc!=0) writes no done-checkpoint; re-running
  retries it; partial output is still visible.
- Mock 501+ DNS results: all of them enter downstream probing (no 500-row
  display cap in the work set); the display cap stays display-only.
- Wildcard answers are filtered identically in the system-resolver fallback.
"""
import json

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools


class _FakeRun:
    """Stands in for core.run: scripted rc/stdout per command pattern."""

    def __init__(self, outputs):
        self.outputs = outputs     # list of (substring, (rc, stdout, stderr))

    def __call__(self, cmd, timeout=300, input_text=None, cwd=None, env=None):
        cmd = list(cmd)
        for needle, res in self.outputs:
            # The wildcard probe carries its name on stdin, not in argv, so the
            # scripted pattern has to be matched against both.
            if any(needle in str(c) for c in cmd) or needle in (input_text or ""):
                return res
        return 0, "", ""


def _fake_run_stream(lines, rc=0):
    """Stands in for core.run_stream: feeds scripted JSONL lines."""
    def run_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        n = 0
        for ln in lines:
            if on_line is not None:
                on_line(ln)
            n += 1
        return rc, n, ""
    return run_stream


def test_dns_wildcard_fallback_filtered():
    """System-resolver fallback applies the SAME wildcard rule as dnsx."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    # wildcard probe: *.wild.example.com answers 9.9.9.9 for random names
    fake = _FakeRun([
        ("wildcard-probe", (0, json.dumps({"host": "findinfo-wildcard-probe-9f3a.wild.example.com",
                                           "a": ["9.9.9.9"]}), "")),
    ])
    # dnsx itself sees nothing; the fallback resolves everything
    def resolve_all(cmd, on_line=None, timeout=300, cwd=None, env=None):
        return 0, 0, ""

    import unittest.mock as mock
    with mock.patch.object(core, "run", fake), \
         mock.patch.object(core, "run_stream", resolve_all), \
         mock.patch.object(socket_mod(), "getaddrinfo",
                           side_effect=lambda d, p: [(None, None, None, None, ("9.9.9.9", 0))] if "wild." in d
                           else [(None, None, None, None, ("8.8.4.4", 0))]):
        r = tools.t_dns(store, ["a.wild.example.com", "real.example.com"])
    stored = {a["canonical"] for a in store.get_assets(kind="domain")}
    assert "real.example.com" in stored
    assert "a.wild.example.com" not in stored, "wildcard answer must not become an asset"
    assert r["ok"] is True
    assert r["count"] == 1
    store.close()


def socket_mod():
    import socket
    return socket


def test_dns_501_records_all_reach_downstream():
    """501+ resolved rows: display list truncates at ROW_LIMIT, store keeps all."""
    core = fresh_core()
    tools = fresh_tools(core)
    core.ROW_LIMIT = 500
    store = core.Store()
    domains = ["s%d.example.com" % i for i in range(501)]
    lines = [json.dumps({"host": d, "a": ["1.2.3.4"]}) for d in domains]

    fake = _FakeRun([("wildcard-probe", (0, "", ""))])
    import unittest.mock as mock
    with mock.patch.object(core, "run", fake), \
         mock.patch.object(core, "run_stream", _fake_run_stream(lines)):
        r = tools.t_dns(store, domains)

    assert r["count"] == 501                      # full work set processed
    assert len(r["domains"]) == 500                # display capped separately
    assert r["truncated"] is True
    stored = [a["canonical"] for a in store.get_assets(kind="domain", match=["example.com"])]
    assert len(stored) == 501, "every record must be stored for downstream stages"
    # and the downstream rebuild (probe input) is NOT capped:
    hosts = [a["canonical"] for a in store.get_assets(kind="domain", match=["example.com"])
             if core.source_tools(a.get("sources") or "") & {"dnsx"}]
    assert len(hosts) == 501
    store.close()


def test_dns_failure_no_done_checkpoint():
    """rc!=0: ok=False, partial rows kept, caller must not checkpoint done."""
    core = fresh_core()
    tools = fresh_tools(core)
    core.ROW_LIMIT = 500
    store = core.Store()
    lines = [json.dumps({"host": "ok.example.com", "a": ["1.2.3.4"]})]
    fake = _FakeRun([("wildcard-probe", (0, "", ""))])
    import unittest.mock as mock
    with mock.patch.object(core, "run", fake), \
         mock.patch.object(core, "run_stream", _fake_run_stream(lines, rc=124)):
        r = tools.t_dns(store, ["ok.example.com", "bad.example.com"])
    assert r["ok"] is False and r["rc"] == 124
    assert r["count"] == 1                      # partial output survived
    store.close()


def test_stage_failed_then_rerun_retries():
    """_stage: a failed stage writes steps=failed; a re-run retries it."""
    core = fresh_core()
    store = core.Store()
    from tests.util import import_findinfo
    fi = import_findinfo()
    run_dir = core.RUNS_DIR / "stage-test"
    run_dir.mkdir(parents=True, exist_ok=True)

    args = type("A", (), {"force_stage": False})()
    calls = {"n": 0}
    summary: dict = {"stages": []}

    def failing_fn():
        calls["n"] += 1
        raise core.StageError("tool rc=124", result={"found": 3})

    ok, res = fi._stage(store, run_dir, summary, "dns", {"domains": ["a.com"]},
                        args, failing_fn, lambda r: {})
    assert ok is False and res == {"found": 3}
    assert summary["stages"][-1]["failed"] is True
    assert store.step_done(fi.ENGAGEMENT, "dns",
                           fi._input_hash({"domains": ["a.com"]})) is False

    def now_ok():
        calls["n"] += 1
        return {"found": 5}

    ok, res = fi._stage(store, run_dir, summary, "dns", {"domains": ["a.com"]},
                        args, now_ok, lambda r: {"found": r["found"]})
    assert ok is True and res == {"found": 5} and calls["n"] == 2

    ok, res = fi._stage(store, run_dir, summary, "dns", {"domains": ["a.com"]},
                        args, now_ok, lambda r: {"found": r["found"]},
                        resume=lambda: {"found": 5})
    assert ok is True and res == {"found": 5} and calls["n"] == 2
    assert summary["stages"][-1] == {"stage": "dns", "skipped": True, "resumed": True}

    # changed inputs change the hash -> stage re-executes
    ok, res = fi._stage(store, run_dir, summary, "dns",
                        {"domains": ["a.com", "b.com"]},
                        args, now_ok, lambda r: {"found": r["found"]})
    assert ok is True and calls["n"] == 3
    store.close()


def _run_args(active=False, crawl=False):
    import argparse
    return argparse.Namespace(
        task="", name="", domain=["example.com"], active=active, ports=False,
        vhost=False, crawl=crawl, brute=False, brute_wordlist="", brute_bandwidth="3m",
        depth=3, invest=51, deep=2, engines="fofa,quake,hunter,shodan,censys",
        no_icp=True, no_onepass=True, top_ports=1000, max_seed=5,
        max_vhost_ips=10, force_stage=False)


def test_passive_then_active_resumes_and_probes():
    """Acceptance: passive run first, then --active runs the active stages.

    After dns is checkpointed, a second run with --active must SKIP dns
    (resume from store) and EXECUTE probe on the FULL host set (no display cap).
    """
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    from tests.util import import_findinfo
    import unittest.mock as mock
    fi = import_findinfo()

    for i in range(520):
        store.upsert_asset("domain", "s%d.example.com" % i, source="dnsx",
                           confidence=0.8, passivity="passive")
    store.upsert_asset("domain", "example.com", source="onepass:crt.sh",
                       confidence=0.9, passivity="passive")

    probed = {}

    def fake_probe(store_, hosts, timeout=0):
        probed["n"] = len(hosts)
        return {"count": len(hosts), "truncated": False, "ok": True, "rc": 0}

    def fake_dns(store_, domains, timeout=0):
        for d in domains:
            store_.upsert_asset("domain", d, source="dnsx", confidence=0.8,
                                passivity="passive")
        return {"count": len(domains), "domains": [], "wildcard": [], "ok": True,
                "rc": 0, "truncated": False}

    with mock.patch.object(tools, "t_onepass", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_certs", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs", return_value={"count": 0}), \
         mock.patch.object(tools, "t_dns", side_effect=fake_dns), \
         mock.patch.object(tools, "t_httpx", side_effect=fake_probe):
        # run 1: passive only
        fi.cmd_run(_run_args(active=False))
        steps1 = {r[0]: r[1] for r in store.conn.execute(
            "SELECT step,status FROM steps")}
        assert steps1.get("dns") == "done"
        assert "probe" not in steps1, "passive run must not probe"

        # run 2: --active appended. dns skips (resume), probe executes on ALL rows
        fi.cmd_run(_run_args(active=True))
        assert probed["n"] == 521, ("full work set, not the 500-row display cap",
                                    probed.get("n"))
        row = store.conn.execute(
            "SELECT status FROM steps WHERE step='probe'").fetchone()
        assert row and row["status"] == "done"
    store.close()


def test_completed_run_then_crawl_executes():
    """Acceptance: a completed run + --crawl runs the crawl stage."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    from tests.util import import_findinfo
    import unittest.mock as mock
    fi = import_findinfo()

    store.upsert_asset("domain", "example.com", source="onepass:crt.sh",
                       confidence=0.9, passivity="passive",
                       attrs={"url": "https://www.example.com/"})
    for i in range(3):
        store.upsert_asset("domain", "s%d.example.com" % i, source="dnsx",
                           confidence=0.8, passivity="passive")

    crawled = {}

    def fake_crawl(store_, urls, depth=3, scope_domains=None, timeout=0):
        crawled["urls"] = list(urls)
        crawled["scope"] = scope_domains
        return {"count": len(urls), "rows": [], "truncated": False, "ok": True,
                "rc": 0, "dropped_out_of_scope": 0, "scope": scope_domains or []}

    def fake_extract(store_, rows, urls=None, timeout=0, fetch_limit=40, scope=None):
        return {"count_domains": 0, "count_ips": 0, "fetched": 0,
                "js_discovered": 0, "api_paths": [], "api_hosts": 0,
                "secrets": {}, "domains": [], "ips": []}

    with mock.patch.object(tools, "t_onepass", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_certs", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs", return_value={"count": 0}), \
         mock.patch.object(tools, "t_dns", return_value={"count": 0, "domains": [],
                                                         "wildcard": [], "ok": True, "rc": 0,
                                                         "truncated": False}), \
         mock.patch.object(tools, "t_httpx", return_value={"count": 0, "truncated": False,
                                                           "ok": True, "rc": 0}), \
         mock.patch.object(tools, "t_crawl", side_effect=fake_crawl), \
         mock.patch.object(tools, "t_extract", side_effect=fake_extract):
        fi.cmd_run(_run_args(active=True, crawl=False))   # completed run
        assert "crawl" not in crawled
        fi.cmd_run(_run_args(active=True, crawl=True))    # append --crawl
        assert "www.example.com/" in str(crawled.get("urls"))
        assert "example.com" in (crawled.get("scope") or [])
    store.close()


def test_rc124_never_checkpoints_done():
    """Acceptance: an rc=124 probe leaves steps=failed, and cmd_run survives."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    from tests.util import import_findinfo
    import unittest.mock as mock
    fi = import_findinfo()

    store.upsert_asset("domain", "example.com", source="onepass:crt.sh",
                       confidence=0.9, passivity="passive")
    store.upsert_asset("domain", "s.example.com", source="dnsx",
                       confidence=0.8, passivity="passive")

    def probe_fails(store_, hosts, timeout=0):
        return {"count": 3, "rows": [], "truncated": False, "ok": False, "rc": 124}

    with mock.patch.object(tools, "t_onepass", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_certs", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs", return_value={"count": 0}), \
         mock.patch.object(tools, "t_dns", return_value={"count": 0, "domains": [],
                                                         "wildcard": [], "ok": True, "rc": 0,
                                                         "truncated": False}), \
         mock.patch.object(tools, "t_httpx", side_effect=probe_fails):
        fi.cmd_run(_run_args(active=True))     # must not raise
    row = store.conn.execute(
        "SELECT status FROM steps WHERE step='probe'").fetchone()
    assert row and row["status"] == "failed", "rc=124 must leave steps=failed"
    store.close()


def test_display_limit_change_does_not_change_coverage():
    """Acceptance: changing the DISPLAY cap must not change actual coverage."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    domains = ["d%d.example.com" % i for i in range(600)]
    lines = [json.dumps({"host": d, "a": ["1.2.3.4"]}) for d in domains]
    fake = _FakeRun([("wildcard-probe", (0, "", ""))])
    import unittest.mock as mock
    with mock.patch.object(core, "run", fake), \
         mock.patch.object(core, "run_stream", _fake_run_stream(lines)):
        core.ROW_LIMIT = 500
        r500 = tools.t_dns(store, domains)
        core.ROW_LIMIT = 50
        r50 = tools.t_dns(store, domains)
    # coverage (count / store) identical; only the display list shrank
    assert r500["count"] == r50["count"] == 600
    assert len(r500["domains"]) == 500 and len(r50["domains"]) == 50
    store.close()


def test_empty_result_vs_tool_failure_distinguishable():
    """Acceptance: JSON distinguishes clean-empty (ok+0) from failure (!ok)."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    fake = _FakeRun([("wildcard-probe", (0, "", ""))])
    import unittest.mock as mock
    with mock.patch.object(core, "run", fake), \
         mock.patch.object(core, "run_stream", _fake_run_stream([], rc=0)):
        clean = tools.t_dns(store, ["nothing.example.com"])
    with mock.patch.object(core, "run", fake), \
         mock.patch.object(core, "run_stream", _fake_run_stream([], rc=124)):
        failed = tools.t_dns(store, ["nothing.example.com"])
    assert clean["ok"] is True and clean["count"] == 0
    assert failed["ok"] is False and failed["rc"] == 124
    store.close()
