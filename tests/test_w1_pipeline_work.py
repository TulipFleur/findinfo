"""Wiring W1 acceptance: the main pipeline reads/writes lib/work.py.

Extends the batch C contracts to the real `_run_pipeline` path: round inputs
come from run_assets (not a fresh shared-graph re-scope), stage invocations
persist per dispatch, JS backlog adopts into the run queue, and outstanding
work items keep a run partial. Synthetic Meituan fixture under reserved
namespaces; collectors are injected, nothing touches the network.

Covers the pipeline half of T08/T09/T11/T16 (the table-level halves live in
tests/test_batch_c_work.py).
"""

import io
import json
import unittest.mock as mock
from contextlib import redirect_stdout

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo


def _args(**over):
    base = dict(
        task="", name="", domain=["mt-a.example.com"], active=False,
        ports=False, vhost=False, crawl=False, brute=False,
        brute_wordlist="", brute_bandwidth="3m", depth=3, invest=51, deep=1,
        engines="fofa,quake,hunter,shodan,censys", no_icp=True,
        no_onepass=True, top_ports=1000, max_seed=5, max_vhost_ips=10,
        force_stage=False, background=False, resume="", rounds=1,
        time_budget=0.0, task_timeout=0.0, tool_timeout=0, entity_timeout=1200)
    base.update(over)
    import argparse
    return argparse.Namespace(**base)


def _quiet():
    """Collectors that answer instantly with empty success."""
    return {
        "t_certs": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True},
        "t_subs": lambda s, d, engines="", timeout=0, **kw: {
            "count": 0, "ok": True},
        "t_dns": lambda s, d, timeout=0, **kw: {
            "count": 0, "ok": True, "rc": 0, "domains": [], "wildcard": []},
    }


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


# ---------------------------------------------------------------- invocations
def test_stage_invocations_persist_per_dispatch():
    """Each stage dispatch lands in stage_invocations, settled."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    assert _run(fi, _args(), _quiet()) == 0
    rd = _latest_run_dir(core)
    store = core.Store()
    from lib import work
    try:
        work.ensure_schema(store)
        rows = store.conn.execute(
            "SELECT stage, state, outcome FROM stage_invocations"
            " WHERE run_id=? ORDER BY rowid", (rd.name,)).fetchall()
    finally:
        store.close()
    stages = {r["stage"] for r in rows}
    assert {"certs", "subs", "dns"} <= stages, [dict(r) for r in rows]
    assert all(r["state"] == "succeeded" for r in rows), [dict(r) for r in rows]


def test_checkpoint_reuse_records_reused_invocation():
    """A second run hitting the checkpoint records a reused invocation."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    assert _run(fi, _args(), _quiet()) == 0
    rd1 = _latest_run_dir(core)
    assert _run(fi, _args(), _quiet()) == 0
    store = core.Store()
    from lib import work
    try:
        work.ensure_schema(store)
        # the second (foreground) run gets its own run dir; the checkpointed
        # stages are skipped and their dispatches are recorded as REUSED
        rows = store.conn.execute(
            "SELECT stage, state, outcome FROM stage_invocations"
            " WHERE state='succeeded' AND outcome='reused' ORDER BY rowid"
        ).fetchall()
    finally:
        store.close()
    stages = {r["stage"] for r in rows}
    assert {"certs", "subs", "dns"} <= stages, [dict(r) for r in rows]
    assert rd1.name  # (rd1 kept as a readable anchor; dirs differ per run)


# ---------------------------------------------------------------- round input
def test_round_input_comes_from_membership_not_foreign_graph():
    """A sibling run's assets must not feed this run's resolver (T08/T11)."""
    core = fresh_core()
    tools = fresh_tools(core)
    # a PREVIOUS, unrelated run left foreign in-graph assets behind
    store = core.Store()
    try:
        for host in ("api.mt-b.example.net", "ct-only.mt-b.example.net"):
            store.upsert_asset("domain", host, source="subfinder",
                               confidence=0.8, parent="mt-b.example.net")
    finally:
        store.close()
    fi = import_findinfo()
    seen: dict = {}

    def fake_dns(store, domains, timeout=0, **kw):
        seen["domains"] = list(domains)
        return {"count": 0, "ok": True, "rc": 0, "domains": [],
                "wildcard": []}

    fakes = _quiet()
    fakes["t_dns"] = fake_dns
    assert _run(fi, _args(), fakes) == 0
    # mt-a's own seed is resolvable; mt-b's rows (shared graph, other run)
    # must NOT enter this run's dns input
    assert "mt-a.example.com" in seen["domains"], seen
    assert all(".mt-b.example.net" not in d and d != "mt-b.example.net"
               for d in seen["domains"]), ("foreign rows leaked", seen)


def test_dns_work_items_created_and_settled_by_the_stage():
    """Seeds become dns work items; the stage settles them (T08)."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    assert _run(fi, _args(), _quiet()) == 0
    rd = _latest_run_dir(core)
    store = core.Store()
    from lib import work
    try:
        work.ensure_schema(store)
        stats = work.queue_stats(store, rd.name)
        assert stats["done"] >= 1, "the seed's dns work item must settle"
        assert stats["outstanding"] == 0, stats
        members = work.run_assets(store, rd.name, "domain")
        assert "mt-a.example.com" in members, members
    finally:
        store.close()


# ---------------------------------------------------------------- T16
def test_outstanding_work_keeps_run_partial():
    """Adopted-but-undrained JS work blocks the complete verdict (T16)."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    bundle = "https://js-only.mt-a.example.com/app.js"
    store = core.Store()
    try:
        store.upsert_asset("domain", "mt-a.example.com", source="seed:user",
                           confidence=0.5, passivity="passive",
                           attrs={"url": "https://mt-a.example.com/"})
        store.upsert_asset("url", bundle, source="katana",
                           confidence=0.7, parent="mt-a.example.com",
                           attrs={"url": bundle})
    finally:
        store.close()

    def fake_extract(store, rows, urls=None, timeout=0, fetch_limit=40,
                     scope=None):
        # enqueue the bundle into the shared legacy queue (the write path
        # inside t_extract); the run then adopts it into its durable queue
        store.js_enqueue([u for u in (urls or []) if u.endswith(".js")])
        return {"count_domains": 0, "count_ips": 0, "fetched": 0,
                "js_discovered": 1, "js_pending": 1, "api_paths": [],
                "api_hosts": 0, "secrets": {}, "domains": [], "ips": [],
                "outcome": core.OUTCOME_PARTIAL}

    fakes = _quiet()
    fakes["t_crawl"] = lambda s, urls, depth=3, scope_domains=None, timeout=0: {
        "count": len(urls or []), "rows": [], "truncated": False, "ok": True,
        "rc": 0, "dropped_out_of_scope": 0, "scope": scope_domains or []}
    fakes["t_extract"] = fake_extract
    fakes["t_httpx"] = lambda s, hosts, timeout=0, **kw: {
        "count": 0, "ok": True, "rc": 0, "truncated": False}
    fakes["t_ipagg"] = lambda s, **kw: {"candidates": [],
                                        "count_candidates": 0}
    rc = _run(fi, _args(active=True, crawl=True, rounds=1), fakes)
    rd = _latest_run_dir(core)
    store = core.Store()
    from lib import work
    try:
        work.ensure_schema(store)
        stats = work.queue_stats(store, rd.name)
        assert stats["pending"] >= 1, "the adopted bundle must be durable work"
    finally:
        store.close()
    summary = json.loads((rd / "summary.jsonl").read_text(
        encoding="utf-8").splitlines()[-1])
    assert summary["result"]["status"] == "partial", summary["result"]
    assert summary["coverage"]["work_queue"]["outstanding"] >= 1
    assert rc == 5, "undrained JS work must keep the run partial"


# ---------------------------------------------------------------- T33 bridge
def test_js_backlog_adopts_into_run_queue():
    """URL assets this run queues become durable run work (T33)."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    bundle = "https://mt-a.example.com/bundle.js"
    # a previous round left the crawl URL in the scoped graph: attrs.url is
    # what feeds the crawl stage, and the url row feeds extract's work set
    store = core.Store()
    try:
        store.upsert_asset("domain", "mt-a.example.com", source="seed:user",
                           confidence=0.5, passivity="passive",
                           attrs={"url": "https://mt-a.example.com/"})
        store.upsert_asset("url", bundle, source="katana",
                           confidence=0.7, parent="mt-a.example.com",
                           attrs={"url": bundle})
    finally:
        store.close()

    def fake_extract(store, rows, urls=None, timeout=0, fetch_limit=40,
                     scope=None):
        store.js_enqueue([u for u in (urls or []) if u.endswith(".js")])
        return {"count_domains": 0, "count_ips": 0, "fetched": 0,
                "js_discovered": 1, "js_pending": 1, "api_paths": [],
                "api_hosts": 0, "secrets": {}, "domains": [], "ips": [],
                "outcome": core.OUTCOME_OK}

    fakes = _quiet()
    fakes["t_crawl"] = lambda s, urls, depth=3, scope_domains=None, timeout=0: {
        "count": len(urls or []), "rows": [], "truncated": False, "ok": True,
        "rc": 0, "dropped_out_of_scope": 0, "scope": scope_domains or []}
    fakes["t_extract"] = fake_extract
    fakes["t_httpx"] = lambda s, hosts, timeout=0, **kw: {
        "count": 0, "ok": True, "rc": 0, "truncated": False}
    fakes["t_ipagg"] = lambda s, **kw: {"candidates": [],
                                        "count_candidates": 0}
    rc = _run(fi, _args(active=True, crawl=True, rounds=1), fakes)
    rd = _latest_run_dir(core)
    store = core.Store()
    from lib import work
    try:
        work.ensure_schema(store)
        items = store.conn.execute(
            "SELECT canonical, status FROM work_items WHERE run_id=?"
            " AND stage=?", (rd.name, work.ROUTE_JS)).fetchall()
    finally:
        store.close()
    assert [r["canonical"] for r in items] == [bundle], (
        "the run's JS bundle must adopt into the durable queue", [dict(r) for r in items])
