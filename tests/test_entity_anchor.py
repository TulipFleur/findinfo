"""Regression: entity anchoring (A: 企业名称 → 实体锚定 → 消除歧义).

The skill requirement says a company NAME must be anchored to a concrete
entity before collection, and name ambiguity must be handled. These tests pin
that behaviour without touching the network: the ENScan collector is faked.
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
        task="", name="测试科技有限公司", domain=[], active=False, ports=False,
        vhost=False, crawl=False, brute=False, brute_wordlist="", brute_bandwidth="3m",
        depth=3, invest=51, deep=2, engines="", no_icp=True, no_onepass=True,
        top_ports=1000, max_seed=5, max_vhost_ips=10, force_stage=False,
        background=False, resume="", rounds=1, time_budget=0.0,
        task_timeout=0.0, tool_timeout=0, entity_timeout=1200)
    base.update(over)
    return argparse.Namespace(**base)


def _fake_enscan(store, name, **kw):
    """Anchor the name to a company and surface its filed domains."""
    store.upsert_asset("company", name, source="enscan", confidence=0.9)
    for d in ("example-anchored.cn", "example-anchored.com"):
        store.upsert_asset("domain", d, source="enscan", confidence=0.9, parent=name)
    store.upsert_asset("icp", "粤ICP备00000000号", source="enscan", confidence=0.9,
                       parent=name)
    return {"rc": 0, "json_files": 1, "stderr": "",
            "companies": [name],
            "icp": ["粤ICP备00000000号"],
            "domains": ["example-anchored.cn", "example-anchored.com"],
            "apps": []}


def test_company_name_anchors_to_domains():
    """A bare company name must yield seed domains via entity anchoring."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    with mock.patch.object(tools, "t_enscan", side_effect=_fake_enscan), \
         mock.patch.object(tools, "t_certs",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_dns",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True, "rc": 0,
                                                         "domains": [], "wildcard": []}):
        with redirect_stdout(io.StringIO()):
            fi.cmd_run(_args())
    store = core.Store()
    try:
        domains = sorted(a["canonical"] for a in store.get_assets(kind="domain"))
        companies = [a["canonical"] for a in store.get_assets(kind="company")]
        icp = [a["canonical"] for a in store.get_assets(kind="icp")]
    finally:
        store.close()
    assert companies == ["测试科技有限公司"]
    assert "example-anchored.cn" in domains and "example-anchored.com" in domains
    assert icp == ["粤ICP备00000000号"]


def test_entity_only_name_without_named_domain_still_runs():
    """No --domain: the anchor supplies the scope; the run must not abort."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    with mock.patch.object(tools, "t_enscan", side_effect=_fake_enscan), \
         mock.patch.object(tools, "t_certs",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_dns",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True, "rc": 0,
                                                         "domains": [], "wildcard": []}):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = fi.cmd_run(_args())
    assert rc in (0, 5), rc
    rd = sorted(core.RUNS_DIR.glob("*"), key=lambda p: p.stat().st_mtime)[-1]
    summary = json.loads((rd / "summary.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert summary["seed_domains"], "the anchor must provide seed domains"
    assert any("example-anchored" in d for d in summary["seed_domains"])


def test_named_domains_sort_ahead_of_anchored_ones():
    """Explicit --domain wins the seed budget over discovered domains."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    with mock.patch.object(tools, "t_enscan", side_effect=_fake_enscan), \
         mock.patch.object(tools, "t_certs",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_dns",
                           side_effect=lambda s, d, **k: {"count": 0, "ok": True, "rc": 0,
                                                         "domains": [], "wildcard": []}):
        with redirect_stdout(io.StringIO()):
            fi.cmd_run(_args(domain=["named-target.cn"], max_seed=1))
    rd = sorted(core.RUNS_DIR.glob("*"), key=lambda p: p.stat().st_mtime)[-1]
    summary = json.loads((rd / "summary.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert summary["seed_domains"][0] == "named-target.cn", summary["seed_domains"]
