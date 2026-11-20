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


# ---------------------------------------------------------------- anchoring gate
# A real run against a college name came back from aiqicha with 13 meituan-group
# companies and 27 of their ICP domains. Nothing in the pipeline noticed: the
# stranger's domains were stored under the requested name at confidence 0.9 and
# the next stage dutifully started probing www.meituan.com. These tests pin the
# gate that now refuses that answer.

def test_name_matching_rejects_a_lookalike_entity():
    """A shared word is not an identity; only real overlap anchors a name."""
    tools = fresh_tools(fresh_core())
    assert tools.name_matches("湖南信息职业技术学院", "湖南信息职业技术学院")
    assert tools.name_matches("北京三快科技有限公司", "北京三快科技有限公司长沙分公司")
    assert tools.name_matches("北京三快科技有限公司", "北京三快科技")
    assert not tools.name_matches("湖南信息职业技术学院", "北京三快科技有限公司")
    assert not tools.name_matches("湖南信息职业技术学院", "长沙民政职业技术学院")


def test_norm_entity_name_strips_legal_form_and_spacing():
    tools = fresh_tools(fresh_core())
    assert tools.norm_entity_name(" 北京三快科技有限公司 ") == "北京三快科技"
    assert tools.norm_entity_name("北京三快科技") == "北京三快科技"


def test_harvested_strangers_are_rejected_and_never_stored():
    """t_enscan must refuse to store an entity that is not the requested one."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    stranger = {
        "enterprise_info": [{"name": "北京三快科技有限公司"}],
        "icp": [{"domain": "meituan.com", "icp": "京ICP备10211739号-1"},
                {"domain": "qiaoyuai.com", "icp": "京ICP备10211739号-64"}],
    }
    outdir = core.RUNS_DIR / "enscan"
    outdir.mkdir(parents=True, exist_ok=True)

    def _write(*_a, **_kw):
        # t_enscan snapshots the directory before running the binary, so the
        # fixture JSON has to appear "when the tool ran", not before it.
        (outdir / "someid.json").write_text(json.dumps(stranger), encoding="utf-8")
        return (0, "", "")

    with mock.patch.object(tools.core, "run", side_effect=_write):
        r = tools.t_enscan(store, "湖南信息职业技术学院", outdir=outdir)
    assert r.get("anchor_failed") is True, r
    assert r["companies"] == [] and r["domains"] == [] and r["icp"] == []
    assert core.Store().get_assets(kind="domain") == [], "stranger's domains were stored"
    assert core.Store().get_assets(kind="company") == [], "stranger was stored as the target"


def test_anchored_entity_still_stores_domains():
    """The gate must not break the normal case: a matching entity is kept."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    good = {
        "enterprise_info": [{"name": "湖南信息职业技术学院"}],
        "icp": [{"domain": "hnxxzy.cn", "icp": "湘ICP备00000000号-1"}],
    }
    outdir = core.RUNS_DIR / "enscan2"
    outdir.mkdir(parents=True, exist_ok=True)

    def _write(*_a, **_kw):
        (outdir / "good.json").write_text(json.dumps(good), encoding="utf-8")
        return (0, "", "")

    with mock.patch.object(tools.core, "run", side_effect=_write):
        r = tools.t_enscan(store, "湖南信息职业技术学院", outdir=outdir)
    assert not r.get("anchor_failed"), r
    assert r["companies"] == ["湖南信息职业技术学院"], r
    assert "hnxxzy.cn" in r["domains"], r

def test_icp_regex_matches_real_registration_numbers():
    """Real filings read "<province>ICP备<n>号-<m>" with NO letter.

    The pattern required one letter between the province and ICP, so every
    real ICP number harvested from ENScan was discarded and the ICP stage
    silently contributed nothing.
    """
    import tests.util  # noqa: F401
    from lib import tools
    assert tools.ICP_RE.findall("湘ICP备05009865号-1") == ["湘ICP备05009865号-1"]
    assert tools.ICP_RE.findall("京ICP备10211739号-64") == ["京ICP备10211739号-64"]
    # the lettered form still parses where a site uses it
    assert tools.ICP_RE.findall("沪ICP证000001号")


def test_harvest_entity_collects_icp_numbers():
    import tests.util  # noqa: F401
    from lib import tools
    row = {"icp": [{"domain": "hniu.cn", "icp": "湘ICP备05009865号-1",
                    "website": "www.hniu.cn"}]}
    got = tools.harvest_entity(row)
    assert "湘ICP备05009865号-1" in got["icp"], got
