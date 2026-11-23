"""ENScan reports are read by their real schema (aqc answer, 2026-11 binary).

One report = one queried company: `enterprise_info` is the subject, and the
icp / app / wx_app / wechat / copyright tables are ITS assets -- every row
there carries a `name` (an app's, a WeChat account's), which is not a company.
Reading those rows as companies turned one real report into 82 "subjects",
left the 16 filed ICP domains attributed to nobody, and seeded nothing.

The fixture mirrors the observed shape (empty `company_name` on ICP rows,
app-store links on app rows); every name and domain in it is synthetic.
"""
import json
from unittest import mock

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools

LEGAL = "示例出行科技集团有限公司"
REPORT = {
    "enterprise_info": [{"name": LEGAL, "pid": "p-1", "legal_person": "x",
                         "status": "存续", "ref": "", "extra": ""}],
    "icp": [
        {"company_name": "", "domain": "example-go.com", "icp": "京ICP备00000009号-1",
         "website": "www.example-go.com", "website_name": "示例出行官网",
         "ref": "", "extra": ""},
        {"company_name": "", "domain": "example-go.cn", "icp": "京ICP备00000009号-2",
         "website": "", "website_name": "示例打车", "ref": "", "extra": ""},
    ],
    "app": [
        {"name": "示例出行", "link": "https://apps.apple.com/cn/app/id000000001",
         "bundle_id": "com.example.go", "ref": "", "extra": ""},
        {"name": "示例车主", "link": "https://appgallery.huawei.com/app/C000",
         "ref": "", "extra": ""},
    ],
    "wechat": [{"name": "示例出行服务号", "wechat_id": "example_go", "ref": "",
                "extra": ""}],
    "copyright": [{"name": "示例出行调度系统", "short_name": "", "reg_num": "2020SR000001",
                   "ref": "", "extra": ""}],
    "invest": [
        {"name": "示例出行（杭州）科技有限公司", "pid": "p-2", "scale": "100%",
         "ref": "", "extra": ""},
        {"name": "无关投资管理有限公司", "pid": "p-3", "ref": "", "extra": ""},
    ],
}


def _run_enscan(name):
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    outdir = core.RUNS_DIR / "enscan-report"
    outdir.mkdir(parents=True, exist_ok=True)

    def _write(*_a, **_kw):
        (outdir / "report.json").write_text(json.dumps(REPORT, ensure_ascii=False),
                                            encoding="utf-8")
        return (0, "", "")

    try:
        with mock.patch.object(tools.core, "run", side_effect=_write):
            r = tools.t_enscan(store, name, outdir=outdir)
        stored = {a["canonical"] for a in store.get_assets(kind="domain")}
    finally:
        store.close()
    return r, stored


def test_report_asset_tables_belong_to_the_report_subject():
    tools = fresh_tools(fresh_core())
    ents = {e["subject_ref"]: e for e in tools.harvest_entities(REPORT)}
    main = ents["id:p-1"]
    assert set(main["domains"]) == {"example-go.com", "example-go.cn"}, main
    assert set(main["icp"]) == {"京ICP备00000009号-1", "京ICP备00000009号-2"}, main
    assert {"示例出行", "示例车主"} <= set(main["apps"]), main
    # app-store links are where an app is sold, not the company's domains
    assert not any("apple.com" in d or "huawei.com" in d for d in main["domains"]), main
    # an app, a WeChat account or a copyright is not a company
    names = {e["legal_name"] for e in ents.values()}
    assert not names & {"示例出行", "示例车主", "示例出行服务号", "示例出行调度系统"}, names
    # invested companies stay separate candidates and own none of the report
    sub = ents["id:p-2"]
    assert sub["domains"] == [] and sub["icp"] == [], sub


def test_the_full_legal_name_seeds_the_filed_domains():
    r, stored = _run_enscan(LEGAL)
    assert not r.get("anchor_failed"), r
    assert {"example-go.com", "example-go.cn"} <= set(r["domains"]), r
    assert {"example-go.com", "example-go.cn"} <= stored, stored


def test_a_brand_anchors_by_the_subjects_own_asset_names():
    """"示例" never matches the legal name, but the company's own apps,
    websites and WeChat account carry it: that is who owns the brand."""
    r, stored = _run_enscan("示例")
    assert not r.get("anchor_failed"), r
    assert r.get("anchor_basis") == "brand_evidence", r
    assert r["companies"] == [LEGAL], r
    assert len(r.get("brand_evidence") or []) >= 2, r
    assert "example-go.com" in r["domains"], r
    assert "example-go.com" in stored, stored


def test_a_brand_no_asset_names_carry_is_still_rejected():
    """Guard: brand evidence must not turn a lookalike answer into an anchor."""
    r, stored = _run_enscan("另一品牌")
    assert r.get("anchor_failed") is True, r
    assert r["domains"] == [] and stored == set(), (r, stored)


# ---------------------------------------------------------------- config
def _fake_bin(tmp_root):
    """A throwaway bin/ + bin/<platform>/enscan.exe: never the real one, which
    sits next to the user's real Cookie."""
    from pathlib import Path
    bin_dir = Path(tmp_root) / "bin"
    plat = bin_dir / "windows"
    plat.mkdir(parents=True, exist_ok=True)
    exe = plat / "enscan.exe"
    exe.write_bytes(b"")
    return bin_dir, exe


def test_enscan_runs_beside_its_binary_and_gets_the_legacy_config(tmp_path):
    core = fresh_core()
    tools = fresh_tools(core)
    bin_dir, exe = _fake_bin(tmp_path)
    (bin_dir / "config.yaml").write_text("version: 0.7\ncookies:\n  aiqicha: 'k=v'\n",
                                         encoding="utf-8")
    store = core.Store()
    seen = {}

    def _run(cmd, **kw):
        seen["cwd"] = kw.get("cwd")
        return (0, "", "")

    try:
        with mock.patch.object(tools.core, "tool", lambda name: str(exe)), \
                mock.patch.object(tools.core, "BIN", bin_dir), \
                mock.patch.object(tools.core, "run", side_effect=_run):
            tools.t_enscan(store, LEGAL, outdir=tmp_path / "out")
    finally:
        store.close()
    assert seen["cwd"] == str(exe.parent), seen
    copied = exe.parent / "config.yaml"
    assert copied.read_text(encoding="utf-8").startswith("version: 0.7"), copied


def test_config_status_names_the_problem_and_never_the_cookie(tmp_path):
    tools = fresh_tools(fresh_core())
    p = tmp_path / "config.yaml"
    assert tools.enscan_config_status(p)["state"] == "missing"
    p.write_text("", encoding="utf-8")
    assert tools.enscan_config_status(p)["state"] == "empty"
    p.write_text("cookies:\n  aiqicha: 'k=v'\n", encoding="utf-8")
    assert tools.enscan_config_status(p)["state"] == "version_mismatch"
    p.write_text('version: "V0.7"\ncookies:\n  aiqicha: \'k=v\'\n', encoding="utf-8")
    assert tools.enscan_config_status(p)["state"] == "version_mismatch"
    p.write_text("version: 0.7\ncookies:\n  aiqicha: ''\n", encoding="utf-8")
    assert tools.enscan_config_status(p)["state"] == "no_cookie"
    p.write_text("version: 0.7\ncookies:\n  aiqicha: 'BAIDUID=secret#1'  # note\n",
                 encoding="utf-8")
    st = tools.enscan_config_status(p)
    assert st["state"] == "ok" and st["aiqicha_cookie_set"] is True, st
    assert "secret" not in json.dumps(st), st


def test_the_config_template_matches_the_bundled_enscan():
    """The example must load in the bundled ENScan as-is (version is a float)."""
    tools = fresh_tools(fresh_core())
    from pathlib import Path
    tpl = Path(tests.util.ROOT) / "bin" / "config.example.yaml"
    text = tpl.read_text(encoding="utf-8")
    assert "\nversion: 0.7\n" in "\n" + text, text[:200]
    for key in ("user_agent:", "app:", "api:", "cookies:", "aiqicha:"):
        assert key in text, key
    st = tools.enscan_config_status(tpl)
    assert st["state"] == "no_cookie", st      # shape valid, cookie left blank
