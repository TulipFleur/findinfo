"""The brief payload: what the `brief` command prints and --with-brief writes.

report.json is sized for scripts -- on a real 1000-domain target it is ~600 KB,
which is more than an agent should ever put in its context. The brief is the
agent-facing digest, so two properties matter as much as the content:

  1. it must stay under its byte ceiling no matter how big the target is;
  2. it must never look complete when it is not -- every array it cut has to
     say so, with the original count, in "truncated".

A brief that silently dropped 400 hosts would be worse than the 600 KB file.
"""
import json
import tempfile
from pathlib import Path

import tests.util  # noqa: F401
from tests.util import fresh_core

BRIEF_KEYS = {"schema", "generated_at", "note", "scope", "counts", "environment",
              "coverage", "top_hosts", "top_hosts_total", "internal_services",
              "internal_services_total", "leaks", "next_steps", "truncated",
              "brief_bytes", "brief_max_bytes"}
HOST_KEYS = {"host", "score", "priority", "reasons", "provenance"}


def _big_store(core):
    """1000 domains, 500 IPs, endpoints -- the shape that made report.json 600 KB."""
    store = core.Store()
    for i in range(1000):
        h = "h" + str(i) + ".example.com"
        store.upsert_asset(
            "domain", h, source="httpx", confidence=0.9, passivity="active",
            attrs={"url": "https://" + h + "/",
                   "status": 403 if i % 5 == 0 else 200,
                   "title": "后台管理系统" if i % 7 == 0 else "Example " + str(i),
                   "tech": ["nginx", "php", "jquery"],
                   "ip": "203.0.113." + str(i % 250 + 1), "port": 443})
    for i in range(500):
        store.upsert_asset("ip", "203.0.113." + str(i % 250 + 1), source="dnsx",
                           confidence=0.7, passivity="active", parent="h0.example.com")
    for i in range(50):
        store.upsert_endpoint("h0.example.com", "GET", "/api/v1/item" + str(i),
                              ["url", "redirect", "id"], source="katana", status=200)
    # one internal service, the way vhost records them
    store.upsert_asset("domain", "internal.example.com", source="hostCollision",
                       confidence=0.8, passivity="active",
                       attrs={"via": "hostCollision", "ip": "10.0.0.9", "status": 200})
    store.close()


def test_brief_is_written_and_small():
    core = fresh_core()
    from lib import report
    _big_store(core)
    store = core.Store()
    data = report.collect(store, match=["example.com"], limit=300, ep_limit=400)
    store.close()
    out = tempfile.mkdtemp()
    paths = report.write_bundle(data, out_dir=out,
                               with_json=True, with_brief=True)

    assert "brief" in paths, paths.keys()
    brief_path = Path(paths["brief"])
    assert brief_path.name == "report.brief.json"
    assert brief_path.exists()
    raw = brief_path.read_bytes()
    # the whole point: readable in one gulp, where report.json is not
    assert len(raw) <= 32 * 1024, "brief is " + str(len(raw)) + " bytes"
    full = Path(paths["json"]).stat().st_size
    assert full > len(raw) * 5, (
        "brief (" + str(len(raw)) + ") should be far smaller than "
        "report.json (" + str(full) + ")")


def test_brief_has_every_documented_field():
    core = fresh_core()
    from lib import report
    _big_store(core)
    store = core.Store()
    data = report.collect(store, match=["example.com"])
    store.close()
    out = tempfile.mkdtemp()
    paths = report.write_bundle(data, out_dir=out, with_brief=True)
    brief = json.loads(Path(paths["brief"]).read_text(encoding="utf-8"))

    missing = BRIEF_KEYS - set(brief)
    assert not missing, "brief is missing " + repr(sorted(missing))
    assert brief["schema"] == "findinfo.brief/1"
    # what an agent needs to act without opening report.json
    assert isinstance(brief["counts"], dict) and brief["counts"]
    assert isinstance(brief["scope"], dict)
    assert "warnings" in brief["environment"]
    for key in ("failed_stages", "not_run_stages", "unavailable"):
        assert key in brief["coverage"], brief["coverage"].keys()
    assert brief["top_hosts"], "no high-priority hosts in a 1000-domain brief"
    for h in brief["top_hosts"]:
        assert HOST_KEYS <= set(h), "host entry is missing " + repr(HOST_KEYS - set(h))
    assert brief["next_steps"], "a brief without next steps cannot be acted on"
    # the brief points at the big file instead of inlining it
    assert "hosts" not in brief, "brief must not carry the full host list"
    assert "endpoints" not in brief and "charts" not in brief


def test_brief_truncation_is_recorded_not_silent():
    """A cut array must carry kept + total; a silent cut reads as complete."""
    core = fresh_core()
    from lib import report
    _big_store(core)
    store = core.Store()
    data = report.collect(store, match=["example.com"])
    store.close()
    brief = report.build_brief(data, top=5)

    trunc = brief["truncated"]
    assert "top_hosts" in trunc, trunc
    assert trunc["top_hosts"]["kept"] == len(brief["top_hosts"]) == 5
    assert trunc["top_hosts"]["total"] == brief["top_hosts_total"] > 5
    # every cut array has both numbers, so a reader can tell how much is missing
    for key, cut in trunc.items():
        if isinstance(cut, dict) and "kept" in cut:
            assert "total" in cut, key + " records kept without total"
            assert cut["total"] >= cut["kept"], key


def test_brief_byte_ceiling_holds_when_forced():
    """Shrink in the documented order and still state every cut."""
    core = fresh_core()
    from lib import report
    _big_store(core)
    store = core.Store()
    data = report.collect(store, match=["example.com"])
    store.close()
    brief = report.build_brief(data, max_bytes=6000)
    size = len(json.dumps(brief, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8"))
    assert size <= 6000, "forced ceiling ignored: " + str(size)
    # the ceiling is met by cutting detail before findings, and it says so
    assert brief["truncated"], "shrank without recording why"
    assert brief["top_hosts"], "shrank away every finding"


def test_brief_counts_are_the_real_counts():
    """The counts block is not truncated, so it must equal report.json's."""
    core = fresh_core()
    from lib import report
    _big_store(core)
    store = core.Store()
    data = report.collect(store, match=["example.com"])
    store.close()
    brief = report.build_brief(data)
    assert brief["counts"] == data["counts"]
    assert brief["leaks"]["domains_total"] == data["counts"]["leak_domains"]
    assert brief["leaks"]["ips_total"] == data["counts"]["leak_ips"]


def test_brief_carries_coverage_gaps():
    """unavailable sources and failed stages must reach the agent verbatim."""
    core = fresh_core()
    from lib import report
    data = {"counts": {}, "scope": {"match": ["example.com"]},
            "environment": {"warnings": ["未执行存活探测（probe）"]},
            "hosts_all": [], "hosts": [], "internal_services": [],
            "leaks": {}, "next_steps": ["补 probe"], "generated_at": "t"}
    coverage = {"failed_stages": [{"stage": "subs", "error": "rc=1"}],
                "not_run_stages": ["probe", "crawl"],
                "skipped_stages": [],
                "unavailable": {"engines_without_key": ["fofa", "quake"]}}
    brief = report.build_brief(data, coverage=coverage)
    cov = brief["coverage"]
    assert cov["failed_stages"] == [{"stage": "subs", "error": "rc=1"}]
    assert cov["not_run_stages"] == ["probe", "crawl"]
    kinds = [u.get("kind") for u in cov["unavailable"]]
    assert kinds == ["engines_without_key", "engines_without_key"], cov["unavailable"]
    reasons = [u.get("reason") for u in cov["unavailable"]]
    assert reasons == ["fofa", "quake"], reasons
    assert cov["unavailable_total"] == 2
    assert brief["environment"]["warnings"] == ["未执行存活探测（probe）"]


def test_brief_does_not_change_report_json():
    """Adding the brief must leave the machine digest byte-identical."""
    core = fresh_core()
    from lib import report
    _big_store(core)
    store = core.Store()
    data = report.collect(store, match=["example.com"])
    store.close()
    a = tempfile.mkdtemp()
    b = tempfile.mkdtemp()
    plain = report.write_bundle(data, out_dir=a, with_json=True,
                                   with_brief=True)
    with_brief = report.write_bundle(data, out_dir=b, with_json=True, with_brief=True,
                                     brief_top=3,
                                     brief_max_bytes=4096, coverage={"x": 1})
    assert Path(plain["json"]).read_bytes() == Path(with_brief["json"]).read_bytes()
    assert Path(plain["md"]).read_bytes() == Path(with_brief["md"]).read_bytes()
    # and the knobs only affect the brief
    small = json.loads(Path(with_brief["brief"]).read_text(encoding="utf-8"))
    assert len(small["top_hosts"]) == 3


def test_brief_bytes_field_matches_the_file():
    core = fresh_core()
    from lib import report
    _big_store(core)
    store = core.Store()
    data = report.collect(store, match=["example.com"])
    store.close()
    out = tempfile.mkdtemp()
    paths = report.write_bundle(data, out_dir=out, with_brief=True)
    raw = Path(paths["brief"]).read_bytes()
    brief = json.loads(raw.decode("utf-8"))
    assert brief["brief_bytes"] == len(raw), (
        "brief_bytes " + str(brief["brief_bytes"]) + " != file " + str(len(raw)))
    assert brief["brief_max_bytes"] == 32 * 1024