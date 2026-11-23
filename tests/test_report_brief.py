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
                                   with_brief=True, with_md=True)
    with_brief = report.write_bundle(data, out_dir=b, with_json=True, with_brief=True,
                                     brief_top=3,
                                     brief_max_bytes=4096, coverage={"x": 1},
                                     with_md=True)
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


def _long_brief_input():
    """Legal coverage prose can be much larger than the brief itself."""
    data = {"counts": {"domains_in_scope": 7},
            "scope": {"match": ["example.com"], "target": "示例公司"},
            "environment": {"warnings": []}, "hosts": [],
            "internal_services": [], "leaks": {}, "next_steps": [],
            "generated_at": "2026-11-22T00:00:00Z"}
    coverage = {
        "known": True, "source": "run-long-errors", "complete": False,
        "requested_complete": False, "_result_status": "partial",
        "failed_stages": [{"stage": "crawl", "error": "收集失败：" * 4000}],
        "partial_stages": [{"stage": "extract", "outcome": "partial",
                            "reason": "仍有待处理任务：" * 4000}],
        "stage_states": {"crawl": "failed", "extract": "partial"},
        "unavailable": {}, "stop_reason": "work_pending"}
    return data, coverage


def test_brief_bounds_long_stage_errors_with_the_final_stdout_encoder():
    fresh_core()
    from lib import core, report
    for ascii_safe in (True, False):
        data, coverage = _long_brief_input()
        before = json.dumps(coverage, ensure_ascii=False)
        brief = report.build_brief(data, coverage=coverage, ascii_safe=ascii_safe)
        # cmd_brief merges more fields after build_brief, then fits again.
        brief["note"] = "最后合并的提示" * 5000
        report.fit_brief(brief, 32768, ascii_safe=ascii_safe)
        raw = core.encode_json_line(brief, ascii_safe).encode("utf-8")
        assert len(raw) == brief["brief_bytes"] <= 32768
        assert brief["coverage"]["source"] == "run-long-errors"
        assert brief["coverage"]["failed_stages"][0]["stage"] == "crawl"
        assert brief["coverage"]["partial_stages"][0]["stage"] == "extract"
        assert brief["coverage"]["complete"] is False
        assert brief["coverage"]["result_status"] == "partial"
        marker = brief["truncated"]["byte_budget"]
        assert marker["shortened_strings"] >= 2
        assert "status --run" in marker["hint"]
        assert json.dumps(coverage, ensure_ascii=False) == before


def test_brief_bounds_long_scope_and_records_original_array_totals():
    fresh_core()
    from lib import core, report
    for ascii_safe in (True, False):
        data, coverage = _long_brief_input()
        data["scope"]["match"] = ["host" + str(i) + ".example.com"
                                  for i in range(5000)]
        # A valid domain may exceed the prose limit. Never clip an identity
        # into an unusable '...'-suffixed domain while shortening its array.
        first_domain = ("a" * 63 + ".") * 3 + "a" * 61
        data["scope"]["match"][0] = first_domain
        data["scope"]["target"] = "长范围说明" * 5000
        coverage["failed_stages"] = [
            {"stage": "stage-" + str(i), "error": "出错" * 2000}
            for i in range(80)]
        brief = report.build_brief(data, coverage=coverage, max_bytes=6000,
                                   ascii_safe=ascii_safe)
        raw = core.encode_json_line(brief, ascii_safe).encode("utf-8")
        assert len(raw) == brief["brief_bytes"] <= 6000
        assert brief["counts"] == data["counts"]
        assert brief["scope"]["match"][0] == first_domain
        assert len(data["scope"]["match"]) == 5000
        assert brief["coverage"]["failed_stages"][0]["stage"] == "stage-0"
        for path, total in (("scope.match", 5000),
                            ("coverage.failed_stages", 80)):
            cut = brief["truncated"][path]
            assert cut["total"] == total and 0 < cut["kept"] < total
        report.fit_brief(brief, 6000, ascii_safe=ascii_safe)
        assert brief["truncated"]["scope.match"]["total"] == 5000


def test_brief_file_uses_the_same_bounded_encoder_without_the_newline():
    fresh_core()
    from lib import report
    data, coverage = _long_brief_input()
    with tempfile.TemporaryDirectory() as directory:
        result = report.write_brief(data, directory, max_bytes=6000,
                                    coverage=coverage)
        raw = Path(result["path"]).read_bytes()
        brief = json.loads(raw)
        assert len(raw) == result["bytes"] == brief["brief_bytes"] <= 6000
        assert raw == report._encode_brief(
            brief, ascii_safe=False, trailing_newline=False).encode("utf-8")
        assert not raw.endswith(b"\n")


def test_brief_refuses_when_required_identity_cannot_fit():
    fresh_core()
    from lib import core, report
    data, coverage = _long_brief_input()
    coverage["source"] = "run-" + "x" * 40000
    try:
        report.build_brief(data, coverage=coverage)
    except core.FindInfoError as exc:
        assert "max_bytes" in str(exc) and "identity" in str(exc)
    else:
        raise AssertionError("oversized required identity returned a successful brief")


def test_brief_cli_long_errors_emit_one_bounded_measured_json_line():
    """Exercise the real final merge -> fit -> emit path, not only the helper."""
    import os
    import subprocess
    import sys
    fresh_core()
    from tests.util import ROOT
    for utf8 in (False, True):
        with tempfile.TemporaryDirectory(prefix="fi-brief-hard-limit-") as home:
            rid = "20261122-000000-example.com"
            rd = Path(home) / "runs" / rid
            rd.mkdir(parents=True)
            _, coverage = _long_brief_input()
            coverage["source"] = rid
            state = {"run_id": rid, "state": "completed", "seq": 1,
                     "attempt": 1, "coverage": coverage,
                     "result": {"status": "partial", "reason": "failed_stages:crawl"}}
            (rd / "status.json").write_text(json.dumps(state), encoding="utf-8")
            env = dict(os.environ, FINDINFO_HOME=home, FINDINFO_TASK="",
                       FINDINFO_EMIT_UTF8="1" if utf8 else "0")
            env.pop("FINDINFO_RUN_DIR", None)
            proc = subprocess.run(
                [sys.executable, str(ROOT / "findinfo.py"), "--home", home,
                 "brief", "--run", rid], capture_output=True, env=env,
                cwd=str(ROOT), timeout=60)
            assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
            brief = json.loads(proc.stdout)
            assert proc.stdout.count(b"\n") == 1
            assert len(proc.stdout) == brief["brief_bytes"] <= 32768
            assert brief["coverage"]["source"] == rid
            assert brief["coverage"]["complete"] is False
            assert brief["coverage"]["failed_stages"][0]["stage"] == "crawl"
            assert brief["coverage"]["partial_stages"][0]["stage"] == "extract"


def test_brief_final_cuts_keep_original_totals_after_arrays_are_emptied():
    fresh_core()
    from lib import core, report
    for ascii_safe in (True, False):
        data, coverage = _long_brief_input()
        data["hosts"] = [
            {"host": "host" + str(i) + ".example.com", "priority": "high",
             "score": 10, "reasons": ["reason"] * 5,
             "provenance": ["source"] * 5} for i in range(3)]
        data["leaks"]["private_ips"] = ["10.0.0." + str(i) for i in range(100)]
        data["next_steps"] = ["step " + str(i) for i in range(12)]
        # The explicit leak example cap must remember 100, not the 20 rows
        # seen later by fit_brief. No byte-pressure cut has happened yet.
        capped = report.build_brief(data, coverage={"known": True},
                                    ascii_safe=ascii_safe)
        assert capped["truncated"]["leaks.private_ips"] == {"kept": 20, "total": 100}

        brief = report.build_brief(data, coverage=coverage, ascii_safe=ascii_safe)
        assert brief["top_hosts"] == []
        assert brief["leaks"]["private_ips"] == []
        assert len(brief["next_steps"]) == 2
        expected = {"top_hosts": {"kept": 0, "total": 3},
                    "leaks.private_ips": {"kept": 0, "total": 100},
                    "next_steps": {"kept": 2, "total": 12}}
        for path, cut in expected.items():
            actual = brief["truncated"][path]
            assert actual["kept"] == cut["kept"]
            assert actual["total"] == cut["total"]
        brief["note"] = "another final merge" * 10000
        report.fit_brief(brief, 32768, ascii_safe=ascii_safe)
        for path, cut in expected.items():
            actual = brief["truncated"][path]
            assert actual["kept"] == cut["kept"]
            assert actual["total"] == cut["total"]
        raw = core.encode_json_line(brief, ascii_safe).encode("utf-8")
        assert len(raw) == brief["brief_bytes"] <= 32768
