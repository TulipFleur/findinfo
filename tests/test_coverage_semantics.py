"""Result semantics: a coverage gap is not a failure, and a timeout is
not a failure either. The agent reads coverage through `brief`, so these
tests pin the whole chain: combine_outcome -> run state -> brief payload.
"""
import argparse
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, import_findinfo


def _oc():
    from lib import core
    return core


def test_all_sources_timing_out_is_a_timeout():
    core = _oc()
    assert core.combine_outcome(core.OUTCOME_TIMEOUT,
                                 core.OUTCOME_TIMEOUT) == core.OUTCOME_TIMEOUT
    assert core.combine_outcome(core.OUTCOME_FAILED,
                                 core.OUTCOME_TIMEOUT) == core.OUTCOME_FAILED
    assert core.combine_outcome(core.OUTCOME_OK,
                                 core.OUTCOME_TIMEOUT) == core.OUTCOME_TIMEOUT


def test_gaps_never_outrank_failures():
    core = _oc()
    assert core.combine_outcome(core.OUTCOME_UNAVAILABLE,
                                 core.OUTCOME_UNAVAILABLE) == core.OUTCOME_UNAVAILABLE
    assert core.combine_outcome(core.OUTCOME_UNAVAILABLE,
                                 core.OUTCOME_OK) == core.OUTCOME_OK
    assert core.combine_outcome(core.OUTCOME_UNAVAILABLE,
                                 core.OUTCOME_FAILED) == core.OUTCOME_FAILED
    assert core.combine_outcome(core.OUTCOME_EMPTY,
                                 core.OUTCOME_UNAVAILABLE) == core.OUTCOME_EMPTY


def test_select_coverage_tells_gaps_from_no_data():
    core = _oc()
    empty = core.empty_coverage()
    assert empty["source"] == core.COVERAGE_SOURCE_NONE
    assert empty["known"] is False
    real = core.select_coverage({"failed_stages": [{"stage": "subs", "error": "rc=1"}]}, "run-1")
    assert real["source"] == "run-1" and real["known"] is True
    assert real["failed_stages"] == [{"stage": "subs", "error": "rc=1"}]
    absent = core.select_coverage(None, "run-1")
    assert absent["known"] is False, "a run with no recorded gaps is unknown"
    # a run that recorded *something* is known even when one bucket is empty
    bare = core.select_coverage({"failed_stages": []}, "run-1")
    assert bare["known"] is True and bare["failed_stages"] == [], bare


def _seed_run(core, jobs, scope, state=None):
    rd = core.new_run_dir("sem" + str(len(scope)))
    jobs.write_spec(rd, entry="findinfo:main", argv=["run"], target=scope[0],
                    scope=list(scope), home=str(core.HOME), root=str(core.ROOT))
    for key, value in (state or {}).items():
        jobs.update_state(rd, **{key: value})
    return rd


def _brief(args):
    fi = import_findinfo()
    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_brief(args)
    return json.loads(buf.getvalue().strip().splitlines()[-1])


def _args(**kw):
    base = dict(match=["example.org"], min_conf=0.3, limit=300, ep_limit=400,
                engagement="default", run="", top=20, max_bytes=32768)
    base.update(kw)
    return argparse.Namespace(**base)


def test_brief_with_run_reads_that_runs_gaps():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    store = core.Store()
    store.upsert_asset("domain", "app.example.org", source="onepass:crt.sh",
                       confidence=0.9)
    store.close()
    rd = _seed_run(core, jobs, ["example.org"], {
        "coverage": {"failed_stages": [{"stage": "crawl", "error": "rc=1"}],
                     "unavailable": {"uncover": "no api key for engines: fofa"},
                     "not_run_stages": ["brute"]}})
    cov = _brief(_args(run=rd.name))["coverage"]
    assert cov["known"] is True and cov["source"] == rd.name, cov
    assert [f["stage"] for f in cov["failed_stages"]] == ["crawl"], cov
    assert [u["kind"] for u in cov["unavailable"]] == ["uncover"], cov
    assert "no api key" in cov["unavailable"][0]["reason"], cov
    assert cov["not_run_stages"] == ["brute"], cov
    assert "hint" not in cov, "a known run needs no hint: " + str(cov)


def test_brief_match_falls_back_to_the_latest_matching_run():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    store = core.Store()
    store.upsert_asset("domain", "app.example.org", source="onepass:crt.sh",
                       confidence=0.9)
    store.close()
    _seed_run(core, jobs, ["other.example.net"], {
        "coverage": {"failed_stages": [{"stage": "probe", "error": "rc=1"}]}})
    mine = _seed_run(core, jobs, ["example.org"], {
        "coverage": {"failed_stages": [{"stage": "subs", "error": "rc=1"}]}})
    cov = _brief(_args(match=["example.org"]))["coverage"]
    assert cov["source"] == mine.name, "picked another scope: " + str(cov)
    assert [f["stage"] for f in cov["failed_stages"]] == ["subs"], cov


def test_brief_without_any_run_says_the_gaps_are_unknown():
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "app.example.org", source="onepass:crt.sh",
                       confidence=0.9)
    store.close()
    cov = _brief(_args(match=["example.org"]))["coverage"]
    assert cov["known"] is False, cov
    assert cov["hint"], "unknown coverage must say how to fix it: " + str(cov)
    assert not cov.get("blocking"), "unknown must not look blocking: " + str(cov)


def test_brief_keeps_a_blocking_gap_visible():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = _seed_run(core, jobs, ["example.org"], {
        "coverage": {"blocking": True, "note": "no DNS resolver reachable",
                     "failed_stages": [{"stage": "dnsx", "error": "rc=1"}]}})
    cov = _brief(_args(run=rd.name))["coverage"]
    assert cov["blocking"] is True, cov
    assert cov["blocking_reason"] == "no DNS resolver reachable", cov
    assert "note" not in cov, "the reason must not be duplicated: " + str(cov)


def test_coverage_flags_are_not_mistaken_for_gaps():
    from lib import report as rep
    block = {"blocking": False, "note": "", "source": "run-1", "known": True,
             "failed_stages": [], "unavailable": {},
             "not_run_stages": ["brute"]}
    out = rep._brief_coverage({"coverage": block})
    assert "blocking" not in out and "note" not in out, out
    assert out["not_run_stages"] == ["brute"], out
    assert out["known"] is True and out["source"] == "run-1", out


def test_report_brief_and_brief_command_agree_on_coverage():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    store = core.Store()
    store.upsert_asset("domain", "app.example.org", source="onepass:crt.sh",
                       confidence=0.9)
    store.close()
    rd = _seed_run(core, jobs, ["example.org"], {
        "coverage": {"failed_stages": [{"stage": "crawl", "error": "rc=1"}],
                     "unavailable": {"uncover": "no key"},
                     "not_run_stages": ["brute"]}})
    via_cmd = _brief(_args(run=rd.name))["coverage"]
    from lib import report as rep
    st = core.Store()
    data = rep.collect(st, match=["example.org"])
    st.close()
    via_file = rep.build_brief(data, top=20,
                              coverage=core.select_coverage(
                                  jobs.read_state(rd.name).get("coverage"), rd.name))
    assert via_file["coverage"] == via_cmd, (via_file["coverage"], via_cmd)


def test_subs_timeout_is_recorded_as_timeout_not_done():
    """A stage whose every source hit its deadline must not be written as
    done: the breakpoint would then hide the gap for the rest of the run."""
    core = _oc()
    assert core.combine_outcome(core.OUTCOME_TIMEOUT) == core.OUTCOME_TIMEOUT
    src = Path(str(Path(core.ROOT) / "findinfo.py")).read_text(encoding="utf-8")
    assert "if oc in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT):" in src, (
        "the subs stage must refuse to checkpoint a timeout")


ALL_TESTS = [name for name in list(globals()) if name.startswith("test_")]
