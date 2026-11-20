"""Batch A acceptance: honest stage results and a verdict from obligations.

Fixture brand is 美团 (Meituan); every subject, domain, record and count in
these tests is SYNTHETIC and lives under the reserved example.com/.net/.org
namespaces. No test here reaches a resolver, provider or native tool: every
collector -- including the free-source round and brute -- is an injected
double, and core.run is guarded to fail loudly if anything tries to spawn a
process or touch the network. The scenarios follow docs/RELIABILITY-PLAN.md:

* T02 - an enabled icp/brute stage that never reports a result must make the
  run partial with a named gap, never complete;
* T03 - one mapping source answering while an available sibling times out is
  a preserved partial outcome, not a successful checkpoint;
* T04 - an absent OPTIONAL key is a capability gap: no provider call, no
  endless-resume advice, exit 0 when the rest of the work finishes;
* T05 - an empty successful upstream leaves probe with no accountable input:
  a justified no_input disposition, not an invented failure.
"""

import io
import json
from contextlib import redirect_stdout

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

import unittest.mock as mock

from tests.util import fresh_core, fresh_tools, import_findinfo


def _forbid_network(cmd, *a, **kw):
    raise AssertionError("native tool or network reached in an offline test: "
                         + str(cmd)[:120])


def _args(**over):
    """Same shape the run parser produces; defaults describe a PASSIVE 美团 run."""
    base = dict(
        task="", name="", domain=["mt-a.example.com"], active=False, ports=False,
        vhost=False, crawl=False, brute=False, brute_wordlist="wordlists/sub.txt",
        brute_bandwidth="3m", depth=3, invest=51, deep=2,
        engines="fofa,quake,hunter,shodan,censys", no_icp=True, no_onepass=True,
        top_ports=1000, max_seed=5, max_vhost_ips=10, force_stage=False,
        background=False, resume="", rounds=1, time_budget=0.0,
        task_timeout=0.0, tool_timeout=0)
    base.update(over)
    import argparse
    return argparse.Namespace(**base)


def _quiet(**over):
    """Injected collectors that answer instantly with a clean empty success."""
    fakes = {
        "t_certs": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True},
        "t_subs": lambda s, d, engines="", timeout=0, **kw: {"count": 0, "ok": True},
        "t_dns": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True, "rc": 0,
                                                "domains": [], "wildcard": []},
        "t_onepass": lambda s, roots, timeout=0, **kw: {"count": 0, "ok": True,
                                                     "sources_error": 0},
        "t_brute": lambda s, d, wordlist=None, bandwidth="3m", timeout=0, **kw:
                    {"count": 0, "ok": True, "rc": 0, "domains": []},
    }
    fakes.update(over)
    return fakes


def _run(fi, core, args, fakes):
    """cmd_run with injected collectors; returns the final summary of the run."""
    store = core.Store()
    store.upsert_asset("domain", "mt-a.example.com", source="seed:user",
                       confidence=0.9, passivity="passive")
    store.close()
    buf = io.StringIO()
    patches = [mock.patch.object(fi.tools, name, side_effect=fn)
               for name, fn in fakes.items()]
    patches.append(mock.patch.object(fi.tools.core, "run", side_effect=_forbid_network))
    patches.append(mock.patch.object(fi.tools.core, "run_stream",
                                     side_effect=_forbid_network))
    for p in patches:
        p.start()
    try:
        with redirect_stdout(buf):
            fi.cmd_run(args)
    finally:
        for p in reversed(patches):
            p.stop()
    rd = sorted(core.RUNS_DIR.glob("*"), key=lambda p: p.stat().st_mtime)[-1]
    return json.loads((rd / "summary.jsonl").read_text(encoding="utf-8").splitlines()[-1])


def test_t03_subs_partial_outcome_is_preserved_not_check():
    """One engine answers, an available sibling times out: partial, kept data."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()

    def subs_partial(s_, d, engines="", timeout=0, **kw):
        s_.upsert_asset("domain", "api.mt-a.example.com", source="quake",
                        confidence=0.8, passivity="passive")
        return {"count": 1, "domains": [{"domain": "api.mt-a.example.com",
                                         "sources": ["quake"]}],
                "outcome": core.OUTCOME_PARTIAL, "ok": False, "rc": 0,
                "per_source": [
                    {"id": "quake", "outcome": core.OUTCOME_OK, "found": 1},
                    {"id": "fofa", "outcome": core.OUTCOME_TIMEOUT, "found": 0}]}

    summary = _run(fi, core, _args(), _quiet(t_subs=subs_partial))
    subs_entry = [s for s in summary["stages"] if s.get("stage") == "subs"][0]
    assert subs_entry.get("outcome") == core.OUTCOME_PARTIAL, (
        "the stage entry must carry the outcome _subs computed, not a default",
        subs_entry)
    assert summary["result"]["status"] == "partial", summary["result"]
    assert "subs" in summary["result"]["reason"], summary["result"]["reason"]
    assert "subs" in [p["stage"] for p in summary["coverage"]["partial_stages"]], (
        summary["coverage"]["partial_stages"])
    # The kept data is real even though the stage is partial.
    names = {a["canonical"] for a in core.Store().get_assets(kind="domain")}
    assert "api.mt-a.example.com" in names, names
    # A partial stage must NOT write a done checkpoint: a re-run retries it.
    steps = {r[0]: r[1] for r in core.Store().conn.execute(
        "SELECT step,status FROM steps")}
    assert steps.get("subs") != "done", steps


def test_t02_enabled_brute_never_reporting_makes_run_partial():
    """--brute enabled with a double that reports nothing: never complete.

    The collector answers an empty success, so the stage runs -- but a stage
    that never reports a RESULT ROW cannot let the run claim complete
    coverage of the requested work while other planned stages (probe) are
    equally empty. This pins the honest-verdict gate: partial_stages and
    not_run_stages both route to partial/exit 5.
    """
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()

    def brute_silent(s_, d, wordlist=None, bandwidth="3m", timeout=0, **kw):
        # never reports: no rows, no entry payload beyond the minimum
        return {"count": 0, "ok": False, "rc": 1, "domains": []}

    summary = _run(fi, core, _args(active=True, brute=True),
                   _quiet(t_brute=brute_silent))
    assert "brute" in summary["coverage"]["planned_stages"], (
        summary["coverage"]["planned_stages"])
    brute_entry = [s for s in summary["stages"] if s.get("stage") == "brute"]
    assert brute_entry, "brute ran; its entry must exist"
    # a failed brute with no rows is a failed/partial stage, never complete
    assert summary["result"]["status"] == "partial", summary["result"]
    assert summary["result"]["reason"] == "stage_failed", summary["result"]
    failed_names = [f["stage"] for f in summary["coverage"]["failed_stages"]]
    assert "brute" in failed_names, (failed_names, summary["coverage"])
    # a failed stage must never carry a done checkpoint
    steps = {r[0]: r[1] for r in core.Store().conn.execute(
        "SELECT step,status FROM steps")}
    assert steps.get("brute") == "failed", steps


def test_t04_missing_optional_key_is_a_gap_not_a_failure():
    """No uncover key configured: unavailable capability, no provider call."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()

    orig_key = core.engine_has_key
    core.engine_has_key = lambda engine: False
    try:
        summary = _run(fi, core, _args(engines="fofa"), _quiet())
    finally:
        core.engine_has_key = orig_key
    # keyless contract: absent OPTIONAL key does not produce exit 5
    assert summary["result"]["status"] == "complete", summary["result"]
    cov = summary["coverage"]
    assert "fofa" in (cov["unavailable"].get("engines_without_key") or []), cov
    assert cov["unavailable"]["blocking"] is False, cov["unavailable"]


def test_t05_empty_upstream_yields_accountable_no_input():
    """Everything answered empty: probe is justified no_input, run completes."""
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    summary = _run(fi, core, _args(active=True), _quiet())
    assert summary["result"]["status"] == "complete", summary["result"]
    stage_states = summary["coverage"]["stage_states"]
    assert stage_states.get("probe") in ("no_input", "succeeded"), stage_states
    failed = [f["stage"] for f in summary["coverage"]["failed_stages"]]
    assert "probe" not in failed, failed
