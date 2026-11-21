"""Each mapping engine is asked in its own query language.

uncover hands `-q` to every engine VERBATIM; it does not translate between
query languages. subs used to send Quake syntax (domain:"x") to FOFA, Hunter,
Shodan and Censys in one dispatch, and icp sent FOFA syntax (icp="x") to Quake
and Hunter. uncover reports an upstream syntax/auth error as rc=0 with no
rows, so every engine but one looked like "found nothing" -- a silent
coverage loss. These tests pin the contract that replaced it:

  1. one dispatch per engine, each in that engine's own syntax
  2. an engine with no known query is a visible gap, never asked blindly
  3. an rc=0 empty answer is reported as unconfirmed, not as a clean empty
  4. the question asked is part of the stage checkpoint (keyed engines only)
"""
import contextlib
import json
import unittest.mock as mock

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo
from tests.test_run_flow import _args, _latest_summary, _quiet, _run_quiet

ICP = "京ICP备10210538号"


def _engine_calls(calls):
    """{engine: [query, ...]} for every uncover dispatch a fake core.run saw."""
    out: dict = {}
    for cmd in calls:
        argv = [str(x) for x in cmd]
        if not argv or "uncover" not in argv[0]:
            continue
        eng = argv[argv.index("-e") + 1]
        out.setdefault(eng, []).append(argv[argv.index("-q") + 1])
    return out


@contextlib.contextmanager
def _keyed(core, engines, run):
    """Credentials for exactly `engines`, an uncover binary, a fake core.run."""
    keyed = set(engines)
    with contextlib.ExitStack() as st:
        st.enter_context(mock.patch.object(core, "api_base", lambda n: ""))
        st.enter_context(mock.patch.object(core, "engine_has_key",
                                           lambda e: e in keyed))
        st.enter_context(mock.patch.object(core, "has_tool",
                                           lambda n: n == "uncover"))
        st.enter_context(mock.patch.object(core, "tool", lambda n: "/fake/" + n))
        st.enter_context(mock.patch.object(core, "run", run))
        st.enter_context(mock.patch.object(core, "mapping_wait", lambda: None))
        st.enter_context(mock.patch.object(core, "throttle", lambda n: None))
        yield


def _recorder(calls, answer=None):
    def run(cmd, *a, **kw):
        calls.append(cmd)
        if answer is not None:
            return answer(cmd)
        return (0, "", "")
    return run


def _engine_of(cmd):
    argv = [str(x) for x in cmd]
    return argv[argv.index("-e") + 1] if "-e" in argv else ""


# ------------------------------------------------------------------ dispatch
# The per-engine dispatch these cases describe now lives in lib/mapdispatch
# (the single `mapping` stage). t_subs/t_icp stayed as PASSIVE collectors and
# are keyless by construction, so they no longer dispatch uncover at all --
# that move is exactly what makes "one question per task" possible.
def test_each_engine_is_asked_in_its_own_language():
    from lib import mapdispatch, mapping
    core = fresh_core()
    calls: list = []
    store = core.Store()
    try:
        mapping.ensure_schema(store)
        with _keyed(core, ["fofa", "quake", "hunter", "shodan"],
                    _recorder(calls)):
            mapdispatch.ask_all(store, "RUNQ", "domain", ["example.com"],
                                engines="fofa,quake,hunter,shodan")
    finally:
        store.close()
    assert _engine_calls(calls) == {
        "fofa": ['domain="example.com"'],
        "quake": ['domain:"example.com"'],
        "hunter": ['domain="example.com"'],
        "shodan": ['hostname:"example.com"'],
    }, _engine_calls(calls)


def test_engine_without_a_query_syntax_is_a_visible_gap():
    """shodan has no known ICP query: never asked, reported as a gap."""
    from lib import mapdispatch, mapping
    core = fresh_core()
    calls: list = []
    store = core.Store()
    try:
        mapping.ensure_schema(store)
        with _keyed(core, ["fofa", "shodan"], _recorder(calls)):
            r = mapdispatch.ask_all(store, "RUNQ", "icp", [ICP],
                                    engines="fofa,shodan")
    finally:
        store.close()
    assert list(_engine_calls(calls)) == ["fofa"], _engine_calls(calls)
    assert any(s["engine"] == "shodan" and "syntax" in s["reason"]
               for s in r["skipped_engines"]), r


def test_each_icp_engine_is_asked_in_its_own_language():
    from lib import mapdispatch, mapping
    core = fresh_core()
    calls: list = []
    store = core.Store()
    try:
        mapping.ensure_schema(store)
        with _keyed(core, ["fofa", "quake", "hunter"], _recorder(calls)):
            mapdispatch.ask_all(store, "RUNQ", "icp", [ICP],
                                engines="fofa,quake,hunter")
    finally:
        store.close()
    assert _engine_calls(calls) == {
        "fofa": ['icp="' + ICP + '"'],
        "quake": ['icp:"' + ICP + '"'],
        "hunter": ['icp.number="' + ICP + '"'],
    }, _engine_calls(calls)


def test_a_failing_engine_is_recorded_not_retried():
    from lib import mapdispatch, mapping, metered
    core = fresh_core()
    calls: list = []

    def answer(cmd):
        if _engine_of(cmd) == "quake":
            return (1, "", "boom")
        return (0, json.dumps({"host": "b.example.com", "ip": "1.2.3.4"}) + chr(10), "")

    store = core.Store()
    try:
        mapping.ensure_schema(store)
        with _keyed(core, ["fofa", "quake"], _recorder(calls, answer)):
            r = mapdispatch.ask_all(store, "RUNQ", "icp", [ICP],
                                    engines="fofa,quake")
            # the failing engine's outcome is on the ledger, not retried
            q = mapping.question("quake", "icp", ICP,
                                 core.uncover_query("icp", "quake", ICP))
            assert mapping.lookup(store, q)["status"] == metered.ST_FAILED
            assert len(calls) == 2, calls
            # a second identical call is a cache hit (no new wire traffic)
            mapdispatch.ask_all(store, "RUNQ", "icp", [ICP],
                                engines="fofa,quake")
            assert len(calls) == 2, ("a recorded failure must not be retried", calls)
    finally:
        store.close()


def test_subs_is_passive_and_keyless():
    """t_subs no longer dispatches uncover, whatever keys are configured."""
    core = fresh_core()
    tools = fresh_tools(core)
    calls: list = []
    store = core.Store()
    try:
        with _keyed(core, ["fofa", "quake", "hunter", "shodan"],
                    _recorder(calls)):
            tools.t_subs(store, "example.com", engines="fofa,quake")
    finally:
        store.close()
    assert _engine_calls(calls) == {}, (
        "subs must not spend mapping quota any more", calls)


def test_query_values_cannot_break_out_of_the_quoted_term():
    core = fresh_core()
    q = core.uncover_query("icp", "fofa", 'X" || domain="evil.example')
    assert q.count('"') == 2, q


# ------------------------------------------------------- checkpoint identity
def test_query_language_is_hashed_only_for_usable_engines():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    with mock.patch.object(core, "engine_has_key", lambda e: False):
        keyless = fi._subs_stage_inputs(["example.com"], "fofa,quake")
        icp_keyless = fi._icp_stage_inputs([ICP], "fofa,quake")
    # keyless checkpoints keep exactly their old identity (no re-run)
    assert set(keyless) == {"seeds", "engines", "usable_engines"}, keyless
    assert set(icp_keyless) == {"codes"}, icp_keyless
    with mock.patch.object(core, "engine_has_key", lambda e: e == "quake"):
        keyed = fi._subs_stage_inputs(["example.com"], "fofa,quake")
        icp_keyed = fi._icp_stage_inputs([ICP], "fofa,quake")
    assert keyed["queries"] == {"quake": 'domain:"{value}"'}, keyed
    assert icp_keyed["usable_engines"] == ["quake"], icp_keyed
    assert icp_keyed["queries"] == {"quake": 'icp:"{value}"'}, icp_keyed


# ------------------------------------------------------------ run coverage
def test_run_surfaces_unconfirmed_and_unsupported_engines_in_coverage():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()

    # The engine gaps now come from the mapping stage (subs is passive), so
    # this injects them where they are actually produced.
    def fake_ask_all(store, run_id, kind, values, *, engines=None,
                     remap=False, timeout=0, ledger=None):
        if kind != "domain":
            return {"kind": kind, "dispatched": 0, "reused": 0,
                    "failures": [], "truncated_sources": [],
                    "skipped_engines": [], "results": []}
        return {"kind": kind, "dispatched": 2, "reused": 0,
                "failures": [{"engine": "quake", "value": "example.com",
                              "status": "empty", "reason": ""}],
                "truncated_sources": [],
                "skipped_engines": [{"engine": "censys",
                                     "reason": "no domain query syntax for this engine"}],
                "results": []}

    patches = [mock.patch.object(fi.mapdispatch, "ask_all",
                                 side_effect=fake_ask_all),
               # the entity stage must not run the real ENScan binary
               mock.patch.object(fi.tools, "t_enscan",
                                 side_effect=lambda st, n, **kw: {
                                     "rc": 0, "json_files": 0,
                                     "companies": [], "icp": [],
                                     "domains": [], "apps": []})]
    for _p in patches:
        _p.start()
    try:
        # a brand run plans the mapping stage (a bare --domain run has no
        # subject to map, so it correctly plans none)
        rc, _ = _run_quiet(fi, _args(name="fixture-brand"), _quiet())
    finally:
        for _p in reversed(patches):
            _p.stop()
    assert rc == 0, "an unconfirmed empty is a gap, not a failed run"
    _, summary = _latest_summary(core)
    gap = summary["coverage"]["unavailable"]
    assert gap["unconfirmed_empty"] == ["uncover:quake"], gap
    assert gap["unsupported_engines"] == ["censys"], gap
    assert "unconfirmed" in gap["note"], gap


def test_brief_lists_the_engine_gaps():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    from lib import report
    stages = [{"stage": "subs", "unconfirmed_empty": ["uncover:quake"],
               "unsupported_engines": ["censys"]},
              {"stage": "icp", "unconfirmed_empty": ["uncover:hunter"]}]
    gap = fi._fold_runtime_unavailable({"engines_without_key": [], "note": ""},
                                       stages, [])
    assert gap["unconfirmed_empty"] == ["uncover:hunter", "uncover:quake"], gap
    cov = report._brief_coverage(coverage={"known": True, "unavailable": gap})
    kinds = {(u["kind"], u.get("reason")) for u in cov["unavailable"]}
    assert ("unconfirmed_empty", "uncover:quake") in kinds, kinds
    assert ("unsupported_engines", "censys") in kinds, kinds
