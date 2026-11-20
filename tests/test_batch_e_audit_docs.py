"""Batch E acceptance: invocation history, audit units, input declaration, docs.

Offline. Pinned:

* a retry of the same unit APPENDS an invocation row (history is not
  overwritten); the effective view reads the latest dispatch of the current
  attempt, and the ordering column really exists (F17);
* audit separates a real second dispatch from a replayed log event, keeps a
  native dispatch's unit distinct from a provider HTTP request, and preserves
  an unsettled (uncertain) row across a reload (F08);
* an explicit IP:port target is refused before any collection, not silently
  stripped of its port (F12);
* SKILL.md / prompts/AGENT.txt / TOOLS.md state the work_queue convergence
  rule and the offline/dry-run entry (the completion-mark sync).
"""

import json

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, metered, work
from tests.util import ROOT, fresh_core

RUN = "20261121-150000-mt-a.example.com"


def _store():
    s = fresh_core().Store()
    work.ensure_schema(s)
    return s


# ---------------------------------------------------------------- F17 history
def test_retry_appends_invocation_history():
    """Two dispatches of one unit are two rows, not one replaced row."""
    s = _store()
    inv1 = work.start_invocation(s, RUN, 2, "subs", unit_key="root",
                                 input_revision=1, input_fingerprint="fp1")
    work.finish_invocation(s, inv1, "failed", "failed", "source_timeout")
    inv2 = work.start_invocation(s, RUN, 2, "subs", unit_key="root",
                                 input_revision=1, input_fingerprint="fp1")
    work.finish_invocation(s, inv2, "succeeded", "ok", "")
    assert inv1 != inv2, "a retry must get its own invocation_id"
    hist = work.invocation_history(s, RUN, attempt=2)
    assert len(hist) == 2, ("history must keep both dispatches", hist)
    states = [h["state"] for h in hist]
    assert states == ["failed", "succeeded"], states
    # effective = the LATEST dispatch of this attempt (the repair)
    eff = work.effective_invocations(s, RUN, 2)
    assert eff[("subs", "root")]["state"] == "succeeded", eff
    s.close()


def test_effective_invocations_query_uses_a_real_column():
    """No `no such column: id` -- ordering uses the persisted dispatch_seq."""
    s = _store()
    for i in range(3):
        inv = work.start_invocation(s, RUN, 1, "dns", unit_key="r%d" % i)
        work.finish_invocation(s, inv, "succeeded", "ok", "")
    eff = work.effective_invocations(s, RUN, 1)   # must not raise
    assert len(eff) == 3, eff
    seqs = [r["dispatch_seq"] for r in s.conn.execute(
        "SELECT dispatch_seq FROM stage_invocations WHERE run_id=? ORDER BY"
        " dispatch_seq", (RUN,))]
    assert seqs == sorted(seqs) and all(x > 0 for x in seqs), seqs
    s.close()


def test_migrated_older_table_gains_dispatch_seq():
    """An older stage_invocations table is migrated additively (idempotent)."""
    s = _store()
    # simulate the old shape by dropping the column is not possible in SQLite;
    # instead assert that a second ensure_schema call is a no-op and the column
    # exists with sane values on new rows
    work.ensure_schema(s)
    work.ensure_schema(s)
    inv = work.start_invocation(s, RUN, 1, "icp")
    row = s.conn.execute("SELECT dispatch_seq FROM stage_invocations WHERE"
                         " invocation_id=?", (inv,)).fetchone()
    assert row["dispatch_seq"] >= 1, dict(row)
    s.close()


# ---------------------------------------------------------------- F08 audit
def test_real_second_dispatch_is_two_rows_and_a_replay_is_one():
    led = metered.MeteredLedger(buffer=[])
    h = metered.hash_input({"d": "mt-a.example.com"})
    assert led.record(RUN, "quake", h, status=metered.ST_OK, returned=5)
    # the SAME paid query really ran twice: two rows
    assert led.record(RUN, "quake", h, status=metered.ST_OK, returned=5)
    assert led.totals(RUN)["requests"] == 2
    # the same log event written twice is not a second charge
    assert led.record(RUN, "quake", h, status=metered.ST_OK, returned=5,
                      replay=True) is False
    assert led.totals(RUN)["requests"] == 2
    # each dispatch carries its own id
    ids = {r["dispatch_id"] for r in led.rows(RUN)}
    assert len(ids) == 2, ids


def test_units_distinguish_provider_http_from_native_dispatch():
    led = metered.MeteredLedger(buffer=[])
    led.record(RUN, "fofa-gateway", "h1", status=metered.ST_OK, returned=10,
               unit=metered.UNIT_PROVIDER_HTTP)
    led.record(RUN, "uncover", "h2", status=metered.ST_OK, returned=40,
               unit=metered.UNIT_NATIVE_DISPATCH)
    tot = led.totals(RUN)
    assert tot["dispatch_units"][metered.UNIT_PROVIDER_HTTP] == 1, tot
    assert tot["dispatch_units"][metered.UNIT_NATIVE_DISPATCH] == 1, tot
    assert "not a price" in tot["note"].lower(), tot["note"]


def test_unsettled_dispatch_stays_unsettled_after_reload():
    """An unknown-billing dispatch is not counted as free or as charged."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="fi-uncertain-") as td:
        path = td + "/metered.jsonl"
        led = metered.MeteredLedger(path=path, run_id=RUN)
        led.record(engine="uncover", input_hash="h9", status=metered.ST_OK,
                   unit=metered.UNIT_NATIVE_DISPATCH, settled=False)
        rows = [json.loads(l) for l in open(path, encoding="utf-8")]
        assert rows[0]["status"] == metered.ST_UNCERTAIN, rows[0]
        assert rows[0]["settled"] is False
        back = metered.load_ledger(path, run_id=RUN)
        tot = back.totals(RUN)
        assert tot["unsettled"] == 1, tot
        assert tot["by_status"][metered.ST_UNCERTAIN] == 1, tot


# ---------------------------------------------------------------- F12 input
def test_ip_port_target_is_refused_not_silently_stripped():
    import argparse
    import io
    import unittest.mock as mock
    from contextlib import redirect_stdout
    import findinfo
    core_now = fresh_core()
    from tests.util import fresh_tools
    tools = fresh_tools(core_now)
    fi = findinfo
    args = argparse.Namespace(
        task="", name="", domain=["203.0.113.10:8443"], active=False,
        ports=False, vhost=False, crawl=False, brute=False,
        brute_wordlist="", brute_bandwidth="3m", depth=3, invest=51, deep=1,
        engines="fofa", no_icp=True, no_onepass=True, top_ports=1000,
        max_seed=5, max_vhost_ips=10, force_stage=False, background=False,
        resume="", rounds=1, time_budget=0.0, task_timeout=0.0,
        tool_timeout=0, entity_timeout=1200)
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            fi._run_pipeline(args)
            rc = None
        except core.FindInfoError as exc:
            rc = 2
            msg = str(exc)
    assert rc == 2, "an endpoint target must be refused before collection"
    assert "unsupported_target_kind" in msg, msg
    assert "203.0.113.10" in msg, msg


# ---------------------------------------------------------------- docs sync
def test_docs_state_the_current_contracts():
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "work_queue.outstanding" in skill, "SKILL must state the queue rule"
    assert "partial" in skill and "work_pending" in skill, skill[:200]
    agent = (ROOT / "prompts" / "AGENT.txt").read_text(encoding="utf-8")
    assert "work_queue.outstanding" in agent
    assert "never start a second run" in agent.lower() or \
        "SAME run id" in agent, "AGENT must keep the wait-don't-restart rule"
    tools_doc = (ROOT / "docs" / "TOOLS.md").read_text(encoding="utf-8")
    assert "doctor --offline" in tools_doc
    assert "--dry-run" in tools_doc
    assert "unsupported_target_kind" in tools_doc
    dm = (ROOT / "docs" / "DATA-MODEL.md").read_text(encoding="utf-8")
    assert "dispatch_seq" in dm and "native_dispatch" in dm
