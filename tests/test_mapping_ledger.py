"""Mapping runs once per task; no other tool ever holds an API key.

Batch 1 acceptance (all offline: fake ``core.run``/``Popen``, a temp task DB,
no sockets). The defects being pinned, from the static review:

* every mapping key was injected into EVERY child (httpx, naabu, katana), and
  several keys never reached the tool that wanted them because the variable
  name differed per consumer (HUNTER_KEY vs HUNTER_API_KEY, ...);
* one seed was sent to FOFA three times in a single run (onepass source, subs
  gateway, subs' ``uncover -e fofa``) and to Quake twice;
* standalone passive/subs/icp had no checkpoint at all;
* the stage checkpoint hashes the WHOLE seed list, so one new seed re-queried
  everything;
* ICP ``-1``/``-2`` suffix variants counted as separate questions;
* uncover's ``-limit`` was unset, so every query silently capped at 100 rows.

TDD note: the assertions below name the contract; the implementation that
satisfies them lives in lib/mapping.py (task ledger), lib/core.py (per-consumer
key env, no key by default) and findinfo.py (the single ``mapping`` stage and
the ``map`` command).
"""
import os

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, mapping, metered
from tests.util import fresh_core


def _store():
    s = fresh_core().Store()
    mapping.ensure_schema(s)
    return s


# ------------------------------------------------------- key environment
def test_no_child_gets_a_key_by_default():
    """tool_env() with no consumer is empty: a child holds no credential."""
    assert core.tool_env() == {}
    assert core.tool_env(None) == {}
    assert core.tool_env("") == {}


def test_keys_are_stripped_from_every_child_environment():
    """A key inherited from the shell never reaches a non-mapping child."""
    env = {"PATH": "/usr/bin", "HUNTER_KEY": "h", "HUNTER_API_KEY": "h2",
           "FOFA_KEY": "f", "VIRUSTOTAL_KEY": "v", "CENSYS_API_TOKEN": "c",
           "ZOOMEYE_API_KEY": "z", "HOME": "/root"}
    out = core.strip_key_env(dict(env))
    assert out == {"PATH": "/usr/bin", "HOME": "/root"}, out


def test_each_consumer_reads_the_variable_its_tool_reads():
    """uncover wants HUNTER_API_KEY / CENSYS_API_TOKEN; onepass wants HUNTER_KEY.

    The old single map sent HUNTER_TOKEN to both, so a configured Hunter key
    was never used by either tool.
    """
    # the variable NAMES each consumer must be able to receive
    uncover_vars = set(core._CONSUMER_VARS["uncover"])
    onepass_vars = set(core._CONSUMER_VARS["onepass"])
    assert "HUNTER_API_KEY" in uncover_vars, uncover_vars
    assert "CENSYS_API_TOKEN" in uncover_vars, uncover_vars
    assert "CENSYS_ORGANIZATION_ID" in uncover_vars, uncover_vars
    assert "ZOOMEYE_API_KEY" in uncover_vars, uncover_vars
    assert "HUNTER_KEY" in onepass_vars, onepass_vars
    assert "VIRUSTOTAL_KEY" in onepass_vars, onepass_vars
    assert "SECURITYTRAILS_KEY" in onepass_vars, onepass_vars
    assert "URLSCAN_KEY" in onepass_vars, onepass_vars
    # the wrong name for a consumer must NOT be what we hand it
    assert "HUNTER_TOKEN" not in uncover_vars | onepass_vars


def test_uncover_engine_list_matches_what_we_can_authenticate():
    """engine_has_key and the uncover table must agree on engine names."""
    for engine in core.CONSUMER_ENV["uncover"]:
        assert engine in core.UNCOVER_ENGINE_KEYS, (
            engine + " is dispatched but unknown to engine_has_key")


# ------------------------------------------------------- question identity
def test_icp_suffix_variants_are_one_question():
    a = mapping.question("fofa", "icp", "京ICP备00000001号-1", "q")
    b = mapping.question("fofa", "icp", "京ICP备00000001号-2", "q")
    assert a["value"] == b["value"] == "京ICP备00000001号", a["value"]
    assert a["query_hash"] == b["query_hash"]
    # a genuinely different filing is a different question
    c = mapping.question("fofa", "icp", "京ICP备00000002号-1", "q")
    assert c["query_hash"] != a["query_hash"]


def test_a_changed_template_is_a_new_question():
    a = mapping.question("fofa", "domain", "mt-a.example.com", 'domain="{value}"')
    b = mapping.question("fofa", "domain", "mt-a.example.com", 'host="{value}"')
    assert a["query_hash"] != b["query_hash"], (
        "a changed query template must not reuse the old paid answer")


def test_question_identity_is_scoped_to_the_task():
    a = mapping.question("fofa", "domain", "mt-a.example.com", "q", task="A")
    b = mapping.question("fofa", "domain", "mt-a.example.com", "q", task="B")
    assert a["query_hash"] == b["query_hash"]
    s = _store()
    mapping.record(s, a, metered.ST_OK, rows=1)
    assert mapping.lookup(s, a) is not None
    assert mapping.lookup(s, b) is None, "another task must not see this row"
    s.close()


# ------------------------------------------------------- ledger semantics
def test_ledger_records_every_outcome_and_never_auto_retries():
    """A failure is spend that already happened: it is recorded, not retried."""
    s = _store()
    for status in (metered.ST_OK, metered.ST_EMPTY, metered.ST_QUOTA,
                   metered.ST_AUTH, metered.ST_FAILED):
        q = mapping.question("quake", "domain", "h%s.example.com" % status, "q")
        mapping.record(s, q, status, rows=0, last_error="x" if status != metered.ST_OK else "")
        row = mapping.lookup(s, q)
        assert row is not None and row["status"] == status, (status, row)
        assert row["attempts"] == 1, row
    # re-recording the same question bumps attempts, it does not insert twice
    q = mapping.question("quake", "domain", "hdup.example.com", "q")
    mapping.record(s, q, metered.ST_FAILED)
    mapping.record(s, q, metered.ST_FAILED)
    assert mapping.lookup(s, q)["attempts"] == 2
    n = s.conn.execute("SELECT COUNT(*) c FROM mapping_ledger").fetchone()["c"]
    assert n == 6, n
    s.close()


def test_results_are_reusable_with_their_original_time():
    """A later run attaches already-paid evidence, not a fresh observation."""
    s = _store()
    q = mapping.question("fofa", "domain", "mt-a.example.com", "q")
    mapping.record(s, q, metered.ST_OK, rows=2,
                   run_id="20261121-120000-a")
    first = core.now()
    mapping.save_results(s, q, "domain",
                         ["a.mt-a.example.com", "b.mt-a.example.com"],
                         observed_at=first)
    rows = mapping.results(s, q, "domain")
    assert [r["canonical"] for r in rows] == ["a.mt-a.example.com",
                                              "b.mt-a.example.com"]
    assert all(r["observed_at"] == first for r in rows), rows
    # saving the same rows again does not duplicate them
    assert mapping.save_results(s, q, "domain",
                                ["a.mt-a.example.com"], observed_at=core.now()) == 0
    s.close()


def test_coverage_counts_questions_per_engine():
    s = _store()
    # three DISTINCT questions (same value would dedupe -- see the next assert)
    for i, status in enumerate((metered.ST_OK, metered.ST_OK, metered.ST_QUOTA)):
        q = mapping.question("fofa", "domain", "x%d.example.com" % i, "q")
        mapping.record(s, q, status)
    # the same question twice is one row, not two (dedupe by query_hash)
    dup = mapping.question("fofa", "domain", "dup.example.com", "q")
    mapping.record(s, dup, metered.ST_OK)
    mapping.record(s, dup, metered.ST_OK)
    assert s.conn.execute(
        "SELECT COUNT(*) c FROM mapping_ledger WHERE value='dup.example.com'"
    ).fetchone()["c"] == 1
    cov = mapping.coverage(s)
    fofa = cov["by_engine"]["fofa"]
    # three distinct questions + one deduped (asked once) = 4 rows
    assert fofa["asked"] == 4, fofa
    assert fofa["reused"] == 3 and fofa["quota"] == 1, fofa
    assert cov["questions"] == 4
    s.close()
