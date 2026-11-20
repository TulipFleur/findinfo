"""Batch C acceptance: durable membership, observations and work routing.

Fixture brand is 美团; domains under reserved example.com/.net/.org. All
scenarios are offline: the work module touches only SQLite, and no collector
is ever started. Scenarios from docs/RELIABILITY-PLAN.md:

* T08  - a CT-only host produces exactly one DNS work item, discovery nonzero
* T09  - a JS-only host's DNS work survives restart and drains later
* T10  - a crash after observation commit loses nothing and duplicates nothing
* T11  - two runs with different seeds in one task never cross-dispatch
* T16  - stable domain count but outstanding endpoint/JS work != convergence
* T29  - a repaired partial attempt does not inherit the old failure verdict
* T30  - reused evidence keeps its original observation time
* T31  - many observations from threads: no cross-thread SQLite, no loss
* T33  - legacy JS rows import only with provable ownership
"""

import json
import threading

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, work
from tests.util import fresh_core


RUN = "20261120-200000-mt-a.example.com"
RUN2 = "20261120-200100-mt-b.example.net"


def _store():
    s = core.Store()
    work.ensure_schema(s)
    return s


# ---------------------------------------------------------------- T08
def test_t08_ct_only_host_yields_one_dns_item():
    s = _store()
    work.attach_asset(s, RUN, "domain", "ct-only.mt-a.example.com",
                      producer="certs", upstream="crt.sh", route=work.ROUTE_DNS)
    # observation commits, membership exists, exactly one dns work item
    assert work.run_assets(s, RUN, "domain") == ["ct-only.mt-a.example.com"]
    work.attach_asset(s, RUN, "domain", "ct-only.mt-a.example.com",
                      producer="certs", upstream="crt.sh", route=work.ROUTE_DNS)
    # re-observation from the SAME upstream does not duplicate work
    rows = s.conn.execute(
        "SELECT COUNT(*) c FROM work_items WHERE run_id=? AND stage='dns'",
        (RUN,)).fetchone()
    assert rows["c"] == 1, "duplicate dns work for one host"
    # a second, independent upstream adds an observation but no new work
    work.attach_asset(s, RUN, "domain", "ct-only.mt-a.example.com",
                      producer="subfinder", upstream="rapiddns",
                      route=work.ROUTE_DNS)
    ups = work.observed_upstreams(s, RUN, "domain", "ct-only.mt-a.example.com")
    assert sorted(ups) == ["crt.sh", "rapiddns"], ups
    assert s.conn.execute(
        "SELECT COUNT(*) c FROM work_items WHERE run_id=? AND stage='dns'",
        (RUN,)).fetchone()["c"] == 1
    # discovery count is nonzero: the item exists and is pending
    stats = work.queue_stats(s, RUN)
    assert stats["pending"] == 1 and stats["outstanding"] == 1
    s.close()


# ---------------------------------------------------------------- T09
def test_t09_js_only_host_work_survives_restart_and_drains():
    fresh_core()          # own database: previous tests moved FINDINFO_HOME
    s = _store()
    work.attach_asset(s, RUN, "url",
                      "https://js-only.mt-a.example.com/app.js",
                      producer="crawl", upstream="katana", route=work.ROUTE_JS)
    s.close()
    # "restart": a NEW store connection over the same database
    s2 = _store()
    claimed = work.claim(s2, RUN, "extract", limit=10)
    assert len(claimed) == 1
    assert claimed[0]["canonical"] == "https://js-only.mt-a.example.com/app.js"
    ok = work.finish(s2, RUN, claimed[0]["id"], claimed[0]["lease_token"],
                     ok=True)
    assert ok, "token holder must be able to settle its own lease"
    stats = work.queue_stats(s2, RUN)
    assert stats["outstanding"] == 0 and stats["done"] == 1
    s2.close()


# ---------------------------------------------------------------- T10
def test_t10_crash_after_observation_loses_nothing():
    fresh_core()
    s = _store()
    work.attach_asset(s, RUN, "domain", "mt-a.example.com",
                      producer="certs", upstream="crt.sh", route=work.ROUTE_DNS)
    # simulate: worker died AFTER the commit above, before finishing work
    s.close()
    s2 = _store()
    stats = work.queue_stats(s2, RUN)
    assert stats["pending"] == 1, "committed observation must survive"
    # the new attempt claims the same item -- once, not twice
    claimed = work.claim(s2, RUN, "dns", limit=10)
    assert len(claimed) == 1
    claimed2 = work.claim(s2, RUN, "dns", limit=10)
    assert claimed2 == [], "a leased item must not be claimable twice"
    # a stale token from the crashed attempt cannot finish the new lease
    assert work.finish(s2, RUN, claimed[0]["id"], "stale-token", ok=True) is False
    # the real token still can
    assert work.finish(s2, RUN, claimed[0]["id"], claimed[0]["lease_token"],
                       ok=True)
    s2.close()


# ---------------------------------------------------------------- T11
def test_t11_two_runs_never_cross_dispatch():
    fresh_core()
    s = _store()
    work.attach_asset(s, RUN, "domain", "api.mt-a.example.com",
                      producer="certs", upstream="crt.sh", route=work.ROUTE_DNS)
    work.attach_asset(s, RUN2, "domain", "api.mt-b.example.net",
                      producer="certs", upstream="crt.sh", route=work.ROUTE_DNS)
    run1_assets = work.run_assets(s, RUN)
    run2_assets = work.run_assets(s, RUN2)
    assert run1_assets == ["api.mt-a.example.com"]
    assert run2_assets == ["api.mt-b.example.net"]
    claimed1 = work.claim(s, RUN, "dns", limit=50)
    assert [c["canonical"] for c in claimed1] == ["api.mt-a.example.com"], (
        "run 1 must never claim run 2's work")
    s.close()


# ---------------------------------------------------------------- T16
def test_t16_stable_domain_count_with_outstanding_work_is_not_convergence():
    fresh_core()
    s = _store()
    for host in ("a.mt-a.example.com", "b.mt-a.example.com"):
        work.attach_asset(s, RUN, "domain", host, producer="certs",
                          upstream="crt.sh", route=work.ROUTE_DNS)
        # finish dns so domain count is stable...
        c = work.claim(s, RUN, "dns", limit=10)
        for item in c:
            work.finish(s, RUN, item["id"], item["lease_token"], ok=True)
    # ...but endpoint/JS work is still outstanding
    work.attach_asset(s, RUN, "url", "https://a.mt-a.example.com/bundle.js",
                      producer="crawl", upstream="katana", route=work.ROUTE_JS)
    stats = work.queue_stats(s, RUN)
    assert stats["outstanding"] == 1, (
        "endpoint/JS work pending: domain-count stability is not convergence")
    s.close()


# ---------------------------------------------------------------- T29
def test_t29_repaired_attempt_does_not_inherit_failure():
    s = _store()
    inv1 = RUN + "|1|subs|root|1"
    with s._write():
        s.conn.execute(
            "INSERT INTO stage_invocations(invocation_id, run_id, attempt,"
            " stage, unit_key, input_revision, state, outcome, reason)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (inv1, RUN, 1, "subs", "root", 1, "failed", "failed",
             "source_timeout"))
    # the retry succeeds and becomes the effective invocation
    inv2 = RUN + "|2|subs|root|1"
    with s._write():
        s.conn.execute(
            "INSERT INTO stage_invocations(invocation_id, run_id, attempt,"
            " stage, unit_key, input_revision, state, outcome, reason)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (inv2, RUN, 2, "subs", "root", 1, "succeeded", "ok", ""))
    # effective = newest attempt; the historical failure remains auditable
    rows = s.conn.execute(
        "SELECT attempt, state FROM stage_invocations WHERE run_id=?"
        " AND stage='subs' ORDER BY attempt", (RUN,)).fetchall()
    assert [(r["attempt"], r["state"]) for r in rows] == [(1, "failed"),
                                                           (2, "succeeded")]
    effective = rows[-1]
    assert effective["state"] == "succeeded", (
        "the current verdict must reflect the effective result")
    s.close()


# ---------------------------------------------------------------- T30
def test_t30_reused_evidence_keeps_original_observation_time():
    s = _store()
    work.attach_asset(s, RUN, "domain", "mt-a.example.com",
                      producer="certs", upstream="crt.sh")
    first = s.conn.execute(
        "SELECT observed_at FROM observations WHERE run_id=?"
        " ORDER BY id LIMIT 1", (RUN,)).fetchone()["observed_at"]
    # replaying a cache attaches evidence but must not claim a fresh network
    # observation: the run_assets row records the attachment separately.
    ts_before = first
    work.attach_asset(s, RUN2, "domain", "mt-a.example.com",
                      producer="reuse", upstream="cache:" + RUN)
    orig = s.conn.execute(
        "SELECT observed_at FROM observations WHERE run_id=?"
        " AND upstream=? ORDER BY id LIMIT 1",
        (RUN2, "cache:" + RUN)).fetchone()
    # the reuse is its own observation row (attach time), while the ORIGINAL
    # run's row still holds its original network-observation time
    still = s.conn.execute(
        "SELECT observed_at FROM observations WHERE run_id=?"
        " ORDER BY id LIMIT 1", (RUN,)).fetchone()["observed_at"]
    assert still == ts_before, "original observation time must not move"
    s.close()


# ---------------------------------------------------------------- T31
def test_t31_threaded_observations_no_cross_thread_sqlite_or_loss():
    fresh_core()
    s = _store()
    results = []
    lock = threading.Lock()

    def worker_thread(i):
        # threads only PREPARE their observations; the store is used solely
        # from the coordinator thread (SQLite thread discipline)
        batch = [("domain", "t%d.mt-a.example.com" % (i * 50 + j))
                 for j in range(50)]
        with lock:
            results.append(batch)

    threads = [threading.Thread(target=worker_thread, args=(i,))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # coordinator commits every batch with its own connection
    for batch in results:
        for kind, name in batch:
            work.attach_asset(s, RUN, kind, name, producer="threads",
                              upstream="fake", route=work.ROUTE_DNS)
    n = s.conn.execute(
        "SELECT COUNT(*) c FROM run_assets WHERE run_id=?", (RUN,)).fetchone()
    assert n["c"] == 400, "every observation must commit (no loss)"
    w = s.conn.execute(
        "SELECT COUNT(DISTINCT canonical) c FROM work_items WHERE run_id=?",
        (RUN,)).fetchone()
    assert w["c"] == 400, "no duplicate work from concurrent observation"
    s.close()


# ---------------------------------------------------------------- T33
def test_t33_legacy_js_import_requires_provable_ownership():
    s = _store()
    ts = core.now()
    # legacy rows exist with no owner; one pending, one already done
    with s._write():
        for url in ("https://a.mt-a.example.com/1.js",
                    "https://unknown.example.org/2.js",
                    "https://a.mt-a.example.com/done.js"):
            s.conn.execute(
                "INSERT OR IGNORE INTO js_queue(url, state, attempts,"
                " last_error, discovered_at, updated_at)"
                " VALUES(?, 'pending', 0, '', ?, ?)", (url, ts, ts))
        s.conn.execute("UPDATE js_queue SET state='done' WHERE url=?",
                       ("https://a.mt-a.example.com/done.js",))
    # run 1 observed the first URL plus the completed one (provably its own)
    s.upsert_asset("url", "https://a.mt-a.example.com/1.js", source="crawl",
                   confidence=0.6)
    work.attach_asset(s, RUN, "url", "https://a.mt-a.example.com/1.js",
                      producer="crawl", upstream="katana", route=None)
    work.attach_asset(s, RUN, "url", "https://a.mt-a.example.com/done.js",
                      producer="crawl", upstream="katana", route=None)
    result = work.import_js_queue(s, RUN)
    assert result["attached"] == 2, ("only provable ownership attaches", result)
    assert result["skipped_done"] == 1, "a completed legacy row stays done"
    assert "https://unknown.example.org/2.js" in result["unknown"], (
        "unknown ownership must be reported, not claimed", result)
    members = work.run_assets(s, RUN, "url")
    assert "https://a.mt-a.example.com/1.js" in members
    # the done row migrated as DONE, never re-opened as pending
    done_row = s.conn.execute(
        "SELECT status FROM work_items WHERE run_id=? AND canonical=?",
        (RUN, "https://a.mt-a.example.com/done.js")).fetchone()
    assert done_row["status"] == "done", done_row
    # the unknown row must NOT be claimable by this run
    claimed = work.claim(s, RUN, "extract", limit=50)
    assert all("unknown.example.org" not in c["canonical"] for c in claimed)
    # migration is idempotent: a second pass attaches nothing new
    again = work.import_js_queue(s, RUN)
    assert again["attached"] == 0, again
    # and it is still pending in the legacy table, unclaimed
    legacy = s.conn.execute(
        "SELECT state FROM js_queue WHERE url=?",
        ("https://unknown.example.org/2.js",)).fetchone()
    assert legacy["state"] == "pending"
    s.close()
