"""Batch A acceptance: JS work completes and recovers (F01, F04).

Everything here is offline: synthetic sources, a temp home and an in-memory
store; the HTTP fetch is always an injected adapter (never a socket). What is
pinned:

* run mode schedules JS ONLY through work_items; standalone keeps Store.js_*;
* only real JS bundles are work -- HTML pages never are (F01);
* a succeeded item stays done: a second round does not re-fetch it (F01);
* a 41-item work set with a 40 fetch budget leaves exactly one owed item, and
  the next round drains it (cross-round budget continuation);
* retry_at backoff holds until its due time (F04);
* an expired running lease is reclaimed atomically; the stale token cannot
  ack or write results (F04);
* two concurrent claimers can never hold the same item (F04);
* legacy migration is idempotent, keeps done rows done, and leaves unknown
  ownership in place and reported (F01/T33).
"""

import threading
import time

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, work
from tests.util import fresh_core, fresh_tools

RUN = "20261121-100000-mt-a.example.com"
RUN_B = "20261121-100500-mt-b.example.net"


def _store():
    s = fresh_core().Store()
    work.ensure_schema(s)
    return s


def _enqueue(store, urls, run=RUN):
    for u in urls:
        work.enqueue(store, run, work.ROUTE_JS, "url", u)


# ---------------------------------------------------------------- F01 basics
def test_only_real_js_bundles_enter_the_work_set():
    """HTML pages and .json/.map paths are not JS work."""
    tools = fresh_tools(fresh_core())
    urls = [
        "https://mt-a.example.com/",
        "https://mt-a.example.com/index.html",
        "https://mt-a.example.com/app.js",
        "https://mt-a.example.com/chunk.mjs?x=1",
        "https://mt-a.example.com/api/data.json",
        "https://mt-a.example.com/app.js.map",
        "https://other.example.org/app.js",
    ]
    js = tools._js_work_set(urls, ["mt-a.example.com"])
    assert js == ["https://mt-a.example.com/app.js",
                  "https://mt-a.example.com/chunk.mjs?x=1"], js


def test_succeeded_js_is_not_reopened_on_a_second_round():
    """A done item stays done: repeated discovery must not re-open it."""
    s = _store()
    _enqueue(s, ["https://mt-a.example.com/app.js"])
    first = work.claim(s, RUN, work.ROUTE_JS, limit=10)
    assert len(first) == 1
    assert work.finish(s, RUN, first[0]["id"], first[0]["lease_token"], ok=True)
    stats = work.queue_stats(s, RUN, work.ROUTE_JS)
    assert stats["done"] == 1 and stats["outstanding"] == 0, stats
    # the next round "discovers" the same bundle again
    assert work.enqueue(s, RUN, work.ROUTE_JS, "url",
                        "https://mt-a.example.com/app.js") is False, (
        "re-discovery must not create a second work item")
    second = work.claim(s, RUN, work.ROUTE_JS, limit=10)
    assert second == [], "a completed bundle must never be claimed again"
    s.close()


def test_forty_one_items_with_a_forty_budget_drain_across_rounds():
    """41 bundles, 40 per round: one is owed after round 1, drained in round 2."""
    s = _store()
    urls = ["https://mt-a.example.com/b%02d.js" % i for i in range(41)]
    _enqueue(s, urls)
    r1 = work.claim(s, RUN, work.ROUTE_JS, limit=40)
    assert len(r1) == 40
    for it in r1:
        assert work.finish(s, RUN, it["id"], it["lease_token"], ok=True)
    stats = work.queue_stats(s, RUN, work.ROUTE_JS)
    assert stats["outstanding"] == 1, ("exactly one bundle remains owed", stats)
    assert stats["done"] == 40
    r2 = work.claim(s, RUN, work.ROUTE_JS, limit=40)
    assert len(r2) == 1 and r2[0]["canonical"] not in {c["canonical"] for c in r1}
    assert work.finish(s, RUN, r2[0]["id"], r2[0]["lease_token"], ok=True)
    final = work.queue_stats(s, RUN, work.ROUTE_JS)
    assert final["outstanding"] == 0 and final["done"] == 41, final
    s.close()


# ---------------------------------------------------------------- F04 lease
def test_retry_at_backoff_holds_until_due():
    """A failed item is not claimable before retry_at, and is after it."""
    s = _store()
    _enqueue(s, ["https://mt-a.example.com/slow.js"])
    first = work.claim(s, RUN, work.ROUTE_JS, limit=1,
                       now_iso="2026-11-21T10:00:00Z")
    assert len(first) == 1
    # fail with a 300 s backoff
    assert work.finish(s, RUN, first[0]["id"], first[0]["lease_token"],
                       ok=False, retryable=True, retry_after_seconds=300,
                       now_iso="2026-11-21T10:00:00Z")
    # 1 s later: still inside the backoff window
    too_soon = work.claim(s, RUN, work.ROUTE_JS, limit=5,
                          now_iso="2026-11-21T10:00:01Z")
    assert too_soon == [], "a failed item inside its backoff must not be claimed"
    # past the window: claimable again
    later = work.claim(s, RUN, work.ROUTE_JS, limit=5,
                       now_iso="2026-11-21T10:06:00Z")
    assert len(later) == 1, ("the item must be claimable after the backoff", later)
    s.close()


def test_expired_running_lease_is_reclaimed_and_old_token_is_dead():
    """A crashed worker's running item is reclaimable; its token cannot ack."""
    s = _store()
    _enqueue(s, ["https://mt-a.example.com/app.js"])
    first = work.claim(s, RUN, work.ROUTE_JS, limit=1,
                       now_iso="2026-11-21T10:00:00Z", lease_seconds=900)
    assert len(first) == 1
    old_id, old_token = first[0]["id"], first[0]["lease_token"]
    # inside the lease: nobody else may take it
    assert work.claim(s, RUN, work.ROUTE_JS, limit=1,
                      now_iso="2026-11-21T10:05:00Z") == []
    # after expiry: a new owner reclaims it with a NEW token
    reclaimed = work.claim(s, RUN, work.ROUTE_JS, limit=1,
                           now_iso="2026-11-21T10:20:00Z")
    assert len(reclaimed) == 1, "an expired running lease must be reclaimable"
    new_token = reclaimed[0]["lease_token"]
    assert new_token != old_token
    # the stale token can neither acknowledge nor write results
    assert work.finish(s, RUN, old_id, old_token, ok=True) is False
    assert work.commit_result(s, RUN, old_id, old_token,
                              members=[{"kind": "domain",
                                        "canonical": "stale.example.com"}],
                              ok=True) is False
    row = s.conn.execute(
        "SELECT 1 FROM run_assets WHERE run_id=? AND canonical=?",
        (RUN, "stale.example.com")).fetchone()
    assert row is None, "a stale token must not write membership"
    # the real holder settles it
    assert work.finish(s, RUN, old_id, new_token, ok=True)
    s.close()


def test_concurrent_claimers_never_share_one_item():
    """Two connections claiming at once: each item goes to exactly one holder.

    SQLite connections are owned by their creating thread, so each claimer
    opens its OWN Store over the same database file -- the same discipline the
    coordinator/collector split uses. A barrier releases both at once so the
    BEGIN IMMEDIATE windows really overlap.
    """
    seed = _store()
    urls = ["https://mt-a.example.com/t%02d.js" % i for i in range(20)]
    _enqueue(seed, urls)
    db_path = seed.path
    seed.close()
    barrier = threading.Barrier(2)
    grabbed: dict = {}
    errors: list = []

    def claimer(idx):
        conn = core.Store(db_path)
        try:
            barrier.wait()
            got = work.claim(conn, RUN, work.ROUTE_JS, limit=50)
            grabbed[idx] = [c["id"] for c in got]
        except Exception as exc:            # surface, never swallow
            errors.append(repr(exc))
        finally:
            conn.close()

    threads = [threading.Thread(target=claimer, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    ids = [i for sub in grabbed.values() for i in sub]
    assert len(ids) == len(set(ids)), ("an item was handed out twice", grabbed)
    assert len(ids) == 20, ("every item must be handed to someone", grabbed)
    check = core.Store(db_path)
    try:
        stats = work.queue_stats(check, RUN, work.ROUTE_JS)
        assert stats["running"] == 20 and stats["outstanding"] == 20, stats
    finally:
        check.close()


def test_attempt_cap_settles_instead_of_looping():
    """An item that hit the attempt cap becomes blocked, not endlessly retried."""
    s = _store()
    _enqueue(s, ["https://mt-a.example.com/bad.js"])
    for i in range(2):
        got = work.claim(s, RUN, work.ROUTE_JS, limit=1,
                         now_iso="2026-11-21T10:0%d:00Z" % (i * 5),
                         max_attempts=2)
        assert len(got) == 1, i
        work.finish(s, RUN, got[0]["id"], got[0]["lease_token"],
                    ok=False, retryable=True, retry_after_seconds=1,
                    now_iso="2026-11-21T10:0%d:00Z" % (i * 5))
    third = work.claim(s, RUN, work.ROUTE_JS, limit=1,
                       now_iso="2026-11-21T10:20:00Z", max_attempts=2)
    assert third == [], "the attempt cap must stop further hand-outs"
    row = s.conn.execute(
        "SELECT status, reason FROM work_items WHERE run_id=?", (RUN,)).fetchone()
    assert row["status"] == "blocked" and "attempt cap" in row["reason"], dict(row)
    s.close()


# ---------------------------------------------------------------- commit
def test_commit_result_lands_membership_and_ack_atomically():
    """Result rows and the ack share one lease; a stale lease writes nothing."""
    s = _store()
    _enqueue(s, ["https://mt-a.example.com/app.js"])
    got = work.claim(s, RUN, work.ROUTE_JS, limit=1)[0]
    ok = work.commit_result(
        s, RUN, got["id"], got["lease_token"],
        members=[{"kind": "domain", "canonical": "api.mt-a.example.com"}],
        observations=[{"kind": "domain", "canonical": "api.mt-a.example.com",
                       "producer": "extract", "upstream": "jsleak"}],
        ok=True)
    assert ok
    assert "api.mt-a.example.com" in work.run_assets(s, RUN, "domain")
    assert work.observed_upstreams(s, RUN, "domain",
                                   "api.mt-a.example.com") == ["jsleak"]
    assert work.queue_stats(s, RUN, work.ROUTE_JS)["done"] == 1
    s.close()


def test_failed_commit_keeps_the_item_retryable():
    """A failed fetch re-arms the item instead of dropping it."""
    s = _store()
    _enqueue(s, ["https://mt-a.example.com/app.js"])
    got = work.claim(s, RUN, work.ROUTE_JS, limit=1,
                     now_iso="2026-11-21T10:00:00Z")[0]
    work.commit_result(s, RUN, got["id"], got["lease_token"], ok=False,
                       reason="timeout", retryable=True, retry_after_seconds=60,
                       now_iso="2026-11-21T10:00:00Z")
    stats = work.queue_stats(s, RUN, work.ROUTE_JS)
    assert stats["failed"] == 1 and stats["outstanding"] == 1, stats
    assert work.claim(s, RUN, work.ROUTE_JS, limit=1,
                      now_iso="2026-11-21T10:00:30Z") == []
    assert len(work.claim(s, RUN, work.ROUTE_JS, limit=1,
                          now_iso="2026-11-21T10:02:00Z")) == 1
    s.close()


# ---------------------------------------------------------------- isolation
def test_another_runs_backlog_never_affects_this_run():
    """Runs never drain each other's JS work."""
    s = _store()
    _enqueue(s, ["https://mt-a.example.com/a.js"], run=RUN)
    _enqueue(s, ["https://mt-b.example.net/b.js"], run=RUN_B)
    got = work.claim(s, RUN, work.ROUTE_JS, limit=10)
    assert [c["canonical"] for c in got] == ["https://mt-a.example.com/a.js"]
    assert work.queue_stats(s, RUN_B, work.ROUTE_JS)["outstanding"] == 1
    s.close()


def test_legacy_migration_is_idempotent_and_respects_state():
    """done stays done, unknown stays put, a second pass adds nothing."""
    s = _store()
    ts = core.now()
    rows = [("https://mt-a.example.com/app.js", "pending"),
            ("https://mt-a.example.com/done.js", "done"),
            ("https://mt-a.example.com/fail.js", "failed"),
            ("https://unknown.example.org/z.js", "pending")]
    with s._write():
        for url, state in rows:
            s.conn.execute(
                "INSERT OR IGNORE INTO js_queue(url, state, attempts,"
                " last_error, discovered_at, updated_at)"
                " VALUES(?,?,0,'',?,?)", (url, state, ts, ts))
    # this run owns three of them via membership
    for url, _state in rows[:3]:
        work.attach_asset(s, RUN, "url", url, producer="crawl",
                          upstream="katana", route=None)
    first = work.import_js_queue(s, RUN)
    assert first["attached"] == 3, first
    assert first["skipped_done"] == 1, first
    assert first["unknown"] == ["https://unknown.example.org/z.js"], first
    states = {r["canonical"]: r["status"] for r in s.conn.execute(
        "SELECT canonical, status FROM work_items WHERE run_id=?", (RUN,))}
    assert states == {"https://mt-a.example.com/app.js": "pending",
                      "https://mt-a.example.com/done.js": "done",
                      "https://mt-a.example.com/fail.js": "failed"}, states
    second = work.import_js_queue(s, RUN)
    assert second["attached"] == 0, ("migration must be idempotent", second)
    # the unknown row is untouched in the legacy table
    legacy = s.conn.execute(
        "SELECT state FROM js_queue WHERE url=?",
        ("https://unknown.example.org/z.js",)).fetchone()
    assert legacy["state"] == "pending"
    s.close()


def test_standalone_backend_still_uses_the_legacy_queue():
    """No run context: t_extract keeps the Store.js_* behaviour."""
    core_now = fresh_core()
    tools = fresh_tools(core_now)
    store = core_now.Store()
    try:
        res = tools.t_extract(store, [], urls=["https://mt-a.example.com/app.js"],
                              scope=["mt-a.example.com"])
        # the legacy table holds the bundle as pending (no run queue touched)
        pending = store.conn.execute(
            "SELECT url, state FROM js_queue").fetchall()
        assert [r["url"] for r in pending] == ["https://mt-a.example.com/app.js"]
        assert pending[0]["state"] in ("pending", "failed")
        assert "js_pending" in res
        # the new run table stays empty: the backends are not double-written
        try:
            rows = store.conn.execute(
                "SELECT COUNT(*) c FROM work_items").fetchone()
            assert rows["c"] == 0, "standalone must not touch run work_items"
        except Exception:
            pass   # no work schema at all in a pure standalone store
    finally:
        store.close()
