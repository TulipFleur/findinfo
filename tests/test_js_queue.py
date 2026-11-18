"""JS work queue: a budgeted round must leave a visible, resumable remainder.

The failure this pins (observed on real runs): t_extract rebuilt the candidate
list from scratch every round and took the first `fetch_limit` entries, so
candidates 41..N were never attempted. The run then reported "no new domains"
and looked converged, while bundles had simply never been fetched.

The contract:
  * discovered/attempted/succeeded/failed/pending are all reported
  * a round with 41 candidates and a budget of 40 leaves pending >= 1
  * the NEXT round processes the remainder instead of the same first 40
  * pending work is a coverage gap, never convergence
"""
import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core, fresh_tools


def _urls(n, prefix="https://example.com/app"):
    return [prefix + str(i) + ".js" for i in range(n)]


def test_queue_survives_across_rounds():
    """41 candidates, budget 40 -> 1 pending; second round finishes it."""
    core = fresh_core()
    store = core.Store()
    try:
        urls = _urls(41)
        store.js_enqueue(urls)
        # round 1: claim 40 of 41
        first = store.js_claim(40)
        assert len(first) == 40, len(first)
        for u in first:
            store.js_finish(u, ok=True)
        st = store.js_stats()
        assert st["discovered"] == 41, st
        assert st["succeeded"] == 40, st
        assert st["pending"] == 1, "the 41st item must still be pending: %r" % (st,)

        # round 2: the remainder, not a repeat of the first 40. Ordering is
        # lexicographic on url (app10 < app2), so assert set identity against
        # "everything not yet done" rather than positional identity.
        second = store.js_claim(40)
        assert len(second) == 1, "round 2 must claim exactly the remainder: %r" % (second,)
        assert second[0] not in first, "round 2 re-claimed an already-done bundle"
        store.js_finish(second[0], ok=True)
        st2 = store.js_stats()
        assert st2["pending"] == 0 and st2["succeeded"] == 41, st2
    finally:
        store.close()


def test_failed_items_are_retried_not_lost():
    core = fresh_core()
    store = core.Store()
    try:
        store.js_enqueue(["https://example.com/a.js"])
        store.js_finish("https://example.com/a.js", ok=False, error="timeout")
        st = store.js_stats()
        assert st["failed"] == 1 and st["pending"] == 0, st
        # a failed bundle is still work, so it must be claimable again
        again = store.js_claim(5)
        assert again == ["https://example.com/a.js"], again
    finally:
        store.close()


def test_enqueue_is_idempotent():
    core = fresh_core()
    store = core.Store()
    try:
        urls = _urls(3)
        assert store.js_enqueue(urls) == 3
        assert store.js_enqueue(urls) == 0, "re-discovering a bundle must not duplicate it"
        assert store.js_stats()["discovered"] == 3
    finally:
        store.close()


def test_done_items_are_never_reclaimed():
    core = fresh_core()
    store = core.Store()
    try:
        store.js_enqueue(["https://example.com/x.js"])
        store.js_finish("https://example.com/x.js", ok=True)
        assert store.js_claim(10) == [], "done work must not be fetched again"
    finally:
        store.close()


def test_secrets_are_redacted_in_output():
    """A full credential must never reach the agent's context."""
    tools = fresh_tools(fresh_core())
    out = tools._redact_secrets({"aws_ak": ["AKIAIOSFODNN7EXAMPLE"],
                                 "jwt": ["short"]})
    assert out["aws_ak"][0].startswith("AKIA"), out
    assert "IOSFODNN7EXAMPLE" not in out["aws_ak"][0], "secret leaked: %r" % out
    assert out["aws_ak"][0].endswith("c"), out
    assert out["jwt"][0].startswith("…"), out
