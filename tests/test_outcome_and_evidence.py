"""Outcome vocabulary, seed verification, cache provenance, shared-IP links.

These four are the "result truthfulness" contracts: an agent must be able to
tell "found nothing" from "never asked", keep a cached witness attributed to
the upstream that actually answered, and see an IP in scope for every domain
it serves -- not only the first one written.
"""
import json

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core, fresh_tools


# ---------------------------------------------------------------- outcomes
def test_outcome_vocabulary_is_ordered_by_severity():
    core = fresh_core()
    assert core.combine_outcome(core.OUTCOME_OK, core.OUTCOME_EMPTY) == core.OUTCOME_EMPTY
    assert core.combine_outcome(core.OUTCOME_OK, core.OUTCOME_PARTIAL) == core.OUTCOME_PARTIAL
    # partial already contains a success, so a sibling failure keeps it partial
    assert core.combine_outcome(core.OUTCOME_PARTIAL, core.OUTCOME_FAILED) == core.OUTCOME_PARTIAL
    assert core.combine_outcome() == core.OUTCOME_OK
    # a source we never configured is a coverage gap, not a failure
    assert core.combine_outcome(core.OUTCOME_OK, core.OUTCOME_UNAVAILABLE) == core.OUTCOME_OK
    assert core.combine_outcome(core.OUTCOME_UNAVAILABLE) == core.OUTCOME_UNAVAILABLE
    assert core.combine_outcome(core.OUTCOME_FAILED,
                                core.OUTCOME_UNAVAILABLE) == core.OUTCOME_FAILED


def test_rc_classification_distinguishes_empty_from_failed():
    core = fresh_core()
    # success + nothing found is a valid empty answer
    assert core.outcome_from_rc(0, 0) == core.OUTCOME_EMPTY
    # non-zero + nothing found is a failure, never an empty success
    assert core.outcome_from_rc(1, 0) == core.OUTCOME_FAILED
    # non-zero but real rows kept -> partial, data stays usable
    assert core.outcome_from_rc(1, 5) == core.OUTCOME_PARTIAL
    # rc=124 is core.run's timeout code
    assert core.outcome_from_rc(124, 0) == core.OUTCOME_TIMEOUT


def test_subs_all_sources_failing_is_not_a_clean_empty():
    """Every passive source dead is FAILED, never a clean empty.

    subs is keyless now, so the sources it can report are the free ones
    (subfinder / chaos-free / onepass CT); the paid engines are no longer
    part of this stage at all.
    """
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()

    def dead(cmd, timeout=0, **kw):
        return 1, "", "boom"

    orig = core.run
    core.run = dead
    try:
        out = tools.t_subs(store, "example.com", engines="fofa")
    finally:
        core.run = orig
        store.close()
    tried = [p for p in out["per_source"]
             if p["outcome"] != core.OUTCOME_UNAVAILABLE]
    assert tried, out["per_source"]
    assert out["outcome"] in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT), out
def test_subs_healthy_empty_is_empty_not_failed():
    core = fresh_core()
    tools = fresh_tools(core)
    import lib.core as C
    orig_run, orig_has, orig_key = C.run, C.has_tool, C.api_key
    C.has_tool = lambda n: n in ("subfinder", "uncover")
    C.api_key = lambda n: ""
    C.run = lambda *a, **k: (0, "", "")
    try:
        out = tools.t_subs(core.Store(), "example.com")
    finally:
        C.run, C.has_tool, C.api_key = orig_run, orig_has, orig_key
    assert out["outcome"] == core.OUTCOME_EMPTY, out
    assert out["ok"] is True, out


def test_onepass_does_not_hardcode_ok():
    """All upstreams failing used to still return "ok": True."""
    core = fresh_core()
    tools = fresh_tools(core)
    import lib.core as C
    orig_run, orig_tool = C.run, C.tool
    C.tool = lambda n: "onepass"
    C.run = lambda *a, **k: (0, json.dumps({
        "ok": True, "domain": "example.com", "records": [],
        "sources_ok": 0, "sources_error": 15,
        "sources": [{"id": "crtsh", "status": "error", "found": 0}]}), "")
    try:
        out = tools.t_onepass(core.Store(), "example.com")
    finally:
        C.run, C.tool = orig_run, orig_tool
    assert out["outcome"] == core.OUTCOME_FAILED, out
    assert out["ok"] is False, "all-sources-failed must not report ok=True: %r" % (out,)


# ---------------------------------------------------------------- seed
def test_explicit_seed_is_stored_as_unverified_seed():
    """A user-named domain is INPUT, not evidence, but it must be in the graph."""
    core = fresh_core()
    store = core.Store()
    try:
        store.upsert_asset("domain", "only.example.com", source="seed:user",
                           confidence=0.5, parent="only.example.com")
        row = [a for a in store.get_assets(kind="domain")
               if a["canonical"] == "only.example.com"][0]
        assert "seed:user" in row["sources"]
        assert row["confidence"] == 0.5, "a seed alone is not corroboration"
    finally:
        store.close()


# ---------------------------------------------------------------- cache
def test_cert_cache_keeps_the_real_upstream():
    """A certspotter result replayed from cache must not become crt.sh."""
    core = fresh_core()
    core.CACHE.put("certs", "ct:example.com",
                   {"schema": "certs/2", "upstream": "certspotter",
                    "data": [{"name_value": "a.example.com"}]})
    got = core.CACHE.get("certs", "ct:example.com", ttl=999)
    assert got["upstream"] == "certspotter", got
    assert got["data"][0]["name_value"] == "a.example.com"


def test_legacy_cache_payload_is_still_readable():
    """Old installs stored a bare list; reading it must not crash or lie."""
    core = fresh_core()
    core.CACHE.put("certs", "ct:legacy.com", [{"name_value": "b.legacy.com"}])
    got = core.CACHE.get("certs", "ct:legacy.com", ttl=999)
    assert isinstance(got, list), got


# ---------------------------------------------------------------- shared IP
def test_one_ip_serves_many_domains_in_scope():
    """ip.parent is COALESCE'd (first wins); asset_links keeps every owner."""
    core = fresh_core()
    store = core.Store()
    try:
        store.upsert_asset("ip", "1.2.3.4", source="dnsx", confidence=0.8,
                           parent="old.com")
        store.upsert_asset("ip", "1.2.3.4", source="dnsx", confidence=0.8,
                           parent="example.com")
        assert store.linked_owners("ip", "1.2.3.4") == ["old.com", "example.com"]
        assert store.assets_linked_to("ip", ["example.com"]) == ["1.2.3.4"], \
            "a scoped aggregation for example.com must still see the shared IP"
        # idempotent: re-observing does not fan out
        store.upsert_asset("ip", "1.2.3.4", source="dnsx", confidence=0.8,
                           parent="example.com")
        assert len(store.linked_owners("ip", "1.2.3.4")) == 2
    finally:
        store.close()
