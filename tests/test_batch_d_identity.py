"""Batch D acceptance: subject identity, typed scope, wildcard evidence.

Fixture brand is 美团; domains under reserved example.com/.net/.org. All
offline: resolver rows are dicts, adapters are injected, no sockets. From
docs/RELIABILITY-PLAN.md:

* T06 - two plausible synthetic legal subjects and no explicit seed:
  identity is ambiguous -> input required, no discovery/active dispatch
* T07 - accepted subject has a different display name than the search alias:
  the seed survives through the subject reference, not string equality
* T12 - a related SAN / same-IP neighbour is evidence, never a scope grant
* T13 - bare IP and ip:port explicit targets keep kind and port end to end
* T14 - DoH probes share ordinary wildcard answers; a candidate with extra
  evidence is retained and labelled, not erased; fake/failed probes prove
  nothing
* T15 - fake-IP, timeout, NODATA and CNAME-only are each distinguished from
  an authoritative NXDOMAIN
"""

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, doh
from tests.util import fresh_core, fresh_tools


def test_t06_ambiguous_brand_reports_input_required():
    """Two plausible subjects, no explicit seed: no discovery, no traffic."""
    tools = fresh_tools(fresh_core())
    candidates = [{"name": "fixture-subject-A", "id": "sa-1"},
                  {"name": "fixture-subject-B", "id": "sb-1"}]
    verdict = tools.resolve_entity_identity(
        raw="美团", candidates=candidates, explicit_domains=[])
    assert verdict["status"] == "identity_ambiguous", verdict
    assert verdict["retryable"] is False
    assert any("input" in s.lower() for s in verdict["next_steps"]), verdict
    assert not verdict.get("subject_id"), "no subject may be auto-picked"


def test_t06_unique_match_anchors():
    tools = fresh_tools(fresh_core())
    verdict = tools.resolve_entity_identity(
        raw="美团", candidates=[{"name": "美团", "id": "sa-1"}],
        explicit_domains=[])
    assert verdict["status"] == "ok", verdict
    assert verdict["subject_id"] == "sa-1"


def test_t06_explicit_seed_bypasses_ambiguity():
    tools = fresh_tools(fresh_core())
    verdict = tools.resolve_entity_identity(
        raw="美团",
        candidates=[{"name": "fixture-subject-A", "id": "sa-1"},
                    {"name": "fixture-subject-B", "id": "sb-1"}],
        explicit_domains=["mt-a.example.com"])
    assert verdict["status"] == "ok", verdict
    assert "explicit seed" in (verdict.get("basis") or "").lower(), verdict


def test_t07_subject_seed_survives_display_name_change():
    """The anchor holds through the subject ID, not the alias string."""
    tools = fresh_tools(fresh_core())
    # alias "美团" accepted subject "上海三快在线科技有限公司" (id sa-1);
    # a store lookup must find the seed by subject reference, not by name
    core_now = fresh_core()
    store = core_now.Store()
    store.upsert_asset("company", "fixture-subject-A", source="enscan",
                       confidence=0.9, parent=None)
    store.upsert_asset("domain", "mt-a.example.com", source="enscan",
                       confidence=0.9, parent="fixture-subject-A")
    store.close()
    seeds = tools.seeds_for_subject(core_now.Store(), "fixture-subject-A")
    assert "mt-a.example.com" in seeds, seeds
    # the ALIAS itself must not be needed anywhere downstream
    assert "美团" not in seeds


def test_t12_related_assets_are_evidence_not_scope():
    """A related SAN or same-IP neighbour never widens the active scope."""
    tools = fresh_tools(fresh_core())
    c = fresh_core()
    store = c.Store()
    store.upsert_asset("domain", "partner.example.org",
                       source="cert-san", confidence=0.3,
                       parent="mt-a.example.com")
    store.close()
    in_active = tools.evidence_grants_scope(
        c.Store(), "partner.example.org", scope=["mt-a.example.com"])
    assert in_active is False, "evidence link must not become an active grant"
    in_active2 = tools.evidence_grants_scope(
        c.Store(), "api.mt-a.example.com", scope=["mt-a.example.com"])
    assert in_active2 is True, "explicit scope suffix must stay active"


def test_t13_bare_ip_and_endpoint_survive_normalisation():
    """Kind and port survive parsing, dedup, storage and probing lists."""
    c = fresh_core()
    tools = fresh_tools(c)
    # canonicalisation keeps the kind and the exact port
    assert tools.endpoint_of("203.0.113.10:8443") == ("203.0.113.10", 8443)
    assert tools.endpoint_of("203.0.113.10") == ("203.0.113.10", None)
    st = c.Store()
    st.upsert_asset("ip", "203.0.113.10", source="seed:user",
                    confidence=0.9)
    st.close()
    kinds = {a["kind"]: a["canonical"]
             for a in c.Store().get_assets(min_conf=0.9)}
    assert kinds.get("ip") == "203.0.113.10", kinds
    assert tools.endpoint_of("203.0.113.10:8443")[1] == 8443, (
        "explicit ports must round-trip exactly, not be dropped")


def test_t14_wildcard_evidence_shared_across_paths():
    """DoH and dnsx probe answers land in ONE evidence dict with ONE key."""
    ev = doh.new_wildcard_evidence()
    # dnsx-style probe answer for example.com
    doh.record_wildcard_probe(ev, "example.com", {"a": ["203.0.113.7"]})
    # DoH-style probe for the SAME zone (name arrives as the probe string)
    key = doh.wildcard_parent("findinfo-wildcard-probe-9f3a.wild.example.com")
    assert key == "example.com", key
    doh.record_wildcard_probe(ev, key, {"a": ["203.0.113.7"]})
    assert doh.wildcard_signature_complete(ev, "example.com"), ev
    # one probe alone is not a signature
    ev2 = doh.new_wildcard_evidence()
    doh.record_wildcard_probe(ev2, "example.net", {"a": ["198.51.100.9"]})
    assert not doh.wildcard_signature_complete(ev2, "example.net"), (
        "one lucky probe must not prove a wildcard zone")


def test_t14_candidate_with_extra_evidence_is_retained():
    ev = doh.new_wildcard_evidence()
    doh.record_wildcard_probe(ev, "example.com", {"a": ["203.0.113.7"]})
    doh.record_wildcard_probe(ev, "example.com", {"a": ["203.0.113.7"]})
    # wildcard-only guess
    assert doh.wildcard_answer_matches(ev, "example.com", ["203.0.113.7"])
    # candidate carrying an additional independent address: kept, labelled
    mixed = ["203.0.113.7", "198.51.100.23"]
    assert not doh.wildcard_answer_matches(ev, "example.com", mixed), (
        "mixed evidence must not be discarded as a wildcard echo")


def test_t14_failed_and_fake_probes_establish_nothing():
    ev = doh.new_wildcard_evidence()
    # fake-IP probe answers are recorded but never count as the signature
    doh.record_wildcard_probe(ev, "example.com", {"a": ["198.18.10.101"]})
    doh.record_wildcard_probe(ev, "example.com", {"a": ["198.19.4.4"]})
    assert ev["example.com"]["fake"], ev
    assert not doh.wildcard_signature_complete(ev, "example.com")
    # a timeout (no answer at all) leaves no signature either
    doh.record_wildcard_probe(ev, "example.net", {"a": []})
    assert not doh.wildcard_signature_complete(ev, "example.net")


def test_t15_negative_answers_are_distinguished():
    """fake-IP / timeout / NODATA / CNAME-only are NOT authoritative NXDOMAIN."""
    tools = fresh_tools(fresh_core())
    cases = [
        ({"a": ["198.18.10.1"]}, "fake_ip", "a synthetic address is not NXDOMAIN"),
        ({"a": []}, "transient", "no answer is an open question, not NXDOMAIN"),
        ({"a": [], "cname": ["alias.example.com"]}, "cname_only",
         "a CNAME-only answer needs the chain resolved, not a verdict"),
        ({"a": ["203.0.113.5"]}, "resolved", "an ordinary answer is resolved"),
    ]
    for answer, expect, why in cases:
        got = tools.classify_negative(answer)
        assert got == expect, (why, answer, got)
    # authoritative NXDOMAIN is the only state that settles a name as absent
    assert tools.classify_nxdomain({"rcode": 3}) is True
    assert tools.classify_nxdomain({"rcode": 0}) is False
    assert tools.classify_nxdomain({}) is False
