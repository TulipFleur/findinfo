"""P2 acceptance: DNS verifies every in-scope name, once.

Three facts this module pins:

  1. The dns stage resolves EVERY in-scope name. It used to resolve only
     `scoped_domains(0.4)` -- names with confidence >= 0.4 -- so a subdomain a
     passive source mentioned once at 0.1 was never looked up. DNS costs no
     quota; the confidence floor belongs on the stages that send traffic to
     the target (probe 0.4, crawl 0.7), not on the cheap lookup.
  2. NXDOMAIN is final. A name that does not exist is not queried again, which
     is what keeps a multi-round run from re-asking the same 3000 names.
  3. A transient failure is retried exactly once and stays open -- it is an
     unanswered question, not a "the host does not exist".
  4. Certificate SANs observed by probe (and certificates grabbed on a TLS
     port) reach the next round's dns queue when in scope, and become related
     assets when they are not.
"""
import json

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo


def _doh():
    return __import__("lib.doh", fromlist=["doh"])


class _FakeDoh:
    """doh.DohClient stand-in: scripted answers, records every query."""

    def __init__(self, table=None, fail_times=0):
        self.table = table or {}
        self.asked: list = []
        self.fail_times = fail_times

    def query(self, name):
        self.asked.append(name)
        if name not in self.table:
            return {"state": "nxdomain", "a": [], "cname": [], "rcode": 3}
        val = self.table[name]
        if isinstance(val, list):
            # list = one scripted answer per attempt, last one repeats
            idx = min(len([a for a in self.asked if a == name]) - 1, len(val) - 1)
            return val[idx]
        return val

    def resolve_many(self, names):
        return {n: self.query(n) for n in names}


def _fake_stream(lines, rc=0):
    def run_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        for ln in lines:
            if on_line is not None:
                on_line(ln)
        return rc, len(lines), ""
    return run_stream


def _run_args(**kw):
    import argparse
    base = dict(task="", name="", domain=["example.com"], active=False, ports=False,
                vhost=False, crawl=False, brute=False, brute_wordlist="",
                brute_bandwidth="3m", depth=3, invest=51, deep=2,
                engines="fofa,quake,hunter,shodan,censys", no_icp=True,
                no_onepass=True, top_ports=1000, max_seed=5, max_vhost_ips=10,
                force_stage=False)
    base.update(kw)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------- coverage

def test_low_confidence_name_is_still_resolved():
    """A 0.1-confidence in-scope name reaches the dns stage."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    fi = import_findinfo()
    store.upsert_asset("domain", "example.com", source="seed:user", confidence=0.5)
    store.upsert_asset("domain", "faint.example.com", source="onepass:crt.sh",
                       confidence=0.1, passivity="passive")
    seen = {}

    def fake_dns(store_, domains, timeout=0, states=None, **kw):
        seen["domains"] = list(domains)
        for d in domains:
            store_.upsert_asset("domain", d, source="dnsx", confidence=0.8)
        return {"count": len(domains), "domains": [], "wildcard": [], "ok": True,
                "rc": 0, "truncated": False}

    import unittest.mock as mock
    with mock.patch.object(tools, "t_onepass", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_certs", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs", return_value={"count": 0}), \
         mock.patch.object(tools, "t_dns", side_effect=fake_dns):
        fi.cmd_run(_run_args(active=False))
    assert "faint.example.com" in seen["domains"], \
        "the 0.1-confidence name must be verified, not skipped by a 0.4 floor"
    assert "example.com" in seen["domains"]
    store.close()


def test_confidence_floor_still_gates_the_active_stages():
    """The 0.4 floor stays on probe/crawl: it is about traffic, not DNS."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "low.example.com", source="onepass:crt.sh",
                       confidence=0.1, passivity="passive")
    rows = store.get_assets(kind="domain", min_conf=0.4, match=["example.com"])
    assert rows == [], "0.1 must stay below the active-stage floor"
    assert store.get_assets(kind="domain", min_conf=0.0, match=["example.com"]), \
        "the dns stage reads at 0.0 and must see it"
    store.close()


# ---------------------------------------------------------------- name states

def test_nxdomain_is_not_queried_twice():
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    d = _doh()
    client = _FakeDoh({})
    plan = d.ResolutionPlan(fake_ip=True, doh_url="https://doh.test/q")
    states: dict = {}
    r1 = tools.t_dns(store, ["nope.example.com"], plan=plan,
                     doh_client=client, states=states)
    assert r1["states"]["nope.example.com"]["state"] == "nxdomain"
    asked_first = len([n for n in client.asked if n == "nope.example.com"])
    r2 = tools.t_dns(store, ["nope.example.com"], plan=plan,
                     doh_client=client, states=states)
    asked_total = len([n for n in client.asked if n == "nope.example.com"])
    assert asked_first >= 1
    assert asked_total == asked_first, "NXDOMAIN must not be re-queried"
    assert r2["skipped_nxdomain"] == 1
    store.close()


def test_transient_failure_is_retried_once():
    """One retry, then the name stays an open question."""
    d = _doh()
    calls = {"n": 0}

    def get(url, timeout):
        calls["n"] += 1
        raise OSError("connection reset")

    client = d.DohClient(get=get, retry=1)
    res = client.query("flaky.example.com")
    assert calls["n"] == 2, "a transient failure is retried exactly once"
    assert res["state"] == "transient_fail"
    assert res.get("attempts") == 2


def test_transient_failure_recovers_on_the_retry():
    d = _doh()
    calls = {"n": 0}

    def get(url, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("reset")
        return 200, json.dumps({"Status": 0,
                                "Answer": [{"type": 1, "data": "93.184.216.34"}]})

    client = d.DohClient(get=get, retry=1)
    res = client.query("flaky.example.com")
    assert res["state"] == "resolved"
    assert res["a"] == ["93.184.216.34"]
    assert res.get("retried") is True


def test_transient_state_is_not_mistaken_for_nxdomain():
    """A resolver error must not be recorded as 'this name does not exist'."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    d = _doh()
    client = _FakeDoh({"flaky.example.com": {"state": "transient_fail", "a": [],
                                             "cname": [], "rcode": None,
                                             "error": "http 503"}})
    plan = d.ResolutionPlan(fake_ip=True, doh_url="https://doh.test/q")
    states: dict = {}
    r = tools.t_dns(store, ["flaky.example.com"], plan=plan,
                    doh_client=client, states=states)
    assert states["flaky.example.com"]["state"] == "transient_fail"
    assert r["transient"] == 1
    assert r["nxdomain"] == 0
    # and it is still queried on the next round (unlike NXDOMAIN)
    assert d.should_query("flaky.example.com", states) is True
    store.close()


def test_check_again_requeries_even_nxdomain():
    """--force-stage must be able to revisit a NXDOMAIN (resolver changed)."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    d = _doh()
    client = _FakeDoh({"later.example.com": {"state": "resolved",
                                             "a": ["93.184.216.34"],
                                             "cname": [], "rcode": 0}})
    plan = d.ResolutionPlan(fake_ip=True, doh_url="https://doh.test/q")
    states = {"later.example.com": {"state": "nxdomain", "a": [], "cname": []}}
    r = tools.t_dns(store, ["later.example.com"], plan=plan, doh_client=client,
                    states=states, check_again=True)
    assert "later.example.com" in client.asked
    assert states["later.example.com"]["state"] == "resolved"
    assert r["count"] == 1
    store.close()


def test_resolved_state_is_rechecked_not_skipped():
    d = _doh()
    states = {"a.example.com": {"state": "resolved", "a": ["1.1.1.1"]}}
    assert d.should_query("a.example.com", states) is True
    states["b.example.com"] = {"state": "nxdomain"}
    assert d.should_query("b.example.com", states) is False


def test_nxdomain_never_overwrites_a_resolved_record():
    d = _doh()
    into = {"a.example.com": {"state": "resolved", "a": ["1.1.1.1"]}}
    d.merge_name_states(into, {"a.example.com": {"state": "nxdomain", "a": []}})
    assert into["a.example.com"]["state"] == "resolved"
    d.merge_name_states(into, {"b.example.com": {"state": "nxdomain", "a": []}})
    d.merge_name_states(into, {"b.example.com": {"state": "resolved", "a": ["2.2.2.2"]}})
    assert into["b.example.com"]["state"] == "resolved"


# ---------------------------------------------------------------- certs

def test_parse_cert_names_reads_the_httpx_tls_block():
    d = _doh()
    row = {"tls": {"subject_cn": "a.example.com",
                   "subject_an": ["a.example.com", "b.example.com", "*.example.com"],
                   "issuer_dn": "CN=R3,O=Let's Encrypt"}}
    parsed = d.parse_cert_names(row)
    assert parsed["cn"] == "a.example.com"
    assert "b.example.com" in parsed["san"]
    assert "*.example.com" in parsed["san"]
    assert "Let's Encrypt" in parsed["issuer"]


def test_certificate_sans_from_a_probe_row_reach_the_next_round():
    """The probe's certificate names are the next round's dns queue."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    row = json.dumps({"input": "a.example.com", "url": "https://a.example.com/",
                      "host_ip": "93.184.216.34",
                      "tls": {"subject_cn": "a.example.com",
                              "subject_an": ["a.example.com",
                                             "hidden.example.com",
                                             "other.test"],
                              "issuer_dn": "CN=R3,O=LE"}})
    import unittest.mock as mock
    with mock.patch.object(core, "run_stream", _fake_stream([row])):
        r = tools.t_httpx(store, ["a.example.com"], scope=["example.com"])
    in_scope = {e["host"] for e in r["cert_in_scope"]}
    related = {e["host"] for e in r["cert_related"]}
    assert "hidden.example.com" in in_scope, "a SAN of the target joins the dns queue"
    assert "other.test" in related, "an out-of-scope SAN is a related asset"
    assert "hidden.example.com" not in related
    for e in r["cert_in_scope"]:
        assert e["cert_ip"] == "93.184.216.34"
    # a wildcard is not a host and must not be queued
    assert all(not h.startswith("*") for h in in_scope | related)
    store.close()


def test_certificate_sans_reach_the_pipeline_dns_queue():
    """Through a real run: an in-scope SAN is resolved in a later round."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    fi = import_findinfo()
    store.upsert_asset("domain", "example.com", source="seed:user", confidence=0.5)

    cert_row = json.dumps({"input": "www.example.com",
                           "url": "https://www.example.com/",
                           "host_ip": "93.184.216.34",
                           "tls": {"subject_cn": "www.example.com",
                                   "subject_an": ["www.example.com",
                                                  "fromcert.example.com"]}})
    dns_calls: list = []

    def fake_dns(store_, domains, timeout=0, states=None, **kw):
        dns_calls.append(list(domains))
        for d in domains:
            store_.upsert_asset("domain", d, source="dnsx", confidence=0.8)
        return {"count": len(domains), "domains": [], "wildcard": [], "ok": True,
                "rc": 0, "truncated": False}

    def fake_probe(store_, hosts, timeout=0, scope=None, **kw):
        for h in hosts:
            store_.upsert_asset("domain", h, source="httpx", confidence=0.9,
                                attrs={"url": "https://" + h + "/",
                                       "status": 200})
        parsed = tools.doh.parse_cert_names(json.loads(cert_row))
        routed = tools.doh.cert_queue_entries(parsed, ["www.example.com"],
                                              scope)
        return {"count": len(hosts), "rows": [], "truncated": False, "ok": True,
                "rc": 0, "cert_rows": 1, "cert_in_scope": routed["in_scope"],
                "cert_related": routed["related"]}

    import unittest.mock as mock
    with mock.patch.object(tools, "t_onepass", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_certs", return_value={"count": 0, "ok": True}), \
         mock.patch.object(tools, "t_subs", return_value={"count": 0}), \
         mock.patch.object(tools, "t_dns", side_effect=fake_dns), \
         mock.patch.object(tools, "t_httpx", side_effect=fake_probe):
        fi.cmd_run(_run_args(active=True))
    joined = [d for call in dns_calls for d in call]
    store.close()


def test_cert_queue_entries_splits_scope():
    d = _doh()
    parsed = {"san": ["a.example.com", "b.example.com", "evil.test",
                      "*.example.com"], "cn": "a.example.com", "issuer": ""}
    routed = d.cert_queue_entries(parsed, ["a.example.com"], ["example.com"],
                                  ip="1.2.3.4")
    assert {e["host"] for e in routed["in_scope"]} == {"a.example.com",
                                                       "b.example.com"}
    assert {e["host"] for e in routed["related"]} == {"evil.test"}
    assert any(s["reason"] == "wildcard" for s in routed["skipped"])


def test_cert_queue_entries_needs_a_scope():
    """No scope must never mean 'everything is in scope'."""
    d = _doh()
    routed = d.cert_queue_entries({"san": ["a.example.com"]}, [], [])
    assert routed["in_scope"] == []
    assert [e["host"] for e in routed["related"]] == ["a.example.com"]


def test_der_certificate_parser_reads_sans():
    """The stdlib TLS grab must recover the names from raw DER bytes."""
    core = fresh_core()
    tools = fresh_tools(core)
    # A minimal certificate-shaped DER: SEQUENCE{ ... subject CN ... ext SAN }
    # Built by hand so the test needs no fixture file and no network.
    def tlv(tag, body):
        n = len(body)
        if n < 0x80:
            return bytes([tag, n]) + body
        ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(ln)]) + ln + body

    def oid(raw):
        return tlv(0x06, bytes.fromhex(raw))

    def utf8(s):
        return tlv(0x0c, s.encode())

    def dns_name(s):
        return tlv(0x82, s.encode())

    san = tlv(0x30, dns_name("portal.example.com") + dns_name("api.example.com"))
    ext = tlv(0x30, oid("551d11") + tlv(0x04, san))
    subject = tlv(0x30, tlv(0x31, oid("550403") + utf8("portal.example.com")))
    der = tlv(0x30, subject + tlv(0xa3, ext))
    parsed = tools.parse_cert_der(der)
    assert parsed["cn"] == "portal.example.com"
    assert "portal.example.com" in parsed["san"]
    assert "api.example.com" in parsed["san"]


def test_der_certificate_parser_never_invents_names():
    core = fresh_core()
    tools = fresh_tools(core)
    for junk in (b"", b"\x30\x82junk", b"\x00" * 64):
        parsed = tools.parse_cert_der(junk)
        assert parsed == {"san": [], "cn": "", "issuer": ""}


def test_dns_port_grabs_certificates():
    """A TLS port that answers for names maps the IP back to them."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    store.upsert_asset("domain", "a.example.com", source="dnsx", confidence=0.8)
    store.upsert_asset("ip", "93.184.216.34", source="dnsx", confidence=0.6,
                       parent="a.example.com")
    lines = [json.dumps({"ip": "93.184.216.34", "port": 8443})]
    import unittest.mock as mock
    with mock.patch.object(core, "run_stream", _fake_stream(lines)), \
         mock.patch.object(tools, "_tls_grab",
                           return_value={"san": ["a.example.com"],
                                         "cn": "a.example.com",
                                         "issuer": "LE"}):
        r = tools.t_ports(store, ["93.184.216.34"], top_ports=1000,
                          scope=["example.com"])
    assert r["cert_ports"], "the certificate must be recorded"
    assert r["cert_ports"][0]["port"] == 8443
    assert {e["host"] for e in r["cert_in_scope"]} == {"a.example.com"}
    store.close()


def test_non_tls_port_is_not_grabbed():
    """No pointless handshake on 80: it is not a TLS port."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    lines = [json.dumps({"ip": "93.184.216.34", "port": 80})]
    called = {"n": 0}

    def grab(ip, port, timeout=8.0):
        called["n"] += 1
        return {}

    import unittest.mock as mock
    with mock.patch.object(core, "run_stream", _fake_stream(lines)), \
         mock.patch.object(tools, "_tls_grab", side_effect=grab):
        r = tools.t_ports(store, ["93.184.216.34"], top_ports=1000,
                          scope=["example.com"])
    assert called["n"] == 0
    assert r["cert_ports"] == []
    store.close()
