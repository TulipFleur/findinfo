"""P2 acceptance: fake-IP is never mistaken for an asset.

Clash/TUN mode answers EVERY A query with an address from 198.18.0.0/15. The
old check was `startswith("198.18.")`, which misses the whole 198.19.x half
of the /15 -- so a synthesised 198.19.0.5 became a "resolved domain" and, worse,
counted as a wildcard answer and filtered real hosts away.

These tests pin four things:
  1. the predicate covers the whole /15 and nothing else on every resolution
     path (dnsx JSON, system fallback, httpx backfill, DoH answers);
  2. doctor publishes `environment.fake_ip_dns` and flags the environment;
  3. the dns stage switches to DoH when fake-IP is detected, and does NOT even
     start dnsx in that case;
  4. the reported `resolution` block names the resolver that actually ran.
"""
import json

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, pin_dns_environment


def _doh():
    return __import__("lib.doh", fromlist=["doh"])


class _FakeRun:
    """core.run stand-in: scripted rc/stdout per command substring."""

    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def __call__(self, cmd, timeout=300, input_text=None, cwd=None, env=None):
        self.calls.append(list(cmd))
        for needle, res in self.outputs:
            if any(needle in str(c) for c in cmd):
                return res
        return 0, "", ""


def _fake_run_stream(lines, rc=0):
    def run_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        for ln in lines:
            if on_line is not None:
                on_line(ln)
        return rc, len(lines), ""
    return run_stream


# ---------------------------------------------------------------- predicate

def test_is_fake_ip_covers_the_whole_15():
    """198.18.x AND 198.19.x are fake; 198.20.x and friends are not."""
    d = _doh()
    for addr in ("198.18.0.1", "198.18.255.255", "198.19.0.1", "198.19.255.254"):
        assert d.is_fake_ip(addr) is True, addr
    for addr in ("198.17.255.255", "198.20.0.1", "8.8.8.8", "10.0.0.1",
                 "1.2.3.4", "not-an-ip", ""):
        assert d.is_fake_ip(addr) is False, addr


def test_prefix_check_would_have_missed_198_19():
    """Guard against a regression back to the string prefix test."""
    d = _doh()
    assert "198.19.0.5".startswith("198.18.") is False, "premise of the bug"
    assert d.is_fake_ip("198.19.0.5") is True


def test_filter_fake_ips_splits_and_preserves_order():
    d = _doh()
    kept, dropped = d.filter_fake_ips(["1.1.1.1", "198.19.1.1", "8.8.4.4",
                                       "198.18.9.9", "", " "])
    assert kept == ["1.1.1.1", "8.8.4.4"]
    assert dropped == ["198.19.1.1", "198.18.9.9"]


def test_dnsx_path_drops_198_19_answers():
    """A dnsx answer in the upper half of the /15 must not become an asset."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    lines = [json.dumps({"host": "fake.example.com", "a": ["198.19.4.4"]})]
    with __import__("unittest.mock", fromlist=["mock"]).patch.object(
            core, "run", _FakeRun([("wildcard-probe", (0, "", ""))])), \
         __import__("unittest.mock", fromlist=["mock"]).patch.object(
            core, "run_stream", _fake_run_stream(lines)):
        r = tools.t_dns(store, ["fake.example.com"])
    assert r["fake_ip_dropped"] == 1
    assert store.get_assets(kind="ip") == [], "a fake IP must never be stored"
    # Baseline semantics (947bfaa): the NAME is still evidence -- the resolver
    # answered it -- so it is stored as a domain even when every address was
    # a placeholder. Only the address is worthless, not the existence.
    stored = {a["canonical"] for a in store.get_assets(kind="domain")}
    assert "fake.example.com" in stored
    store.close()


def test_system_fallback_drops_198_19_answers():
    """The OS resolver is filtered by the same rule, not just dnsx."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    import unittest.mock as mock

    def rs(cmd, on_line=None, timeout=300, cwd=None, env=None):
        return 0, 0, ""                      # dnsx sees nothing

    with mock.patch.object(core, "run",
                           _FakeRun([("wildcard-probe", (0, "", ""))])), \
         mock.patch.object(core, "run_stream", rs), \
         mock.patch.object(__import__("socket"), "getaddrinfo",
                           return_value=[(None, None, None, None, ("198.19.7.7", 0))]):
        r = tools.t_dns(store, ["sys.example.com"])
    assert r["count"] == 0
    assert r["fake_ip_dropped"] == 1
    assert r["states"]["sys.example.com"]["state"] == "nxdomain"
    store.close()


def test_httpx_fake_ip_is_not_a_cert_anchor():
    """A certificate observed on a fake address must not anchor related names."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    pin_dns_environment(True)
    try:
        row = json.dumps({"input": "a.example.com", "url": "https://a.example.com/",
                          "host_ip": "198.19.3.3",
                          "tls": {"subject_cn": "a.example.com",
                                  "subject_an": ["a.example.com"]}})
        import unittest.mock as mock
        with mock.patch.object(core, "run_stream", _fake_run_stream([row])):
            r = tools.t_httpx(store, ["a.example.com"], scope=["example.com"])
    finally:
        pin_dns_environment(False)
    assert r["cert_in_scope"], r
    assert all(e["cert_ip"] == "" for e in r["cert_in_scope"]), \
        "a synthesised address must not be recorded as the certificate's IP"
    store.close()


# ---------------------------------------------------------------- doctor

def test_detect_fake_ip_reports_a_synthetic_answer():
    d = _doh()
    block = d.detect_fake_ip(lambda name: ["198.19.0.120"])
    assert block["fake_ip_dns"] is True
    assert block["fake_ip"] == "198.19.0.120"
    assert "198.18.0.0/15" in block["reason"]


def test_detect_fake_ip_is_honest_when_nxdomain():
    d = _doh()
    block = d.detect_fake_ip(lambda name: [])
    assert block["fake_ip_dns"] is False
    assert "NXDOMAIN" in block["reason"] or "empty" in block["reason"]


def test_detect_fake_ip_does_not_claim_clean_on_resolver_error():
    """No network is not evidence of a healthy resolver."""
    d = _doh()
    def boom(name):
        raise OSError("no route to host")
    block = d.detect_fake_ip(boom)
    assert block["fake_ip_dns"] is False
    assert "no evidence" in block["reason"]


def test_doctor_publishes_fake_ip_dns():
    core = fresh_core()
    tools = fresh_tools(core)
    d = _doh()
    pin_dns_environment(True)
    try:
        import unittest.mock as mock
        with mock.patch.object(tools, "_env_selfcheck", return_value={"python_ok": True,
                                                                      "python_version": "3.11.0"}):
            rep = tools.doctor()
    finally:
        d.reset_environment_cache()
        pin_dns_environment(False)
    env = rep["environment"]
    assert env["fake_ip_dns"]["fake_ip_dns"] is True
    assert env["resolution"]["mode"] == "doh"
    assert env["fake_ip_hint"]


# ---------------------------------------------------------------- DoH switch

class _FakeDoh:
    """Stands in for doh.DohClient: answers from a scripted table."""

    def __init__(self, table):
        self.table = table
        self.asked = []

    def query(self, name):
        self.asked.append(name)
        return self.table.get(name, {"state": "nxdomain", "a": [], "cname": [],
                                     "rcode": 3})

    def resolve_many(self, names):
        return {n: self.query(n) for n in names}


def test_dns_stage_uses_doh_when_fake_ip_detected():
    """Detected fake-IP: the dns stage queries DoH and never starts dnsx."""
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    d = _doh()
    plan = d.ResolutionPlan(fake_ip=True, doh_url="https://doh.test/q")
    client = _FakeDoh({"a.example.com": {"state": "resolved",
                                         "a": ["93.184.216.34"],
                                         "cname": [], "rcode": 0}})
    ran = _FakeRun([])
    import unittest.mock as mock
    with mock.patch.object(core, "run", ran):
        r = tools.t_dns(store, ["a.example.com"], plan=plan, doh_client=client)
    assert client.asked, "the DoH client must have been used"
    assert not ran.calls, "dnsx must not run when the resolver is fake-IP"
    assert r["count"] == 1
    assert r["resolution"]["resolver"] == "doh"
    assert r["resolution"]["doh_url"] == "https://doh.test/q"
    store.close()


def test_dns_stage_does_not_use_doh_without_detection():
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    d = _doh()
    plan = d.ResolutionPlan(fake_ip=False)
    client = _FakeDoh({})
    lines = [json.dumps({"host": "a.example.com", "a": ["93.184.216.34"]})]
    import unittest.mock as mock
    with mock.patch.object(core, "run",
                           _FakeRun([("wildcard-probe", (0, "", ""))])), \
         mock.patch.object(core, "run_stream", _fake_run_stream(lines)):
        r = tools.t_dns(store, ["a.example.com"], plan=plan, doh_client=client)
    assert not client.asked
    assert r["resolution"]["mode"] == "local"
    assert r["resolution"]["resolver"] == "dnsx"
    store.close()


def test_status_states_which_resolver_ran():
    """The explanation an agent reads must name the resolver, not the plan."""
    d = _doh()
    plan = d.ResolutionPlan(fake_ip=True, doh_url="https://doh.test/q")
    block = d.resolution_payload(plan, d.RESOLVER_DOH)
    assert block["resolver"] == "doh"
    assert "DoH" in d.explain_resolution(block)
    # the plan said DoH, but the system resolver is what answered
    block2 = d.resolution_payload(plan, d.RESOLVER_SYSTEM)
    assert block2["resolver"] == "system-dns"
    assert block2["planned_resolver"] == "doh"
    assert "system resolver" in d.explain_resolution(block2)


def test_doh_answers_in_the_fake_range_are_dropped():
    """DoH is not automatically trustworthy: 198.19 answers are still fake."""
    d = _doh()
    client = d.DohClient(get=lambda url, timeout: (
        200, json.dumps({"Status": 0,
                         "Answer": [{"type": 1, "data": "198.19.9.9"}]})))
    res = client.query("a.example.com")
    assert res["a"] == []
    assert res["state"] == "nxdomain"
