"""Wiring W5 acceptance: one wildcard evidence API behind every resolver (T14/T15).

The dnsx probe loop, the DoH path and the accept filter share
doh.new_wildcard_evidence / record_wildcard_probe /
wildcard_signature_complete / wildcard_answer_matches:

* the key is the REGISTRABLE parent -- never the probe name, never a
  "wild." label (the old DoH path keyed "wild.example.com" while dnsx
  keyed "example.com", so one zone was two unrelated entries);
* multiple unpredictable probes per parent, no extra label;
* ordinary A/CNAME answers count toward the signature; fake-IP and
  timeout probes establish nothing;
* a candidate whose addresses are ALL the wildcard's echo is dropped;
  one carrying an additional independent address is kept.

Everything is injected (a fake DoH client / stubbed core.run): no socket.
"""

import json
from unittest import mock

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, pin_dns_environment


class _Store:
    def __init__(self) -> None:
        self.assets = []

    def upsert_asset(self, kind, key, **kw) -> None:
        self.assets.append((kind, key))


class _FakeDoh:
    """Resolver stub: probe answers + candidate answers, all offline.

    Probe names are UNPREDICTABLE (secrets.token_hex), so a `probe_answer`
    applies to any name carrying the probe label; explicit answers win.
    """

    def __init__(self, answers: dict, probe_answer: dict | None = None):
        self.answers = answers
        self.probe_answer = probe_answer
        self.seen: list = []

    def resolve_many(self, names):
        out = {}
        for n in names or []:
            self.seen.append(n)
            if n in self.answers:
                out[n] = self.answers[n]
            elif "findinfo-wildcard-probe-" in n and self.probe_answer is not None:
                out[n] = dict(self.probe_answer)
            else:
                out[n] = {"a": [], "cname": []}
        return out


def _bind(fake_ip: bool = True):
    core = fresh_core()
    tools = fresh_tools(core)      # its pin_environment() resets the cache
    pin_dns_environment(fake_ip=fake_ip)   # so pin AFTER the reload
    return core, tools


def test_doh_probes_carry_no_wild_label_and_key_the_registrable_parent():
    _, tools = _bind()
    client = _FakeDoh({}, probe_answer={"a": ["203.0.113.7"]})
    store = _Store()
    res = tools.t_dns(store, ["ghost.example.com"], doh_client=client)
    # the probes had no "wild." label and the report keys the parent
    for name in client.seen:
        assert ".wild." not in name, name
    parents = {w["parent"] for w in res["wildcard"]}
    assert "example.com" in parents, res["wildcard"]
    assert not any("wild.example.com" == p for p in parents), parents


def test_doh_wildcard_echo_dropped_and_mixed_evidence_kept():
    _, tools = _bind()
    client = _FakeDoh({
        # candidate 1: ONLY the wildcard's own address -> dropped
        "ghost.example.com": {"a": ["203.0.113.7"]},
        # candidate 2: the wildcard address PLUS its own -> kept (mixed)
        "real.example.com": {"a": ["203.0.113.7", "198.51.100.9"]},
    }, probe_answer={"a": ["203.0.113.7"]})
    store = _Store()
    tools.t_dns(store, ["ghost.example.com", "real.example.com"],
                doh_client=client)
    stored = {k for (kind, k) in store.assets if kind == "domain"}
    assert stored == {"real.example.com"}, store.assets


def test_doh_fake_probe_establishes_no_signature():
    _, tools = _bind()
    client = _FakeDoh({
        # a candidate that would be dropped if the fake answers counted
        "ghost.example.com": {"a": ["198.18.10.101"]},
    }, probe_answer={"a": ["198.18.10.101"]})
    store = _Store()
    res = tools.t_dns(store, ["ghost.example.com"], doh_client=client)
    # no signature -> the filter never engaged
    row = [w for w in res["wildcard"] if w["parent"] == "example.com"]
    assert row and row[0]["signature"] is False, res["wildcard"]
    # and the fake address was never stored as an asset
    ips = {k for (kind, k) in store.assets if kind == "ip"}
    assert ips == set(), store.assets


def test_doh_one_probe_answer_is_not_a_signature():
    _, tools = _bind()
    class _Once:
        # first probe answers, the second times out: one lucky hit only
        def __init__(self):
            self.n = 0
        def resolve_many(self, names):
            out = {}
            for n in names or []:
                if "findinfo-wildcard-probe-" in n:
                    self.n += 1
                    out[n] = ({"a": ["203.0.113.7"]} if self.n == 1
                              else {"a": [], "cname": []})
                elif n in {"ghost.example.com"}:
                    out[n] = {"a": ["203.0.113.7"]}
                else:
                    out[n] = {"a": [], "cname": []}
            return out
    client = _Once()
    store = _Store()
    res = tools.t_dns(store, ["ghost.example.com"], doh_client=client)
    row = [w for w in res["wildcard"] if w["parent"] == "example.com"]
    assert row and row[0]["signature"] is False, res["wildcard"]
    stored = {k for (kind, k) in store.assets if kind == "domain"}
    assert "ghost.example.com" in stored, (
        "one lucky probe must not discard a candidate", store.assets)


def test_dnsx_and_doh_evidence_share_one_table():
    """A zone probed by dnsx filters DoH answers too (same key, same rules)."""
    _, tools = _bind()
    # dnsx probes answered 203.0.113.7 twice (core.run stub), then the DoH
    # path answers a candidate with the same echo -> filtered by the dnsx
    # evidence because both paths fill ONE table.
    probes_seen: list = []

    def fake_run(cmd, *a, **kw):
        name = kw.get("input_text") or ""
        probes_seen.append(name)
        return 0, json.dumps({"host": name, "a": ["203.0.113.7"]}) + chr(10), ""

    client = _FakeDoh({"ghost.example.com": {"a": ["203.0.113.7"]}})
    store = _Store()
    with mock.patch.object(tools.core, "run", side_effect=fake_run), \
         mock.patch.object(tools.core, "run_stream",
                           return_value=(0, 0, "")):
        # fake_ip forced OFF so the dnsx path runs; the DoH client stays unused
        pin_dns_environment(fake_ip=False)
        res = tools.t_dns(store, ["ghost.example.com"], doh_client=client)
    row = [w for w in res["wildcard"] if w["parent"] == "example.com"]
    assert row and row[0]["signature"] is True, res["wildcard"]
    stored = {k for (kind, k) in store.assets if kind == "domain"}
    assert stored == set(), ("the wildcard echo must be dropped", store.assets)
