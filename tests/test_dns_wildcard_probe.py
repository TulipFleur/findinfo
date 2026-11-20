"""The dnsx wildcard probe: a broken call and a lying resolver.

Two live-run findings are locked down here.

1. `dnsx -d NAME` is the wordlist driver and exits with
   "missing wordlist(w) flag required with domain(d) input". The probe used
   it, so every probe returned rc=1 with an empty body, the wildcard table was
   always empty, and every name inside a wildcard zone was stored as a real
   asset.
2. A fake-IP resolver (Clash/TUN, 198.18.0.0/15) answers EVERY name, so the
   corrected probe reports a wildcard for every parent. Dropping all names in
   a "wildcard" zone then discards the whole target. The filter must stand
   down instead.
"""
from __future__ import annotations

import json
from unittest import mock

from lib import tools


class _Store:
    def __init__(self) -> None:
        self.assets = []

    def upsert_asset(self, kind, key, **kw) -> None:
        self.assets.append((kind, key))

    def domain_assets(self):
        return [k for (kind, k) in self.assets if kind == "domain"]


def _patches(probe_ip, answers):
    """Stub the probe (core.run) and the resolver feed (core.run_stream)."""
    calls = []

    def run(cmd, *a, **kw):
        name = kw.get("input_text") or ""
        calls.append((list(cmd), name))
        if probe_ip is None:
            return 0, "", ""
        return 0, json.dumps({"host": name, "a": [probe_ip]}) + chr(10), ""

    def stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        if on_line:
            for host, addr in answers.items():
                on_line(json.dumps({"host": host, "a": [addr]}))
        return 0, len(answers), ""

    return calls, mock.patch.object(tools.core, "run", run), \
        mock.patch.object(tools.core, "run_stream", stream)


def test_the_probe_passes_the_name_on_stdin_not_via_dash_d():
    calls, p_run, p_stream = _patches(None, {})
    with p_run, p_stream:
        tools.t_dns(_Store(), ["www.example.com"], timeout=0)
    probe_calls = [(c, n) for (c, n) in calls if "probe" in n]
    assert probe_calls, calls
    for cmd, name in probe_calls:
        assert "-d" not in cmd, ("dnsx -d needs a wordlist and fails: %s" % (cmd,))
        assert name.endswith(".example.com"), name


def test_a_name_that_only_echoes_the_wildcard_address_is_dropped():
    answers = {"ghost.example.com": "203.0.113.7"}
    calls, p_run, p_stream = _patches("203.0.113.7", answers)
    with p_run, p_stream:
        store = _Store()
        result = tools.t_dns(store, ["ghost.example.com"], timeout=0)
    assert store.domain_assets() == [], store.assets
    assert result["wildcard"], "the affected zone must still be reported"


def test_a_name_with_its_own_address_in_a_wildcard_zone_survives():
    # Shared hosting: the host has its own A record inside a wildcard zone.
    answers = {"real.example.com": "198.51.100.9"}
    calls, p_run, p_stream = _patches("203.0.113.7", answers)
    with p_run, p_stream:
        store = _Store()
        tools.t_dns(store, ["real.example.com"], timeout=0)
    assert store.domain_assets() == ["real.example.com"], store.assets


def test_a_fake_ip_resolver_stands_the_filter_down():
    answers = {"a.example.com": "198.18.10.42"}
    calls, p_run, p_stream = _patches("198.18.10.101", answers)
    with p_run, p_stream:
        store = _Store()
        tools.t_dns(store, ["a.example.com"], timeout=0)
    # The resolver lies about every name; refusing to filter is the only way
    # to keep the target. The fake IP itself is still never stored as an IP.
    assert store.domain_assets() == ["a.example.com"], store.assets
    assert [k for (kind, k) in store.assets if kind == "ip"] == []
