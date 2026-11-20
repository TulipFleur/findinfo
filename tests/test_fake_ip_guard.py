"""A transparent-proxy placeholder must never become an asset.

Failure this pins (live run, university target): the machine sat behind a
Clash/TUN proxy that answers every A query with 198.18.210.x. t_dns filtered
that range only on the system-resolver FALLBACK path, so the dnsx main path
stored 35 "IP assets" that were all proxy placeholders -- ports, vhost and
TLS-grab then aimed at the local proxy instead of the target, and the report
claimed 35 hosts no scan had actually reached.
"""
import tests.util  # noqa: F401

import json
import unittest.mock as mock

from lib import doh
from tests.util import fresh_core, fresh_tools


def test_is_fake_ip_covers_the_whole_benchmark_block():
    core = fresh_core()
    tools = fresh_tools(core)
    for fake in ("198.18.0.1", "198.18.210.124", "198.19.255.255"):
        assert doh.is_fake_ip(fake), fake
    for real in ("1.2.3.4", "192.168.1.1", "10.0.0.1", "198.20.0.1", ""):
        assert not doh.is_fake_ip(real), real


def _feed(payload):
    """Stand in for run_stream: hand each JSONL line to the caller's handler."""
    def _run_stream(cmd, on_line=None, timeout=0, cwd=None, env=None):
        for line in payload.splitlines():
            if on_line:
                on_line(line)
        return 0, 0, ""
    return _run_stream

def _dnsx_rows(domains, ips):
    return chr(10).join(json.dumps({"host": d, "a": ips}) for d in domains)


def test_dnsx_answers_in_the_fake_range_are_not_stored_as_ips():
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    domains = ["www.hniu.cn", "ehall.hniu.cn"]
    out = _dnsx_rows(domains, ["198.18.210.120"])
    with mock.patch.object(tools.core, "has_tool", return_value=True):
        with mock.patch.object(tools.core, "tool", return_value="dnsx.exe"):
            with mock.patch.object(tools.core, "run", return_value=(0, "", "")):
                with mock.patch.object(tools.core, "run_stream",
                                       side_effect=_feed(out)):
                    res = tools.t_dns(store, domains, timeout=1)
    ips = {a["canonical"] for a in store.get_assets(kind="ip")}
    stored_domains = {a["canonical"] for a in store.get_assets(kind="domain")}
    store.close()
    assert not any(ip.startswith("198.18.") for ip in ips), ips
    # The names themselves are still evidence and stay as assets.
    assert "www.hniu.cn" in stored_domains, stored_domains


def test_a_real_answer_is_still_stored():
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    domains = ["www.hniu.cn"]
    out = _dnsx_rows(domains, ["203.0.113.9"])
    with mock.patch.object(tools.core, "has_tool", return_value=True):
        with mock.patch.object(tools.core, "tool", return_value="dnsx.exe"):
            with mock.patch.object(tools.core, "run", return_value=(0, "", "")):
                with mock.patch.object(tools.core, "run_stream",
                                       side_effect=_feed(out)):
                    tools.t_dns(store, domains, timeout=1)
    ips = {a["canonical"] for a in store.get_assets(kind="ip")}
    store.close()
    assert ips == {"203.0.113.9"}, ips
