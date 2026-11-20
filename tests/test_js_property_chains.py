"""Regressions for JS property chains that end in a real public suffix.

`i.find.id`, `ge.td`, `xt.host`, `li.eq` are object accesses from minified
bundles, not hostnames: every label is a property word and the last one is a
working gTLD/ccTLD, so the public-suffix gate alone lets them through. A live
run of the hniu.cn engagement reported them as related domains because the
word list that was supposed to stop them could never be complete ("find").
"""
from __future__ import annotations

from lib import core


JS_CHAINS = [
    "i.find.id", "b.filter.id", "d.find.id", "i.find.name", "ob.id", "ex.name",
    "ce.fn", "ge.td", "nt.td", "at.th", "ke.th", "ra.td", "xt.host",
    "mt.host", "li.eq", "li.on", "opt.is", "v.tween.prototype.run",
    "e.clienty-n.top", "t.top-i.top", "window.top",
]

REAL_HOSTS = [
    "hniu.cn", "www.hniu.cn", "hniu.com", "mail.example.com",
    "api.example.com.au", "cdn.jsdelivr.net", "my-api.example.cn",
    "api-v2.example.cn", "school.example.id", "abc123.example.top",
    "hr.lh.rendd.cn",
]


def test_js_property_chains_ending_in_a_real_tld_are_rejected():
    leaked = [d for d in JS_CHAINS if core.canon_domain(d)]
    assert not leaked, ("JS property chain accepted as a domain: %s" % leaked)


def test_real_hosts_are_never_collateral_damage():
    lost = [d for d in REAL_HOSTS if not core.canon_domain(d)]
    assert not lost, ("real host rejected: %s" % lost)


def test_hyphenated_or_numeric_labels_stay_valid_under_ambiguous_tlds():
    # .id/.top are ambiguous, but a hyphen or a digit is decisive evidence of
    # a real registrable label rather than a property access.
    assert core.canon_domain("smk-negeri.example.id") == "smk-negeri.example.id"
    assert core.canon_domain("sekolah2.example.id") == "sekolah2.example.id"
    assert core.canon_domain("my-api.example.top") == "my-api.example.top"


def test_unambiguous_tlds_are_left_alone():
    # .com/.cn/.org are not in the ambiguous set, so a short second-level label
    # is still accepted -- otherwise "abc.com" would be dropped.
    for host in ("abc.com", "jobs.cn", "job.org", "baidu.net"):
        assert core.canon_domain(host) == host, host
