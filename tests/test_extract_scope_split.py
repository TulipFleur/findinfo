"""Extraction must separate the target's hosts from lookalike noise.

Failure this pins (observed on a live run of a university target):
t_extract stored every host-shaped string a bundle contained at the same
confidence, so a run that had found 36 real hosts reported 747 "domains" --
the extra ones were JavaScript property chains (browserinfo.name,
e.animation.on, abel.tr, e.clienty-n.top) that happen to end in a real TLD
word, plus third-party CDNs (jquery.com, w3.org). Downstream stages ranked
and reported the noise alongside the target.

Two rules, both covered here:
  * an in-scope name becomes a domain asset;
  * an out-of-scope name is REPORTED (related_domains) but never stored, so
    asset queries and counts keep describing the target.
"""
import tests.util  # noqa: F401

import unittest.mock as mock

from tests.util import fresh_core, fresh_tools

BODY = ('{"url": "https://ehall.hniu.cn/a"} '
        'see www.hniu.cn and mail.hniu.com. '
        'noise: browserinfo.name e.animation.on e.clienty-n.top options.mr '
        'third party: cdn.jsdelivr.net jquery.com www.w3.org')


def _extract(scope=None, text=None):
    core = fresh_core()
    tools = fresh_tools(core)
    store = core.Store()
    import lib.jsleak as jsleak
    empty = {"domains": [], "ips": [], "api_paths": [], "secrets": {},
             "sourcemaps": [], "path_meta": {}}
    with mock.patch.object(jsleak, "extract", return_value=empty):
        with mock.patch.object(tools.core, "curl", return_value=(1, "", "")):
            res = tools.t_extract(store, [{"url": text or BODY}], urls=[],
                                  timeout=1, scope=scope)
    stored = {a["canonical"] for a in store.get_assets(kind="domain")}
    store.close()
    return res, stored


def test_in_scope_extraction_is_stored_as_an_asset():
    res, stored = _extract(scope=["hniu.cn", "hniu.com"])
    assert "www.hniu.cn" in stored, stored
    assert "mail.hniu.com" in stored, stored


def test_out_of_scope_extraction_is_reported_but_not_stored():
    res, stored = _extract(scope=["hniu.cn", "hniu.com"])
    for third_party in ("jquery.com", "www.w3.org", "cdn.jsdelivr.net"):
        assert third_party not in stored, (third_party, stored)
        assert third_party in res["related_domains"], (third_party,
                                                       res["related_domains"])


def test_js_property_chains_never_reach_the_store():
    res, stored = _extract(scope=["hniu.cn"])
    for junk in ("browserinfo.name", "e.animation.on", "e.clienty-n.top",
                 "options.mr"):
        assert junk not in stored, (junk, sorted(stored))
        assert junk not in res["domains"], (junk, res["domains"])


def test_related_domains_are_counted_separately():
    res, stored = _extract(scope=["hniu.cn", "hniu.com"])
    assert res["count_related"] == len(res["related_domains"])
    assert res["count_related"] >= 1
    # count_domains still reports everything seen; the split is what tells the
    # caller which of those are actually theirs.
    assert res["count_domains"] >= res["count_related"]


def test_empty_scope_keeps_every_hit_as_an_asset():
    # No scope (standalone `extract` on a run file): nothing is "out of scope",
    # so behaviour matches the historical single-bucket store write.
    res, stored = _extract(scope=None)
    assert "www.hniu.cn" in stored
    assert res["count_related"] == 0
