"""P3 acceptance: source attribution, alias normalization, confidence.

- Same two sources: forward order, reverse order, and re-runs all produce the
  same source set and the same confidence; 0.7 never climbs to 0.95.
- The same CT upstream reached via different collectors counts once.
- CertSpotter attribution is exact.
- Historical alias-format rows ("onepass:crt.sh,rapiddns") normalize on read.
- A provably inflated stored score (0.95 from the retired alias bug with only
  2 real upstreams) is corrected instead of being preserved via max().
"""
import tests.util  # noqa: F401

from tests.util import fresh_core


def test_source_token_normalization():
    core = fresh_core()
    # prefixed token
    assert core.split_source_token("onepass:crt.sh") == ("onepass", "crt.sh")
    # bare collector
    assert core.split_source_token("dnsx") == ("dnsx", None)
    # legacy rows where only the first token carried the prefix
    assert core.split_source_token("rapiddns") == ("onepass", "rapiddns")
    assert core.split_source_token("subfinder") == ("subfinder", None)
    # 'crawl' is katana
    assert core.split_source_token("crawl") == ("katana", None)


def test_upstream_id_groups_collectors():
    core = fresh_core()
    # crt.sh direct == crt.sh via onepass (one upstream)
    assert core.upstream_id("crt.sh", None) == core.upstream_id("onepass", "crtsh")
    # fofa gateway == fofa via onepass
    assert core.upstream_id("fofa-gateway", None) == core.upstream_id("onepass", "fofa")
    # distinct upstreams stay distinct
    assert core.upstream_id("onepass", "crtsh") != core.upstream_id("onepass", "rapiddns")


def test_order_and_repeats_do_not_inflate_confidence():
    """The literal acceptance case: two sources, forward/reverse/repeat."""
    core = fresh_core()
    store = core.Store()

    def conf_now():
        return store.get_assets(kind="domain", min_conf=0.0)[0]["confidence"]

    store.upsert_asset("domain", "x.example.com", source="onepass:crt.sh", confidence=0.7)
    store.upsert_asset("domain", "x.example.com", source="onepass:rapiddns", confidence=0.7)
    c1 = conf_now()
    assert c1 == 0.7, c1

    # reverse order on a fresh row must give the same result
    store2 = core.Store()  # same db, different row
    store2.upsert_asset("domain", "y.example.com", source="onepass:rapiddns", confidence=0.7)
    store2.upsert_asset("domain", "y.example.com", source="onepass:crt.sh", confidence=0.7)
    c2 = store2.get_assets(kind="domain")[0]["confidence"]
    assert c1 == c2, (c1, c2)

    # re-running the SAME two sources changes nothing: 0.7 stays 0.7
    for _ in range(3):
        store.upsert_asset("domain", "x.example.com", source="onepass:crt.sh,onepass:rapiddns",
                           confidence=0.7)
    assert conf_now() == 0.7, "re-runs must not inflate confidence"
    store.close()
    store2.close()


def test_three_upstreams_reach_095():
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "z.example.com", source="onepass:crt.sh", confidence=0.7)
    store.upsert_asset("domain", "z.example.com", source="onepass:rapiddns", confidence=0.7)
    store.upsert_asset("domain", "z.example.com", source="onepass:anubis", confidence=0.7)
    row = store.get_assets(kind="domain")[0]
    assert row["confidence"] == 0.95, row["confidence"]
    assert len(core.source_upstreams(row["sources"])) == 3
    store.close()


def test_same_upstream_two_collectors_counts_once():
    """crt.sh direct (t_certs) + crt.sh via onepass: ONE independent vote."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "w.example.com", source="crt.sh", confidence=0.5)
    store.upsert_asset("domain", "w.example.com", source="onepass:crtsh", confidence=0.6)
    row = store.get_assets(kind="domain")[0]
    assert core.source_upstreams(row["sources"]) == {"crt.sh"}
    # two collectors, one upstream: confidence must NOT jump to the 2-source floor
    assert row["confidence"] == 0.6, row["confidence"]
    store.close()


def test_legacy_alias_rows_normalize_on_read():
    core = fresh_core()
    raw = "onepass:crt.sh,rapiddns,subfinder"
    ups = core.source_upstreams(raw)
    assert ups == {"crt.sh", "rapiddns", "subfinder"}, ups
    tools = core.source_tools(raw)
    assert tools == {"onepass", "subfinder"}, tools


def test_inflated_history_is_corrected():
    """Stored 0.95 backed by only 2 real upstreams (alias-bug artifact)."""
    core = fresh_core()
    store = core.Store()
    # simulate the retired bug: bare onepass subs counted as separate tools
    store.upsert_asset("domain", "legacy.example.com",
                       source="onepass:crt.sh,rapiddns,anubis", confidence=0.95)
    row = store.get_assets(kind="domain")[0]
    # after normalization this row has 3 REAL upstreams -> 0.95 is legitimate
    assert row["confidence"] == 0.95
    # but a 0.95 row with only 2 upstreams is provably inflated: a re-upsert
    # with the same two sources pulls it back under the 3-upstream cap
    store.conn.execute("UPDATE assets SET sources='onepass:crt.sh,onepass:rapiddns' "
                       "WHERE canonical='legacy.example.com'")
    store.conn.commit()
    store.upsert_asset("domain", "legacy.example.com", source="onepass:crt.sh,onepass:rapiddns",
                       confidence=0.7)
    row = store.get_assets(kind="domain")[0]
    assert row["confidence"] == 0.7, row["confidence"]
    store.close()


def test_enscan_anchor_survives_weak_observation():
    """A strong single-source claim is preserved through max(): no regression."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "anchor.example.com", source="enscan", confidence=0.9)
    store.upsert_asset("domain", "anchor.example.com", source="dnsx", confidence=0.8)
    row = store.get_assets(kind="domain")[0]
    assert row["confidence"] == 0.9, row["confidence"]
    store.close()


def test_certspotter_attribution():
    """t_certs fallback results name certspotter, not crt.sh."""
    import unittest.mock as mock
    core = fresh_core()
    from tests.util import fresh_tools
    tools = fresh_tools(core)
    store = core.Store()
    # crt.sh fails on every attempt, certspotter answers. Each source is tried
    # with the configured retry budget (limits.source_retries), so the fake
    # must stay "None" for the whole crt.sh window, not just once.
    retries = 1 + max(0, int((core.CFG.get("limits") or {}).get("source_retries") or 0))

    def fake_curl(url, headers=None, timeout=60, **kw):
        return None if "crt.sh" in str(url) else [{"dns_names": ["a.example.com"]}]

    with mock.patch.object(core, "curl_json", side_effect=fake_curl), \
         mock.patch.object(core.time, "sleep", lambda *_: None):
        r = tools.t_certs(store, "example.com")
    assert retries >= 1
    assert r["upstream"] == "certspotter"
    assert r["ok"] is True
    assert r["count"] == 1
    row = store.get_assets(kind="domain")[0]
    # collector = certs (findinfo's own CT lookup), upstream = certspotter
    assert core.source_tools(row["sources"]) == {"certs"}
    assert core.source_upstreams(row["sources"]) == {"certspotter"}
    # and it groups with certspotter reached via onepass: ONE vote, not two
    store.upsert_asset("domain", "a.example.com", source="onepass:certspotter",
                       confidence=0.7)
    row = store.get_assets(kind="domain")[0]
    assert core.source_upstreams(row["sources"]) == {"certspotter"}
    assert row["confidence"] == 0.7, "same upstream twice must not bump the floor"

    # both unreachable -> ok=False so the caller records failure, not "empty"
    core.CACHE = core.Cache(core.CACHE_DIR / "isolated-p2")
    with mock.patch.object(core, "curl_json", return_value=None), \
         mock.patch.object(core.time, "sleep", lambda *_: None):
        r = tools.t_certs(store, "other.example.org")
    assert r["ok"] is False and r["count"] == 0
    assert r["upstream"] == "crt.sh"
    store.close()
