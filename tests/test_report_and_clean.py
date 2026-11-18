"""P5 acceptance: report scoping, failed stages, clean --kind, passivity."""
import tests.util  # noqa: F401

from tests.util import fresh_core


def test_report_scope_by_asset_type():
    """domain->suffix, url->hostname, ip->parent attribution."""
    core = fresh_core()
    from lib import report
    store = core.Store()
    # in-scope domain + URL; out-of-scope rows of every kind
    store.upsert_asset("domain", "www.example.com", source="httpx",
                       confidence=0.9, passivity="active",
                       attrs={"url": "https://www.example.com/", "status": 200})
    store.upsert_asset("url", "https://www.example.com/api/x", source="katana",
                       confidence=0.7, passivity="active", parent="www.example.com")
    store.upsert_asset("domain", "other.org", source="httpx", confidence=0.9,
                       passivity="active")
    store.upsert_asset("url", "https://other.org/a", source="katana",
                       confidence=0.7, passivity="active", parent="other.org")
    # URL whose host is in scope but whose text looks like another domain
    store.upsert_asset("url", "https://sub.example.com/redirect?to=other.org",
                       source="katana", confidence=0.7, passivity="active",
                       parent="sub.example.com")
    # IPs: one attributed to an in-scope host, one to an out-of-scope host
    store.upsert_asset("ip", "1.1.1.1", source="httpx", confidence=0.7,
                       passivity="active", parent="www.example.com")
    store.upsert_asset("ip", "2.2.2.2", source="httpx", confidence=0.7,
                       passivity="active", parent="other.org")
    store.close()

    store = core.Store()
    data = report.collect(store, match=["example.com"], limit=10, ep_limit=10)
    hosts = {h["host"] for h in data["hosts"]}
    assert "www.example.com" in hosts
    assert "other.org" not in hosts
    # ip attribution: 1.1.1.1 reported (parent in scope), 2.2.2.2 dropped
    assert data["counts"]["ips_in_scope"] == 1, data["counts"]
    # dropped assets are counted, not silently hidden
    assert data["counts"]["domains_dropped"] >= 2
    store.close()


def test_report_invalid_match_raises():
    """An explicit garbage scope errors instead of degrading to whole-library."""
    core = fresh_core()
    from lib import report
    store = core.Store()
    store.upsert_asset("domain", "x.example.com", source="httpx", confidence=0.9,
                       passivity="passive")
    store.close()
    store = core.Store()
    try:
        report.collect(store, match=["!!!not a domain!!!"])
        raise AssertionError("collect must raise on an unusable explicit scope")
    except Exception as exc:
        assert not isinstance(exc, AssertionError)
    store.close()


def test_failed_stage_not_counted_as_done():
    """A steps row with status=failed is not an executed stage."""
    core = fresh_core()
    from lib import report
    store = core.Store()
    store.upsert_asset("domain", "x.example.com", source="httpx", confidence=0.9,
                       passivity="passive")
    store.set_step("default", "dns", "h1", "failed")
    store.set_step("default", "probe", "h2", "done")
    store.close()

    store = core.Store()
    data = report.collect(store, match=["example.com"])
    steps = {s["step"]: s["status"] for s in data["stages"]}
    assert steps == {"dns": "failed", "probe": "done"}
    # the failed stage must appear in next_steps as "needs retry", and must NOT
    # silence the "未执行阶段" hint
    joined = " ".join(data["next_steps"])
    assert "dns" in joined
    assert "失败" in joined
    store.close()


def test_clean_kind_endpoint_semantics():
    """--kind ip never deletes host-keyed endpoints; --kind domain does."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "a.example.com", source="httpx", confidence=0.9,
                       passivity="passive")
    store.upsert_asset("ip", "1.2.3.4", source="httpx", confidence=0.7,
                       passivity="active", parent="a.example.com")
    store.upsert_endpoint("a.example.com", "GET", "/api", ["q"], "katana")
    store.close()

    # --kind ip: only the ip asset row goes
    store = core.Store()
    res = store.purge(match=["example.com"], kinds=["ip"])
    assert res["assets"] == 1 and res["endpoints"] == 0
    assert res["endpoints_touched"] is False
    assert len(store.get_endpoints()) == 1
    assert store.count_assets().get("domain") == 1
    store.close()

    # --kind domain: the domain asset AND its endpoints go
    store = core.Store()
    res = store.purge(match=["example.com"], kinds=["domain"])
    assert res["assets"] == 1 and res["endpoints"] == 1
    assert res["endpoints_touched"] is True
    assert len(store.get_endpoints()) == 0
    store.close()


def test_clean_never_deletes_out_of_scope():
    """clean --match example.com leaves other.org rows untouched."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "a.example.com", source="httpx", confidence=0.9,
                       passivity="passive")
    store.upsert_asset("domain", "b.other.org", source="httpx", confidence=0.9,
                       passivity="passive")
    store.upsert_asset("ip", "1.1.1.1", source="httpx", confidence=0.7,
                       passivity="active", parent="b.other.org")
    store.close()
    store = core.Store()
    res = store.purge(match=["example.com"])
    assert res["assets"] == 1
    counts = store.count_assets()
    assert counts.get("domain") == 1          # b.other.org survives
    assert counts.get("ip") == 1
    store.close()


def test_passivity_merge_rule():
    """Active confirmation upgrades the row; passive never downgrades it."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "p.example.com", source="onepass:crt.sh",
                       confidence=0.7, passivity="passive")
    assert store.get_assets(kind="domain")[0]["passivity"] == "passive"
    store.upsert_asset("domain", "p.example.com", source="httpx",
                       confidence=0.9, passivity="active")
    row = store.get_assets(kind="domain")[0]
    assert row["passivity"] == "active"
    store.upsert_asset("domain", "p.example.com", source="subfinder",
                       confidence=0.5, passivity="passive")
    assert store.get_assets(kind="domain")[0]["passivity"] == "active"
    store.close()


def test_report_keeps_section_numbers_and_explains_missing_vhost():
    """Section 4 must appear even when empty, and say why (no silent gaps)."""
    core = fresh_core()
    from lib import report
    store = core.Store()
    store.upsert_asset("domain", "www.example.com", source="httpx", confidence=0.9,
                       passivity="active",
                       attrs={"url": "https://www.example.com/", "status": 200,
                              "title": "demo"})
    data = report.collect(store, match=["example.com"])
    md = report.build_md(data)
    heads = [ln for ln in md.splitlines() if ln.startswith("## ")]
    numbers = [h.split(".")[0].replace("## ", "") for h in heads]
    assert numbers == [str(i) for i in range(1, len(numbers) + 1)], (
        "report section numbers must be contiguous, got " + repr(numbers))
    sec4 = [h for h in heads if h.startswith("## 4.")]
    assert sec4, "section 4 vanished when there were no internal services"
    i = md.index(sec4[0])
    body = md[i:i + 400]
    assert "vhost" in body, (
        "an empty section 4 must say whether vhost ran; body was " + repr(body[:200]))
    store.close()
