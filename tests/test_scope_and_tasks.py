"""P1 acceptance: task isolation and scope control.

- Chinese/special-char task names get stable, distinct directories; the same
  name always maps to the same directory.
- Plain ASCII names keep their legacy directory (compat with existing installs).
- Two different Chinese tasks never share a database; unrelated old targets
  never enter the active stages of a new one.
- registrable_domain() is public-suffix aware: customer.co.uk is not co.uk.
"""
import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core


def test_task_name_mapping():
    core = fresh_core()
    # ASCII names stay verbatim (existing installs keep their directory)
    assert core._safe_task_name("hniu") == "hniu"
    assert core._safe_task_name("default") == "default"
    assert core._safe_task_name("proj-2024_a") == "proj-2024_a"
    # pure Chinese: distinct stable tokens, never the shared "default"
    a1 = core._safe_task_name("美团")
    b1 = core._safe_task_name("百度")
    assert a1.startswith("task-") and b1.startswith("task-") and a1 != b1
    assert core._safe_task_name("美团") == a1          # stable across calls
    # mixed names that sanitize identically stay distinct (a b vs a.b)
    m1 = core._safe_task_name("a b")
    m2 = core._safe_task_name("a.b")
    assert m1 != m2 and m1.startswith("a_b-") and m2.startswith("a_b-")
    # empty / whitespace-only never maps onto a real task's directory
    assert core._safe_task_name("###").startswith("task-")
    assert core._safe_task_name("").startswith("task-")


def test_two_chinese_tasks_distinct_dbs():
    core_a = fresh_core(task="美团")
    assert core_a.HOME.name == core_a._safe_task_name("美团")
    db_a = str(core_a.DATA / "findinfo.db")
    store_a = core_a.Store()
    store_a.upsert_asset("domain", "meituan.com", source="enscan", confidence=0.9)
    store_a.close()
    core_b = fresh_core(task="百度")
    db_b = str(core_b.DATA / "findinfo.db")
    assert db_a != db_b
    store_b = core_b.Store()
    assert store_b.count_assets() == {}, "task 美团 assets must not leak into task 百度"
    store_b.close()


def test_registrable_domain_suffix_aware():
    core = fresh_core()
    assert core.registrable_domain("www.hniu.cn") == "hniu.cn"
    assert core.registrable_domain("hniu.cn") == "hniu.cn"
    # multi-label public suffixes: last-two-labels must NOT be used here
    assert core.registrable_domain("customer.co.uk") == "customer.co.uk"
    assert core.registrable_domain("www.customer.co.uk") == "customer.co.uk"
    assert core.registrable_domain("service.example.com.au") == "example.com.au"
    assert core.registrable_domain("a.b.com.cn") == "b.com.cn"
    # garbage in, None out
    assert core.registrable_domain("http://x") is None
    assert core.registrable_domain("") is None


def test_in_scope_and_co_uk():
    core = fresh_core()
    scope = ["customer.co.uk"]
    assert core.in_scope("customer.co.uk", scope)
    assert core.in_scope("shop.customer.co.uk", scope)
    assert not core.in_scope("unrelated.co.uk", scope), \
        "co.uk is a public suffix: unrelated.co.uk must not be accepted"
    assert not core.in_scope("customer.co.uk.attacker.io", scope)
    # empty scope = no restriction (documented semantics)
    assert core.in_scope("anything.example", [])
    assert core.in_scope("anything.example", None)
    # non-host values never match
    assert not core.in_scope("not a host", ["example.com"])


def test_active_stages_scoped_to_current_target():
    """DB has old.other.com; a run scoped to new.example.com must not read it."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "old.other.com", source="onepass:crt.sh",
                       confidence=0.8, passivity="passive")
    store.upsert_asset("domain", "sub.new.example.com", source="onepass:crt.sh",
                       confidence=0.8, passivity="passive")
    store.upsert_asset("domain", "new.example.com", source="onepass:crt.sh",
                       confidence=0.8, passivity="passive")
    store.upsert_asset("ip", "1.2.3.4", source="httpx", confidence=0.7,
                       passivity="active", parent="old.other.com")
    store.close()
    store = core.Store()
    scoped = store.get_assets(kind="domain", min_conf=0.4, match=["new.example.com"])
    got = {a["canonical"] for a in scoped}
    assert got == {"new.example.com", "sub.new.example.com"}, got
    # scoped IP read follows the parent attribution
    ips = store.get_assets(kind="ip", match=["new.example.com"])
    assert ips == []
    ips = store.get_assets(kind="ip", match=["old.other.com"])
    assert [a["canonical"] for a in ips] == ["1.2.3.4"]
    store.close()


def test_large_scope_python_fallback():
    """Scope lists >50 entries fall back to the same predicate in Python."""
    core = fresh_core()
    store = core.Store()
    store.upsert_asset("domain", "t3.example.com", source="onepass:crt.sh",
                       confidence=0.8, passivity="passive")
    store.close()
    store = core.Store()
    scope = ["x%d.example.org" % i for i in range(60)] + ["example.com"]
    got = [a["canonical"] for a in store.get_assets(kind="domain", match=scope)]
    assert got == ["t3.example.com"]
    store.close()
