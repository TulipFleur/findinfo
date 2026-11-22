"""An unscoped store read is resolved by policy, and always says how.

The store is shared, so "no --scope" used to mean either "read everything"
(old behaviour: one target's assets feed another target's stage) or "refuse"
(the strict gate). Both are wrong as a permanent rule: a store that holds ONE
target reads fine without a flag, and a script written before the gate must
still be able to say "all of it" out loud.

`scope.unscoped_reads` picks the policy:

* ``infer``  (default) use the store's single registrable domain, and report
             `scope_source: "inferred"`. A store mixing targets is refused --
             an inference there would hand one engagement to another.
* ``refuse`` never infer.
* ``legacy`` read everything, with a log line (never silent).

Every read also reports `scope_source` ("explicit" / "inferred" /
"whole_store" / "legacy") so a caller can tell a guess from a typed scope, and
a refusal carries `candidates`: the domains the store itself offers.

`ports` additionally never scans a private/reserved address taken from the
store -- the run pipeline calls the same function, so the guard lives there.
"""
import contextlib
import io
import json
import unittest.mock as mock
from contextlib import redirect_stdout

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo

STAGES = ("t_onepass", "t_subs", "t_icp", "t_dns", "t_httpx", "t_ipagg",
          "t_ports", "t_vhost", "t_crawl", "t_extract")


def _seed(core, domains=("a.example.com",), extra_ips=()):
    store = core.Store()
    try:
        for d in domains:
            store.upsert_asset("domain", d, source="httpx", confidence=0.8,
                               attrs={"url": "https://" + d + "/"})
        for ip in extra_ips:
            store.upsert_asset("ip", ip, source="dnsx", confidence=0.6,
                               parent=domains[0])
    finally:
        store.close()


def _cli(fi, argv):
    calls: list = []

    def rec(name):
        def f(*a, **kw):
            calls.append((name, a, kw))
            return {"count": 0, "ok": True, "rows": [], "domains": [],
                    "ips": [], "candidates": [], "count_candidates": 0}
        return f

    buf = io.StringIO()
    with contextlib.ExitStack() as st:
        for n in STAGES:
            st.enter_context(mock.patch.object(fi.tools, n, side_effect=rec(n)))
        with redirect_stdout(buf):
            try:
                rc = fi.main(argv)
            except SystemExit as exc:
                rc = exc.code
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip().startswith("{")]
    return rc, (json.loads(lines[-1]) if lines else None), calls


def _setup(domains=("a.example.com",), mode=None, extra_ips=()):
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    if mode is not None:
        core.CFG.setdefault("scope", {})["unscoped_reads"] = mode
    _seed(core, domains, extra_ips)
    return core, fi


# ------------------------------------------------------------- infer (default)
def test_a_single_target_store_is_inferred_and_says_so():
    """No --scope, one registrable domain in the store -> read that, labelled."""
    _, fi = _setup(domains=("a.example.com", "www.example.com"))
    rc, payload, calls = _cli(fi, ["probe"])
    assert rc == 0, payload
    assert calls and calls[0][1][1] == ["a.example.com", "www.example.com"], calls
    assert payload["scope_source"] == "inferred", payload


def test_an_ambiguous_store_is_still_refused_with_candidates():
    """Two targets in the store: guessing would mix engagements, so refuse.

    The refusal carries the domains the store offers, so the caller does not
    have to invent a name and re-run.
    """
    _, fi = _setup(domains=("a.example.com", "b.other.org"))
    rc, payload, calls = _cli(fi, ["probe"])
    assert rc == 2, (rc, payload)
    assert payload["error"] == "scope_required", payload
    assert calls == [], calls
    assert "example.com" in payload["candidates"], payload
    assert "other.org" in payload["candidates"], payload
    assert payload["scope_source"] == "refused", payload


def test_an_empty_store_is_not_an_inference():
    """Nothing to infer from -> refuse; an empty scope is not "everything"."""
    _, fi = _setup(domains=())
    rc, payload, calls = _cli(fi, ["probe"])
    assert rc == 2, (rc, payload)
    assert payload["error"] == "scope_required", payload
    assert calls == [], calls


# ------------------------------------------------------------- refuse mode
def test_refuse_mode_never_infers():
    _, fi = _setup(domains=("a.example.com",), mode="refuse")
    rc, payload, calls = _cli(fi, ["probe"])
    assert rc == 2, (rc, payload)
    assert payload["error"] == "scope_required", payload
    assert calls == [], calls


# ------------------------------------------------------------- legacy mode
def test_legacy_mode_reads_everything_and_says_so():
    _, fi = _setup(domains=("a.example.com", "b.other.org"), mode="legacy")
    rc, payload, calls = _cli(fi, ["probe"])
    assert rc == 0, payload
    assert sorted(calls[0][1][1]) == ["a.example.com", "b.other.org"], calls
    assert payload["scope_source"] == "legacy", payload


# ------------------------------------------------------------- labels
def test_an_explicit_scope_is_labelled_explicit():
    _, fi = _setup(domains=("a.example.com", "b.other.org"))
    rc, payload, calls = _cli(fi, ["probe", "--scope", "example.com"])
    assert rc == 0, payload
    assert payload["scope_source"] == "explicit", payload


def test_whole_store_is_labelled_whole_store():
    _, fi = _setup(domains=("a.example.com", "b.other.org"))
    rc, payload, calls = _cli(fi, ["probe", "--whole-store"])
    assert rc == 0, payload
    assert payload["scope_source"] == "whole_store", payload


def test_an_unknown_mode_falls_back_to_infer():
    """A typo in config.json must not disable the guard."""
    core, fi = _setup(domains=("a.example.com", "b.other.org"), mode="nonsense")
    assert core.scope_mode() == "infer"
    rc, payload, calls = _cli(fi, ["probe"])
    assert rc == 2 and payload["error"] == "scope_required", (rc, payload)


# ------------------------------------------------------------- ports
def test_ports_never_scans_a_private_address_from_the_store():
    """The pipeline calls t_ports directly, so the guard lives in the tool."""
    core, fi = _setup(domains=("a.example.com",),
                      extra_ips=("93.184.216.34", "10.1.2.3", "198.18.0.9"))
    seen: list = []

    def fake_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        with open(cmd[cmd.index("-l") + 1], encoding="utf-8") as fh:
            seen.extend(ln.strip() for ln in fh if ln.strip())
        return 0, 0, ""

    store = core.Store()
    try:
        with mock.patch.object(fi.tools.core, "run_stream", fake_stream), \
                mock.patch.object(fi.tools.core, "has_tool", lambda n: False):
            res = fi.tools.t_ports(store, ["93.184.216.34", "10.1.2.3",
                                           "198.18.0.9"])
    finally:
        store.close()
    assert seen == ["93.184.216.34"], ("naabu must not see a private IP", seen)
    assert sorted(res["skipped_private"]) == ["10.1.2.3", "198.18.0.9"], res


def test_ports_with_only_private_addresses_does_not_scan():
    core, fi = _setup(domains=("a.example.com",), extra_ips=("10.5.5.5",))
    store = core.Store()
    try:
        with mock.patch.object(fi.tools.core, "run_stream",
                               side_effect=AssertionError("naabu must not run")):
            res = fi.tools.t_ports(store, ["10.5.5.5"])
    finally:
        store.close()
    assert res["count"] == 0 and res["skipped_private"] == ["10.5.5.5"], res


def test_an_explicit_private_ip_is_still_scanned():
    """--ip is the operator's own decision: t_ports(allow_private=True)."""
    core, fi = _setup(domains=("a.example.com",))
    seen: list = []

    def fake_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        with open(cmd[cmd.index("-l") + 1], encoding="utf-8") as fh:
            seen.extend(ln.strip() for ln in fh if ln.strip())
        return 0, 0, ""

    store = core.Store()
    try:
        with mock.patch.object(fi.tools.core, "run_stream", fake_stream), \
                mock.patch.object(fi.tools.core, "has_tool", lambda n: False):
            fi.tools.t_ports(store, ["10.0.0.5"], allow_private=True)
    finally:
        store.close()
    assert seen == ["10.0.0.5"], seen
