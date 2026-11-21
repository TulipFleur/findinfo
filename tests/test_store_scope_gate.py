"""Single-stage commands never take their targets from the whole store by default.

The asset store is shared across engagements (and across tasks when --task is
omitted). probe/dns/passive/ports/... used to fall back to EVERY asset in it
when no input or scope was given: a second target inherited the first one's
hosts, and `ports` without --ip port-scanned every IP ever stored -- including
addresses scraped out of pages/JS (private ranges, no owning domain) and the
IPs of an ICP reverse lookup. These tests pin the replacement contract:

  1. a store read needs an explicit scope, or the explicit --whole-store opt-in
  2. a scope that canonicalises to nothing is refused, never widened
  3. ports takes only IPs owned by an in-scope domain, minus private ranges
  4. explicit targets (--ip / --host / --url / --code) are honoured as given
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


def _seed(core):
    """Two engagements in one store, plus IPs without an in-scope owner."""
    store = core.Store()
    try:
        store.upsert_asset("domain", "a.example.com", source="httpx",
                           confidence=0.8, attrs={"url": "https://a.example.com/"})
        store.upsert_asset("domain", "b.other.org", source="httpx",
                           confidence=0.8, attrs={"url": "https://b.other.org/"})
        store.upsert_asset("ip", "1.2.3.4", source="dnsx", confidence=0.6,
                           parent="a.example.com")
        store.upsert_asset("ip", "10.1.2.3", source="dnsx", confidence=0.6,
                           parent="intra.example.com")
        store.upsert_asset("ip", "5.6.7.8", source="dnsx", confidence=0.6,
                           parent="b.other.org")
        store.upsert_asset("ip", "9.9.9.9", source="leak-extract", confidence=0.4)
        store.upsert_asset("ip", "8.8.4.4", source="icp:10210538号",
                           confidence=0.5, parent="京ICP备10210538号")
        store.upsert_asset("url", "https://a.example.com/app.js", source="katana",
                           confidence=0.8)
        store.upsert_asset("url", "https://b.other.org/x.js", source="katana",
                           confidence=0.8)
    finally:
        store.close()


def _cli(fi, argv):
    """findinfo main() in-process, every collector replaced by a recorder."""
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
            except SystemExit as exc:      # argparse rejected the command line
                rc = exc.code
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip().startswith("{")]
    return rc, (json.loads(lines[-1]) if lines else None), calls


def _setup():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    _seed(core)
    return core, fi


UNSCOPED = [
    ["probe"], ["probe", "--from-store"],
    ["dns"], ["dns", "--from-store"],
    ["passive"], ["passive", "--from-store"],
    ["subs", "--from-store"],
    ["icp", "--from-store"],
    ["ipagg"],
    ["ports"],
    ["vhost", "--ip", "1.2.3.4"], ["vhost", "--ip", "1.2.3.4", "--from-store"],
    ["crawl"], ["crawl", "--from-store"],
    ["extract", "--from-store"],
]


def test_unscoped_store_reads_are_refused():
    _, fi = _setup()
    for argv in UNSCOPED:
        rc, payload, calls = _cli(fi, argv)
        assert rc == 2, (argv, rc, payload)
        assert payload and payload.get("error") == "scope_required", (argv, payload)
        assert payload.get("hint"), (argv, payload)
        assert calls == [], (argv, calls)


def test_scoped_probe_reads_only_its_scope():
    _, fi = _setup()
    rc, payload, calls = _cli(fi, ["probe", "--scope", "example.com"])
    assert rc == 0, payload
    assert [c[0] for c in calls] == ["t_httpx"], calls
    assert calls[0][1][1] == ["a.example.com"], calls


def test_whole_store_is_an_explicit_opt_in():
    _, fi = _setup()
    rc, payload, calls = _cli(fi, ["probe", "--whole-store"])
    assert rc == 0, payload
    assert sorted(calls[0][1][1]) == ["a.example.com", "b.other.org"], calls


def test_a_scope_with_no_valid_domain_is_refused_not_widened():
    _, fi = _setup()
    rc, payload, calls = _cli(fi, ["probe", "--scope", "bad scope!!"])
    assert rc == 2, payload
    assert payload["error"] == "scope_required", payload
    assert calls == [], calls


def test_private_tld_scope_never_widens_to_the_whole_store():
    core, fi = _setup()
    store = core.Store()
    try:
        rows = store.get_assets(kind="domain", match=["dev.corp.local"])
    finally:
        store.close()
    assert rows == [], [r["canonical"] for r in rows]
    rc, payload, calls = _cli(fi, ["probe", "--scope", "dev.corp.local"])
    assert rc == 0, payload
    assert calls[0][1][1] == [], calls


def test_ipagg_private_tld_scope_never_widens():
    core, fi = _setup()
    tools = fi.tools
    store = core.Store()
    try:
        with mock.patch.object(core, "has_tool", lambda n: False):
            res = tools.t_ipagg(store, None, scope=["dev.corp.local"])
    finally:
        store.close()
    assert res["ips"] == [], res


def test_ports_takes_only_public_ips_owned_by_the_scope():
    _, fi = _setup()
    for flag in ("--scope", "--domain"):
        rc, payload, calls = _cli(fi, ["ports", flag, "example.com"])
        assert rc == 0, (flag, payload)
        assert calls[0][1][1] == ["1.2.3.4"], (flag, calls)
        assert payload["skipped_private"] == ["10.1.2.3"], (flag, payload)


def test_ports_whole_store_still_skips_private_and_keeps_explicit_ips():
    _, fi = _setup()
    rc, payload, calls = _cli(fi, ["ports", "--whole-store"])
    assert rc == 0, payload
    assert "10.1.2.3" not in calls[0][1][1], calls
    rc, payload, calls = _cli(fi, ["ports", "--ip", "10.0.0.5"])
    assert rc == 0, payload
    assert calls[0][1][1] == ["10.0.0.5"], "explicit --ip must be used verbatim"


def test_vhost_wordlist_bases_come_from_the_explicit_hosts():
    _, fi = _setup()
    rc, payload, calls = _cli(fi, ["vhost", "--ip", "1.2.3.4",
                                   "--host", "a.example.com", "--wordlist", "vhost"])
    assert rc == 0, payload
    hosts = calls[0][1][2]
    assert hosts and all(h.endswith("example.com") for h in hosts), hosts


def test_crawl_and_extract_from_store_read_only_their_domain():
    _, fi = _setup()
    rc, payload, calls = _cli(fi, ["crawl", "--from-store", "--domain", "example.com"])
    assert rc == 0, payload
    assert calls[0][1][1] == ["https://a.example.com/"], calls
    rc, payload, calls = _cli(fi, ["extract", "--from-store", "--domain", "example.com"])
    assert rc == 0, payload
    urls = calls[0][2]["urls"]
    assert urls and not any("other.org" in u for u in urls), urls


# command -> (flags that are explicit targets, flags that scope a store read)
_STORE_READERS = {
    "passive": (("--domain",), ("--scope",)),
    "subs": (("--domain",), ("--scope",)),
    "icp": (("--code",), ("--scope",)),
    "dns": (("--domain",), ("--scope",)),
    "probe": (("--host",), ("--scope",)),
    "ipagg": (("--ip",), ("--scope",)),
    "ports": (("--ip",), ("--scope", "--domain")),
    "vhost": (("--host",), ("--domain",)),
    "crawl": (("--url",), ("--domain",)),
    "extract": (("--url", "--from-run"), ("--domain",)),
}
# reads the store only when asked to explicitly (no implicit fallback)
_FROM_STORE_ONLY = {"subs", "icp", "extract"}


def _documented_commands():
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    cmd_re = re.compile(r"^\s*(?:\$\s*)?(?:[a-z_]+\s+)?python findinfo\.py "
                        r"(?:--task \S+ )?(?:--home \S+ )?([a-z_]+)(.*)$")
    for doc in ("SKILL.md", "README.md", "docs/TOOLS.md", "prompts/AGENT.txt",
                "docs/TROUBLESHOOTING.md", "docs/DATA-MODEL.md"):
        path = root / doc
        if not path.exists():
            continue
        pending = ""
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pending:
                line, pending = pending + " " + line.strip(), ""
            if line.rstrip().endswith("\\"):
                pending = line.rstrip()[:-1].strip()
                continue
            m = cmd_re.match(line)
            if m:
                yield doc, lineno, m.group(1), m.group(2).split("#")[0]


def test_documented_store_reads_carry_a_scope():
    """A documented example must not teach a command the CLI now refuses."""
    bad = []
    for doc, lineno, cmd, rest in _documented_commands():
        if cmd not in _STORE_READERS:
            continue
        targets, scopes = _STORE_READERS[cmd]
        flags = set(rest.split())
        reads_store = ("--from-store" in flags or
                       (cmd not in _FROM_STORE_ONLY and not flags & set(targets)))
        if reads_store and not flags & (set(scopes) | {"--whole-store"}):
            bad.append("%s:%d %s%s" % (doc, lineno, cmd, rest.rstrip()))
    assert not bad, "documented store reads without a scope:\n" + "\n".join(bad)


def test_explicit_targets_need_no_scope():
    _, fi = _setup()
    for argv, stage in ((["probe", "--host", "a.example.com"], "t_httpx"),
                        (["dns", "--domain", "a.example.com"], "t_dns"),
                        (["passive", "--domain", "example.com"], "t_onepass"),
                        (["icp", "--code", "京ICP备10210538号"], "t_icp"),
                        (["ipagg", "--ip", "1.2.3.4"], "t_ipagg"),
                        (["crawl", "--url", "https://a.example.com/"], "t_crawl")):
        rc, payload, calls = _cli(fi, argv)
        assert rc == 0, (argv, payload)
        assert [c[0] for c in calls] == [stage], (argv, calls)
