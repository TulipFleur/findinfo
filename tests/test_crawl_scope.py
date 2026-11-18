"""Regression P11/P12: the crawl request filter must be a working regex.

Two live failures, same code path:
- P11: 7163 allow domains -> sorted() -> [:20] dropped the actual target, so
  katana crawled unrelated sites from an entity anchor.
- P12: the follow-up fix passed "-fs rdn:host", a syntax this katana build does
  not support: every result was filtered out (crawl produced zero URLs for a
  host that streams thousands without the flag).
"""
import unittest.mock as mock

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools


def _crawl_cmd(core, tools, scope_domains, depth=1):
    seen = {}

    def fake_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        seen["cmd"] = list(cmd)
        return 0, 0, ""

    with mock.patch.object(core, "run_stream", fake_stream):
        tools.t_crawl(core.Store(), ["https://seed.example.com"], depth=depth,
                      scope_domains=scope_domains)
    return seen["cmd"]


def _filters(cmd):
    return [cmd[i + 1] for i, a in enumerate(cmd[:-1]) if a == "-fs"]


def test_target_domain_survives_a_huge_allow_list():
    core = fresh_core()
    tools = fresh_tools(core)
    decoys = ["0%d.a%d.cn" % (i, i) for i in range(3000)]
    decoys += ["%d.chaoxing.com" % i for i in range(2000)]
    decoys += ["%d.hniu.cn" % i for i in range(2000)]
    cmd = _crawl_cmd(core, tools, ["meituan.com"] + decoys)
    joined = chr(32).join(_filters(cmd))
    assert "meituan" in joined, ("target dropped from katana filter", joined[:200])


def test_filter_never_uses_unsupported_rdn_syntax():
    """-fs rdn:<host> silently filters out EVERY result on this build."""
    core = fresh_core()
    tools = fresh_tools(core)
    decoys = ["%d.hniu.cn" % i for i in range(3000)]
    cmd = _crawl_cmd(core, tools, ["meituan.com"] + decoys)
    for f in _filters(cmd):
        assert not f.startswith("rdn:"), "unsupported -fs rdn: form emitted"


def test_filter_argument_budget_respected():
    core = fresh_core()
    tools = fresh_tools(core)
    scope = ["t%d.example%d.com" % (i, i) for i in range(3000)]
    cmd = _crawl_cmd(core, tools, scope)
    assert max(len(a) for a in cmd) < 8000, "argument too long for Windows"
    assert _filters(cmd), "some request-level filter must remain"


def test_small_scope_keeps_exact_regex():
    core = fresh_core()
    tools = fresh_tools(core)
    cmd = _crawl_cmd(core, tools, ["a.example.com", "b.example.com"])
    joined = chr(32).join(_filters(cmd))
    assert "(^|" in joined, joined
    assert "a" in joined and "example" in joined, joined
