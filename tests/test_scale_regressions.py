"""Regression: tools must survive real-world scale (found by live runs).

Each case comes from a failure observed against a real target:
- katana turned 7000+ scope domains into one command-line regex -> WinError 206
- report with one seed reported the other seed hosts as out-of-scope noise
"""
import io
import json
import unittest.mock as mock
import argparse
from contextlib import redirect_stdout
from pathlib import Path

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools, import_findinfo


def test_katana_scope_command_stays_short():
    """A huge allow-list must not be stuffed into one -fs regex."""
    core = fresh_core()
    tools = fresh_tools(core)
    seen = {}

    def fake_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        seen["cmd"] = list(cmd)
        return 0, 0, ""

    hosts = ["h%d.example.com" % i for i in range(8000)]
    with mock.patch.object(core, "run_stream", fake_stream):
        tools.t_crawl(core.Store(), ["https://h0.example.com"], depth=1,
                      scope_domains=hosts)
    cmd = seen["cmd"]
    longest = max(len(a) for a in cmd)
    assert longest < 8000, "single argument too long for Windows: %d" % longest
    assert sum(1 for a in cmd if a == "-fs") >= 1, "scope filter still applied"


def test_katana_small_scope_uses_exact_regex():
    core = fresh_core()
    tools = fresh_tools(core)
    seen = {}

    def fake_stream(cmd, on_line=None, timeout=300, cwd=None, env=None):
        seen["cmd"] = list(cmd)
        return 0, 0, ""

    with mock.patch.object(core, "run_stream", fake_stream):
        tools.t_crawl(core.Store(), ["https://a.example.com"], depth=1,
                      scope_domains=["a.example.com", "b.example.com"])
    joined = " ".join(seen["cmd"])
    assert "(^|\\.)" in joined, "small scope keeps the exact regex"


def test_report_scope_comes_from_run_when_match_omitted():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    store = core.Store()
    for d in ("a.example.com", "x.other.com", "y.other.com"):
        store.upsert_asset("domain", d, source="dnsx", confidence=0.8)
    store.close()

    rd = core.new_run_dir("scope-report")
    jobs.write_spec(rd, entry="findinfo:main", argv=["run"],
                    target="example", scope=["example.com", "other.com"],
                    home=str(core.HOME), root=str(core.ROOT))
    jobs.update_state(rd, state="completed", stage_total=1, stage_index=1)

    fi = import_findinfo()
    args = argparse.Namespace(match=None, min_conf=0.0, limit=50, ep_limit=50,
                              json_limit=0, out=str(Path(core.HOME) / "rep"),
                              slug="scope", engagement="default", run=rd.name,
                              brief_top=20, brief_max_bytes=32768,
                              with_json=False, with_brief=False,
                              print_md=False, print_json=False)
    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_report(args)
    payload = json.loads(buf.getvalue().strip().splitlines()[-1])
    assert payload["scope"]["match"] == ["example.com", "other.com"]
    assert payload["counts"]["domains_in_scope"] == 3
