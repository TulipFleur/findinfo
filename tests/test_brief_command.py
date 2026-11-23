"""The brief command: the agent's unified read API over the library.

report is now the human deliverable (HTML by default); an agent
gets its data by querying the store directly through `brief`, which prints
ONE JSON line to stdout and writes no files. These tests pin that split.
"""
import argparse
import io
import json
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, import_findinfo


def _seed(core):
    store = core.Store()
    store.upsert_asset("domain", "app.example.org", source="onepass:crt.sh",
                       confidence=0.9)
    store.upsert_asset("domain", "vpn.example.org",
                       source="onepass:crt.sh,subfinder:chaos", confidence=0.95)
    store.upsert_asset("ip", "203.0.113.10", source="dnsx", confidence=0.7)
    store.close()


def _brief_args(**kw):
    base = dict(match=["example.org"], min_conf=0.3, limit=300, ep_limit=400,
                engagement="default", run="", top=20, max_bytes=32768)
    base.update(kw)
    return argparse.Namespace(**base)


def test_brief_prints_one_json_line_and_writes_no_files():
    core = fresh_core()
    fi = import_findinfo()
    _seed(core)
    before = sorted(p.name for p in Path(core.DATA).rglob("*") if p.is_file())
    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_brief(_brief_args())
    lines = [ln for ln in buf.getvalue().strip().splitlines() if ln.strip()]
    assert len(lines) == 1, "brief must be ONE stdout line, got " + str(len(lines))
    brief = json.loads(lines[0])
    assert brief["schema"] == "findinfo.brief/1"
    assert brief["counts"]["domains_in_scope"] == 2
    assert brief["brief_bytes"] <= brief["brief_max_bytes"]
    # the unified entry must not leave files behind: stdout is the deliverable
    after = sorted(p.name for p in Path(core.DATA).rglob("*") if p.is_file())
    assert before == after, "brief wrote files: " + str(set(after) - set(before))


def test_brief_respects_match_and_scope_fallback():
    """Same scope semantics as report: --match wins, --run falls back to the
    run's own scope, and a garbage --match fails loudly."""
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    fi = import_findinfo()
    _seed(core)
    rd = core.new_run_dir("sc")
    jobs.write_spec(rd, entry="findinfo:main", argv=["run"],
                    target="example", scope=["example.org"],
                    home=str(core.HOME), root=str(core.ROOT))

    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_brief(_brief_args(run=rd.name, match=None))
    brief = json.loads(buf.getvalue().strip().splitlines()[-1])
    assert brief["scope"]["match"] == ["example.org"]

    try:
        fi.cmd_brief(_brief_args(match=["!!!garbage!!!"]))
        raise AssertionError("garbage scope must fail loudly")
    except Exception as exc:
        assert "no valid domain" in str(exc), exc


def test_brief_ceiling_is_enforced():
    """A tiny --max-bytes must shrink the payload and record every cut."""
    core = fresh_core()
    fi = import_findinfo()
    store = core.Store()
    for i in range(300):
        store.upsert_asset("domain", "h" + str(i) + ".example.org",
                           source="httpx", confidence=0.9,
                           attrs={"title": "后台", "status": 200})
    store.close()
    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_brief(_brief_args(max_bytes=3000))
    brief = json.loads(buf.getvalue().strip().splitlines()[-1])
    assert brief["brief_bytes"] <= 3000, brief["brief_bytes"]
    assert brief["truncated"], "shrank without recording the cut"


def test_report_default_writes_only_human_files():
    """HTML is the default; Markdown and machine files need explicit flags."""
    core = fresh_core()
    fi = import_findinfo()
    _seed(core)
    out = Path(tempfile.mkdtemp()) / "rep"
    args = argparse.Namespace(match=["example.org"], min_conf=0.3, limit=300,
                              ep_limit=400, engagement="default", run="",
                              json_limit=0, out=str(out), slug="t",
                              brief_top=20, brief_max_bytes=32768,
                              with_json=False, with_brief=False, with_md=False,
                              print_md=False, print_json=False)
    args._sub = "report"
    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_report(args)
    payload = json.loads(buf.getvalue().strip().splitlines()[-1])
    files = sorted(p.name for p in out.iterdir())
    assert files == ["report.html"], files
    assert "html" in payload["paths"] and "md" not in payload["paths"]
    assert "brief" not in payload["paths"] and "json" not in payload["paths"]

    # and the opt-in flags bring the machine files back
    out2 = Path(tempfile.mkdtemp()) / "rep2"
    args2 = argparse.Namespace(**{**vars(args), "out": str(out2),
                                  "with_json": True, "with_brief": True})
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        fi.cmd_report(args2)
    files2 = sorted(p.name for p in out2.iterdir())
    assert files2 == ["report.brief.json", "report.html", "report.json"], files2

    # Markdown remains available without enabling the machine files.
    out3 = Path(tempfile.mkdtemp()) / "rep3"
    args3 = argparse.Namespace(**{**vars(args), "out": str(out3),
                                  "with_md": True})
    buf3 = io.StringIO()
    with redirect_stdout(buf3):
        fi.cmd_report(args3)
    payload3 = json.loads(buf3.getvalue().strip().splitlines()[-1])
    assert sorted(p.name for p in out3.iterdir()) == ["report.html", "report.md"]
    assert Path(payload3["paths"]["md"]).read_text(encoding="utf-8").strip()

    # Returning Markdown on stdout does not opt into a Markdown file.
    out4 = Path(tempfile.mkdtemp()) / "rep4"
    args4 = argparse.Namespace(**{**vars(args), "out": str(out4),
                                  "print_md": True})
    buf4 = io.StringIO()
    with redirect_stdout(buf4):
        fi.cmd_report(args4)
    payload4 = json.loads(buf4.getvalue().strip().splitlines()[-1])
    assert payload4["md"].strip()
    assert sorted(p.name for p in out4.iterdir()) == ["report.html"]
    assert "md" not in payload4["paths"]


def test_brief_and_report_brief_payload_agree():
    """The command and the --with-brief file must carry the same facts: an
    agent that switches between them must never see different numbers."""
    core = fresh_core()
    fi = import_findinfo()
    _seed(core)
    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_brief(_brief_args())
    via_cmd = json.loads(buf.getvalue().strip().splitlines()[-1])

    from lib import report as rep
    store = core.Store()
    data = rep.collect(store, match=["example.org"])
    store.close()
    via_file = rep.build_brief(data, top=20)
    for key in ("counts", "top_hosts_total", "internal_services_total"):
        assert via_cmd[key] == via_file[key], key
