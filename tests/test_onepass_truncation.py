"""onepass reports the sources whose upstream holds more than it returned.

VirusTotal, urlscan, FOFA, Quake and Hunter cap one response at 100-200 rows,
and onepass used to make exactly one request per source: on a large target
everything past the first page was dropped and nothing said so. onepass now
pages the free cursor APIs (VirusTotal, urlscan) within a page budget and
reports the cap of the billed engines (truncated + total) instead of spending
quota on more pages. These tests pin that the report reaches the stage result,
the run's coverage and the brief.
"""
import json
import unittest.mock as mock

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo
from tests.test_run_flow import _args, _latest_summary, _quiet, _run_quiet


def _onepass_line(with_paging=True):
    vt = {"id": "virustotal", "status": "ok", "found": 1}
    crt = {"id": "crtsh", "status": "ok", "found": 0}
    if with_paging:
        vt.update({"pages": 4, "truncated": True, "total": 1200})
        crt.update({"pages": 1, "truncated": False, "total": None})
    body = {"ok": True, "domain": "example.com", "elapsed_ms": 5,
            "sources_used": 2, "sources_ok": 2, "sources_error": 0, "found": 1,
            "records": [{"domain": "a.example.com", "sources": ["virustotal"],
                         "confidence": 0.48}],
            "sources": [crt, vt]}
    if with_paging:
        body["truncated_sources"] = ["virustotal"]
    return json.dumps(body) + "\n"


def _t_onepass(core, tools, line):
    store = core.Store()
    try:
        with mock.patch.object(core, "tool", lambda n: "/fake/" + n), \
             mock.patch.object(core, "run", lambda cmd, *a, **kw: (0, line, "")):
            return tools.t_onepass(store, "example.com")
    finally:
        store.close()


def test_t_onepass_reports_truncated_sources():
    core = fresh_core()
    tools = fresh_tools(core)
    r = _t_onepass(core, tools, _onepass_line())
    assert r["truncated_sources"] == ["onepass:virustotal"], r
    vt = next(p for p in r["per_source"] if p["id"] == "virustotal")
    assert (vt["truncated"], vt["total"], vt["pages"]) == (True, 1200, 4), vt
    # a cap is a coverage limit, not a failed source
    assert r["outcome"] == core.OUTCOME_OK, r


def test_older_onepass_output_without_paging_fields_still_works():
    core = fresh_core()
    tools = fresh_tools(core)
    r = _t_onepass(core, tools, _onepass_line(with_paging=False))
    assert r["truncated_sources"] == [], r
    assert r["count"] == 1, r


def test_run_surfaces_truncated_onepass_sources_in_coverage():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()

    def fake_onepass(s, d, *a, **kw):
        return {"count": 1, "sources_error": 0, "outcome": core.OUTCOME_OK,
                "truncated_sources": ["onepass:virustotal"]}

    rc, _ = _run_quiet(fi, _args(no_onepass=False), _quiet(t_onepass=fake_onepass))
    assert rc == 0, "a capped upstream is a coverage limit, not a failed run"
    _, summary = _latest_summary(core)
    gap = summary["coverage"]["unavailable"]
    assert gap["truncated_sources"] == ["onepass:virustotal"], gap
    assert "capped" in gap["note"], gap


def test_brief_lists_truncated_sources():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    from lib import report
    gap = fi._fold_runtime_unavailable(
        {"engines_without_key": [], "note": ""},
        [{"stage": "onepass", "truncated_sources": ["onepass:virustotal"]}], [])
    cov = report._brief_coverage(coverage={"known": True, "unavailable": gap})
    kinds = {(u["kind"], u.get("reason")) for u in cov["unavailable"]}
    assert ("truncated_sources", "onepass:virustotal") in kinds, kinds
