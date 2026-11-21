"""Wiring W4 acceptance: the entity stage consults the subject gate (T06).

A brand that resolves to MORE than one plausible legal subject and carries
no explicit --domain seed must stop the run with identity_ambiguous and
input-required next steps -- no discovery, no active dispatch, no guessed
company. The batch D table-level tests (tests/test_batch_d_identity.py)
pin resolve_entity_identity itself; these pin the pipeline call.
"""

import io
import json
import unittest.mock as mock
from contextlib import redirect_stdout

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo


def _args(**over):
    import argparse
    base = dict(
        task="", name="美团", domain=[], active=False, ports=False,
        vhost=False, crawl=False, brute=False, brute_wordlist="",
        brute_bandwidth="3m", depth=3, invest=51, deep=1,
        engines="fofa,quake,hunter,shodan,censys", no_icp=False,
        no_onepass=True, top_ports=1000, max_seed=5, max_vhost_ips=10,
        force_stage=False, background=False, resume="", rounds=1,
        time_budget=0.0, task_timeout=0.0, tool_timeout=0, entity_timeout=1200,
        supplier=False, branch=False)
    base.update(over)
    return argparse.Namespace(**base)


def _run(fi, args, fakes):
    buf = io.StringIO()
    patches = [mock.patch.object(fi.tools, n, side_effect=f)
               for n, f in fakes.items()]
    for p in patches:
        p.start()
    try:
        with redirect_stdout(buf):
            rc = fi.cmd_run(args)
        lines = [l for l in buf.getvalue().splitlines()
                 if l.strip().startswith("{")]
        return rc, (json.loads(lines[-1]) if lines else {})
    finally:
        for p in reversed(patches):
            p.stop()


def _fakes():
    return {
        "t_certs": lambda s, d, timeout=0, **kw: {"count": 0, "ok": True},
        "t_subs": lambda s, d, engines="", timeout=0, **kw: {
            "count": 0, "ok": True},
        "t_dns": lambda s, d, timeout=0, **kw: {
            "count": 0, "ok": True, "rc": 0, "domains": [], "wildcard": []},
    }


def test_ambiguous_brand_stops_before_discovery():
    """Two plausible subjects, no seed: the run stops, nothing collects."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    probes: dict = {"certs": 0, "dns": 0}

    def fake_enscan(store, name, **kw):
        # two DIFFERENT plausible legal subjects for the brand
        return {"rc": 0, "json_files": 2, "stderr": "",
                "companies": ["fixture-subject-A", "fixture-subject-B"],
                "icp": [], "domains": [], "apps": []}

    def fake_certs(store, d, timeout=0):
        probes["certs"] += 1
        return {"count": 0, "ok": True}

    def fake_dns(store, domains, timeout=0, **kw):
        probes["dns"] += 1
        return {"count": 0, "ok": True, "rc": 0, "domains": [], "wildcard": []}

    fakes = _fakes()
    fakes["t_enscan"] = fake_enscan
    fakes["t_certs"] = fake_certs
    fakes["t_dns"] = fake_dns
    rc, payload = _run(fi, _args(), fakes)
    assert rc == 5, "an ambiguous identity is a partial (gap), not success"
    # discovery NEVER ran: no certs/dns call happened after the gate
    assert probes["certs"] == 0, probes
    assert probes["dns"] == 0, probes
    # the coverage names the gap; the stage result carries the candidates
    failed = payload.get("coverage", {}).get("failed_stages") or []
    assert any("identity_ambiguous" in str(f.get("error", "")) for f in failed), failed


def test_explicit_seed_bypasses_the_ambiguity_gate():
    """With --domain the brand is context; the gate passes and discovery runs."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()

    def fake_enscan(store, name, **kw):
        return {"rc": 0, "json_files": 2, "stderr": "",
                "companies": ["fixture-subject-A", "fixture-subject-B"],
                "icp": [], "domains": [], "apps": []}

    fakes = _fakes()
    fakes["t_enscan"] = fake_enscan
    rc, payload = _run(fi, _args(domain=["mt-a.example.com"], no_icp=True), fakes)
    assert rc == 0, payload.get("result")
    assert payload["result"]["status"] == "complete"


def test_unique_company_run_is_unaffected():
    """One anchored subject: the gate passes and the run behaves as before."""
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()

    def fake_enscan(store, name, **kw):
        # exact single match; store what the real collector would store so
        # the icp stage has codes to chew on
        store.upsert_asset("company", "美团", source="enscan",
                           confidence=0.9, parent=None)
        store.upsert_asset("icp", "京ICP备00000001号-1", source="enscan",
                           confidence=0.9, parent=name)
        store.upsert_asset("domain", "mt-a.example.com", source="enscan",
                           confidence=0.9, parent="美团")
        return {"rc": 0, "json_files": 1, "stderr": "",
                "companies": ["美团"],
                "icp": ["京ICP备00000001号-1"],
                "domains": ["mt-a.example.com"], "apps": []}

    fakes = _fakes()
    fakes["t_enscan"] = fake_enscan
    fakes["t_icp"] = lambda s, codes, engines="", timeout=0, **kw: {
        "domains": [], "errors": [], "count": 0, "ok": True,
        "codes": list(codes), "ips": []}
    rc, payload = _run(fi, _args(), fakes)
    assert rc == 0, payload.get("result")
    # the icp code harvested from the anchor feeds the icp stage plan
    assert "mapping" in payload.get("planned_stages", []), payload.get("planned_stages")
