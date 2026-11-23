"""Full collection is an explicit workflow, independent of paid credentials.

The CLI remains passive by default.  The skill's full workflow supplies each
optional active flag, and a worker replays the same RunSpec without launching a
second worker.  Collectors below are in-process adapters: orchestration, stage
dispatch, scope, checkpoints, membership and final coverage are the real code.
Run this module in the isolated test checkout; no live target is required.
"""
from __future__ import annotations

import contextlib
import functools
import io
import json
import os
import unittest.mock as mock

import tests.util  # noqa: F401 -- isolated home before any runtime import
from tests.util import fresh_core, fresh_tools, import_findinfo


DOMAIN = "full-workflow.example.com"
IP = "203.0.113.41"
LIVE_URL = "https://" + DOMAIN
JS_URL = LIVE_URL + "/app.js"
ENGINES = "fofa,quake,hunter,shodan,censys"
FULL_ARGV = [
    "run", "--domain", DOMAIN, "--active", "--ports", "--vhost", "--crawl",
    "--background", "--rounds", "3",
]
FULL_PLAN = [
    "onepass", "certs", "subs", "mapping", "dns", "probe", "ipagg",
    "ports", "vhost", "crawl", "extract",
]


def _standalone_environment(fn):
    """A prior worker test must not fence this new foreground run's status."""
    @functools.wraps(fn)
    def isolated():
        with mock.patch.dict(os.environ):
            for name in ("FINDINFO_RUN_DIR", "FINDINFO_LAUNCH_TOKEN",
                         "FINDINFO_ATTEMPT"):
                os.environ.pop(name, None)
            return fn()
    return isolated


def _runtime():
    core = fresh_core()
    fresh_tools(core)
    return core, import_findinfo()


@_standalone_environment
def test_full_command_and_worker_spec_plan_every_keyless_stage():
    """The advertised command survives CLI -> RunSpec -> worker argv intact."""
    _, fi = _runtime()
    from lib import spec

    parser = fi.build_parser()
    launch = parser.parse_args(FULL_ARGV)
    requested = spec.from_cli(launch)
    assert launch.background is True
    assert requested.rounds == 3
    assert all(getattr(requested, flag) for flag in
               ("active", "ports", "vhost", "crawl"))
    assert requested.brute is False, "full Web collection does not imply brute"
    active = fi._active_enabled(launch)
    assert fi._plan_stages(launch, active) == FULL_PLAN
    assert fi._plan_stages_pure(requested, active) == FULL_PLAN

    worker = parser.parse_args(requested.to_worker_argv())
    assert worker.background is False, "the worker must not recursively detach"
    assert fi._plan_stages(worker, fi._active_enabled(worker)) == FULL_PLAN
    assert spec.from_cli(worker).to_json() == requested.to_json()


@_standalone_environment
def test_bare_run_and_active_only_keep_their_existing_meaning():
    """Fixing skill routing must not silently widen direct CLI invocations."""
    _, fi = _runtime()
    parser = fi.build_parser()
    passive = parser.parse_args(["run", "--domain", DOMAIN])
    assert fi._active_enabled(passive) is False
    assert fi._plan_stages(passive, False) == FULL_PLAN[:5]
    active = parser.parse_args(["run", "--domain", DOMAIN, "--active"])
    assert fi._plan_stages(active, fi._active_enabled(active)) == FULL_PLAN[:7]


@_standalone_environment
def test_keyless_full_pipeline_reaches_extraction_before_delivery():
    """No keys skips paid dispatch, while every requested active adapter runs."""
    core, fi = _runtime()
    from lib import spec

    # Execute the real foreground pipeline as a worker would.  Background
    # lifecycle has separate tests; spawning here would add no workflow check.
    launch = fi.build_parser().parse_args(FULL_ARGV)
    args = fi.build_parser().parse_args(spec.from_cli(launch).to_worker_argv())
    calls = []

    def onepass(store, domain, **kw):
        assert domain == DOMAIN
        calls.append("onepass")
        return {"count": 0, "sources_error": 0, "outcome": core.OUTCOME_EMPTY}

    def certs(store, domain, **kw):
        assert domain == DOMAIN
        calls.append("certs")
        return {"count": 0, "ok": True}

    def subs(store, domain, **kw):
        assert domain == DOMAIN
        calls.append("subs")
        return {"count": 0, "ok": True, "outcome": core.OUTCOME_EMPTY}

    def dns(store, domains, **kw):
        assert DOMAIN in domains
        calls.append("dns")
        for domain in domains:
            store.upsert_asset("domain", domain, source="dnsx", confidence=0.9,
                               attrs={"ips": [IP]})
        return {"count": len(domains), "ok": True, "rc": 0,
                "domains": list(domains), "wildcard": []}

    def probe(store, hosts, **kw):
        assert DOMAIN in hosts
        assert kw["scope"] == [DOMAIN]
        calls.append("probe")
        store.upsert_asset("domain", DOMAIN, source="httpx", confidence=0.9,
                           passivity="active", attrs={"url": LIVE_URL,
                                                       "ips": [IP]})
        store.upsert_asset("ip", IP, source="httpx", confidence=0.9,
                           passivity="active", parent=DOMAIN)
        return {"count": 1, "ok": True, "rc": 0}

    def ipagg(store, **kw):
        assert kw["scope"] == [DOMAIN]
        rows = store.get_assets(kind="domain", match=[DOMAIN])
        assert any((row.get("attrs") or {}).get("url") == LIVE_URL
                   for row in rows), "IP aggregation must follow probe storage"
        calls.append("ipagg")
        return {"candidates": [{"ip": IP, "domains": [DOMAIN]}],
                "count_candidates": 1}

    def ports(store, ips, **kw):
        assert ips == [IP]
        assert kw["top_ports"] == 1000
        calls.append("ports")
        return {"count": 1, "ok": True, "rc": 0}

    def vhost(store, ip, hosts, **kw):
        assert ip == IP and DOMAIN in hosts
        calls.append("vhost")
        return {"hits": 1, "ok": True}

    def crawl(store, urls, **kw):
        assert LIVE_URL in urls
        assert DOMAIN in kw["scope_domains"]
        calls.append("crawl")
        store.upsert_asset("url", JS_URL, source="katana", confidence=0.9,
                           passivity="active", parent=DOMAIN)
        return {"count": 1, "ok": True, "rc": 0}

    def extract(store, crawl_rows, **kw):
        assert crawl_rows == []
        assert JS_URL in kw["urls"], "crawl output must reach extraction"
        assert kw["scope"] == [DOMAIN] and kw["run_id"]
        calls.append("extract")
        store.upsert_endpoint(DOMAIN, "GET", "/api/health", [],
                              source="js-leak")
        return {"count_domains": 0, "count_ips": 0, "fetched": 1,
                "api_paths": ["/api/health"], "api_hosts": 1,
                "outcome": core.OUTCOME_OK}

    def forbidden(*a, **kw):
        raise AssertionError("keyless full workflow attempted a live dispatch")

    adapters = {"t_onepass": onepass, "t_certs": certs, "t_subs": subs,
                "t_dns": dns, "t_httpx": probe, "t_ipagg": ipagg,
                "t_ports": ports, "t_vhost": vhost, "t_crawl": crawl,
                "t_extract": extract}
    output = io.StringIO()
    with contextlib.ExitStack() as stack:
        # API availability is synthetic and the real mapping dispatcher stays
        # live: it must decide to skip, rather than a fake mapping hiding it.
        for name in ("api_key", "api_base"):
            stack.enter_context(mock.patch.object(core, name, return_value=""))
        stack.enter_context(mock.patch.object(core, "engine_has_key",
                                              return_value=False))
        stack.enter_context(mock.patch.object(core, "has_tool", return_value=True))
        stack.enter_context(mock.patch.object(core, "run", forbidden))
        stack.enter_context(mock.patch.object(core, "curl", forbidden))
        paid = stack.enter_context(mock.patch.object(fi.mapdispatch, "ask",
                                                     side_effect=forbidden))
        for name, adapter in adapters.items():
            stack.enter_context(mock.patch.object(fi.tools, name,
                                                  side_effect=adapter))
        with contextlib.redirect_stdout(output):
            rc = fi.cmd_run(args)

    paid.assert_not_called()
    payload = json.loads([line for line in output.getvalue().splitlines()
                          if line.lstrip().startswith("{")][-1])
    assert calls == [stage for stage in FULL_PLAN if stage != "mapping"]
    coverage = payload["coverage"]
    assert coverage["planned_stages"] == FULL_PLAN
    assert [entry["stage"] for entry in payload["stages"]] == FULL_PLAN
    assert coverage["failed_stages"] == []
    assert coverage["not_run_stages"] == []
    assert coverage["unavailable"]["blocking"] is False
    assert set(coverage["unavailable"]["engines_without_key"]) == set(
        ENGINES.split(","))
    mapping = next(entry for entry in payload["stages"]
                   if entry["stage"] == "mapping")
    # The mapping entry exposes its unavailable sources, while _stage's
    # generic summary outcome defaults to OK after entry_fn projection.
    # Coverage and zero dispatch, rather than an assumed raw tool outcome,
    # establish that missing optional keys did not become a stage failure.
    assert mapping["status"] == "succeeded", mapping
    assert mapping["dispatched"] == 0 and not mapping.get("failed"), mapping
    assert "no api key" in mapping.get("unavailable_sources", []), mapping
    assert payload["extract_findings"]["api_paths"] == ["/api/health"]
    assert payload["result"]["status"] == "complete" and rc == 0, payload["result"]
    assert coverage["complete"] is True
    assert coverage["stop_reason"] == "no_new_assets"
