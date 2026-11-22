"""All approved seeds are expanded by default; positive budgets remain explicit.

Collectors are replaced throughout: these tests never contact a real target.
"""
import io
import json
from contextlib import ExitStack, redirect_stdout
from unittest import mock

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools, import_findinfo
from lib import spec


def test_default_seed_limit_agrees_across_parser_spec_and_offline_plan():
    fresh_tools(fresh_core())
    fi = import_findinfo()
    args = fi.build_parser().parse_args(["run", "--domain", "example.com"])
    assert args.max_seed == spec.from_cli(args).max_seed == spec.RunSpec().max_seed == 0
    offline = fi._parse_offline_args(["run", "--domain", "example.com"])
    assert spec.from_cli(offline).max_seed == 0
    replay = fi.build_parser().parse_args(spec.RunSpec(domain=("example.com",)).to_worker_argv())
    assert replay.max_seed == 0


def _run_entity_seed_collection(cap=None):
    core = fresh_core()
    tools = fresh_tools(core)
    fi = import_findinfo()
    name = "合成采集测试有限公司"
    roots = ["collection-root-%d.com" % i for i in range(8)]
    called = {"onepass": [], "certs": [], "subs": [], "dns": []}

    def entity(store, query, **kw):
        assert query == name
        store.upsert_asset("company", name, source="enscan", confidence=0.9)
        for root in roots:
            store.upsert_asset("domain", root, source="enscan", confidence=0.9,
                               parent="subject:synthetic")
        return {"rc": 0, "json_files": 1, "companies": [name], "domains": roots,
                "icp": [], "subjects": [{"ref": "subject:synthetic",
                                           "legal_name": name, "approved": True}]}

    def collector(stage):
        def collect(store, domain, **kw):
            called[stage].append(domain)
            return {"count": 0, "ok": True, "rc": 0, "outcome": "empty"}
        return collect

    def dns(store, domains, **kw):
        called["dns"].extend(domains)
        return {"count": 0, "ok": True, "rc": 0, "domains": [], "wildcard": []}

    argv = ["run", "--name", name, "--no-mapping"]
    if cap is not None:
        argv += ["--max-seed", str(cap)]
    args = fi.build_parser().parse_args(argv)
    output = io.StringIO()
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(core, "run", side_effect=AssertionError(
            "external execution is forbidden in seed-expansion tests")))
        stack.enter_context(mock.patch.object(tools, "t_enscan", side_effect=entity))
        for stage, method in (("onepass", "t_onepass"), ("certs", "t_certs"),
                              ("subs", "t_subs")):
            stack.enter_context(mock.patch.object(tools, method,
                                                  side_effect=collector(stage)))
        stack.enter_context(mock.patch.object(tools, "t_dns", side_effect=dns))
        stack.enter_context(redirect_stdout(output))
        rc = fi.cmd_run(args)
    assert rc in (0, 5)
    payload = json.loads(output.getvalue().strip().splitlines()[-1])
    return roots, called, payload


def test_entity_with_more_than_five_roots_expands_every_root_by_default():
    roots, called, payload = _run_entity_seed_collection()
    for stage in ("onepass", "certs", "subs"):
        assert called[stage] == roots, (stage, called)
    assert set(called["dns"]) == set(roots)
    assert payload["seed_domains"] == roots
    assert "coverage_limits" not in payload


def test_positive_seed_cap_still_limits_expansion_but_not_dns_scope():
    roots, called, payload = _run_entity_seed_collection(cap=2)
    for stage in ("onepass", "certs", "subs"):
        assert called[stage] == roots[:2], (stage, called)
    assert set(called["dns"]) == set(roots)
    assert payload["coverage_limits"]["seeds_total"] == 8
    assert payload["coverage_limits"]["seeds_scanned"] == 2


def test_stored_explicit_cap_is_preserved_and_negative_cap_rejected():
    stored = spec.RunSpec.from_json(spec.RunSpec(max_seed=5).to_json())
    assert stored.max_seed == 5
    assert stored.resume_patch(spec.RunSpec()).max_seed == 5
    try:
        spec.RunSpec(max_seed=-1)
    except ValueError as exc:
        assert "max_seed" in str(exc)
    else:
        raise AssertionError("negative seed budgets must not mean a negative slice")
