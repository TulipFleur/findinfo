"""findinfo.py is the CLI; the run pipeline lives in lib/pipeline.py.

The CLI re-exports the pipeline's names so `findinfo.<name>` keeps meaning the
SAME object the run executes: a second copy left in findinfo.py would let a
caller (or a test patch) talk to code the run never calls.
"""
import re
from types import SimpleNamespace
from unittest import mock

import tests.util as util
from tests.util import fresh_core, fresh_tools, import_findinfo

REEXPORTED = ("ENGAGEMENT", "_run_pipeline", "_stage", "_write_status",
              "_plan_stages", "_round_plan", "_active_enabled", "_attach",
              "_adopt_membership", "_not_run_stages", "_coverage_unavailable",
              "_fold_runtime_unavailable", "_subs_stage_inputs", "_input_hash")


def test_cli_reexports_the_pipeline_objects_themselves():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    from lib import pipeline
    assert fi.pipeline is pipeline
    for name in REEXPORTED:
        assert getattr(fi, name) is getattr(pipeline, name), name


def test_pipeline_reaches_core_through_the_module_only():
    """lib.core resolves HOME/DB at import time and the tests reload it in
    place: a value bound out of core when the pipeline is imported would keep
    pointing at the previous home."""
    src = (util.ROOT / "lib" / "pipeline.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*from\s+(\.|lib\.)core\s+import", src, re.M)


def test_a_stage_runs_on_its_own_from_a_run_context():
    """Each stage is a function of the run's context: certs runs with no other
    stage around it. This is the seam the StageRegistry runners plug into."""
    core = fresh_core("stage-unit")
    tools = fresh_tools(core)
    from lib import pipeline
    store = core.Store()
    try:
        rd = core.new_run_dir("stage-unit")
        summary = {"stages": [], "_run_public_id": rd.name, "attempt": 1}
        ctx = pipeline.RunContext(
            args=SimpleNamespace(), store=store, run_id=None, run_dir=rd,
            summary=summary, active=False, attempt=1, target_label="stage-unit",
            planned=["certs"], ledger=None, rounds=1, time_budget=0.0,
            tool_timeout=0, max_seed=0, t_start=0.0, seeds=["example.com"])
        asked = []

        def certs(store_, domain, timeout=0):
            asked.append(domain)
            return {"count": 2, "ok": True}

        with mock.patch.object(tools, "t_certs", certs):
            pipeline._stage_certs(ctx)
        assert asked == ["example.com"]
        entry = summary["stages"][-1]
        assert entry["stage"] == "certs" and entry["found"] == 2, entry
    finally:
        store.close()


def test_planned_stages_run_through_their_registered_runners_in_order():
    """StageRegistry is the scheduler: the plan decides WHICH stages take part,
    the registry decides the order and what runs for each."""
    from lib import pipeline
    calls = []
    reg = pipeline.StageRegistry()
    for name, phase in (("b", "round"), ("s", "seed"), ("a", "round"), ("c", "round")):
        reg.register(name, runner=lambda ctx, n=name: calls.append(n), phase=phase)
    ctx = SimpleNamespace(planned=["a", "s", "b"])
    with mock.patch.object(pipeline, "STAGE_REGISTRY", reg.validate()):
        pipeline._run_planned(ctx, "round")
    assert calls == ["b", "a"], calls


def test_the_shipped_registry_holds_the_real_stage_functions():
    from lib import pipeline
    reg = pipeline.STAGE_REGISTRY
    assert reg.order("seed") == ["entity", "onepass", "certs", "subs", "brute",
                                 "mapping", "icp"]
    assert reg.order("round") == ["dns", "probe", "ipagg", "ports", "vhost",
                                  "crawl", "extract"]
    assert reg.runner("certs") is pipeline._stage_certs
    assert reg.runner("dns") is pipeline._stage_dns
