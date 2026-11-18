"""Coverage truthfulness: a checkpoint hit is not a gap; disabled is not missing.

The bug this pins: only stages that passed a `resume` callback counted as
"covered", so every second run reported entity/onepass/certs/subs/brute/icp/
ports/vhost/crawl/extract as not_run -- gaps the agent was told to fill even
though the work was already done. That produces an agent that re-runs forever.
"""
import argparse

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import import_findinfo


def _fi():
    return import_findinfo()


def _args(**over):
    base = dict(name="", domain=["example.com"], active=False, ports=False,
                vhost=False, crawl=False, brute=False, no_icp=False,
                no_onepass=False, engines="fofa", max_seed=5, top_ports=1000,
                depth=3, invest=51, deep=2, max_vhost_ips=10,
                brute_wordlist="", brute_bandwidth="3m")
    base.update(over)
    return argparse.Namespace(**base)


def test_checkpoint_hit_is_not_a_gap():
    fi = _fi()
    planned = ["certs", "subs", "dns"]
    # every stage skipped by checkpoint with NO resume callback (the old shape)
    stages = [{"stage": "certs", "skipped": True, "resumed": False},
              {"stage": "subs", "skipped": True, "resumed": False},
              {"stage": "dns", "skipped": True, "resumed": True}]
    assert fi._not_run_stages(planned, stages) == [], \
        "a completed checkpoint must never be reported as not run"


def test_stage_absent_from_the_run_is_a_gap():
    fi = _fi()
    assert fi._not_run_stages(["certs", "subs"], [{"stage": "certs", "elapsed": 1.0}]) == ["subs"]


def test_no_input_is_reported_separately_not_as_a_gap():
    fi = _fi()
    stages = [{"stage": "dns", "elapsed": 1.0},
              {"stage": "probe", "skipped": True, "reason": "no_hosts"}]
    assert fi._not_run_stages(["dns", "probe"], stages) == [], \
        "probe with nothing to probe is no_input, not a missing stage"


def test_failed_stage_still_counts_as_a_gap():
    fi = _fi()
    stages = [{"stage": "dns", "failed": True, "elapsed": 1.0}]
    assert fi._not_run_stages(["dns"], stages) == ["dns"]


def test_no_icp_removes_the_stage_from_the_plan():
    """A disabled stage must not be planned, so it cannot become a fake gap."""
    fi = _fi()
    with_icp = fi._plan_stages(_args(no_icp=False), active=False)
    without = fi._plan_stages(_args(no_icp=True), active=False)
    assert "icp" in with_icp, with_icp
    assert "icp" not in without, "an explicitly disabled stage must not be planned"


def test_no_onepass_removes_the_stage_from_the_plan():
    fi = _fi()
    assert "onepass" not in fi._plan_stages(_args(no_onepass=True), active=False)


def test_active_stages_only_planned_when_active():
    fi = _fi()
    passive = fi._plan_stages(_args(), active=False)
    active = fi._plan_stages(_args(vhost=True), active=True)
    assert "probe" not in passive and "vhost" not in passive, passive
    assert "probe" in active and "vhost" in active, active
