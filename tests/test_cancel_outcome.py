"""Regression: F 四态表达 — cancelled must be visible and truthful.

The requirement lists four outcomes: complete / partial / failed / cancelled.
Cancellation already flips the job state; these tests pin that the CLI-facing
view says so too, and that a cancelled run never claims coverage.
"""
import argparse
import io
import json
import time
from contextlib import redirect_stdout

import tests.util  # noqa: F401
from tests.util import fresh_core, import_findinfo


def _make_job(core, jobs, **kw):
    rd = core.new_run_dir(kw.get("tag", "cancel-demo"))
    jobs.write_spec(rd, entry="tests.fake_pipeline:run",
                    args={"run_dir": str(rd), "stages": 3, "sleep": 0.3},
                    target="example.com", scope=["example.com"], dedupe_key="c",
                    root=str(core.ROOT), home=str(core.HOME),
                    env={"FINDINFO_HOME": str(core.HOME)})
    jobs.update_state(rd, state="queued", stage_total=3, stage_index=0)
    jobs.update_state(rd, pid=jobs.spawn(rd))
    jobs.wait_status(rd, ["running"], timeout=30)
    return rd


def test_cancel_marker_sets_state_and_exit_code():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = _make_job(core, jobs)
    jobs.cancel(rd, reason="user")
    res = jobs.wait_status(rd, ["terminal"], timeout=30)
    st = res["state_doc"]
    assert st["state"] == "cancelled", st.get("state")
    assert st.get("exit_code") == 130, st.get("exit_code")


def test_status_reports_cancelled_and_never_claims_coverage():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    fi = import_findinfo()
    rd = _make_job(core, jobs, tag="cancel-status")
    jobs.cancel(rd, reason="user")
    jobs.wait_status(rd, ["terminal"], timeout=30)

    args = argparse.Namespace(run=rd.name, task="", full=False)
    buf = io.StringIO()
    with redirect_stdout(buf):
        fi.cmd_status(args)
    payload = json.loads(buf.getvalue().strip().splitlines()[-1])
    assert payload["state"] == "cancelled", payload.get("state")
    cov = payload.get("coverage") or {}
    assert cov.get("complete") is not True, "a cancelled run must not look complete"


def test_cancelled_is_terminal_for_wait():
    """wait must return immediately once cancelled: no further polling."""
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = _make_job(core, jobs, tag="cancel-wait")
    jobs.cancel(rd, reason="user")
    jobs.wait_status(rd, ["terminal"], timeout=30)
    t0 = time.time()
    res = jobs.wait(rd, timeout=10)
    elapsed = time.time() - t0
    assert res["state"] == "cancelled"
    assert res.get("terminal") is True
    assert elapsed < 5, "wait blocked %.1fs on an already-cancelled run" % elapsed
