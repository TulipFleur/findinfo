"""Acceptance: background job lifecycle with a simulated collector.

Covers: launch returns a run id at once, status by run id, repeated waits that
return running (timeout is not failure), completion, interrupt detection,
injected failure, resume, de-duplication of an in-flight job, cancellation and
isolation between concurrent runs.

Event-driven, not sleep-driven: waiting is done with jobs.wait_status(...)
which returns as soon as the target state appears, so the suite does not pay
fixed delays and stays stable on a loaded machine.
"""
import json
import time

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core


def _make_job(core, *, sleep=0.0, stages=1, fail_at=0, result_status="complete",
              first_delay=0.0, key="k1", spec_extra=None):
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("sim")
    spec = {"entry": "tests.fake_pipeline:run",
            "args": {"run_dir": str(rd), "stages": stages, "sleep": sleep,
                     "fail_at": fail_at, "result_status": result_status,
                     "first_delay": first_delay},
            "target": "example.com", "scope": ["example.com"],
            "dedupe_key": key, "home": str(core.HOME), "root": str(core.ROOT),
            "env": {"FINDINFO_HOME": str(core.HOME)}}
    spec.update(spec_extra or {})
    jobs.write_spec(rd, **spec)
    jobs.update_state(rd, state="queued", stage="queued", stage_state="queued",
                      planned_stages=["stage-1", "stage-2", "stage-3"],
                      stage_index=0, stage_total=3, dedupe_key=key)
    pid = jobs.spawn(rd)                 # publish_state(pid) happens inside
    assert jobs.read_state(rd).get("pid") == pid, "spawn must publish its pid at once"
    return jobs, rd


def _wait_terminal(jobs, rd, timeout=60.0):
    """Return the terminal state, without fixed sleeps."""
    res = jobs.wait_status(rd, ["terminal"], timeout=timeout)
    assert res["matched"], "job did not finish: " + json.dumps(
        jobs.read_state(rd), ensure_ascii=False)[:300]
    return jobs.derive(jobs.read_state(rd))


def test_launch_returns_run_id_and_paths_immediately():
    core = fresh_core()
    jobs, rd = _make_job(core)
    st = jobs.read_state(rd)
    assert st["run_id"] == rd.name
    assert st.get("pid"), "pid is published synchronously by spawn()"
    for name in ("job.json", "status.json", "stdout.log", "stderr.log"):
        assert (rd / name).exists(), name
    spec = jobs.read_spec(rd)
    assert spec["target"] == "example.com" and spec["scope"] == ["example.com"]
    _wait_terminal(jobs, rd)


def test_wait_returns_running_on_timeout_then_completes():
    core = fresh_core()
    # a slow stage: the job is guaranteed to still be running right after launch.
    # Wait for the worker to settle into its idle first_delay first, so the next
    # wait really observes an idle window (no fixed sleep, no racing the startup
    # sequence: queued -> running -> first heartbeat).
    jobs, rd = _make_job(core, sleep=0.25, stages=2, first_delay=0.5)
    jobs.wait_status(rd, ["running"], timeout=10)
    first = jobs.wait(rd, timeout=0.05, since_seq=jobs.read_state(rd).get("seq"))
    assert first["timed_out"] is True, "an idle window must report a timeout"
    assert first["state"] in ("queued", "running")
    assert first["progress"]["percent"] is not None      # stage budget is known
    assert first["run_id"] == rd.name
    st = _wait_terminal(jobs, rd)
    assert st["state"] == "completed"
    assert st["result"]["status"] == "complete"
    # a terminal job answers immediately, without waiting
    t0 = time.time()
    done = jobs.wait(rd, timeout=5)
    assert done["timed_out"] is False and done["state"] == "completed"
    assert time.time() - t0 < 1.0


def test_progress_change_returns_early():
    core = fresh_core()
    jobs, rd = _make_job(core, sleep=0.02)
    seq = jobs.read_state(rd).get("seq")
    res = jobs.wait(rd, timeout=30, since_seq=seq)
    assert res["timed_out"] is False, "any progress must return early"
    assert res.get("seq") != seq
    _wait_terminal(jobs, rd)


def test_interrupted_detection_and_resume():
    core = fresh_core()
    jobs, rd = _make_job(core, sleep=0.5)
    pid = jobs.read_state(rd).get("pid")
    assert pid
    jobs.kill_tree(pid)                     # simulate a crash / power loss
    assert not jobs.pid_alive(pid), "killed worker must not look alive (zombie trap)"
    # a dead pid is conclusive once the worker has published a heartbeat, so no
    # sleeping and no clock manipulation is needed here
    st = jobs.derive(jobs.read_state(rd))
    assert st["interrupted"] is True, st
    assert str(rd.name) in (st.get("hint") or "")
    spec = jobs.read_spec(rd)
    spec["args"]["sleep"] = 0.0            # finish fast on resume
    spec["attempt"] = int(spec.get("attempt") or 1) + 1
    jobs.write_spec(rd, **spec)
    jobs.update_state(rd, state="queued", pid=None, last_error=None)
    jobs.update_state(rd, pid=jobs.spawn(rd))
    st2 = _wait_terminal(jobs, rd)
    assert st2["state"] == "completed"
    assert int(st2.get("attempt") or 1) >= 2


def test_injected_failure_records_error():
    core = fresh_core()
    jobs, rd = _make_job(core, stages=1, fail_at=1)
    st = _wait_terminal(jobs, rd)
    assert st["state"] == "failed"
    err = st.get("last_error") or {}
    assert err.get("message") or err.get("traceback_tail")
    assert st["exit_code"] not in (0, None)


def test_cancel_marks_cancelled():
    core = fresh_core()
    jobs, rd = _make_job(core, sleep=1.0)
    res = jobs.cancel(rd, reason="test")
    assert res["state"] == "cancelled"
    assert (rd / "cancel").exists()
    assert jobs.wait(rd, timeout=2)["state"] == "cancelled"


def test_dedupe_reuses_inflight_job():
    core = fresh_core()
    jobs, rd = _make_job(core, sleep=1.0, key="same-target")
    found = jobs.find_inflight("same-target")
    assert found is not None and found.name == rd.name
    jobs.cancel(rd)
    assert jobs.find_inflight("same-target") is None, "a finished job is not reused"


def test_concurrent_runs_do_not_share_state():
    core = fresh_core()
    # two jobs launched back to back, deliberately different shapes
    jobs1, rd1 = _make_job(core, stages=2, sleep=0.05, key="a")
    jobs2, rd2 = _make_job(core, stages=1, key="b")
    assert rd1 != rd2
    s1 = _wait_terminal(jobs1, rd1)
    s2 = _wait_terminal(jobs2, rd2)
    assert s1["result"]["counts"]["domain"] == 20      # 2 stages x 10
    assert s2["result"]["counts"]["domain"] == 10      # 1 stage x 10
    assert (rd1 / "stage2.done").exists() and not (rd1 / "stage3.done").exists()
    assert (rd2 / "stage1.done").exists() and not (rd2 / "stage2.done").exists()
    assert (rd1 / "stdout.log").exists() and (rd2 / "stdout.log").exists()
    # each run's state file only ever described its own job
    st1 = jobs1.read_state(rd1)
    st2 = jobs2.read_state(rd2)
    assert st1["run_id"] == rd1.name and st2["run_id"] == rd2.name


def test_recovery_by_run_id_only():
    """A fresh process (no memory of the launch) can still query the run."""
    core = fresh_core()
    jobs, rd = _make_job(core, key="recover")
    _wait_terminal(jobs, rd)
    rid = rd.name
    jobs2 = __import__("lib.jobs", fromlist=["jobs"])
    assert jobs2.resolve(rid).name == rid
    st = jobs2.derive(jobs2.read_state(rid))
    assert st["state"] == "completed"
    assert jobs2.read_spec(rid)["target"] == "example.com"
