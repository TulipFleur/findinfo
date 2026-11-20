"""Batch B acceptance: resume ownership and the agent wait contract (F05, F13).

Offline: temp home, the local fake pipeline entry, thread barriers for the
interleavings. Nothing here starts a real collector or touches the network.
Pinned:

* every protected state write validates the token INSIDE the state lock: an
  old attempt's heartbeat, stage progress and final verdict are all refused
  once a newer attempt owns the job (F05);
* the first launch carries an attempt/token, so it is fenced too;
* two resumes racing produce ONE effective attempt/worker, and a still-alive
  old worker makes resume report occupancy instead of starting a second one;
* a legacy job without a token is migrated by the CONTROL entry, not by a
  worker silently minting one;
* wait compares the PERSISTED progress cursor: a change between two calls is
  reported on the next `--since <old seq>`, while heartbeats are not progress;
* compact and full wait payloads both carry attempt/terminal/reaped_by_host
  and the gap list (F13).
"""

import json
import threading
import time

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import ROOT, fresh_core


def _cli(home, *argv, timeout=180):
    import os
    import subprocess
    import sys
    env = dict(os.environ, FINDINFO_HOME=home, FINDINFO_TASK="")
    env.pop("FINDINFO_RUN_DIR", None)
    proc = subprocess.run([sys.executable, str(ROOT / "findinfo.py"),
                           "--home", home] + list(argv),
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=timeout,
                          cwd=str(ROOT))
    lines = [l for l in (proc.stdout or "").splitlines()
             if l.strip().startswith("{")]
    return proc.returncode, (json.loads(lines[-1]) if lines else {}), proc


def _run_dir(home, task, rid):
    import os
    return os.path.join(home, "tasks", task, "runs", rid)


# ---------------------------------------------------------------- F05 fencing
def test_old_attempt_cannot_write_progress_heartbeat_or_verdict():
    """Every protected write of a superseded attempt is refused."""
    core = fresh_core()
    from lib import jobs
    rd = core.RUNS_DIR / "20261121-130000-fence-a"
    rd.mkdir(parents=True, exist_ok=True)
    jobs.write_spec(rd, entry="tests.fake_pipeline:run", argv=[],
                    root=str(ROOT), home=str(core.HOME), attempt=1,
                    launch_token="old-token")
    jobs.update_state(rd, state="running", attempt=1, launch_token="old-token",
                      stage="dns", counts={"domain": 1})
    # a resume installs attempt 2
    jobs.update_state(rd, state="queued", attempt=2, launch_token="new-token")
    before = jobs.read_state(rd)
    # the old attempt tries: heartbeat, stage progress, and a final verdict
    assert jobs.fenced_write(rd, "old-token", beat=1) is False
    assert jobs.fenced_write(rd, "old-token", stage="probe", stage_index=3) is False
    assert jobs.fenced_write(rd, "old-token", state="completed", exit_code=0,
                             result={"status": "complete"}) is False
    after = jobs.read_state(rd)
    assert after.get("state") == "queued", after.get("state")
    assert after.get("stage") == before.get("stage")
    assert after.get("launch_token") == "new-token"
    assert (after.get("result") or {}).get("status") != "complete"
    # the new attempt still may write
    assert jobs.fenced_write(rd, "new-token", state="running", stage="dns") is True


def test_empty_token_cannot_bypass_an_existing_fence():
    """A writer with no token is refused once the job carries one."""
    core = fresh_core()
    from lib import jobs
    rd = core.RUNS_DIR / "20261121-130100-fence-b"
    rd.mkdir(parents=True, exist_ok=True)
    jobs.update_state(rd, state="running", launch_token="the-token")
    assert jobs.fenced_write(rd, "", state="completed") is False
    assert jobs.read_state(rd).get("state") == "running"


def test_first_launch_is_fenced_from_the_start():
    """A background launch publishes an attempt token before the worker runs."""
    import tempfile
    home = tempfile.mkdtemp(prefix="fi-b-launch-")
    try:
        rc, payload, proc = _cli(home, "--task", "b1", "run", "--domain",
                                 "mt-a.example.com", "--background",
                                 "--no-onepass", "--no-icp")
        assert rc == 0, proc.stderr[-300:]
        rid = payload["run_id"]
        st = json.loads(open(_run_dir(home, "b1", rid) + "/status.json",
                             encoding="utf-8").read())
        spec = json.loads(open(_run_dir(home, "b1", rid) + "/job.json",
                               encoding="utf-8").read())
        assert st.get("launch_token"), ("the first launch needs a token", st)
        assert st.get("attempt") == 1
        # the worker carries the SAME immutable identity the launcher published
        assert spec.get("launch_token") == st.get("launch_token"), (
            "worker identity must be the launcher's, not re-read later")
        _cli(home, "--task", "b1", "cancel", "--run", rid)
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------- F05 resume
def test_concurrent_resumes_yield_one_effective_attempt():
    """Two resumes race: one attempt bump, one worker, the other reuses."""
    import tempfile
    home = tempfile.mkdtemp(prefix="fi-b-race-")
    try:
        rc, payload, proc = _cli(home, "--task", "b2", "run", "--domain",
                                 "mt-a.example.com", "--background",
                                 "--no-onepass", "--no-icp")
        rid = payload["run_id"]
        _cli(home, "--task", "b2", "cancel", "--run", rid)
        # let the cancelled worker exit before resuming
        deadline = time.time() + 60
        while time.time() < deadline:
            st = json.loads(open(_run_dir(home, "b2", rid) + "/status.json",
                                 encoding="utf-8").read())
            if not st.get("pid") or not _pid_alive(st.get("pid")):
                break
            time.sleep(0.2)
        results: list = []
        lock = threading.Lock()

        def resume():
            r = _cli(home, "--task", "b2", "run", "--resume", rid)
            with lock:
                results.append(r[1])

        threads = [threading.Thread(target=resume) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        attempts = {r.get("attempt") for r in results if r.get("attempt")}
        assert len(attempts) <= 1, ("both resumes bumped separately", results)
        started = [r for r in results if r.get("resumed")]
        assert len(started) == 1, ("exactly one resume may take the job", results)
        spec = json.loads(open(_run_dir(home, "b2", rid) + "/job.json",
                               encoding="utf-8").read())
        assert int(spec.get("attempt") or 1) == 2, spec.get("attempt")
        _cli(home, "--task", "b2", "cancel", "--run", rid)
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def _pid_alive(pid) -> bool:
    from lib import jobs
    return jobs.pid_alive(pid)


def test_resume_reports_occupancy_when_a_worker_is_still_alive():
    """A live old worker means 'occupied', never a second worker."""
    core = fresh_core()
    from lib import jobs
    import findinfo as fi_mod  # noqa: F401  (CLI path is what we exercise)
    rd = core.RUNS_DIR / "20261121-130200-occupied"
    rd.mkdir(parents=True, exist_ok=True)
    jobs.write_spec(rd, entry="tests.fake_pipeline:run",
                    args={"run_dir": str(rd), "stages": 1, "sleep": 30},
                    argv=["run", "--domain", "mt-a.example.com"], attempt=1,
                    launch_token="tok-1", root=str(ROOT), home=str(core.HOME))
    jobs.update_state(rd, state="running", pid=None, attempt=1,
                      launch_token="tok-1")
    # pretend the old worker is alive: a pid that this process can prove live
    import os
    jobs.update_state(rd, pid=os.getpid())
    import argparse
    argv = ["run", "--resume", rd.name]
    import findinfo
    parser = findinfo.build_parser()
    args = parser.parse_args(argv)
    from contextlib import redirect_stdout
    import io
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = findinfo._resume_run(args)
    payload = json.loads([l for l in buf.getvalue().splitlines()
                          if l.startswith("{")][-1])
    assert rc == 0, payload
    assert payload.get("reused") is True and payload.get("resumed") is False
    assert payload.get("occupied_by_pid"), payload
    # no second attempt was written
    spec = jobs.read_spec(rd)
    assert int(spec.get("attempt") or 1) == 1, spec.get("attempt")


def test_legacy_job_is_migrated_by_the_control_entry_only():
    """A tokenless job is readable; resume (control entry) assigns identity."""
    core = fresh_core()
    from lib import jobs
    rd = core.RUNS_DIR / "20261121-130300-legacy"
    rd.mkdir(parents=True, exist_ok=True)
    jobs.write_spec(rd, entry="tests.fake_pipeline:run",
                    args={"run_dir": str(rd), "stages": 1, "sleep": 0.01},
                    argv=["run", "--domain", "mt-a.example.com"], attempt=1,
                    root=str(ROOT), home=str(core.HOME))   # no launch_token
    jobs.update_state(rd, state="failed", exit_code=1)
    # a worker must NOT mint a token for itself: claim_launch returns "" (legacy)
    # and an empty-token write against a tokenless job is still allowed (the
    # migration is the control entry's job, below)
    spec = jobs.read_spec(rd)
    assert not spec.get("launch_token")
    # the control entry migrates on resume
    import findinfo
    args = findinfo.build_parser().parse_args(["run", "--resume", rd.name])
    from contextlib import redirect_stdout
    import io
    with redirect_stdout(io.StringIO()):
        rc = findinfo._resume_run(args)
    assert rc == 0
    spec2 = jobs.read_spec(rd)
    assert spec2.get("launch_token"), "resume must assign identity to a legacy job"
    assert spec2.get("legacy_migrated_at"), spec2
    assert int(spec2.get("attempt") or 1) == 2


# ---------------------------------------------------------------- F13 wait
def test_wait_since_sees_progress_that_happened_between_calls():
    """A change between two waits is reported by the next --since call."""
    core = fresh_core()
    from lib import jobs
    rd = core.RUNS_DIR / "20261121-130400-cursor"
    rd.mkdir(parents=True, exist_ok=True)
    jobs.update_state(rd, state="running", stage="dns", stage_index=1,
                      stage_total=5)
    first = jobs.wait(rd, timeout=5.0)
    assert first.get("timed_out") is True, first
    cursor = first.get("cursor")
    assert cursor is not None
    # progress happens BETWEEN the two calls (no waiter is blocked)
    jobs.update_state(rd, stage="probe", stage_index=2)
    second = jobs.wait(rd, timeout=1.0, since_seq=cursor)
    assert second.get("changed") is True, (
        "progress between calls must be visible to --since", second)
    assert second.get("timed_out") is False, second


def test_heartbeat_only_does_not_count_as_progress():
    """A heartbeat bumps seq but neither the cursor nor `changed`."""
    core = fresh_core()
    from lib import jobs
    rd = core.RUNS_DIR / "20261121-130500-heartbeat"
    rd.mkdir(parents=True, exist_ok=True)
    jobs.update_state(rd, state="running", stage="dns", counts={"domain": 1})
    base = jobs.read_state(rd)
    cursor = base.get("progress_seq")
    jobs.update_state(rd, beat=1)          # heartbeat: no substantive field
    after = jobs.read_state(rd)
    assert after.get("seq") != base.get("seq"), "seq must advance"
    assert after.get("progress_seq") == cursor, (
        "a heartbeat must not move the progress cursor", after)
    res = jobs.wait(rd, timeout=0.5, since_seq=cursor)
    assert res.get("changed") is False and res.get("timed_out") is True, res


def test_wait_payload_carries_recovery_fields_in_both_modes():
    """compact and full both expose attempt/terminal/reaped/host and gaps."""
    core = fresh_core()
    from lib import jobs
    rd = core.RUNS_DIR / "20261121-130600-payload"
    rd.mkdir(parents=True, exist_ok=True)
    jobs.update_state(rd, state="completed", attempt=3, exit_code=0,
                      result={"status": "partial", "reason": "stage_failed"},
                      coverage={"complete": False,
                                "not_run_stages": ["icp", "vhost"]},
                      reaped_by_host=False)
    full = jobs.wait(rd, timeout=1.0)
    for key in ("attempt", "terminal", "reaped_by_host", "gap_count", "gaps",
                "result", "coverage"):
        assert key in full, ("missing in full payload", key)
    assert full["attempt"] == 3
    assert full["terminal"] is True
    assert full["reaped_by_host"] is False      # false is preserved, not dropped
    assert full["gaps"] == ["icp", "vhost"], full["gaps"]
    # the CLI compact projection keeps the same decision fields
    import findinfo
    import argparse
    args = argparse.Namespace(run=rd.name, timeout=1.0, since=None, full=False)
    from contextlib import redirect_stdout
    import io
    buf = io.StringIO()
    with redirect_stdout(buf):
        findinfo.cmd_wait(args)
    compact = json.loads([l for l in buf.getvalue().splitlines()
                          if l.startswith("{")][-1])
    for key in ("attempt", "terminal", "reaped_by_host", "gap_count", "gaps"):
        assert key in compact, ("compact dropped a decision field", key, compact)
    assert compact["attempt"] == 3 and compact["terminal"] is True
    assert compact["reaped_by_host"] is False
    assert compact["gaps"] == ["icp", "vhost"]
