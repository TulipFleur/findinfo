"""Wiring W6 acceptance: every worker state write passes the launch fence.

worker_main claims its launch token once at entry (claim_launch); after
that, its running write, its hard-timeout verdict and its terminal
publish all go through fenced_write (docs par.11, T17/T18): a superseded
attempt cannot overwrite a newer attempt's progress or verdict, and the
timeout path is fenced like every other write. These tests drive
worker_main in-process with the fake pipeline entry (no sockets, no
real tools); the batch E table-level contracts stay in
tests/test_batch_e_jobs.py.
"""

import json
import os
import tempfile
from pathlib import Path

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)
from tests.util import ROOT, fresh_core


def _make_run(core, rd_name, *, attempt=2, spec_token=None,
              state_token=None, task_timeout=0.0, cancel=False, argv=None,
              sleep=0.01):
    """spec_token: what THIS worker's job.json carries; state_token: what
    status.json holds. Equal -> the worker owns the launch; the spec token
    older than the state token -> superseded (a newer attempt took over)."""
    rd = core.RUNS_DIR / rd_name
    rd.mkdir(parents=True, exist_ok=True)
    from lib import jobs
    jobs.write_spec(rd, entry="tests.fake_pipeline:run",
                    args={"run_dir": str(rd), "stages": 1, "sleep": sleep},
                    argv=argv or [], root=str(ROOT), home=str(core.HOME),
                    attempt=attempt, task_timeout=task_timeout,
                    launch_token=spec_token,
                    env={"FINDINFO_HOME": str(core.HOME)})
    st = {"state": "queued", "attempt": attempt,
          "launch_token": state_token, "pid": None, "seq": 1}
    (rd / "status.json").write_text(json.dumps(st), encoding="utf-8")
    if cancel:
        (rd / "cancel").write_text("", encoding="utf-8")
    return rd


def test_superseded_attempt_writes_nothing_and_returns_4():
    core = fresh_core()
    from lib import jobs
    rd = _make_run(core, "20261121-120000-fenced-a", attempt=2,
                   spec_token="old-attempt-token",
                   state_token="newer-attempt-token")
    rc = jobs.worker_main(rd)
    assert rc == 4, "a superseded attempt must exit fenced, not publish"
    st = jobs.read_state(rd)
    # nothing the worker would have written is there: no pid, no running
    assert st.get("state") == "queued", st
    assert st.get("pid") is None, st


def test_owning_attempt_publishes_through_the_fence():
    core = fresh_core()
    from lib import jobs
    token = "20261121-120100-fenced-b|2|owner"
    rd = _make_run(core, "20261121-120100-fenced-b", attempt=2,
                   spec_token=token, state_token=token)
    rc = jobs.worker_main(rd)
    assert rc == 0, rc
    st = jobs.read_state(rd)
    # the write went THROUGH the fence: state published, token still ours
    assert st.get("state") == "completed", st
    assert st.get("launch_token") == token, st.get("launch_token")
    assert st.get("pid"), st


def test_timeout_verdict_is_fenced_not_blind():
    """The hard-deadline write respects a fence flip mid-flight.

    Runs in a SUBPROCESS: the deadline handler terminates the worker with
    os._exit(124), which would take the test process down with it.
    """
    import subprocess
    import sys
    core = fresh_core()
    from lib import jobs
    token = "20261121-120200-fenced-c|2|owner"
    rd = _make_run(core, "20261121-120200-fenced-c", attempt=2,
                   spec_token=token, state_token=token, task_timeout=1.0,
                   sleep=30.0)
    # a newer attempt takes the job while this worker is still running:
    # the deadline that fires afterwards must NOT overwrite the newer token
    import threading
    def flip():
        jobs.update_state(rd, launch_token="newer-token-2",
                          state="queued", result=None, coverage=None)
    t = threading.Timer(0.3, flip)
    t.start()
    try:
        code = ("import sys; sys.path.insert(0, %r); from lib import jobs; "
                "raise SystemExit(jobs.worker_main(sys.argv[1]))" % str(ROOT))
        proc = subprocess.run([sys.executable, "-c", code, str(rd)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60)
        rc = proc.returncode
    finally:
        t.cancel()
    assert rc == 124, rc                      # the deadline fired as designed
    st = jobs.read_state(rd)
    assert st.get("launch_token") == "newer-token-2", st.get("launch_token")
    # the fenced timeout verdict did NOT land: no task_timeout reason under
    # the newer attempt's token
    assert (st.get("coverage") or {}).get("reason") != "task_timeout", st


def test_terminal_write_of_a_stale_attempt_is_dropped():
    """A worker finishing after being superseded cannot publish its result."""
    core = fresh_core()
    from lib import jobs
    token = "20261121-120300-fenced-d|2|owner"
    rd = _make_run(core, "20261121-120300-fenced-d", attempt=2,
                   spec_token=token, state_token=token, sleep=5.0)
    # supersede DURING the run: a newer attempt bumped the token
    import threading
    def flip():
        jobs.update_state(rd, launch_token="newer-token-3",
                          state="queued", result=None, coverage=None)
    t = threading.Timer(0.05, flip)
    t.start()
    try:
        jobs.worker_main(rd)
    finally:
        t.cancel()
    st = jobs.read_state(rd)
    assert st.get("launch_token") == "newer-token-3", st
    # the stale worker's TERMINAL publish was dropped wholesale: no exit
    # code, no finished stamp from it (whatever the entry itself wrote
    # mid-run is that entry's own bookkeeping, not the worker's verdict)
    assert st.get("exit_code") is None, st
    assert st.get("state") != "failed", st
