"""Host-reaping detection: a worker killed before running any Python.

A consumer-grade agent host may reap detached child processes seconds after
the launching call returns. The observable signature is exact: state stuck in
queued/running, pid dead, and stderr.log EMPTY (the worker's first action is
to write its '[worker] entered' breadcrumb). This suite pins the detection
and the divergent guidance: a reaped worker must NOT be told to retry
--background, because the retry dies the same way.
"""
import json

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core


def _fake_state(jobs, rd, **kw):
    """A raw status.json snapshot with caller-chosen fields."""
    st = {"run_id": rd.name, "run_dir": str(rd), "state": "running",
          "pid": 999999999, "updated_ts": jobs.now_ts() - 120, "seq": 3}
    st.update(kw)
    return st


def test_reaped_worker_is_flagged_and_guided_away_from_background():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("reap")
    (rd / "stderr.log").write_text("", encoding="utf-8")     # empty: never ran
    st = jobs.derive(_fake_state(jobs, rd))
    assert st["interrupted"] is True
    assert st["reaped_by_host"] is True, st
    assert "Do NOT retry --background" in st["hint"], st["hint"]


def test_crashed_worker_after_breadcrumb_is_not_reaped():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("crash")
    (rd / "stderr.log").write_text("[worker] entered pid=123\nTraceback...\n",
                                   encoding="utf-8")
    st = jobs.derive(_fake_state(jobs, rd))
    assert st["interrupted"] is True
    assert st["reaped_by_host"] is False, "a worker that wrote its breadcrumb ran Python"
    assert "run --resume" in st["hint"], "an ordinary crash is resumable"


def test_running_alive_job_is_never_reaped():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("live")
    (rd / "stderr.log").write_text("", encoding="utf-8")
    st = jobs.derive(_fake_state(jobs, rd, pid=jobs.os.getpid(),
                                 state="running"))
    assert st["alive"] is True and st["interrupted"] is False
    assert st["reaped_by_host"] is False


def test_terminal_states_do_not_read_logs():
    """completed/failed/cancelled rows must not grow a reaped flag."""
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("done")
    st = jobs.derive(_fake_state(jobs, rd, state="completed"))
    assert st["terminal"] is True
    assert st["reaped_by_host"] is False


def test_missing_stderr_file_is_not_reaped():
    """No stderr.log at all (older layout / manual dir) must not crash derive
    nor claim host reaping: absent evidence is not evidence of reaping.
    (spawn() opens the log before starting the child, so real backgrounded
    runs always have the file -- this state is hand-built or legacy.)"""
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("nolog")
    st = jobs.derive(_fake_state(jobs, rd))
    assert st["interrupted"] is True
    assert st["reaped_by_host"] is False


def test_wait_payload_carries_reaped_flag():
    """The wait() output an agent polls must expose reaped_by_host directly,
    so the fallback decision needs one field check, not log forensics."""
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("reapwait")
    (rd / "status.json").write_text(
        json.dumps({"run_id": rd.name, "state": "queued",
                    "pid": 999999999, "updated_ts": jobs.now_ts() - 60}),
        encoding="utf-8")
    (rd / "stderr.log").write_text("", encoding="utf-8")
    res = jobs.wait(rd, timeout=0.2, since_seq=0)
    assert res["interrupted"] is True
    assert res.get("reaped_by_host") is True, res
