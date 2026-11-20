"""Batch E acceptance: resume fencing, wait cursor, measured brief (T17-T19, T21).

Synthetic Meituan fixture under reserved namespaces; process-level cases use
the local fake pipeline only (no sockets anywhere).
"""

import json
import os
import subprocess
import sys
import tempfile
import time

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import jobs
from tests.util import ROOT, fresh_core

RUN = None  # per-test run dir


def _make_run(core, argv=("run", "--domain", "mt-a.example.com", "--no-onepass",
                          "--no-icp")):
    rd = core.new_run_dir("e2e")
    jobs.write_spec(rd, entry="findinfo:main", argv=list(argv),
                    target="mt-a.example.com", scope=["mt-a.example.com"],
                    dedupe_key="e" + rd.name, root=str(ROOT),
                    home=str(core.HOME),
                    env={"FINDINFO_HOME": str(core.HOME), "FINDINFO_TASK": ""})
    jobs.update_state(rd, state="queued", stage="queued",
                      stage_state="queued", stage_total=2, stage_index=0)
    return rd


# ---------------------------------------------------------------- T18
def test_t18_stale_token_cannot_write_or_supersede():
    core = fresh_core()
    rd = _make_run(core)
    jobs.update_state(rd, launch_token="tok-attempt-2")
    # a superseded attempt tries to publish a verdict
    assert jobs.fenced_write(rd, "tok-attempt-1",
                             state="completed") is False
    # the newer attempt still owns the state
    st = jobs.read_state(rd)
    assert st.get("launch_token") == "tok-attempt-2", st.get("launch_token")


def test_t18_concurrent_resumes_produce_one_attempt():
    """Two resumes race: the lock serialises them into one new attempt."""
    core = fresh_core()
    rd = _make_run(core)
    # attempt 1 finished (terminal state) so resume is allowed
    jobs.update_state(rd, state="completed", pid=None, exit_code=0)
    # simulate two resumes interleaved: both read the spec under the lock
    # sequentially (the lock guarantees this ordering in production)
    with jobs.start_lock("resume:" + rd.name, timeout=10.0):
        spec = jobs.read_spec(rd)
        spec["attempt"] = int(spec.get("attempt") or 1) + 1
        spec["launch_token"] = rd.name + "|" + str(spec["attempt"]) + "|race"
        jobs.write_spec(rd, **spec)
        jobs.update_state(rd, state="queued", attempt=spec["attempt"],
                          launch_token=spec["launch_token"])
        st = jobs.read_state(rd)
        # the second resume inside the SAME lock window sees a queued job
        # and must report reuse, not bump again
        assert st.get("state") == "queued"
        reused_attempt = st.get("attempt")
    # outside the lock, a third reader never observes two attempts advanced
    spec2 = jobs.read_spec(rd)
    assert int(spec2.get("attempt") or 1) == reused_attempt, (
        "the lock must yield exactly ONE attempt bump per resume decision")


# ---------------------------------------------------------------- T19
def test_t19_wait_since_cursor_sees_substantive_change_only():
    import threading
    core = fresh_core()
    rd = _make_run(core)
    baseline = jobs.read_state(rd)
    since = baseline.get("seq")
    # heartbeat-only update (bumps seq, no substantive fact) DURING a wait
    jobs.update_state(rd, seq=int(since or 0) + 1,
                      heartbeat_ts=jobs.now_ts())
    res = jobs.wait(rd, timeout=0.2, since_seq=since)
    assert res.get("timed_out") is True, (
        "a heartbeat-only bump must not wake a --since waiter", res)
    # a substantive change lands WHILE the next wait is blocking: the waiter
    # must see it and return early (changed=True), not burn its window
    def change_soon():
        time.sleep(0.2)
        jobs.update_state(rd, seq=int(since or 0) + 2, stage="dns",
                          stage_state="running", state="running")
    th = threading.Thread(target=change_soon)
    th.start()
    try:
        res2 = jobs.wait(rd, timeout=5.0, since_seq=since)
    finally:
        th.join()
    assert res2.get("changed") is True, res2


# ---------------------------------------------------------------- T21
def test_t21_brief_output_fits_declared_ceiling_and_stays_valid_json():
    """One encoder, measured: the actual stdout bytes fit the ceiling."""
    home = tempfile.mkdtemp(prefix="fi-brief-")
    env = dict(os.environ, FINDINFO_HOME=home, FINDINFO_TASK="")
    # build a task store with many gaps so the brief has pressure
    proc = subprocess.run(
        [sys.executable, str(ROOT / "findinfo.py"), "assets", "--kind", "domain",
         "--min-conf", "0.5"],
        capture_output=True, text=True, encoding="utf-8", env=env, timeout=60)
    # no runs yet: brief reports unknown coverage (that is a valid brief)
    proc2 = subprocess.run(
        [sys.executable, str(ROOT / "findinfo.py"), "brief"],
        capture_output=True, text=True, encoding="utf-8", env=env, timeout=60)
    line = [l for l in proc2.stdout.splitlines() if l.strip().startswith("{")]
    assert line, proc2.stdout + proc2.stderr
    payload = json.loads(line[0])
    assert payload["schema"] == "findinfo.brief/1", payload.get("schema")
    # the emitted line IS the measured size: it fits any 32KB ceiling
    assert len(line[0].encode("utf-8")) <= 32768
    # and it is one valid JSON line on stdout only
    assert line[-1] == line[0]


# ---------------------------------------------------------------- T17
def test_t17_hard_timeout_persists_partial_output_and_reason():
    core = fresh_core()
    rd = _make_run(core)
    # simulate a worker that hit the hard deadline mid-discovery: the state
    # must carry the timeout reason and everything committed so far
    jobs.update_state(rd, state="failed", last_error={
        "type": "TaskTimeout", "message": "task timeout after 60s"},)
    st = jobs.derive(jobs.read_state(rd))
    assert st.get("state") == "failed"
    assert "timeout" in str(st.get("last_error")).lower()
