"""Job lifecycle reliability: context, spawn failure, attempt ownership, budgets.

Each test pins a failure that made an agent loop, wait forever, or report a
wrong conclusion:

* follow-up commands must be addressable from a NEW process (no inherited env)
* a failed spawn must not leave a permanently queued job
* a resumed attempt that dies must not publish the previous attempt's success
* an explicit budget on resume must actually reach the worker
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core

ROOT = Path(__file__).resolve().parent.parent


def _env_clean(extra=None):
    env = dict(os.environ)
    env.pop("FINDINFO_TASK", None)
    env.pop("FINDINFO_HOME", None)
    if extra:
        env.update(extra)
    return env


def _cli(home, *args, timeout=120, env=None):
    """Run the real CLI in a subprocess with a clean environment."""
    r = subprocess.run([sys.executable, str(ROOT / "findinfo.py")] + list(args),
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env or _env_clean(), timeout=timeout,
                       cwd=str(ROOT))
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "")


# ---------------------------------------------------------------- 1. context
def test_followup_command_carries_task_and_home():
    """`next` must be runnable in a fresh process: it encodes task + home."""
    home = tempfile.mkdtemp(prefix="fn-ctx-")
    try:
        rc, out, err = _cli(home, "--home", home, "--task", "proj",
                            "run", "--domain", "example.com", "--background",
                            "--no-onepass")
        assert rc == 0, err[-300:]
        payload = json.loads(out)
        nxt = payload["next"]
        assert "--task proj" in nxt, "next lost the task: " + nxt
        assert "--home" in nxt, "next lost the home: " + nxt
        assert payload["run_id"] in nxt, "next lost the run id: " + nxt

        # The real acceptance: execute it in a clean env and get the same job.
        import shlex
        cmd = shlex.split(nxt)
        cmd[0] = sys.executable
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=_env_clean(), timeout=120,
                           cwd=str(ROOT))
        assert r.returncode == 0, (r.stdout or "") + (r.stderr or "")[-300:]
        got = json.loads(r.stdout)
        assert got["run_id"] == payload["run_id"], got
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_two_tasks_do_not_see_each_others_jobs():
    """Context is explicit, not ambient: same run id lookup in task B fails."""
    home = tempfile.mkdtemp(prefix="fn-iso-")
    try:
        rc, out, _ = _cli(home, "--home", home, "--task", "alpha",
                          "run", "--domain", "example.com", "--background",
                          "--no-onepass")
        rid = json.loads(out)["run_id"]
        rc2, out2, err2 = _cli(home, "--home", home, "--task", "beta",
                               "status", "--run", rid)
        assert rc2 != 0, "task beta must not resolve alpha's run: " + out2
        assert "not found" in (out2 + err2).lower(), out2 + err2
    finally:
        shutil.rmtree(home, ignore_errors=True)


# ------------------------------------------------------------ 2. spawn failure
def test_spawn_failure_is_terminal_and_retryable():
    """A spawn that raises must not leave a queued job that looks alive."""
    from lib import jobs as J
    core = fresh_core()
    rd = core.RUNS_DIR / "20260101-000000-spawnfail"
    rd.mkdir(parents=True, exist_ok=True)
    J.write_spec(rd, argv=["run", "--domain", "x"], root=str(core.ROOT),
                 dedupe_key="k-spawn", attempt=1)
    J.update_state(rd, state="queued", stage="queued", attempt=1)

    orig = subprocess.Popen

    def boom(*a, **k):
        raise OSError("injected spawn failure")

    subprocess.Popen = boom
    try:
        raised = False
        try:
            J.spawn(rd)
        except Exception:
            raised = True
        assert raised, "spawn must surface the failure"
    finally:
        subprocess.Popen = orig

    st = J.read_state(rd)
    assert st.get("state") == "failed", st
    assert (st.get("last_error") or {}).get("type") == "spawn_failed", st
    assert J.derive(st).get("terminal") is True
    # The dedupe key must be released so a retry can actually start.
    assert J.find_inflight("k-spawn") is None, "a failed spawn still blocks retries"


def test_queued_without_pid_does_not_look_alive_forever():
    from lib import jobs as J
    fresh_core()
    fresh = {"state": "queued", "updated_ts": J.now_ts()}
    old = {"state": "queued", "updated_ts": J.now_ts() - 120}
    assert J.derive(fresh)["alive"] is True, "a just-queued job is legitimately alive"
    d = J.derive(old)
    assert d["alive"] is False, "a queued job with no pid for 2 minutes is not alive"
    assert d["interrupted"] is True, d


# --------------------------------------------------------- 3. attempt ownership
def test_summary_from_another_attempt_is_not_adopted():
    """state=failed must never coexist with the previous attempt's complete."""
    from lib import jobs as J
    core = fresh_core()
    rd = core.RUNS_DIR / "20260101-000000-attempts"
    rd.mkdir(parents=True, exist_ok=True)
    # attempt 1 succeeded and wrote its summary
    (rd / "summary.jsonl").write_text(json.dumps({
        "attempt": 1,
        "result": {"status": "complete", "reason": "all_stages_done"},
        "coverage": {"complete": True}}) + chr(10), encoding="utf-8")

    assert J._last_summary(rd, 1) is not None, "attempt 1 must read its own summary"
    assert J._last_summary(rd, 2) is None, \
        "attempt 2 must NOT adopt attempt 1's summary"
    # without an attempt filter the newest row is still available for forensics
    assert J._last_summary(rd) is not None


def test_worker_failure_without_own_summary_reports_failure():
    """No summary for THIS attempt -> explicit failure, never the old result."""
    from lib import jobs as J
    core = fresh_core()
    rd = core.RUNS_DIR / "20260101-000000-nosummary"
    rd.mkdir(parents=True, exist_ok=True)
    J.write_spec(rd, argv=["run", "--domain", "x"], root=str(core.ROOT),
                 attempt=2, entry="tests.fake_pipeline:run",
                 args={"run_dir": str(rd), "stages": 1, "sleep": 0.01,
                       "fail_at": 1}, task_timeout=0)
    (rd / "summary.jsonl").write_text(json.dumps({
        "attempt": 1, "result": {"status": "complete"},
        "coverage": {"complete": True}}) + chr(10), encoding="utf-8")
    J.update_state(rd, state="queued", attempt=2)
    rc = J.worker_main(rd)
    assert rc != 0, rc
    st = J.read_state(rd)
    assert st.get("state") == "failed", st
    res = st.get("result") or {}
    assert res.get("status") == "failed", "must not keep the old complete: %r" % (res,)
    assert res.get("attempt") == 2, res
    assert (st.get("coverage") or {}).get("complete") is False, st.get("coverage")


# ---------------------------------------------------------------- 4. budgets
def test_resume_merges_explicit_budget_overrides():
    """`run --resume <id> --rounds 3` must change what the worker executes."""
    home = tempfile.mkdtemp(prefix="fn-resume-")
    try:
        rc, out, _ = _cli(home, "--home", home, "--task", "b",
                          "run", "--domain", "example.com", "--background",
                          "--no-onepass", "--rounds", "1")
        rid = json.loads(out)["run_id"]
        # stop it so resume is allowed
        _cli(home, "--home", home, "--task", "b", "cancel", "--run", rid)
        rc2, out2, err2 = _cli(home, "--home", home, "--task", "b",
                               "run", "--resume", rid, "--rounds", "3")
        assert rc2 == 0, err2[-300:]
        spec = json.loads((Path(home) / "tasks" / "b" / "runs" / rid / "job.json")
                          .read_text(encoding="utf-8"))
        argv = spec["argv"]
        assert "--rounds" in argv, argv
        assert argv[argv.index("--rounds") + 1] == "3", \
            "the explicit override did not reach the replayed argv: %r" % (argv,)
        assert spec["budget"]["rounds"] == 3, spec["budget"]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_resume_keeps_unspecified_budget():
    """Only what was typed changes; everything else keeps the original spec."""
    home = tempfile.mkdtemp(prefix="fn-keep-")
    try:
        rc, out, _ = _cli(home, "--home", home, "--task", "c",
                          "run", "--domain", "example.com", "--background",
                          "--no-onepass", "--rounds", "2", "--tool-timeout", "60")
        rid = json.loads(out)["run_id"]
        _cli(home, "--home", home, "--task", "c", "cancel", "--run", rid)
        rc2, _, err2 = _cli(home, "--home", home, "--task", "c",
                            "run", "--resume", rid, "--rounds", "4")
        assert rc2 == 0, err2[-300:]
        spec = json.loads((Path(home) / "tasks" / "c" / "runs" / rid / "job.json")
                          .read_text(encoding="utf-8"))
        argv = spec["argv"]
        assert argv[argv.index("--rounds") + 1] == "4"
        assert argv[argv.index("--tool-timeout") + 1] == "60", \
            "an unspecified flag must keep its stored value: %r" % (argv,)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_task_timeout_reaches_the_spec_and_worker():
    """The hard deadline field the worker reads must actually be written."""
    home = tempfile.mkdtemp(prefix="fn-hard-")
    try:
        rc, out, _ = _cli(home, "--home", home, "--task", "d",
                          "run", "--domain", "example.com", "--background",
                          "--no-onepass", "--task-timeout", "11")
        rid = json.loads(out)["run_id"]
        spec = json.loads((Path(home) / "tasks" / "d" / "runs" / rid / "job.json")
                          .read_text(encoding="utf-8"))
        assert float(spec.get("task_timeout") or 0) == 11.0, \
            "worker_main reads spec['task_timeout']; got %r" % (spec.get("task_timeout"),)
        _cli(home, "--home", home, "--task", "d", "cancel", "--run", rid)
    finally:
        shutil.rmtree(home, ignore_errors=True)
