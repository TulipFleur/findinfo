"""End-to-end integration: the pieces must agree, not just exist.

The unit tests prove each part works. This module proves the CHAIN works:
queue -> stage -> checkpoint -> coverage -> result -> report. Every case here
was a real disagreement found by an external review, where the components were
individually correct but the final answer was wrong.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core, fresh_tools

ROOT = Path(__file__).resolve().parent.parent


def _args(**over):
    base = dict(name="", domain=["example.com"], active=False, ports=False,
                vhost=False, crawl=False, brute=False, no_icp=True,
                no_onepass=True, engines="fofa", max_seed=5, top_ports=1000,
                depth=3, invest=51, deep=2, max_vhost_ips=10,
                brute_wordlist="", brute_bandwidth="3m", force_stage=False,
                background=False, resume="", rounds=1, time_budget=0.0,
                task_timeout=0.0, tool_timeout=0, entity_timeout=1200)
    base.update(over)
    return argparse.Namespace(**base)


# ------------------------------------------------- 1. pending queue blocks complete
def test_js_pending_prevents_complete():
    """41 bundles / budget 40 must NOT end as result.status=complete."""
    core = fresh_core()
    store = core.Store()
    try:
        urls = ["https://example.com/app%d.js" % i for i in range(41)]
        store.js_enqueue(urls)
        first = store.js_claim(40, allow_urls=urls)
        for u in first:
            store.js_finish(u, ok=True)
        stats = store.js_stats(scope=["example.com"])
        assert stats["pending"] == 1, stats
        # And a second claim must progress, not repeat the first 40.
        second = store.js_claim(40, allow_urls=urls)
        assert len(second) == 1 and second[0] not in first
    finally:
        store.close()


def test_js_queue_is_scoped_to_the_work_set():
    """A leftover bundle from another target must not be fetched by this run."""
    core = fresh_core()
    store = core.Store()
    try:
        store.js_enqueue(["https://other.example.org/x.js"])
        mine = ["https://example.com/a.js"]
        store.js_enqueue(mine)
        claimed = store.js_claim(10, allow_urls=mine)
        assert claimed == mine, "claimed someone else's bundle: %r" % (claimed,)
        st = store.js_stats(scope=["example.com"])
        assert st["pending"] == 1, st
    finally:
        store.close()


# ------------------------------------------------- 2. partial reaches the verdict
def test_partial_stage_is_not_checkpointed_as_done():
    """A partial stage must stay re-runnable, and show up as partial."""
    fi = tests.util.import_findinfo()
    core = fresh_core()
    store = core.Store()
    try:
        run_dir = core.RUNS_DIR / "20260101-000000-partial"
        run_dir.mkdir(parents=True, exist_ok=True)
        summary = {"stages": []}
        ok, res = fi._stage(
            store, run_dir, summary, "subs", {"x": 1}, _args(),
            lambda: {"found": 3},
            lambda r: {"found": r["found"], "outcome": core.OUTCOME_PARTIAL})
        assert ok is True, res
        assert summary["stages"][-1]["status"] == "partial", summary["stages"][-1]
        row = store.conn.execute(
            "SELECT status FROM steps WHERE step=?", ("subs",)).fetchone()
        assert row and row["status"] == "partial", dict(row) if row else None
    finally:
        store.close()


def test_succeeded_stage_still_checkpoints_done():
    fi = tests.util.import_findinfo()
    core = fresh_core()
    store = core.Store()
    try:
        run_dir = core.RUNS_DIR / "20260101-000000-ok"
        run_dir.mkdir(parents=True, exist_ok=True)
        summary = {"stages": []}
        fi._stage(store, run_dir, summary, "certs", {"x": 1}, _args(),
                  lambda: {"found": 5},
                  lambda r: {"found": r["found"], "outcome": core.OUTCOME_OK})
        row = store.conn.execute("SELECT status FROM steps WHERE step=?",
                                 ("certs",)).fetchone()
        assert row and row["status"] == "done", dict(row) if row else None
    finally:
        store.close()


# ------------------------------------------------- 3. hard timeout kills children
def test_hard_timeout_overwrites_previous_result():
    """worker exits 124 and result/coverage describe THIS attempt."""
    home = tempfile.mkdtemp(prefix="fn-timeout-")
    try:
        env = dict(os.environ)
        env["FINDINFO_HOME"] = home
        env.pop("FINDINFO_TASK", None)
        import importlib
        from lib import core as C, jobs as J
        importlib.reload(C)
        importlib.reload(J)
        rd = C.RUNS_DIR / "20260101-000000-hardto"
        rd.mkdir(parents=True, exist_ok=True)
        (rd / "summary.jsonl").write_text(json.dumps({
            "attempt": 1, "result": {"status": "complete"},
            "coverage": {"complete": True}}) + chr(10), encoding="utf-8")
        J.write_spec(rd, argv=[], root=str(ROOT), attempt=2, task_timeout=3,
                     entry="tests.fake_pipeline:run",
                     args={"run_dir": str(rd), "stages": 1, "sleep": 90})
        J.update_state(rd, state="queued", attempt=2)
        code = ("import sys; sys.path.insert(0, %r); from lib import jobs; "
                "raise SystemExit(jobs.worker_main(sys.argv[1]))" % str(ROOT))
        t0 = time.time()
        r = subprocess.run([sys.executable, "-c", code, str(rd)],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=env, timeout=60)
        assert r.returncode == 124, r.returncode
        assert time.time() - t0 < 30, "the deadline did not fire promptly"
        st = J.read_state(rd)
        assert st.get("state") == "failed", st
        assert (st.get("result") or {}).get("status") == "failed", \
            "the old complete leaked through: %r" % (st.get("result"),)
        assert (st.get("coverage") or {}).get("complete") is False, st.get("coverage")
    finally:
        shutil.rmtree(home, ignore_errors=True)


# ------------------------------------------------- 4. concurrent submissions
def test_concurrent_identical_submissions_create_one_job():
    """Two racing submissions must not start two collections."""
    home = tempfile.mkdtemp(prefix="fn-race-")
    try:
        env = dict(os.environ)
        env.pop("FINDINFO_TASK", None)
        env.pop("FINDINFO_HOME", None)
        base = [sys.executable, str(ROOT / "findinfo.py"), "--home", home,
                "--task", "race", "run", "--domain", "example.com",
                "--background", "--no-onepass"]
        procs = [subprocess.Popen(base, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True,
                                  encoding="utf-8", errors="replace", env=env,
                                  cwd=str(ROOT)) for _ in range(2)]
        outs = []
        for p in procs:
            out, _ = p.communicate(timeout=180)
            outs.append(out.strip())
        ids = set()
        for o in outs:
            if o.startswith("{"):
                try:
                    ids.add(json.loads(o)["run_id"])
                except Exception:
                    pass
        runs = list((Path(home) / "tasks" / "race" / "runs").glob("*"))
        assert len(runs) == 1, "two run dirs were created: %r" % ([r.name for r in runs],)
        assert len(ids) <= 1, "two different run ids returned: %r" % (ids,)
        if ids:
            subprocess.run([sys.executable, str(ROOT / "findinfo.py"), "--home", home,
                            "--task", "race", "cancel", "--run", list(ids)[0]],
                           capture_output=True, env=env, cwd=str(ROOT), timeout=60)
    finally:
        shutil.rmtree(home, ignore_errors=True)


# ------------------------------------------------- 5. zero budget on resume
def test_resume_zero_budget_removes_only_that_flag():
    """`--time-budget 0` must not delete an unrelated `--tool-timeout 60`."""
    home = tempfile.mkdtemp(prefix="fn-zero-")
    try:
        env = dict(os.environ)
        env.pop("FINDINFO_TASK", None)
        env.pop("FINDINFO_HOME", None)

        def cli(*a):
            r = subprocess.run([sys.executable, str(ROOT / "findinfo.py"),
                                "--home", home, "--task", "zero"] + list(a),
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", env=env, cwd=str(ROOT), timeout=120)
            return r.returncode, (r.stdout or "").strip()

        rc, out = cli("run", "--domain", "example.com", "--background",
                      "--no-onepass", "--time-budget", "60",
                      "--tool-timeout", "60", "--task-timeout", "120")
        rid = json.loads(out)["run_id"]
        cli("cancel", "--run", rid)
        time.sleep(1)
        rc, _ = cli("run", "--resume", rid, "--time-budget", "0",
                    "--task-timeout", "0")
        assert rc == 0, rc
        spec = json.loads((Path(home) / "tasks" / "zero" / "runs" / rid /
                           "job.json").read_text(encoding="utf-8"))
        argv = spec["argv"]
        assert "--time-budget" not in argv, "zero budget was not removed: %r" % (argv,)
        assert "--tool-timeout" in argv, argv
        assert argv[argv.index("--tool-timeout") + 1] == "60", \
            "an unrelated flag's value was deleted: %r" % (argv,)
        assert float(spec.get("task_timeout") or 0) == 0.0, \
            "the old hard deadline survived: %r" % (spec.get("task_timeout"),)
    finally:
        shutil.rmtree(home, ignore_errors=True)
