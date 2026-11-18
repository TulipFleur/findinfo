"""Regression: a real worker survives the launcher (host-independence).

Measures the liveness claim this skill actually makes: the background worker is
a detached Python process, not a child of the shell or tool call that started
it. Verified by starting a job, killing the *parent* Python process that
spawned it, and checking the job still finishes by itself.

Scope: this proves detachment from the launcher. It does NOT prove survival of
a machine reboot -- that needs a service manager and is documented as a
non-guarantee in SKILL.md.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import tests.util  # noqa: F401
from tests.util import fresh_core

ROOT = Path(__file__).resolve().parent.parent


def test_worker_outlives_its_launcher():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("orphan")
    jobs.write_spec(rd, entry="tests.fake_pipeline:run",
                    args={"run_dir": str(rd), "stages": 2, "sleep": 0.4},
                    target="example.com", scope=["example.com"], dedupe_key="orphan",
                    root=str(ROOT), home=str(core.HOME),
                    env={"FINDINFO_HOME": str(core.HOME)})

    # A launcher process starts the job and is then killed mid-flight, exactly
    # like a tool call whose parent goes away. The worker must keep going.
    launch = chr(10).join([
        "import sys, os",
        "sys.path.insert(0, " + repr(str(ROOT)) + ")",
        "from lib import core, jobs",
        "rd = core.new_run_dir(\"orphan\")",
        "jobs.write_spec(rd, entry=\"tests.fake_pipeline:run\",",
        "                args={\"run_dir\": str(rd), \"stages\": 2, \"sleep\": 0.4},",
        "                target=\"example.com\", scope=[\"example.com\"],",
        "                dedupe_key=\"orphan\", root=" + repr(str(ROOT)) + ",",
        "                home=os.environ[\"FINDINFO_HOME\"],",
        "                env={\"FINDINFO_HOME\": os.environ[\"FINDINFO_HOME\"]})",
        "jobs.update_state(rd, state=\"queued\", stage_total=2, stage_index=0)",
        "pid = jobs.spawn(rd)",
        "jobs.update_state(rd, pid=pid)",
        "print(rd.name)",
        "sys.stdout.flush()",
        "import time; time.sleep(30)",
    ])
    env = dict(os.environ)
    env["FINDINFO_HOME"] = str(core.HOME)
    proc = subprocess.Popen([sys.executable, "-c", launch], stdout=subprocess.PIPE,
                            text=True, env=env, cwd=str(ROOT))
    run_id = proc.stdout.readline().strip()
    assert run_id, "launcher did not report a run id"
    worker = jobs.read_state(run_id).get("pid")
    assert worker, "worker pid must be published before the launcher dies"

    proc.kill()                       # the launcher disappears
    proc.wait(timeout=30)
    assert not jobs.pid_alive(proc.pid)
    assert jobs.pid_alive(worker), "the worker must not die with its launcher"

    res = jobs.wait_status(run_id, ["terminal"], timeout=60)
    st = res["state_doc"]
    assert res["matched"], ("the detached worker did not finish on its own",
                            st.get("state"), st.get("last_error"))
    assert st["state"] == "completed"
    assert (Path(jobs.resolve(run_id)) / "stage2.done").exists()
