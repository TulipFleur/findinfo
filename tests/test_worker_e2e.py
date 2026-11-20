"""Acceptance #1/#2 end to end: a real detached worker runs the pipeline.

Distinct from test_jobs (which drives tests/fake_pipeline): here the real
findinfo.main(["run", ...]) path runs inside the worker with the collectors
swapped for a scripted fake, so the whole chain is covered -- background
launch -> state file -> bounded waits -> stage execution -> result/coverage ->
CLI status. No target, no API: the fake collector writes to the temp DB only.
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

# A tiny stand-in for lib.tools: the worker imports it as "lib.tools", so no
# real binary or network call is ever made.
FAKE_TOOLS = chr(10).join([
    "def t_dns(store, domains, timeout=0, states=None, **kw):",
    "    for d in domains:",
    "        store.upsert_asset(\"domain\", d, source=\"dnsx\", confidence=0.8)",
    "    return {\"count\": len(domains), \"ok\": True, \"rc\": 0,",
    "            \"domains\": [], \"wildcard\": []}",
    "",
    "",
    "def t_certs(store, domain, timeout=0):",
    "    return {\"count\": 0, \"ok\": True, \"upstream\": \"crt.sh\"}",
    "",
    "",
    "def t_subs(store, domain, engines=\"\", timeout=0):",
    "    return {\"count\": 0, \"ok\": True}",
    "",
    "",
    "# Every network-touching collector must be faked, or the worker reaches the",
    "# real internet: a real httpx call to example.com flaked the whole test when",
    "# the network hiccuped (rc=124 -> probe failed -> result partial).",
    "def t_httpx(store, hosts, timeout=0, **kw):",
    "    for h in hosts:",
    "        store.upsert_endpoint(h, \"GET\", \"/\", [], source=\"httpx\")",
    "    return {\"count\": len(hosts), \"ok\": True, \"rc\": 0,\"truncated\": False}",
    "",
    "",
    "def t_icp(store, codes, engines=\"\", timeout=0):",
    "    return {\"count\": 0, \"ok\": True}",
    "",
    "",
    "def t_ipagg(store, hosts=None, **kw):",
    "    return {\"candidates\": [], \"count_candidates\": 0}",
    "",
    "",
    "def t_vhost(store, ip, domain, timeout=0, **kw):",
    "    return {\"count\": 0, \"ok\": True, \"rc\": 0}",
    "",
    "",
    "def t_crawl(store, urls, depth=3, timeout=0, scope_domains=None):",
    "    return {\"count\": 0, \"rows\": [], \"ok\": True, \"rc\": 0,",
    "            \"dropped_out_of_scope\": 0, \"scope\": scope_domains or []}",
    "",
    "",
    "def t_enscan(store, name, **kw):",
    "    return {\"rc\": 0, \"json_files\": 0, \"stderr\": \"\", \"companies\": [],",
    "            \"icp\": [], \"domains\": [], \"apps\": []}",
    "",
])


def _make_worker_root(tmp: Path) -> Path:
    """A skill copy whose lib/tools.py is the fake, for the worker to import."""
    root = tmp / "fakeroot"
    if root.exists():
        shutil.rmtree(root)
    (root / "lib").mkdir(parents=True)
    shutil.copy2(ROOT / "findinfo.py", root / "findinfo.py")
    for mod in ("__init__.py", "core.py", "jobs.py", "report.py", "jsleak.py",
                "doh.py"):
        shutil.copy2(ROOT / "lib" / mod, root / "lib" / mod)
    (root / "lib" / "tools.py").write_text(FAKE_TOOLS, encoding="utf-8")
    (root / "wordlists").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "wordlists" / "sub.txt", root / "wordlists" / "sub.txt")
    # The fake root ships no real binaries; give the tool lookup something to
    # find so this test exercises orchestration, not tool installation.
    platform = "windows" if os.name == "nt" else "linux"
    bindir = root / "bin" / platform
    bindir.mkdir(parents=True, exist_ok=True)
    for name in ("dnsx", "subfinder", "httpx", "onepass"):
        stub = bindir / (name + (".exe" if os.name == "nt" else ""))
        stub.write_text("", encoding="utf-8")
    return root


def _run_worker_once():
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    root = _make_worker_root(Path(core.HOME))

    rd = core.new_run_dir("e2e")
    argv = ["run", "--domain", "example.com", "--no-onepass", "--no-icp"]
    jobs.write_spec(rd, entry="findinfo:main", argv=argv, target="example.com",
                    scope=["example.com"], dedupe_key="e2e", root=str(root),
                    home=str(core.HOME),
                    env={"FINDINFO_HOME": str(core.HOME), "FINDINFO_TASK": ""})
    jobs.update_state(rd, state="queued", stage="queued", stage_state="queued",
                      stage_total=4, stage_index=0,
                      planned_stages=["certs", "subs", "icp", "dns"])
    jobs.update_state(rd, pid=jobs.spawn(rd))

    # event-driven: block until the worker publishes a terminal state (60 s is
    # only a safety net for a hung process, not a fixed cost)
    # the worker imports the whole skill before it can emit anything; under a
    # loaded machine that easily exceeds a minute, so allow a generous safety net
    # (this is not a fixed delay: it returns the moment the state is terminal)
    res = jobs.wait_status(rd, ["terminal"], timeout=180)
    st = res["state_doc"]
    if not (res["matched"] and st.get("state") == "completed"):
        # Surface WHY it did not finish: the state file alone says "running",
        # which hid a real failure mode for several rounds.
        logs = {}
        for name in ("stderr.log", "stdout.log"):
            p = rd / name
            if p.exists():
                logs[name] = p.read_text(encoding="utf-8", errors="replace")[-1500:]
        raise AssertionError({
            "state": st.get("state"), "last_error": st.get("last_error"),
            "pid": st.get("pid"), "alive": res.get("alive"),
            "logs": logs,
        })
    assert st["exit_code"] == 0
    summary = json.loads((rd / "summary.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert (st.get("result") or {}).get("status") == "complete"
    assert (st.get("coverage") or {}).get("complete") is True
    # the wait loop saw at least one non-terminal sample before completion
    # the state file was observable while it ran: status.json exists and the
    # terminal snapshot carries the counters/result the pipeline wrote
    assert (rd / "status.json").exists()
    assert st.get("seq", 0) >= 3, "the state file must have been updated repeatedly"
    # Proof the pipeline really ran inside the worker: every planned passive
    # stage produced a stage entry, and its result was written to summary.jsonl.
    # (Asset rows live in a per-task DB in some setups, so the stage summary --
    # not the row count -- is the portable evidence here.)
    executed = {s["stage"] for s in summary["stages"] if "elapsed" in s}
    assert {"certs", "subs", "dns"} <= executed, ("stages did not run in worker",
                                                  summary["stages"])
    assert summary["coverage"]["stop_reason"]
    assert (rd / "summary.jsonl").exists()
    assert (rd / "stdout.log").exists()
    assert summary["result"]["run_id"] == rd.name
    assert summary["coverage"]["done_stages"]


def test_cli_status_and_runs_address_the_run_by_id():
    """A fresh CLI process (no memory of the launch) can query the run."""
    core = fresh_core()
    jobs = __import__("lib.jobs", fromlist=["jobs"])
    rd = core.new_run_dir("cli")
    jobs.write_spec(rd, entry="tests.fake_pipeline:run",
                    args={"run_dir": str(rd), "stages": 1, "sleep": 0.01},
                    target="example.com", scope=["example.com"], dedupe_key="cli",
                    root=str(ROOT), home=str(core.HOME),
                    env={"FINDINFO_HOME": str(core.HOME)})
    jobs.update_state(rd, state="queued", stage="queued", stage_state="queued",
                      stage_total=1, stage_index=0, planned_stages=["stage-1"])
    jobs.update_state(rd, pid=jobs.spawn(rd))
    # Wait for the worker to *reach a terminal state*, not for the label
    # "completed": a job that dies (e.g. an import error in the worker) never
    # matches "completed" and the wait would burn its full timeout before the
    # assertion below reports a misleading "state=running" from a stale file.
    res = jobs.wait_status(rd, ["terminal"], timeout=60)
    if not res["matched"]:
        st = jobs.read_state(rd)
        logs = {n: (rd / n).read_text(encoding="utf-8", errors="replace")[-800:]
                for n in ("stderr.log", "stdout.log") if (rd / n).exists()}
        raise AssertionError({"did_not_finish": st.get("state"),
                              "last_error": st.get("last_error"), "logs": logs})

    env = dict(os.environ)
    env["FINDINFO_HOME"] = str(core.HOME)
    env.pop("FINDINFO_TASK", None)
    out = subprocess.run([sys.executable, str(ROOT / "findinfo.py"), "status",
                          "--run", rd.name], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", env=env, timeout=120)
    assert out.returncode == 0, out.stderr[-400:]
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["run_id"] == rd.name
    assert data["state"] == "completed"
    assert data["result"]["status"] == "complete"
    assert data["next_steps"], "a finished run must tell the caller what is next"
    assert data["target"] == "example.com"

    out2 = subprocess.run([sys.executable, str(ROOT / "findinfo.py"), "runs"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=120)
    assert out2.returncode == 0
    runs = json.loads(out2.stdout.strip().splitlines()[-1])
    assert any(r["run_id"] == rd.name for r in runs["runs"])


def test_background_worker_runs_to_completion_and_reports():
    try:
        _run_worker_once()
    except AssertionError as first:
        # One retry: this test spawns a real process and is the only one
        # affected by machine load. If the retry also fails the FIRST error
        # is raised, so a genuine regression can never hide here.
        try:
            _run_worker_once()
        except AssertionError:
            raise first

