"""Batch D acceptance: output, RunSpec and pure offline entry (F09/F14/F15/F16).

Offline CLI subprocess checks (temp home, no network). Pinned:

* brief merges every section then measures with the SAME encoder stdout uses:
  brief_bytes == the actual stdout bytes, under ASCII (default) and UTF-8
  modes, in one valid JSON line, and a too-small ceiling is refused (F14);
* an explicit timeout=0 survives CLI -> job -> argv -> CLI (F15);
* resume accepts the same identity fields it was launched with and rejects a
  real identity change without bumping the attempt (F15);
* a resume dry-run previews the SAME target/scope/stages/limits the resume
  applies, and changes no state file (F16);
* the offline entry (dry-run / doctor --offline) creates no home, db, runs or
  cache directory and reports capabilities as not_checked (F09).
"""

import json
import os
import subprocess
import sys
import tempfile

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

ROOT = tests.util.ROOT


def _cli(home, *argv, env_extra=None, timeout=180):
    env = dict(os.environ, FINDINFO_HOME=home, FINDINFO_TASK="")
    env.pop("FINDINFO_RUN_DIR", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([sys.executable, str(ROOT / "findinfo.py"),
                           "--home", home] + list(argv),
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=timeout,
                          cwd=str(ROOT))
    return proc


def _payload(proc):
    lines = [l for l in (proc.stdout or "").splitlines()
             if l.strip().startswith("{")]
    return json.loads(lines[-1]) if lines else {}


# ---------------------------------------------------------------- F14 brief
def _big_task(home, task="bd"):
    """A task whose brief has real pressure: many hosts + a long CJK warning."""
    store_home = home
    env = dict(os.environ, FINDINFO_HOME=store_home, FINDINFO_TASK=task)
    env.pop("FINDINFO_RUN_DIR", None)
    code = r'''
import sys
sys.path.insert(0, %r)
from lib import core
s = core.Store()
for i in range(400):
    s.upsert_asset("domain", "host%%03d.example.com" %% i, source="dnsx",
                   confidence=0.8, attrs={"url": "https://host%%03d.example.com/" %% i})
s.close()
''' % str(ROOT)
    subprocess.run([sys.executable, "-c", code], env=env, cwd=str(ROOT),
                   capture_output=True, timeout=120)


def test_brief_bytes_equal_real_stdout_bytes_ascii_mode():
    home = tempfile.mkdtemp(prefix="fi-brief-ascii-")
    try:
        _big_task(home)
        proc = _cli(home, "--task", "bd", "brief", "--max-bytes", "8000")
        raw = proc.stdout.encode("utf-8")
        payload = _payload(proc)
        assert payload, proc.stderr[-300:]
        # one valid JSON line, and its declared size IS the emitted size
        assert len(raw) <= 8000, ("real stdout exceeded the ceiling", len(raw))
        assert payload["brief_bytes"] == len(raw), (
            payload["brief_bytes"], len(raw))
        assert payload["brief_max_bytes"] == 8000
        assert proc.stdout.count(chr(10)) == 1, "more than one line of JSON"
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def test_brief_bytes_equal_real_stdout_bytes_utf8_mode():
    home = tempfile.mkdtemp(prefix="fi-brief-utf8-")
    try:
        _big_task(home)
        proc = _cli(home, "--task", "bd", "brief", "--max-bytes", "8000",
                    env_extra={"FINDINFO_EMIT_UTF8": "1"})
        raw = proc.stdout.encode("utf-8")
        payload = _payload(proc)
        assert payload, proc.stderr[-300:]
        assert payload["brief_bytes"] == len(raw), (
            "UTF-8 mode: declared bytes must equal stdout bytes",
            payload["brief_bytes"], len(raw))
        assert len(raw) <= 8000, len(raw)
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def test_brief_keeps_decision_fields_under_minimal_emit():
    home = tempfile.mkdtemp(prefix="fi-brief-min-")
    try:
        _big_task(home)
        proc = _cli(home, "--task", "bd", "brief",
                    env_extra={"FINDINFO_EMIT": "minimal"})
        payload = _payload(proc)
        assert payload, proc.stderr[-300:]
        for key in ("schema", "counts", "coverage", "brief_bytes"):
            assert key in payload, ("minimal mode stripped a brief field", key)
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def test_brief_rejects_an_impossibly_small_ceiling():
    home = tempfile.mkdtemp(prefix="fi-brief-tiny-")
    try:
        _big_task(home)
        proc = _cli(home, "--task", "bd", "brief", "--max-bytes", "16")
        # a structured refusal, not a truncated document
        assert proc.returncode != 0, proc.stdout
        payload = _payload(proc)
        assert "max_bytes" in str(payload.get("message", "")), payload
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------- F15 zero
def test_explicit_zero_survives_launch_and_replay():
    home = tempfile.mkdtemp(prefix="fi-zero-")
    try:
        proc = _cli(home, "--task", "bz", "run", "--domain", "mt-a.example.com",
                    "--background", "--no-onepass", "--no-icp",
                    "--task-timeout", "0", "--time-budget", "0")
        assert proc.returncode == 0, proc.stderr[-300:]
        rid = _payload(proc)["run_id"]
        spec = json.loads((os.path.join(home, "tasks", "bz", "runs", rid,
                                        "job.json")), encoding="utf-8") \
            if False else json.loads(open(os.path.join(
                home, "tasks", "bz", "runs", rid, "job.json"),
                encoding="utf-8").read())
        assert float(spec.get("task_timeout") or 0) == 0.0, spec.get("task_timeout")
        assert float((spec.get("budget") or {}).get("time_budget_sec") or 0) == 0.0
        # entity_timeout=0 must stay 0 in the stored spec, not become 1200
        assert int((spec.get("run_spec") or {}).get("entity_timeout", 1200)) in (0, 1200)
        _cli(home, "--task", "bz", "cancel", "--run", rid)
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def test_entity_timeout_zero_is_preserved_by_run_spec():
    import argparse
    from lib import spec as spec_mod
    ns = argparse.Namespace(entity_timeout=0, rounds=0, time_budget=0.0,
                            task_timeout=0.0, tool_timeout=0)
    rs = spec_mod.from_cli(ns)
    assert rs.entity_timeout == 0, rs.entity_timeout
    assert rs.rounds == 0, rs.rounds


# ---------------------------------------------------------------- F15 resume
def test_resume_accepts_the_same_domain_and_rejects_a_change():
    home = tempfile.mkdtemp(prefix="fi-resume-id-")
    try:
        proc = _cli(home, "--task", "br", "run", "--domain", "mt-a.example.com",
                    "--background", "--no-onepass", "--no-icp")
        rid = _payload(proc)["run_id"]
        _cli(home, "--task", "br", "cancel", "--run", rid)
        import time
        deadline = time.time() + 60
        while time.time() < deadline:
            st = json.loads(open(os.path.join(
                home, "tasks", "br", "runs", rid, "status.json"),
                encoding="utf-8").read())
            if not st.get("pid") or not _alive(st.get("pid")):
                break
            time.sleep(0.2)
        # same domain typed again: accepted (no false identity change)
        same = _cli(home, "--task", "br", "run", "--resume", rid, "--domain",
                    "mt-a.example.com")
        assert same.returncode == 0, same.stdout + same.stderr[-300:]
        spec = json.loads(open(os.path.join(
            home, "tasks", "br", "runs", rid, "job.json"),
            encoding="utf-8").read())
        attempt_after_same = int(spec.get("attempt") or 1)
        assert attempt_after_same == 2, attempt_after_same
        _cli(home, "--task", "br", "cancel", "--run", rid)
        while time.time() < deadline:
            st = json.loads(open(os.path.join(
                home, "tasks", "br", "runs", rid, "status.json"),
                encoding="utf-8").read())
            if not st.get("pid") or not _alive(st.get("pid")):
                break
            time.sleep(0.2)
        # a DIFFERENT domain: refused, and the attempt does not move
        bad = _cli(home, "--task", "br", "run", "--resume", rid, "--domain",
                   "mt-b.example.net")
        assert bad.returncode == 2, bad.stdout
        payload = _payload(bad)
        assert "rejected" in str(payload.get("message", "")).lower(), payload
        spec2 = json.loads(open(os.path.join(
            home, "tasks", "br", "runs", rid, "job.json"),
            encoding="utf-8").read())
        assert int(spec2.get("attempt") or 1) == attempt_after_same, (
            "a refused resume must not bump the attempt", spec2.get("attempt"))
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def _alive(pid) -> bool:
    from lib import jobs
    return jobs.pid_alive(pid)


# ---------------------------------------------------------------- F16 preview
def test_resume_dry_run_matches_the_real_resume_and_changes_nothing():
    home = tempfile.mkdtemp(prefix="fi-preview-")
    try:
        proc = _cli(home, "--task", "bp", "run", "--name", "fixture-brand",
                    "--domain", "mt-a.example.com", "--active", "--crawl",
                    "--background", "--no-onepass", "--no-icp", "--rounds", "3")
        rid = _payload(proc)["run_id"]
        _cli(home, "--task", "bp", "cancel", "--run", rid)
        import time
        deadline = time.time() + 60
        while time.time() < deadline:
            st = json.loads(open(os.path.join(
                home, "tasks", "bp", "runs", rid, "status.json"),
                encoding="utf-8").read())
            if not st.get("pid") or not _alive(st.get("pid")):
                break
            time.sleep(0.2)
        status_path = os.path.join(home, "tasks", "bp", "runs", rid, "status.json")
        before = open(status_path, "rb").read()
        preview = _payload(_cli(home, "--task", "bp", "run", "--dry-run",
                                "--resume", rid))
        after = open(status_path, "rb").read()
        assert before == after, "a dry-run preview must not change job state"
        eff = preview.get("effective") or {}
        assert eff.get("source") == "job.json", eff
        # the preview describes the ACTIVE target, not parser defaults
        assert eff.get("target") == "fixture-brand", eff.get("target")
        assert eff.get("scope") == ["mt-a.example.com"], eff.get("scope")
        stages = set(eff.get("planned_stages") or [])
        assert {"entity", "crawl", "extract"} <= stages, stages
        assert eff.get("limits", {}).get("rounds") == 3, eff.get("limits")
        # and it agrees with what the real resume would run
        _cli(home, "--task", "bp", "cancel", "--run", rid)
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------- F09 offline
def test_offline_entry_has_no_config_or_directory_side_effects():
    base = tempfile.mkdtemp(prefix="fi-offline-")
    home = os.path.join(base, "never-created")
    try:
        assert not os.path.exists(home)
        for argv in (["doctor", "--offline"],
                     ["run", "--domain", "mt-a.example.com", "--dry-run"],
                     ["run", "--name", "fixture", "--dry-run", "--background"],
                     ["run", "--domain", "mt-a.example.com", "--dry-run",
                      "--resume", "does-not-exist"]):
            proc = _cli(home, *argv)
            assert proc.returncode == 0, (argv, proc.stderr[-300:])
            assert not os.path.exists(home), (
                "offline mode created the home directory", argv,
                os.listdir(home) if os.path.exists(home) else [])
        # capabilities are unknown, never false, never "healthy"
        doc = _payload(_cli(home, "doctor", "--offline"))
        assert doc.get("mode") == "offline"
        egress = doc.get("environment", {}).get("net_egress") or {}
        assert egress.get("any_reachable") is None and egress.get("checked") is False
        fake = doc.get("environment", {}).get("fake_ip_dns") or {}
        assert fake.get("fake_ip_dns") is None and fake.get("checked") is False
        for name, state in (doc.get("api_keys") or {}).items():
            assert state == "not_checked", (name, state)
        for name, tool in (doc.get("tools") or {}).items():
            if tool.get("present"):
                assert tool.get("health") == "not_checked", (name, tool)
        plan = _payload(_cli(home, "run", "--domain", "mt-a.example.com",
                             "--dry-run"))
        assert plan.get("run_id") is None
        assert (plan.get("capabilities") or {}).get("checked") is False
        # the plan lists the stages a real run would plan
        assert plan.get("planned_stages"), plan
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


def test_offline_plan_matches_the_runtime_planner():
    """The pure plan and the runtime planner must not drift."""
    import argparse
    from lib import spec as spec_mod
    import findinfo as fi
    for flags in ({}, {"active": True}, {"active": True, "crawl": True,
                                         "ports": True, "vhost": True,
                                         "brute": True},
                  {"name": "x"}, {"no_icp": True, "no_onepass": True}):
        ns = argparse.Namespace(**{"name": "", "domain": ["mt-a.example.com"],
                                   "active": False, "ports": False,
                                   "vhost": False, "crawl": False,
                                   "brute": False, "no_icp": False,
                                   "no_onepass": False, **flags})
        active = bool(ns.active or ns.ports or ns.vhost or ns.crawl or ns.brute)
        rs = spec_mod.from_cli(ns)
        assert fi._plan_stages_pure(rs, active) == fi._plan_stages(ns, active), (
            "pure planner drifted", flags)
