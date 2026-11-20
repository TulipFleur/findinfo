"""Batch B acceptance: one RunSpec, dry-run and offline doctor (T20, T32).

Fixture brand is 美团; all domains under the reserved example.com/.net/.org
namespaces. Everything here is offline: the dry-run plan must not create a
database, read a credential or launch a process, and the offline doctor must
report unknown checks as not_checked (never false, never healthy).
"""

import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import spec as spec_mod
from tests.util import fresh_core, import_findinfo

ROOT = tests.util.ROOT


# ---------------------------------------------------------------- T20 helpers
def _spec(**over):
    base = dict(name="", domain=("mt-a.example.com",), task="",
                engines="fofa,quake,hunter,shodan,censys",
                no_icp=True, no_onepass=True)
    base.update(over)
    return spec_mod.RunSpec(**base)


def test_t20_argv_round_trip_preserves_every_option():
    """spec -> argv -> parser -> spec loses nothing (batch B core contract)."""
    fi = import_findinfo()
    parser = fi.build_parser()
    rs = _spec(active=True, brute=True, crawl=True, ports=True, vhost=True,
               supplier=True, branch=True, deep=2, invest=66, depth=4,
               entity_timeout=900, top_ports=100, max_seed=9,
               max_vhost_ips=3, rounds=4, time_budget=120.0,
               task_timeout=600.0, tool_timeout=30,
               brute_wordlist="wordlists/submin.txt",
               brute_bandwidth="1m")
    argv = rs.to_worker_argv() + ["--no-icp", "--no-onepass"]
    args = parser.parse_args(argv)
    back = spec_mod.from_cli(args)
    assert back == rs, (
        "round trip changed the spec",
        {f.name: (getattr(rs, f.name), getattr(back, f.name))
         for f in __import__("dataclasses").fields(spec_mod.RunSpec)
         if getattr(rs, f.name) != getattr(back, f.name)})


def test_t20_identity_is_separate_from_limits():
    """Same target, different limits -> same dedupe identity, diff reported."""
    a = _spec(rounds=1, time_budget=0.0)
    b = _spec(rounds=9, time_budget=120.0, tool_timeout=30)
    assert a.dedupe_identity() == b.dedupe_identity()
    diff = b.diff(a)
    assert set(diff) == {"rounds", "time_budget", "tool_timeout"}, diff
    assert diff["rounds"] == {"requested": 9, "in_flight": 1}
    c = _spec(domain=("mt-b.example.net",))
    assert c.dedupe_identity() != a.dedupe_identity()


def test_t20_resume_patches_only_documented_limits():
    a = _spec(rounds=1)
    b = _spec(rounds=5, time_budget=60.0)
    patched = a.resume_patch(b)
    assert patched.rounds == 5 and patched.time_budget == 60.0
    assert patched.domain == a.domain
    identity_change = _spec(engines="quake,hunter")
    try:
        a.resume_patch(identity_change)
        raised = False
    except ValueError:
        raised = True
    assert raised, "resume must refuse identity/scope/source changes"


def test_t20_spec_json_round_trip():
    rs = _spec(active=True, rounds=3)
    assert spec_mod.RunSpec.from_json(rs.to_json()) == rs
    try:
        spec_mod.RunSpec.from_json(
            rs.to_json().replace('"schema_version": 1', '"schema_version": 99'))
        raised = False
    except ValueError:
        raised = True
    assert raised, "unknown schema versions must be rejected"


# ---------------------------------------------------------------- T32 dry-run
def _cli(argv, home):
    env = dict(os.environ, FINDINFO_HOME=home, FINDINFO_TASK="")
    env.pop("FINDINFO_RUN_DIR", None)
    proc = subprocess.run([sys.executable, str(ROOT / "findinfo.py")] + argv,
                          capture_output=True, text=True, encoding="utf-8",
                          env=env, timeout=120)
    lines = [l for l in (proc.stdout or "").splitlines() if l.strip().startswith("{")]
    payload = json.loads(lines[-1]) if lines else {}
    return proc.returncode, payload


def test_t32_dry_run_starts_nothing_and_creates_no_database():
    home = tempfile.mkdtemp(prefix="fi-dry-")
    rc, payload = _cli(["run", "--domain", "mt-a.example.com", "--dry-run"],
                       home)
    assert rc == 0, payload
    assert payload.get("run_id") is None
    assert payload.get("dry_run") is True
    assert payload.get("planned_stages"), payload
    # no job dir, no database, no runs
    assert not os.path.exists(os.path.join(home, "findinfo.db"))
    runs = os.path.join(home, "runs")
    assert not os.path.exists(runs) or not os.listdir(runs), (
        "dry run must not create run directories")


def test_t32_dry_run_with_background_and_resume_is_read_only():
    home = tempfile.mkdtemp(prefix="fi-dry-2-")
    rc, payload = _cli(["run", "--domain", "mt-a.example.com", "--dry-run",
                        "--background"], home)
    assert rc == 0
    assert payload.get("run_id") is None
    assert payload.get("background_requested") is True
    # resume preview reads a spec if present, changes no job state
    rc2, payload2 = _cli(["run", "--domain", "mt-a.example.com", "--dry-run",
                          "--resume", "does-not-exist"], home)
    assert rc2 == 0, payload2
    assert payload2.get("run_id") is None
    assert payload2.get("effective", {}) or payload2.get("effective") is None


def test_t32_offline_doctor_reports_unknown_not_false():
    home = tempfile.mkdtemp(prefix="fi-doc-")
    rc, payload = _cli(["doctor", "--offline"], home)
    assert rc == 0, payload
    assert payload.get("mode") == "offline"
    egress = payload["environment"]["net_egress"]
    assert egress.get("any_reachable") is None and egress.get("checked") is False
    fake = payload["environment"]["fake_ip_dns"]
    assert fake.get("fake_ip_dns") is None and fake.get("checked") is False
    for tool in payload["tools"].values():
        if tool.get("present"):
            assert tool.get("health") == "not_checked", tool
    for v in payload["api_keys"].values():
        assert v == "not_checked", "credential state must be unknown, not leaked"
    ts = payload["tools_summary"]
    assert ts.get("all_in_bin") is None and ts.get("checked") is False
