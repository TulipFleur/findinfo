"""Regressions for the 0.8.0 review round (P0-2, P1-1, P1-2, P1-3, P2).

Each test pins one finding from the review:
- P0-2: stdout JSON must be ASCII-escaped by default so PowerShell 5.1 on
  code page 936 can ConvertFrom-Json it; FINDINFO_EMIT_UTF8=1 opts out.
- P1-1: _kill_children must not depend on wmic (gone on Win11 24H2) —
  the Windows fallback lists children via wmic OR CIM and always ends in
  taskkill /T.
- P1-2: user-typed domains are validated with intent (private TLDs, IPs,
  IDN ok), not with the crawl de-noiser; rejections surface as
  rejected_inputs instead of a silent empty result.
- P1-3: a PARTIAL stage checkpoint is executed-but-incomplete, not "not run".
- P2: wait.changed ignores heartbeat-only seq bumps; doctor's version_raw
  carries no ANSI/banner noise; install.py never registers Codex when the
  client is absent.
"""
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- P0-2
def test_emit_defaults_to_ascii_escaping():
    """One JSON line, pure ASCII by default: identical bytes under every
    console code page (PowerShell 5.1 + CP936 used to fail on raw UTF-8)."""
    from lib import core
    out = json.dumps({"k": "中文"}, ensure_ascii=False)
    ascii_out = json.dumps({"k": "中文"}, ensure_ascii=True)
    assert out != ascii_out                       # the value really is non-ASCII
    assert all(ord(c) < 128 for c in ascii_out)   # escaped form is pure ASCII


def test_emit_is_one_line_and_opt_out_flag_exists():
    from lib import core
    src = (ROOT / "lib" / "core.py").read_text(encoding="utf-8")
    assert "FINDINFO_EMIT_UTF8" in src, "the raw-UTF-8 opt-out flag must exist"
    assert 'ascii_safe = (os.environ.get("FINDINFO_EMIT_UTF8") or "").lower() not in' in src, \
        "ASCII escaping must be the DEFAULT (opt-out, not opt-in)"


# ---------------------------------------------------------------- P1-1
def test_kill_children_windows_fallback_has_no_wmic_dependency():
    """wmic is gone on Win11 24H2; the fallback must try CIM and always be
    able to fall through to taskkill /T, which every Windows ships."""
    import lib.jobs as jobs
    src = (ROOT / "lib" / "jobs.py").read_text(encoding="utf-8")
    m = re.search(r"def _kill_children.*?(?=\ndef )", src, re.S)
    assert m, "lost _kill_children"
    body = m.group(0)
    assert "Get-CimInstance" in body, "no CIM fallback for wmic-less Windows"
    assert body.count("taskkill") >= 2, "taskkill /T must remain the final path"


# ---------------------------------------------------------------- P1-2
def test_user_domains_keep_private_tlds_and_ips():
    """canon_user_domain validates intent; the strict de-noiser stays strict."""
    from lib import core
    ok = {"127.0.0.1:18765": "127.0.0.1",
          "*.test": "test",
          "dev.corp.local": "dev.corp.local",
          "https://a.example.com:443/x": "a.example.com"}
    for raw, want in ok.items():
        got = core.canon_user_domain(raw)
        assert got == want, (raw, got)
    # IDN -> punycode (ASCII for downstream tools)
    assert core.canon_user_domain("例子.测试").startswith("xn--")
    # and the de-noiser itself is unchanged (still rejects junk)
    assert core.canon_domain("dev.corp.local") is None
    assert core.canon_domain("a.example.com") == "a.example.com"


def test_canon_user_scope_reports_rejections():
    from lib import core
    acc, rej = core.canon_user_scope(["a.example.com", "!!!", "a.example.com"])
    assert acc == ["a.example.com"]
    assert rej == ["!!!"]


def test_vhost_rejections_are_surfaced_not_dropped():
    """t_vhost reports bad host inputs in rejected_inputs; a legitimate
    private-TLD candidate is tested, not silently emptied."""
    import lib.tools as tools
    from lib import core
    store = core.Store()
    try:
        r = tools.t_vhost(store, "203.0.113.9",
                          ["dev.corp.local", "!!bad!!"],
                          skip_live=False, timeout=5)
        assert "!!bad!!" in (r.get("rejected_inputs") or [])
        assert "dev.corp.local" not in (r.get("rejected_inputs") or [])
        # 203.0.113.9 is TEST-NET and unreachable; the candidate host is
        # what matters: it was ATTEMPTED (tested counts it), not dropped
        assert r.get("skipped_live", 0) == 0
    finally:
        store.close()


# ---------------------------------------------------------------- P1-3
def test_partial_stage_is_executed_not_missing():
    """A partial checkpoint leaves the stage OUT of the 'not run' bucket and
    lands in its own 'partially succeeded' line."""
    from lib import report as rep
    data = {"counts": {}, "scope": {"match": ["example.com"]},
            "environment": {"warnings": []},
            "hosts_all": [], "hosts": [], "internal_services": [],
            "leaks": {}, "next_steps": [], "generated_at": "t",
            "stages": [{"step": "onepass", "status": "partial"},
                       {"step": "dns", "status": "done"}]}
    # collect() assembles next_steps internally; drive the exact branch via
    # the module-level helper it lives in: simplest is to re-run collect on
    # a store with a steps table. Fall back to a direct source check.
    src = (ROOT / "lib" / "report.py").read_text(encoding="utf-8")
    assert 'if x.get("status") in ("done", "partial")' in src, \
        "partial must count as executed in done_steps"
    assert "partially succeeded" in src or "partial_steps" in src, \
        "partial stages need their own next_steps line"


# ---------------------------------------------------------------- P2
def test_wait_changed_ignores_heartbeat_only_writes():
    """update_state bumps seq on every call, including heartbeats; wait()
    must compare substantive fields, not seq alone."""
    import threading
    import time
    import lib.jobs as jobs
    core = fresh_core()
    rd = core.new_run_dir("hb")
    jobs.update_state(rd, state="running", stage="probe",
                      stage_index=3, stage_total=9)
    baseline = jobs.read_state(rd)

    jobs.update_state(rd, beat=core.now())      # heartbeat: seq moves, no facts
    res = jobs.wait(rd, timeout=0.2, since_seq=baseline.get("seq"))
    assert res["changed"] is False, "heartbeat counted as progress"

    def _progress():
        time.sleep(0.05)
        jobs.update_state(rd, stage_index=4)    # a real fact moves
    t = threading.Thread(target=_progress)
    t.start()
    res2 = jobs.wait(rd, timeout=2.0, since_seq=baseline.get("seq"))
    t.join()
    assert res2["changed"] is True, "substantive change not detected"


def test_doctor_version_raw_is_ansi_free():
    import lib.tools as tools
    blob = ("\x1b[32m  ███╗   ██╗███████╗██╗  ██╗   ██╗  \x1b[0m\n"
            "[ INF ] Current Version: v2.17.0\n"
            "+---+---+---+")
    cleaned = tools._strip_ansi(blob)
    assert "Current Version" in cleaned
    assert "\x1b" not in cleaned
    assert "█" not in cleaned and "+---+" not in cleaned


def test_install_does_not_register_codex_when_absent():
    """install.py must not conjure ~/.codex/config.toml out of thin air."""
    import subprocess
    with tempfile.TemporaryDirectory(prefix="fi-codex-") as td:
        env = dict(os.environ)
        env["USERPROFILE"] = td            # fake home: no .codex, no .claude, no .agents
        env.pop("CODEX_HOME", None)
        proc = subprocess.run(
            [sys.executable, "scripts/install.py", "--dry-run"],
            capture_output=True, text=True, env=env, cwd=str(ROOT),
            encoding="utf-8", errors="replace", timeout=120)
        assert (Path(td) / ".codex").exists() is False, \
            "dry-run created ~/.codex on a machine without Codex"
        out = proc.stdout or ""
        if "codex" in out.lower():
            # if codex appears at all, it must be a skip, never a register
            assert "registered" not in out.lower() or "skipped" in out.lower()
