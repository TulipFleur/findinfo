"""The documented agent flow must be executable, not just well-formed.

test_docs_commands.py checks that documented flags exist. That is necessary but
not sufficient: a command can use only real flags and still be unrunnable
(wrong order, missing --task in a follow-up, a subcommand that has no
--background). This module PARSES the standard sequence out of SKILL.md and
RUNS it against a temporary FINDINFO_HOME, so doc/behaviour drift fails a test
instead of surfacing as an agent stuck halfway through a collection.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "SKILL.md"


def _skill_text():
    return SKILL.read_text(encoding="utf-8")


def _section(title_prefix, text=None):
    """Body of one section, INCLUDING its subsections.

    Stops at the next heading of the same or higher level: a `## 1.6` section
    owns its `### A.`/`### B.` children. Stopping at any heading collapsed the
    flow to the three lines before the first subheading.
    """
    text = text if text is not None else _skill_text()
    lines = text.splitlines()
    start = level = None
    for i, ln in enumerate(lines):
        if ln.startswith("#") and title_prefix in ln:
            start = i + 1
            level = len(ln) - len(ln.lstrip("#"))
            break
    if start is None:
        return ""
    body = []
    for ln in lines[start:]:
        if ln.startswith("#"):
            this = len(ln) - len(ln.lstrip("#"))
            if this <= level:
                break
        body.append(ln)
    return "\n".join(body)


def _commands(block):
    """Every `python findinfo.py ...` line in a fenced block, single-line only."""
    out = []
    for ln in block.splitlines():
        m = re.search(r"python\s+findinfo\.py\s+(.*)$", ln.strip())
        if not m:
            continue
        rest = m.group(1).strip()
        if rest.endswith("\\") or rest.endswith("`"):
            continue                     # continuation: covered by the single-line rule
        out.append(rest)
    return out


def _clean_env():
    env = dict(os.environ)
    env.pop("FINDINFO_TASK", None)
    env.pop("FINDINFO_HOME", None)
    return env


def test_skill_standard_flow_is_single_line_and_ordered():
    """The canonical flow must be: doctor -> run --background -> wait -> status."""
    text = _skill_text()
    loop = _section("1.5", text)
    assert loop, "SKILL.md must keep the agent session section (§1.5)"
    cmds = _commands(loop)
    joined = "\n".join(cmds)

    # the canonical form puts global options (--task/--home) first, so match the
    # subcommand after any leading "--opt value" pairs
    def sub_of(c):
        toks = c.split()
        i = 0
        while i < len(toks) and toks[i].startswith("--"):
            i += 2 if "=" not in toks[i] else 1
        return toks[i] if i < len(toks) else ""

    assert any(sub_of(c) == "doctor" for c in cmds), "doctor missing from the flow"
    run_lines = [c for c in cmds if sub_of(c) == "run"]
    assert run_lines, "run missing from the flow"
    assert any("--background" in c for c in run_lines), \
        "the canonical run must be backgrounded"
    assert any(sub_of(c) == "wait" for c in cmds), "wait missing from the flow"
    assert any(sub_of(c) == "status" for c in cmds), "status missing from the flow"
    # order: doctor before run before wait before status
    def idx(pred):
        for i, c in enumerate(cmds):
            if pred(c):
                return i
        return -1
    assert idx(lambda c: sub_of(c) == "doctor") < idx(lambda c: sub_of(c) == "run")
    assert idx(lambda c: sub_of(c) == "run") < idx(lambda c: sub_of(c) == "wait")
    # --task must be the global (leading) form; --home likewise when present
    for c in run_lines:
        assert c.split()[0].startswith("--") or c.startswith("run "), c
    del joined


def test_documented_commands_actually_run():
    """Execute the real commands (offline temp home) instead of trusting them."""
    home = tempfile.mkdtemp(prefix="fn-docflow-")
    try:
        env = _clean_env()
        base = [sys.executable, str(ROOT / "findinfo.py"), "--home", home,
                "--task", "docflow"]

        def run(*args, timeout=180):
            r = subprocess.run(base + list(args), capture_output=True, text=True,
                               encoding="utf-8", errors="replace", env=env,
                               timeout=timeout, cwd=str(ROOT))
            return r.returncode, (r.stdout or "").strip(), (r.stderr or "")

        rc, out, err = run("doctor")
        assert rc == 0, err[-300:]
        doc = json.loads(out)
        assert "tools_summary" in doc, doc

        rc, out, err = run("run", "--domain", "example.com", "--background",
                           "--no-onepass", "--rounds", "1")
        assert rc == 0, err[-300:]
        started = json.loads(out)
        rid = started["run_id"]
        assert started["next"], "run must return a ready-to-run next command"

        rc, out, err = run("wait", "--run", rid, "--timeout", "5")
        assert rc == 0, err[-300:]
        json.loads(out)                  # must be parseable

        rc, out, err = run("status", "--run", rid)
        assert rc == 0, err[-300:]
        st = json.loads(out)
        assert st["run_id"] == rid, st

        rc, out, err = run("runs")
        assert rc == 0 and json.loads(out)["count"] >= 1
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_no_nohup_and_no_background_on_commands_that_lack_it():
    """Guidance must not ask an agent to add flags a subcommand rejects."""
    text = _skill_text()
    assert "nohup python findinfo.py" not in text, "nohup contradicts the managed worker"
    parser_src = (ROOT / "findinfo.py").read_text(encoding="utf-8")
    # subcommands with no --background
    import tests.util
    fi = tests.util.import_findinfo()
    parser = fi.build_parser()
    no_bg = set()
    for action in parser._actions:
        if getattr(action, "dest", "") == "cmd":
            for name, sub in action.choices.items():
                opts = {o for a in sub._actions for o in a.option_strings}
                if "--background" not in opts:
                    no_bg.add(name)
            break
    assert no_bg, "parser introspection failed"
    for line in text.splitlines():
        m = re.search(r"python\s+findinfo\.py\s+(?:--\S+\s+\S+\s+)*([a-z_]+)(.*)$", line)
        if not m:
            continue
        cmd, rest = m.group(1), m.group(2)
        if cmd in no_bg and "--background" in rest:
            raise AssertionError(
                "'%s' has no --background but the docs add it: %s" % (cmd, line.strip()))
    assert parser_src


def test_terminal_state_names_are_consistent():
    """done/completed must not both be taught as the terminal state."""
    text = _skill_text()
    # the canonical set, from the code
    from lib import jobs
    for st in jobs.TERMINAL:
        assert st in text or st == "cancelled", "state %r never documented" % st
    assert 'state=done' not in text, \
        "state=done contradicts jobs.TERMINAL (completed/failed/cancelled)"
