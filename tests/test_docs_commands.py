"""Doc/CLI consistency: every documented command must exist with those flags.

Acceptance item 10 ("Skill 中每个示例命令都对应真实可用接口"): the docs are
parsed for `python findinfo.py <cmd> <flags>` and every flag is checked against
the real argparse parser, so a doc/implementation drift fails the suite.
"""
import re
from pathlib import Path

import tests.util  # noqa: F401
from tests.util import import_findinfo

DOCS = ["SKILL.md", "README.md", "docs/TOOLS.md", "prompts/AGENT.txt"]
CMD_RE = re.compile(r"^\s*(?:\$\s*)?python findinfo\.py (?:--task \S+ )?([a-z_]+)(.*)$")
FLAG_RE = re.compile(r"(?<![-\w])(--[a-z][a-z0-9-]*)")


def _parser():
    fi = import_findinfo()
    return fi.build_parser()


def test_documented_commands_and_flags_exist():
    """Every `python findinfo.py <cmd> --flag` in the docs is real."""
    parser = _parser()
    root = Path(__file__).resolve().parent.parent
    subparsers = None
    for action in parser._actions:
        if getattr(action, "dest", "") == "cmd":
            subparsers = action.choices
            break
    assert subparsers, "no subcommands found"
    bad = []
    checked = 0
    for doc in DOCS:
        path = root / doc
        if not path.exists():
            continue
        # join backslash continuations first: a wrapped example is one command
        joined = []
        pending = ""
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pending:
                line = pending + " " + line.strip()
                pending = ""
            if line.rstrip().endswith("\\"):
                pending = line.rstrip()[:-1].strip()
                continue
            joined.append((lineno, line))
        if pending:
            joined.append((lineno, pending))
        for lineno, line in joined:
            m = CMD_RE.match(line)
            if not m:
                continue
            cmd, rest = m.group(1), m.group(2)
            if cmd.startswith("__"):
                continue
            if cmd not in subparsers:
                bad.append((doc, lineno, cmd, "unknown subcommand"))
                continue
            flags = {f for f in FLAG_RE.findall(rest)
                     if not f.startswith("--run_id") and "<" not in f}
            # --task is a global option (declared on the root parser, valid on
            # every subcommand), so accept it anywhere.
            flags.discard("--task")
            allowed = set()
            for act in subparsers[cmd]._actions:
                allowed.update(act.option_strings)
            for act in parser._actions:
                allowed.update(act.option_strings)
            for flag in sorted(flags):
                checked += 1
                if flag not in allowed:
                    bad.append((doc, lineno, cmd, flag))
    assert not bad, "docs reference capabilities that do not exist: " + repr(bad[:10])
    assert checked >= 12, "expected to check a meaningful number of flags, got " + str(checked)


def test_no_shell_background_in_standard_flow():
    """The Agent flow must not need nohup/&/bash wrappers for long tasks."""
    root = Path(__file__).resolve().parent.parent
    for doc in ("SKILL.md", "prompts/AGENT.txt", "README.md"):
        text = (root / doc).read_text(encoding="utf-8")
        assert "nohup python findinfo.py" not in text, doc + " still tells the agent to use nohup"
        assert "findinfo.py run" in text, doc + " must show the python run entry point"


def test_docs_document_wait_and_status_run():
    root = Path(__file__).resolve().parent.parent
    skill = (root / "SKILL.md").read_text(encoding="utf-8")
    tools_doc = (root / "docs/TOOLS.md").read_text(encoding="utf-8")
    for needle in ("wait --run", "status --run", "run --domain", "runs"):
        assert needle in skill, "SKILL.md missing " + needle
    for needle in ("## wait", "## cancel", "## runs", "## status"):
        assert needle in tools_doc, "docs/TOOLS.md missing " + needle
