"""P0 regressions: --task placement and clean --all confirmation.

Two failure modes that made an agent fail while following the docs:

1. `run --task X` (the form every doc used) hit argparse prefix matching and
   died with "argument --task-timeout: invalid float value: 'X'" -- rc=2 with
   an error pointing at the wrong flag. The global form `--task X run` worked,
   so the docs and the code disagreed with each other.
2. `clean --all` emptied the whole asset graph (shared by every engagement)
   with no confirmation and no preview.

Both are now accepted, the docs use one canonical form, and neither can
regress without a test failing.
"""
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core, import_findinfo

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- --task forms
def _parse(fi, argv):
    """Parse argv with the real parser; returns the namespace."""
    return fi.build_parser().parse_args(argv)


def test_task_after_subcommand_is_accepted():
    """`run --task X` must parse (it used to die on --task-timeout)."""
    fi = import_findinfo()
    ns = _parse(fi, ["run", "--domain", "example.com", "--task", "proj"])
    assert ns.task == "proj", "late --task did not reach the namespace: %r" % (ns.task,)
    assert ns.domain == ["example.com"]


def test_task_before_subcommand_is_accepted():
    """`--task X run` (the documented global form) must keep working.

    This is the case a naive fix breaks: a real default on the subparser
    option would overwrite the value the global option already parsed.
    """
    fi = import_findinfo()
    ns = _parse(fi, ["--task", "proj", "run", "--domain", "example.com"])
    assert ns.task == "proj"


def test_task_equals_form_is_accepted():
    fi = import_findinfo()
    ns = _parse(fi, ["run", "--domain", "example.com", "--task=proj"])
    assert ns.task == "proj"


def test_task_after_subcommand_on_every_command():
    """The regression was command-wide: doctor/assets said 'unrecognized'."""
    fi = import_findinfo()
    for argv in (["doctor", "--task", "proj"],
                 ["assets", "--task", "proj"],
                 ["status", "--task", "proj"]):
        ns = _parse(fi, argv)
        assert ns.task == "proj", argv


def test_task_timeout_is_not_shadowed():
    """The alias must not swallow the real --task-timeout flag."""
    fi = import_findinfo()
    ns = _parse(fi, ["run", "--domain", "x", "--task-timeout", "30"])
    assert ns.task in (None, ""), "bare --task-timeout leaked into task: %r" % (ns.task,)
    assert ns.task_timeout == 30.0


def test_subcommand_guard_matches_the_real_parser():
    """_SUBCOMMANDS gates what may follow a bare --task; it must not drift."""
    import argparse as _ap
    fi = import_findinfo()
    parser = fi.build_parser()
    real = set()
    for action in parser._actions:
        if isinstance(action, _ap._SubParsersAction):
            real = set(action.choices)
            break
    assert real, "no subparser action found"
    assert fi._SUBCOMMANDS == real, (
        "_SUBCOMMANDS drifted: missing=%r extra=%r"
        % (sorted(real - set(fi._SUBCOMMANDS)), sorted(set(fi._SUBCOMMANDS) - real)))


def test_task_prescan_handles_both_positions():
    """The pre-import scan is what makes the late form work; it must find both."""
    fi = import_findinfo()
    assert fi._prescan_task(["findinfo.py", "run", "--task", "a"]) == "a"
    assert fi._prescan_task(["findinfo.py", "--task", "a", "run"]) == "a"
    assert fi._prescan_task(["findinfo.py", "--task=a", "run"]) == "a"
    # a value that looks like a flag must not swallow the subcommand
    assert fi._prescan_task(["findinfo.py", "--task", "run", "doctor"]) == ""
    # absent everywhere
    assert fi._prescan_task(["findinfo.py", "doctor"]) == ""


def test_docs_put_task_before_the_subcommand():
    """One canonical form in the docs: --task right after the program name.

    The late form now works, but the docs should not teach a dependency on
    argparse prefix matching. Every physical line containing both
    `findinfo.py` and `--task` must place --task immediately after the program.
    """
    bad = []
    for doc in ("SKILL.md", "README.md", "docs/TOOLS.md", "prompts/AGENT.txt"):
        p = ROOT / doc
        if not p.exists():
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if "findinfo.py" not in line or "--task" not in line:
                continue
            tail = line.split("findinfo.py", 1)[1].lstrip()
            if not tail.startswith("--task"):
                bad.append((doc, i, line.strip()[:90]))
    assert not bad, "docs put --task after the subcommand: " + repr(bad[:6])


def test_docs_continuation_lines_carry_no_task():
    """A multi-line shell command may only carry --task on its first line.

    Only backslash-continued command lines are considered: prose that mentions
    `--task` inline (tables, rules, warnings) is not a command and must not be
    mistaken for one.
    """
    bad = []
    for doc in ("SKILL.md", "docs/TOOLS.md", "prompts/AGENT.txt"):
        p = ROOT / doc
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8").splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if "findinfo.py" not in line or not line.rstrip().endswith("\\"):
                i += 1
                continue
            # assemble the whole continued command
            parts = [line]
            j = i
            while lines[j].rstrip().endswith("\\") and j + 1 < len(lines):
                j += 1
                parts.append(lines[j])
            head = parts[0].split("findinfo.py", 1)[1].lstrip()
            if not head.startswith("--task"):
                for k, part in enumerate(parts[1:], 1):
                    if "--task" in part:
                        bad.append((doc, i + k + 1, part.strip()[:80]))
            i = j + 1
    assert not bad, "continuation line carries --task under a late-form command: " + repr(bad[:6])


# ---------------------------------------------------------------- clean --all
def _seed(core, *domains):
    store = core.Store()
    try:
        for d in domains:
            store.upsert_asset("domain", d, source="dnsx", confidence=0.8)
    finally:
        store.close()


def _count(core):
    store = core.Store()
    try:
        return store.count_assets()
    finally:
        store.close()


def _clean(argv):
    """Run cmd_clean with parsed args; returns the one-line JSON payload."""
    fi = import_findinfo()
    args = fi.build_parser().parse_args(["clean"] + argv)
    buf = io.StringIO()
    with redirect_stdout(buf):
        args.func(args)
    return json.loads(buf.getvalue().strip().splitlines()[-1])


def test_clean_all_without_yes_refuses_and_keeps_data():
    core = fresh_core()
    _seed(core, "a.example.com", "b.example.com")
    payload = _clean(["--all"])
    assert payload.get("deleted") is False
    assert "error" in payload
    assert payload["would_delete"]["assets"] == 2
    assert _count(core).get("domain") == 2, "data was deleted without --yes"


def test_clean_all_dry_run_previews_without_deleting():
    core = fresh_core()
    _seed(core, "a.example.com")
    payload = _clean(["--all", "--dry-run"])
    assert payload.get("dry_run") is True
    assert payload.get("deleted") is False
    assert payload["assets"] == 1
    assert _count(core).get("domain") == 1, "dry-run deleted data"


def test_clean_all_with_yes_deletes():
    core = fresh_core()
    _seed(core, "a.example.com", "b.example.com")
    payload = _clean(["--all", "--yes"])
    assert payload.get("deleted") is True
    assert payload["assets"] == 2
    assert not _count(core), "store not emptied after --all --yes"


def test_clean_match_dry_run_agrees_with_real_run():
    core = fresh_core()
    _seed(core, "a.example.com", "b.other.com")
    preview = _clean(["--match", "example.com", "--dry-run"])
    assert preview.get("dry_run") is True
    assert _count(core).get("domain") == 2, "dry-run deleted data"
    real = _clean(["--match", "example.com"])
    assert real["assets"] == preview["assets"], (
        "preview said %s, real run deleted %s" % (preview["assets"], real["assets"]))
