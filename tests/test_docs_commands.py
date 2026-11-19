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
CMD_RE = re.compile(r"^\s*(?:\$\s*)?(?:[a-z_]+\s+)?python findinfo\.py (?:--task \S+ )?([a-z_]+)(.*)$")
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
        assert "findinfo.py" in text and " run " in text, doc + " must show run"


def test_docs_document_wait_and_status_run():
    root = Path(__file__).resolve().parent.parent
    skill = (root / "SKILL.md").read_text(encoding="utf-8")
    tools_doc = (root / "docs/TOOLS.md").read_text(encoding="utf-8")
    for needle in ("wait --run", "status --run", "run --domain", "runs"):
        assert needle in skill, "SKILL.md missing " + needle
    for needle in ("## wait", "## cancel", "## runs", "## status"):
        assert needle in tools_doc, "docs/TOOLS.md missing " + needle


# ---------------------------------------------------------------- drift guards

DOC_PATHS = ["SKILL.md", "README.md", "prompts/AGENT.txt"] + [
    "docs/" + p for p in (
        "TOOLS.md", "LINUX.md", "CLIENTS.md", "API-KEYS.md", "DEVELOPMENT.md",
        "DATA-MODEL.md", "TROUBLESHOOTING.md",
    )
]

# Phrases that legitimately mention a flag outside a `python findinfo.py` line
# but are not claims about this CLI (third-party tools, shell builtins, config).
_FOREIGN_FLAGS = frozenset("""
--progress --no-check-certificate --connect-timeout --max-time --insecure
--cap-add --cap-drop --network --rm -v --add-host --env-file
--run --timeout --resume --force-stage --task-timeout --no-icp --no-onepass
# flags of external tools the docs quote verbatim (curl, useradd, ...)
--resolve --shell --home --system --proxy --header --user-agent --data --output
--root --user --config --cacert --capath --cert --keep --match --all --vacuum
""" .split())


def _root_and_subparsers():
    parser = _parser()
    sub = None
    for action in parser._actions:
        if getattr(action, "dest", "") == "cmd":
            sub = action.choices
            break
    assert sub, "no subcommands found"
    return parser, sub


def _all_flags(parser, sub, cmd=None):
    """Every option string accepted on the root parser, optionally + one subcommand."""
    allowed = set()
    for act in parser._actions:
        allowed.update(act.option_strings)
    if cmd and cmd in sub:
        for act in sub[cmd]._actions:
            allowed.update(act.option_strings)
    return allowed


def _script_flags() -> set:
    """Flags accepted by the shipped helper scripts (not the Python CLI).

    The docs legitimately show `scripts/install.py --verify`,
    `setup-linux.sh --dry-run` and `findinfo.sh -t ...`; none of those are
    claims about findinfo.py subcommands, so collect their flags from source.
    """
    root = Path(__file__).resolve().parent.parent
    text = ""
    for rel in ("scripts/findinfo.sh", "scripts/install.py",
                "scripts/setup-linux.sh", "scripts/build-onepass.sh",
                "scripts/build-enscan.sh"):
        f = root / rel
        if f.exists():
            text += f.read_text(encoding="utf-8")
    flags = set(FLAG_RE.findall(text))
    flags |= set(re.findall(r"(?<![\w-])(-[a-zA-Z])(?![\w-])", text))
    return flags

def _is_wrapper_line(line: str) -> bool:
    return "findinfo.sh" in line


def test_every_flag_in_prose_is_known_to_some_subcommand():
    """A --flag written inside a command-ish code span must exist in the CLI.

    The line-anchored test only sees `python findinfo.py ...` lines, so prose
    like "entity/crawl/... 用 `--tool-timeout` 设上限" slipped through even when
    the flag did not exist. Scanning every flag in every sentence, however,
    drags in flags of other tools (curl --resolve, systemctl --now) and even
    flags the docs explicitly say were REMOVED ("setup-linux.sh 不再接受
    --prefix") -- neither is a claim about this CLI.

    So the scan is limited to backtick code spans, which is where the docs put
    commands and option names, and known-foreign flags are excluded.
    """
    root = Path(__file__).resolve().parent.parent
    parser, sub = _root_and_subparsers()
    known = _FOREIGN_FLAGS | _script_flags()
    for _c in sub:
        known |= _all_flags(parser, sub, _c)
    span_re = re.compile(r"`([^`]+)`")
    bad = []
    for doc in DOC_PATHS:
        path = root / doc
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("|"):
                continue  # table cells list options per stage in shorthand
            for span in span_re.findall(line):
                if span.startswith("-") and "-" not in span.lstrip("-"):
                    continue  # a bare flag being introduced on its own
                for flag in FLAG_RE.findall(span):
                    if flag in known or flag.startswith("--run_id"):
                        continue
                    if span.rstrip("`").endswith("..."):
                        continue  # placeholder like --no-..., not a flag name
                        continue
                    bad.append((doc, lineno, flag, span.strip()[:60]))
    assert not bad, ("docs mention flags the CLI does not accept: " + repr(bad[:8]))


def test_prose_flag_matches_the_subcommand_it_names():
    """When the docs write `cmd --flag` adjacently, that subcommand must accept it.

    Direct regression guard for the original bug: prompts/AGENT.txt told agents
    to bound entity/crawl/probe/... with --tool-timeout while only `run`
    defined it, so those commands died with rc=2.

    Only the adjacent shape counts as evidence. Merely mentioning a stage and,
    elsewhere in the sentence, an unrelated option ("install.py --verify will
    run doctor") says nothing about that stage options; flagging those was
    noise. Real typos are still caught by the "flag exists somewhere" test.
    """
    root = Path(__file__).resolve().parent.parent
    parser, sub = _root_and_subparsers()
    wrapper = _script_flags()
    names = sorted(sub, key=len, reverse=True)
    adjacent = re.compile(r"(?<![\w-])(" + "|".join(names) + r")(\s+--[a-z][a-z0-9-]*)*")
    bad = []
    for doc in DOC_PATHS:
        path = root / doc
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _is_wrapper_line(line):
                continue
            cm = CMD_RE.match(line)
            if cm and cm.group(1) in sub:
                continue  # literal command, already validated by the anchored test
            for m in adjacent.finditer(line):
                cmd = m.group(1)
                flags = FLAG_RE.findall(m.group(0))
                for flag in flags:
                    if flag in _FOREIGN_FLAGS or flag.startswith("--run_id"):
                        continue
                    if flag in _all_flags(parser, sub, cmd) or flag in wrapper:
                        continue
                    bad.append((doc, lineno, cmd, flag, m.group(0)[:60]))
    assert not bad, ("docs pair a subcommand with a flag it rejects: " + repr(bad[:8]))



def test_findinfo_sh_flags_exist():
    """Flags documented for the shell wrapper must be accepted by its own parser."""
    root = Path(__file__).resolve().parent.parent
    script = (root / "scripts" / "findinfo.sh").read_text(encoding="utf-8")
    # the while-loop cases are the source of truth for accepted flags
    case_flags = set(re.findall(r"(?:^|\s)(--[a-z][a-z0-9-]*)\)", script, re.M))
    case_flags |= set(re.findall(r"(-[a-z])\)", script, re.M))
    doc_flags = {f for f in FLAG_RE.findall(
        (root / "SKILL.md").read_text(encoding="utf-8"))}
    bad = []
    for doc in DOC_PATHS:
        path = root / doc
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not _is_wrapper_line(line):
                continue
            for flag in FLAG_RE.findall(line):
                if flag in _FOREIGN_FLAGS:
                    continue
                if flag not in case_flags:
                    bad.append((doc, lineno, flag))
    assert not bad, ("findinfo.sh does not accept documented flags: " + repr(bad[:8]))


def test_docs_do_not_hardcode_the_tool_count():
    """The tool count lives in doctor; docs must not restate it.

    tlsx/gau/ffuf and later jsluice were removed, and each time the docs kept
    saying "13 个工具". Pointing at tools_summary.total keeps them true.

    The onepass sentence "15 个上游源不会算成 15 个工具" is about *sources*, so
    it is exempt: it neither states nor implies the doctor tool count.
    """
    root = Path(__file__).resolve().parent.parent
    bad = []
    for doc in DOC_PATHS:
        path = root / doc
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "\u4e0d\u4f1a\u7b97\u6210" in line:
                continue          # onepass source-count sentence, not a tool claim
            for m in re.finditer(r"(\d+)\s*\u4e2a\s*\u5de5\u5177", line):
                bad.append((doc, lineno, m.group(0)))
    assert not bad, ("docs hardcode the tool count; use tools_summary.total: "
                     + repr(bad[:8]))

def test_docs_do_not_describe_a_path_fallback():
    """core.tool() only looks in bin/<platform>/; docs must not promise PATH.

    The PATH fallback was removed, but SKILL.md kept telling agents that
    `source: path` meant "borrowed from PATH" and that tool_missing could mean
    "not in PATH either".
    """
    root = Path(__file__).resolve().parent.parent
    banned = [
        "source: bundle|path",
        "source: path",
    ]
    bad = []
    for doc in DOC_PATHS:
        path = root / doc
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for needle in banned:
            if needle in text:
                bad.append((doc, needle))
    assert not bad, ("docs still describe a PATH fallback: " + repr(bad))


def test_single_stage_commands_expose_tool_timeout():
    """Every stage that shells out must accept --tool-timeout.

    prompts/AGENT.txt told agents to bound single-stage commands with
    --tool-timeout while only `run` defined it, so those commands died with rc=2.
    """
    _parser_root, sub = _root_and_subparsers()
    stage_cmds = [
        "entity", "certs", "icp", "passive", "subs", "dns", "probe",
        "ipagg", "ports", "vhost", "crawl", "extract", "brute",
    ]
    missing = []
    for cmd in stage_cmds:
        assert cmd in sub, "subcommand disappeared: " + cmd
        if "--tool-timeout" not in _all_flags(_parser_root, sub, cmd):
            missing.append(cmd)
    assert not missing, ("these single-stage commands reject --tool-timeout: "
                         + repr(missing))


def test_docs_point_agents_at_the_brief_not_the_full_digest():
    """report.json is 600 KB on a real target; the brief is the agent entry.

    The docs used to tell agents to read report.json and slice it with jq --
    a tool Windows does not ship, and a file an agent should never open whole.
    """
    root = Path(__file__).resolve().parent.parent
    must_mention = ["SKILL.md", "prompts/AGENT.txt"]
    for doc in must_mention:
        text = (root / doc).read_text(encoding="utf-8")
        # The entry point is the `brief` subcommand (library -> stdout, no
        # file); report.brief.json only appears with --with-brief, so
        # requiring the file name would force agents back to a file path.
        assert "brief" in text, doc + " never mentions the brief entry point"
        assert "findinfo.py brief" in text or "brief --match" in text, (
            doc + " never shows the brief command")

    # jq is not installed on Windows and the brief makes slicing unnecessary
    bad = []
    for doc in DOC_PATHS:
        path = root / doc
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        if "jq" in text:
            bad.append(doc)
    assert not bad, "docs still depend on jq: " + repr(bad)


def test_brief_flags_exist():
    """The docs and the CLI must agree on the brief knobs."""
    p, subs = _root_and_subparsers()
    flags = _all_flags(p, subs, "report")
    for flag in ("--brief-top", "--brief-max-bytes"):
        assert flag in flags, "report is missing " + flag + ": " + repr(sorted(flags))

# ------------------------------------------------- prompts/AGENT.txt contract
#
# prompts/AGENT.txt is a workflow template: a fresh agent copies its commands
# verbatim. So every command there has to be executable as written, and has to
# obey the file's own hard rules (--task on every command, a scope argument on
# every --from-store read). These checks are stricter than the general doc
# tests on purpose -- they are about *this* file only.

AGENT_TXT = "prompts/AGENT.txt"
# Subcommands that read back from the shared asset graph instead of collecting.
_SCOPE_ARG = {
    "subs": "--scope", "passive": "--scope", "icp": "--scope", "dns": "--scope",
    "probe": "--domain", "crawl": "--domain", "extract": "--domain",
    "vhost": "--domain", "ports": "--domain", "brute": "--domain",
}
_AGENT_CMD_RE = re.compile(
    r"python findinfo\.py (?:(?!--)\S+ )*?([a-z][a-z_]*)(?= |$)")


def _agent_commands():
    """Yield (lineno, cmd, tail) for every python findinfo.py line in AGENT.txt.

    Only real command lines count: the text fences hold diagrams and the final
    template, and comment lines inside bash fences start with '#'.
    """
    root = Path(__file__).resolve().parent.parent
    text = (root / AGENT_TXT).read_text(encoding="utf-8")
    fence = ""
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            fence = stripped[3:].strip()
            continue
        if fence not in ("", "bash", "sh"):
            continue
        if "python findinfo.py" not in line:
            continue
        if stripped.startswith("#") or stripped.startswith("|"):
            continue
        m = _AGENT_CMD_RE.search(line)
        if not m:
            continue
        cmd = m.group(1)
        yield lineno, cmd, line[m.end():]


def test_agent_txt_commands_are_executable():
    """Every command in the template names a real subcommand and real flags."""
    root = Path(__file__).resolve().parent.parent
    parser, sub = _root_and_subparsers()
    bad = []
    for lineno, cmd, tail in _agent_commands():
        if cmd not in sub:
            bad.append((lineno, "unknown subcommand " + cmd))
            continue
        allowed = _all_flags(parser, sub, cmd) | _script_flags()
        for flag in FLAG_RE.findall(tail):
            if flag in allowed or flag.startswith("--run_id"):
                continue
            bad.append((lineno, cmd + " rejects " + flag))
    assert not bad, (AGENT_TXT + " contains commands that would fail: "
                     + repr(bad[:10]))


def test_agent_txt_every_command_carries_task():
    """Hard rule 3 of the template says every command isolates its task."""
    bad = []
    for lineno, cmd, tail in _agent_commands():
        if "--task" not in " ".join([cmd, tail]):
            bad.append((lineno, cmd))
    assert not bad, ("commands in " + AGENT_TXT + " omit --task: " + repr(bad[:10]))


def test_agent_txt_from_store_is_scoped():
    """An unscoped --from-store read pulls in other engagements' assets.

    Hard rule 4 says so, and the template used to violate it on every path.
    """
    bad = []
    for lineno, cmd, tail in _agent_commands():
        if "--from-store" not in tail:
            continue
        want = _SCOPE_ARG.get(cmd)
        if not want:
            bad.append((lineno, cmd + " has no scope argument at all"))
            continue
        if want not in tail:
            bad.append((lineno, cmd + " --from-store without " + want))
    assert not bad, (AGENT_TXT + " reads the store unscoped: " + repr(bad[:10]))


def test_agent_txt_has_no_shell_only_constructs():
    """The template must run on any host: no bash loop, no continuation, no jq."""
    root = Path(__file__).resolve().parent.parent
    lines = (root / AGENT_TXT).read_text(encoding="utf-8").splitlines()
    bad = []
    for lineno, line in enumerate(lines, 1):
        if line.rstrip().endswith("\\") and not line.lstrip().startswith("|"):
            bad.append((lineno, "backslash continuation"))
        if re.match(r"^\s*for \w+ in ", line) and "python -c" not in line:
            bad.append((lineno, "bash for loop"))
            continue
        if re.search(r"(?<![\w-])jq(?![\w-])", line):
            bad.append((lineno, "jq"))
    assert not bad, (AGENT_TXT + " depends on shell-only syntax: " + repr(bad[:10]))


def test_agent_txt_keeps_brute_in_the_active_section():
    """brute sends raw DNS packets; the template once filed it under "passive"."""
    root = Path(__file__).resolve().parent.parent
    lines = (root / AGENT_TXT).read_text(encoding="utf-8").splitlines()
    section = ""
    bad = []
    seen = False
    for lineno, line in enumerate(lines, 1):
        if line.startswith("#"):
            section = line.strip("# ").strip()
        if "python findinfo.py" in line and " brute " in line:
            seen = True
            if "主动" not in section:
                bad.append((lineno, section))
        if "被动" in line and "brute" in line:
            bad.append((lineno, "brute described as passive: " + line.strip()[:60]))
    assert seen, AGENT_TXT + " no longer shows the brute command at all"
    assert not bad, (AGENT_TXT + " files brute under a non-active section: "
                     + repr(bad[:6]))


def test_agent_txt_places_authorization_before_active_stages():
    """No active stage may be reachable without the authorization gate."""
    root = Path(__file__).resolve().parent.parent
    text = (root / AGENT_TXT).read_text(encoding="utf-8")
    gate = text.find("授权与范围确认")
    assert gate != -1, AGENT_TXT + " lost its authorization gate section"
    for needle in ("run --domain {{TARGET}} --active", "--active --vhost --crawl"):
        pos = text.find(needle)
        assert pos != -1, AGENT_TXT + " no longer shows " + needle
        assert pos > gate, AGENT_TXT + " runs an active stage before the gate: " + needle


# ---------------------------------------------------------------- size budgets

# SKILL.md is loaded into the agent's context on every invocation and
# AGENT.txt is pasted in whole, so both have a hard size budget. The numbers are
# deliberately explicit: "it grew a bit" is how 25 KB became 28 KB.
SKILL_BUDGET = 15 * 1024
AGENT_BUDGET = 12 * 1024
DESCRIPTION_BUDGET = 1024


def _size_of(rel):
    """Logical size of a doc: text with LF endings.

    The checkout converts to CRLF on Windows (core.autocrlf=true), which
    adds one byte per line; measuring bytes on disk would make the budget
    depend on the host instead of on how much text the agent must read.
    """
    root = Path(__file__).resolve().parent.parent
    text = (root / rel).read_text(encoding="utf-8")
    return len(text.replace("\r\n", "\n").encode("utf-8"))


def test_skill_md_stays_within_its_context_budget():
    size = _size_of("SKILL.md")
    assert size <= SKILL_BUDGET, (
        "SKILL.md is " + str(size) + " bytes, over the " + str(SKILL_BUDGET)
        + "-byte budget; move detail into docs/TOOLS.md and leave a link")


def test_agent_template_stays_within_its_paste_budget():
    size = _size_of(AGENT_TXT)
    assert size <= AGENT_BUDGET, (
        AGENT_TXT + " is " + str(size) + " bytes, over the " + str(AGENT_BUDGET)
        + "-byte budget; put rules that also live in SKILL.md behind a pointer")


def test_skill_description_fits_the_client_limit():
    """Clients cap the frontmatter description; over-long ones get truncated."""
    import yaml  # noqa: F401  (only to confirm the dependency exists)

    root = Path(__file__).resolve().parent.parent
    text = (root / "SKILL.md").read_text(encoding="utf-8")
    assert text.startswith("---"), "SKILL.md must open with YAML frontmatter"
    front = text.split("---", 2)[1]
    desc = ""
    for line in front.splitlines():
        if line.startswith("description:"):
            desc = line.split(":", 1)[1].strip()
    assert desc, "SKILL.md frontmatter has no description"
    assert len(desc) <= DESCRIPTION_BUDGET, (
        "description is " + str(len(desc)) + " characters, over "
        + str(DESCRIPTION_BUDGET))
