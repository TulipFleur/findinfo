"""The release zip and the --copy install ship the same files.

Two ignore lists is how they drifted once: install.py excluded the glob
"config.yaml", which dropped the eight tool directories' default configs,
while the zip packed them. These tests pin the single manifest and prove a
real --copy produces exactly it.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import tests.util  # noqa: F401  (isolate FINDINFO_HOME before lib.* imports)

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path):
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    # match the file stem, so build-release.py's own "import shipped"
    # resolves to the same module object these tests loaded (private keys
    # would make two copies and hide real duplication)
    key = path.stem.replace("-", "_")
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


def _shipped():
    return _load("shipped", SCRIPTS / "shipped.py")


def _build_release():
    return _load("build-release", SCRIPTS / "build-release.py")


def _install():
    return _load("install", SCRIPTS / "install.py")


def _host():
    return "windows" if os.name == "nt" else "linux"


def test_there_is_exactly_one_manifest_rule():
    """build-release re-exports the shared module instead of keeping its own."""
    br = _build_release()
    sh = _shipped()
    assert br.shipped_files("windows", ROOT) == sh.shipped_files("windows", ROOT)
    assert br.shipped_files("linux", ROOT) == sh.shipped_files("linux", ROOT)
    for attr in ("PLATFORM_ONLY", "DEV_DIRS", "DEV_FILES", "SECRETS"):
        assert getattr(br, attr) == getattr(sh, attr), attr + " drifted"
    # DEV_FILES is rebound in shipped.py after the tool-config tuple is built,
    # so identity is only meaningful for the manifest function itself.
    assert br.shipped_files is sh.shipped_files, "two manifest functions"


def test_install_copy_ships_the_manifest_file_for_file(tmp_path=None):
    """The whole point: what --copy writes equals what the zip carries."""
    inst = _install()
    sh = _shipped()
    platform = _host()
    want = sh.shipped_files(platform, ROOT)

    dst = Path(tmp_path) / "copy"
    inst._install_one("agents", dst, "copy", force=False, dry=False)

    got = []   # sorted the same way the manifest is
    for p in sorted(dst.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(dst).as_posix()
        if rel == inst.MARKER:      # install bookkeeping, not skill content
            continue
        got.append(rel)
    assert sorted(got) == sorted(want), ("copy install differs from the release manifest: "
                         "missing=" + repr(sorted(set(want) - set(got)))
                         + " extra=" + repr(sorted(set(got) - set(want))))


def test_install_copy_leaves_no_private_ignore_list():
    """A second copy of the rule is the bug; the module must be the only one."""
    src = (SCRIPTS / "install.py").read_text(encoding="utf-8")
    assert "ignore_patterns" not in src, (
        "install.py went back to its own ignore list; membership belongs "
        "to scripts/shipped.py")
    assert "shipped_files()" in src


def test_tool_default_configs_are_not_shipped():
    """Nothing reads <tool>/config.yaml: cwd is bin/, not the repo root."""
    sh = _shipped()
    for platform in ("windows", "linux"):
        files = sh.shipped_files(platform, ROOT)
        leaks = [f for f in files if f in sh.TOOL_DEFAULT_CONFIGS]
        assert not leaks, platform + " still ships " + repr(leaks)
        assert "subfinder/provider-config.yaml" not in files
    # the cookie file is excluded by path, not by name
    assert "bin/config.yaml" in sh.SECRETS
    for platform in ("windows", "linux"):
        assert "bin/config.example.yaml" in sh.shipped_files(platform, ROOT)


def test_changelog_covers_every_commit_since_0_7_2():
    """A changelog entry without a commit behind it is fiction."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    import subprocess
    proc = subprocess.run(["git", "log", "--format=%h", "e793464..HEAD"],
                          cwd=str(ROOT), capture_output=True)
    if proc.returncode != 0:
        return                      # shallow clone / no history: nothing to pin
    hashes = proc.stdout.decode("utf-8", "replace").split()
    if not hashes:
        return
    # Only the newest commits may be missing: the one that edits this file
    # cannot contain its own hash, and a follow-up commit may be needed to
    # repair the entry. Anything older than the last two must be named, and
    # every later commit can always add the hash of an older one.
    hashes = hashes[2:]
    missing = [h for h in hashes if ("`" + h + "`") not in text]
    assert not missing, ("CHANGELOG.md never mentions commit(s) " + repr(missing)
                         + "; every change needs the commit that made it")


def test_version_is_bumped_and_matches_skill_md():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    # the version must be a released section in the changelog, not just a
    # number in a file: a bundle whose VERSION has no entry cannot be audited
    assert version and all(c.isdigit() or c == "." for c in version), (
        "VERSION is not a plain x.y.z: " + version)
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "0.7.2" not in skill
    cl = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [" + version + "]" in cl, (
        "CHANGELOG has no section for VERSION " + version)
    assert "## [0.8.0]" in cl, "the 0.8.0 section must stay for history"


# ------------------------------------------------- agent-facing docs only
# Reviews, plans and dated snapshots describe the code AT A COMMIT. An agent
# that finds "60/100, F01..F16" in the bundle takes fixed defects for the
# present and stops trusting wait/pipeline. They stay in the source repo.
DEV_ONLY_DOCS = (
    "docs/REVIEW-2026-11-21.md", "docs/CAPABILITY-REVIEW-2026-11-22.md",
    "docs/AUTOMATION-REPAIR.md", "docs/NON-DNS-REPAIR.md",
    "docs/RELIABILITY-PLAN.md", "docs/DEVELOPMENT.md",
    "docs/DIDI-COLLECTION-WORKFLOW.md", "CHANGELOG.md",
)


# The dev-session constraints prompt: the file a developing agent follows is
# not a file a consuming agent should ever see in its bundle.
DEV_ONLY_PROMPTS = ("prompts/DEV.txt",)


def test_reviews_plans_and_dated_docs_never_ship():
    sh = _shipped()
    import re
    for platform in ("windows", "linux"):
        files = set(sh.shipped_files(platform, ROOT))
        leaked = [d for d in DEV_ONLY_DOCS if d in files]
        assert not leaked, platform + " ships developer docs " + repr(leaked)
        leaked_prompts = [d for d in DEV_ONLY_PROMPTS if d in files]
        assert not leaked_prompts, platform + " ships dev prompts " + repr(leaked_prompts)
        dated = [f for f in files if f.startswith("docs/")
                 and re.search(r"\d{4}-\d{2}-\d{2}", f)]
        assert not dated, platform + " ships dated docs " + repr(dated)
    # the rule, not just today's list: a future dated review stays out too
    assert sh.is_dev_doc("docs/REVIEW-2027-01-31.md")
    assert sh.is_dev_doc("docs/CAPABILITY-REVIEW-2027-02-01.md")
    assert not sh.is_dev_doc("docs/TOOLS.md")


def test_every_link_in_the_bundle_resolves_inside_the_bundle():
    """A shipped doc must not send the agent to a file the bundle lacks."""
    import posixpath
    import re
    sh = _shipped()
    link = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?\)")
    for platform in ("windows", "linux"):
        files = set(sh.shipped_files(platform, ROOT))
        broken = []
        for doc in sorted(files):
            if not (doc.endswith(".md") or doc.endswith(".txt")):
                continue
            text = (ROOT / doc).read_text(encoding="utf-8", errors="replace")
            # a prompt template is pasted into a session that has cd'ed into
            # the skill root, so its links are root-relative by design
            base = "" if doc.startswith("prompts/") else posixpath.dirname(doc)
            for target in link.findall(text):
                if re.match(r"[a-z]+:", target):        # http:, https:, mailto:
                    continue
                path = posixpath.normpath(posixpath.join(base, target))
                if path not in files and not (ROOT / path).is_dir():
                    broken.append(doc + " -> " + target)
        assert not broken, platform + " bundle has dangling links " + repr(broken)
