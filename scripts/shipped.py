"""The release manifest: one rule for the bundle and install.py --copy.

Both the zipped release (scripts/build-release.py) and a consumer copy
(scripts/install.py --copy) ship the same set of files. Keeping two ignore
lists was how they drifted: install.py used a glob named "config.yaml" that
dropped every tool directory's file, while the zip packed them, so a copy
install was missing eight files the release had.

Rules live here and nowhere else:

  * tracked files only (git ls-files)  -> no __pycache__, no .env, no state
  * plus this platform's bin/<platform>/* (binaries are not tracked)
  * minus developer-only material (tests/, agent-records/, rust/ sources,
    the agent-record tool)
  * minus reviews, plans and dated snapshots (is_dev_doc): they describe the
    code at a commit, and an agent reading them takes fixed defects for the
    present
  * minus files that only apply to the other platform (PLATFORM_ONLY)
  * minus secrets (SECRETS), always

This module has no side effects at import and only needs git on PATH, so
both scripts can import it (file names contain dashes; they use importlib).
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = ("windows", "linux")

# Files that only make sense on one platform. Never "just this one has docs":
# every removal below has to be justified by what the file does.
PLATFORM_ONLY = {
    # shell installers are POSIX-only (bash); deploy/ units are systemd units
    "linux": (),
    "windows": (
        "scripts/setup-linux.sh",     # installs ELF binaries via curl + tar
        "deploy/findinfo@.service",   # systemd unit
        "deploy/findinfo@.timer",     # systemd timer
    ),
}

# Directories that hold developer material, not shippable skill content.
DEV_DIRS = (
    "tests/",          # self-check harness; pytest is not a consumer need
    "agent-records/",  # per-session agent collaboration log
    "rust/",           # onepass sources; rebuild from the repo, not the bundle
    "deploy/",         # systemd units are per-platform (see PLATFORM_ONLY)
)

# Documents for the people who build findinfo, not for the agent that uses it.
# Reviews and plans are snapshots of the code at a commit ("60/100, F01..F16",
# "75/100"); in the agent's view they read as the present and steer it wrong
# (distrusting wait, bypassing the pipeline). They stay in the source repo.
DEV_DOCS = (
    "CHANGELOG.md",                     # history; the release notes carry it
    "docs/DEVELOPMENT.md",              # building and testing the skill
    "docs/RELIABILITY-PLAN.md",         # design plan, partly superseded
    "docs/AUTOMATION-REPAIR.md",        # repair plan snapshot
    "docs/NON-DNS-REPAIR.md",           # repair plan snapshot
    "docs/DIDI-COLLECTION-WORKFLOW.md",  # one target's walk-through
)
# Any review, and any doc whose NAME carries a date, is a snapshot by
# convention: it never ships, so a new one cannot slip into the bundle.
_DEV_DOC_PATTERNS = (re.compile(r"^docs/(?:[A-Z-]*REVIEW[A-Z-]*)[^/]*\.md$"),
                     re.compile(r"^docs/[^/]*\d{4}-\d{2}-\d{2}[^/]*$"))


def is_dev_doc(rel: str) -> bool:
    """A developer document: listed in DEV_DOCS, a review, or dated."""
    rel = rel.replace("\\", "/")
    return rel in DEV_DOCS or any(p.match(rel) for p in _DEV_DOC_PATTERNS)


# Single developer files.
DEV_FILES = (
    "prompts/DEV.txt",          # dev-session constraints; agents developing the
                                # skill follow it, consumers never load it
    "scripts/agent-record.py",   # dev record tool, unrelated to using the skill
    "scripts/build-onepass.sh",  # build script, superseded by DEV_DIRS for both
    "scripts/build-enscan.sh",
    ".gitignore",                # repo bookkeeping, not skill content
)

# ProjectDiscovery tool directories holding the config.yaml goflags generates.
# Nothing reads them: core.run passes cwd=bin/, and goflags only looks for a
# config.yaml in the working directory or $HOME/.config/<tool>/. findinfo.py
# and lib/ never mention these paths, and every argument that matters is
# passed on the command line. They were artefacts of running the binaries
# from the repo root once; shipping them made the bundle bigger and made the
# two packaging rules disagree. bin/config.yaml (the ENScan cookie) is a
# different file and stays excluded through SECRETS.

TOOL_DEFAULT_CONFIGS = tuple(
    name + "/config.yaml"
    for name in ("cdncheck", "chaos", "dnsx", "httpx", "katana", "naabu",
                 "subfinder", "uncover")
) + ("subfinder/provider-config.yaml",)   # only read via -pc / $HOME/.config

DEV_FILES = (*DEV_FILES, *TOOL_DEFAULT_CONFIGS)

# Files that must never leave the author's machine, in any platform.
SECRETS = (
    "bin/config.yaml",       # ENScan cookie
    "config/.env",           # API keys
    "config/config.json",
    "config/scope.json",
)


def _norm(rel: str) -> str:
    rel = rel.replace(os.sep, "/")
    return rel[2:] if rel.startswith("./") else rel


def _under(rel: str, prefixes) -> bool:
    return any(rel == p.rstrip("/") or rel.startswith(p) for p in prefixes)


def tracked_files(root: Path = ROOT) -> list:
    """Every file git knows about, relative and slash-separated."""
    proc = subprocess.run(["git", "ls-files", "-z"], cwd=str(root),
                          capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("git ls-files failed in " + str(root) + ": "
                         + proc.stderr.decode("utf-8", "replace"))
    out = proc.stdout.decode("utf-8", "replace").split("\0")
    return [_norm(p) for p in out if p]


def platform_binaries(platform: str, root: Path = ROOT) -> list:
    """This platform's binaries: bin/<platform>/* (not tracked in git).

    Hidden support files (e.g. bin/linux/.installed-versions, the manifest
    setup-linux.sh keeps for --check) are part of a working install, so they
    travel too; only secrets and bytecode are filtered.
    """
    d = root / "bin" / platform
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.rglob("*")):
        if not p.is_file():
            continue
        rel = _norm(str(p.relative_to(root)))
        # bin/<platform>/config.yaml is the ENScan cookie; the .example
        # next to it is what ships
        if rel in SECRETS or p.name in ("config.yaml", ".env"):
            continue
        out.append(rel)
    return out


def excluded_paths(platform: str, root: Path = ROOT) -> list:
    """Absolute-in-bundle paths that must never be packed, for this platform."""
    if platform not in PLATFORMS:
        raise SystemExit("unknown platform " + platform
                         + " (choose from " + ", ".join(PLATFORMS) + ")")
    bad = list(SECRETS)
    wrong = "linux" if platform == "windows" else "windows"
    bad += platform_binaries(wrong, root)     # other platform's binaries
    bad += list(PLATFORM_ONLY[platform])
    bad += list(DEV_FILES)
    return bad


def shipped_files(platform: str, root: Path = ROOT) -> list:
    """The bundle manifest: sorted, slash-separated, relative paths.

    A copy install (install.py --copy) ships exactly this set. If a file is
    not here, it is not in the bundle, and nothing else decides membership.
    """
    if platform not in PLATFORMS:
        raise SystemExit("unknown platform " + platform
                         + " (choose from " + ", ".join(PLATFORMS) + ")")
    keep = set(tracked_files(root)) | set(platform_binaries(platform, root))
    excluded = set(excluded_paths(platform, root))

    result = []
    for rel in sorted(keep):
        if rel in excluded:
            continue
        if _under(rel, DEV_DIRS) or is_dev_doc(rel):
            continue
        # never ship the other platform's binaries even if they were tracked
        parts = rel.split("/")
        if len(parts) > 1 and parts[0] == "bin" and parts[1] in PLATFORMS and parts[1] != platform:
            continue
        if _under(rel, ("docs/",)) and rel.endswith(".pyc"):
            continue
        result.append(rel)
    return result


def host_platform() -> str:
    """The platform this interpreter can ship binaries for."""
    return "windows" if os.name == "nt" else "linux"

