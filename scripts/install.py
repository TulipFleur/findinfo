#!/usr/bin/env python
"""Install the findinfo skill into every supported agent client.

The skill directory is the single source of truth. Client skill folders get a
link (or a copy) that points at it, so editing here is immediately visible in
Claude Code, Codex and DSH without reinstalling.

    python scripts/install.py                  # link into every detected client
    python scripts/install.py --status         # show what is installed where
    python scripts/install.py --copy           # real copy instead of a link
    python scripts/install.py --project .      # also install at project level
    python scripts/install.py --uninstall      # remove our links/copies

Exit codes: 0 ok / 2 bad arguments / 3 refused (would overwrite a real dir).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SKILL_NAME = "findinfo"
MARKER = ".findinfo-skill.json"

# directory that holds the real skill (the parent of scripts/)
SOURCE = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- fs helpers
def _is_reparse_point(p: Path) -> bool:
    """True for symlinks and Windows junctions."""
    try:
        st = p.lstat()
    except OSError:
        return False
    if p.is_symlink():
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & 0x400)          # FILE_ATTRIBUTE_REPARSE_POINT


def _make_link(src: Path, dst: Path) -> str:
    """Create a directory link; junction on Windows when symlink is denied."""
    if os.name == "nt":
        try:
            os.symlink(src, dst, target_is_directory=True)
            return "symlink"
        except OSError:
            proc = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(dst), str(src)],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace")
            if proc.returncode == 0:
                return "junction"
            raise OSError("symlink and junction both failed: " +
                          (proc.stderr or proc.stdout or "").strip())
    os.symlink(src, dst, target_is_directory=True)
    return "symlink"


def _remove_link(p: Path) -> None:
    if p.is_symlink():
        p.unlink()
        return
    try:
        os.rmdir(p)                      # junction / empty dir
    except OSError:
        shutil.rmtree(p)


def _describe(p: Path) -> str:
    if not p.exists() and not _is_reparse_point(p):
        return "missing"
    if _is_reparse_point(p):
        return "junction" if not p.is_symlink() else "symlink"
    return "dir"


# ---------------------------------------------------------------- targets
def _home() -> Path:
    return Path.home()


def target_dirs(project: str | None) -> dict[str, Path]:
    h = _home()
    targets = {
        "agents": h / ".agents" / "skills" / SKILL_NAME,   # canonical store (DSH reads this)
        "claude": h / ".claude" / "skills" / SKILL_NAME,
        "codex": h / ".codex" / "skills" / SKILL_NAME,
    }
    if project:
        base = Path(project).expanduser().resolve()
        targets["project-agents"] = base / ".agents" / "skills" / SKILL_NAME
        targets["project-claude"] = base / ".claude" / "skills" / SKILL_NAME
    return targets


def _selected(kind: str, wanted: list[str], project: str | None) -> bool:
    """Explicit --targets wins; otherwise a --project run stays project-scoped
    and a plain run stays user-scoped, so one never deletes the other."""
    if wanted:
        return kind in wanted
    if project:
        return kind.startswith("project-")
    return not kind.startswith("project-")


def _client_present(kind: str, project: str | None) -> bool:
    if kind in ("agents", "claude", "codex"):
        parent = {"agents": ".agents", "claude": ".claude", "codex": ".codex"}[kind]
        return (_home() / parent).exists()
    if kind.startswith("project-"):
        base = Path(project).expanduser().resolve() if project else None
        return bool(base and base.exists())
    return False


# ---------------------------------------------------------------- commands
def cmd_status(project: str | None) -> int:
    rows = []
    for kind, dst in target_dirs(project).items():
        state = _describe(dst)
        resolved = ""
        if state != "missing":
            try:
                resolved = str(dst.resolve())
            except OSError:
                resolved = "?"
        ok = state != "missing" and (dst / "SKILL.md").exists() and (dst / "findinfo.py").exists()
        rows.append({"client": kind, "path": str(dst), "state": state,
                     "resolved": resolved, "usable": ok})
    print(json.dumps({"source": str(SOURCE), "targets": rows}, ensure_ascii=False, indent=2))
    return 0


def _install_one(kind: str, dst: Path, mode: str, force: bool, dry: bool) -> dict:
    state = _describe(dst)
    result = {"client": kind, "path": str(dst), "action": "", "state_before": state}

    if state != "missing":
        ours = _is_reparse_point(dst) or (dst / MARKER).exists()
        if not ours and not force:
            result["action"] = "refused"
            result["reason"] = ("existing real directory is not managed by this "
                                "installer; pass --force to replace it")
            return result
        # already pointing at the right place and manifest unchanged
        if _is_reparse_point(dst):
            try:
                if dst.resolve() == SOURCE.resolve() and mode == "link":
                    result["action"] = "unchanged"
                    return result
            except OSError:
                pass
        if not dry:
            _remove_link(dst)
        result["replaced"] = state

    if dry:
        result["action"] = "would-" + ("link" if mode == "link" else "copy")
        return result

    dst.parent.mkdir(parents=True, exist_ok=True)
    if mode == "link":
        link_type = _make_link(SOURCE, dst)
        result["action"] = "linked"
        result["link_type"] = link_type
        return result

    # never copy secret-bearing files into a shared/project location
    shutil.copytree(SOURCE, dst, ignore=shutil.ignore_patterns(
        "data", "cache", "runs", "_tmp", "__pycache__", "*.pyc", ".git",
        ".env", "config.yaml"))
    (dst / MARKER).write_text(json.dumps(
        {"skill": SKILL_NAME, "source": str(SOURCE), "mode": "copy"},
        ensure_ascii=False, indent=2), encoding="utf-8")
    result["action"] = "copied"
    return result


def cmd_install(project: str | None, targets_wanted: list[str], mode: str,
                force: bool, dry: bool) -> int:
    all_targets = target_dirs(project)
    results = []
    for kind, dst in all_targets.items():
        if not _selected(kind, targets_wanted, project):
            continue
        if not targets_wanted and not _client_present(kind, project):
            results.append({"client": kind, "path": str(dst),
                            "action": "skipped", "reason": "client not installed"})
            continue
        results.append(_install_one(kind, dst, mode, force, dry))

    refused = [r for r in results if r.get("action") == "refused"]
    print(json.dumps({"source": str(SOURCE), "mode": mode, "dry_run": dry,
                      "results": results}, ensure_ascii=False, indent=2))
    if refused:
        print("refused: " + ", ".join(r["client"] for r in refused), file=sys.stderr)
        return 3
    return 0


def cmd_uninstall(project: str | None, wanted: list[str], dry: bool) -> int:
    removed = []
    for kind, dst in target_dirs(project).items():
        if not _selected(kind, wanted, project):
            continue
        state = _describe(dst)
        if state == "missing":
            continue
        ours = _is_reparse_point(dst) or (dst / MARKER).exists()
        if not ours:
            removed.append({"client": kind, "path": str(dst),
                            "action": "kept", "reason": "not managed by this installer"})
            continue
        if not dry:
            _remove_link(dst)
        removed.append({"client": kind, "path": str(dst), "action": "removed"})
    print(json.dumps({"results": removed}, ensure_ascii=False, indent=2))
    return 0


def cmd_verify(project: str | None) -> int:
    checks = []
    for kind, dst in target_dirs(project).items():
        if _describe(dst) == "missing":
            continue
        entry = dst / "findinfo.py"
        if not entry.exists():
            checks.append({"client": kind, "ok": False, "reason": "findinfo.py missing"})
            continue
        proc = subprocess.run([sys.executable, str(entry), "doctor"],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120)
        try:
            data = json.loads(proc.stdout.strip().splitlines()[-1])
            ok = "tools" in data and "home" in data
            checks.append({"client": kind, "ok": ok, "home": data.get("home"),
                           "db": data.get("db"),
                           "tools_ok": sum(1 for t in data["tools"].values() if t.get("present"))})
        except Exception as exc:  # noqa: BLE001
            checks.append({"client": kind, "ok": False,
                           "reason": "doctor did not return JSON: " + repr(exc),
                           "stdout": proc.stdout[-300:], "stderr": proc.stderr[-300:]})
    print(json.dumps({"checks": checks}, ensure_ascii=False, indent=2))
    return 0 if all(c["ok"] for c in checks) else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="install", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default="",
                    help="comma list: agents,claude,codex,project-agents,project-claude")
    ap.add_argument("--project", default="", help="project dir for project-level install")
    ap.add_argument("--mode", choices=["link", "copy"], default="link")
    ap.add_argument("--force", action="store_true", help="replace a non-managed directory")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    args = ap.parse_args(argv)

    wanted = [t.strip() for t in args.targets.split(",") if t.strip()]
    project = args.project or None

    if args.status:
        return cmd_status(project)
    if args.verify:
        return cmd_verify(project)
    if args.uninstall:
        return cmd_uninstall(project, wanted, args.dry_run)
    return cmd_install(project, wanted, args.mode, args.force, args.dry_run)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
