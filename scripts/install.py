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
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKILL_NAME = "findinfo"
MARKER = ".findinfo-skill.json"

# directory that holds the real skill (the parent of scripts/)
SOURCE = Path(__file__).resolve().parent.parent

# scripts/shipped.py owns what a consumer install contains; the release zip
# reads the same manifest, so --copy and the archive cannot disagree again.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import shipped as _shipped                                    # noqa: E402


def shipped_files(path: Path | None = None) -> list:
    # Manifest for this host platform, relative to path (the skill root).
    root = SOURCE if path is None else path
    return _shipped.shipped_files(_shipped.host_platform(), root)


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


# ---------------------------------------------------------------- codex config
# Codex (CLI 0.166+) does NOT scan ~/.codex/skills: it reads explicit
# [[skills.config]] entries from ~/.codex/config.toml. Installing only a link
# there leaves the skill invisible to Codex, so registration is part of install.
def _codex_home() -> Path:
    env = os.environ.get("CODEX_HOME")
    return Path(env).expanduser() if env else (_home() / ".codex")


def _codex_config() -> Path:
    return _codex_home() / "config.toml"


def _toml_str(s: str) -> str:
    """Prefer a TOML literal string so Windows backslashes stay literal."""
    if "'" not in s:
        return "'" + s + "'"
    return json.dumps(s)


def _codex_entry_path() -> str:
    return str((SOURCE / "SKILL.md").resolve())


def _read_text_keep_eol(p: Path) -> tuple[str, str]:
    """Read a config file and remember its line ending (CRLF vs LF).

    Rewriting a CRLF config as LF makes the whole file show up in diffs and
    can upset tools that compare it byte-wise, so the original EOL is reused.
    """
    raw = p.read_bytes()
    text = raw.decode("utf-8", "replace")
    eol = "\r\n" if "\r\n" in text else "\n"
    return text.replace("\r\n", "\n"), eol


def _write_text_keep_eol(p: Path, text_lf: str, eol: str) -> None:
    data = text_lf.replace("\r\n", "\n")
    if eol == "\r\n":
        data = data.replace("\n", "\r\n")
    p.write_text(data, encoding="utf-8", newline="")


def _codex_state() -> dict:
    """Is findinfo registered in Codex's config, and are skills even included?"""
    cfg = _codex_config()
    info = {"config": str(cfg), "exists": cfg.exists(), "registered": False,
            "include_instructions": None}
    if not cfg.exists():
        return info
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return info
    want = _codex_entry_path()
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("path") and "=" in s:
            val = s.split("=", 1)[1].strip().strip("'\"")
            if val.lower() == want.lower():
                info["registered"] = True
    m = re.search(r"(?m)^include_instructions\s*=\s*(true|false)", text)
    if m:
        info["include_instructions"] = (m.group(1) == "true")
    return info


def codex_register(dry: bool = False) -> dict:
    cfg = _codex_config()
    st = _codex_state()
    if st["registered"]:
        return {"action": "unchanged", **st}
    # Codex's schema requires BOTH fields; a path-only entry fails with
    # "invalid data" (missing field) and the whole config stops loading.
    block = ("[[skills.config]]\npath = " + _toml_str(_codex_entry_path()) +
             "\nenabled = true\n")
    try:
        if cfg.exists():
            text, eol = _read_text_keep_eol(cfg)
        else:
            text, eol = "", "\n"
    except OSError as exc:
        return {"action": "error", "reason": repr(exc), **st}
    # keep the two skills.config entries next to each other: insert before [skills]
    lines = text.splitlines()
    idx = next((i for i, ln in enumerate(lines)
                if ln.strip() == "[skills]"), None)
    if idx is None:
        new_text = text.rstrip("\n") + ("\n\n" if text.strip() else "") + block
    else:
        new_text = "\n".join(lines[:idx]) + "\n" + block + "\n" + "\n".join(lines[idx:]) + "\n"
    if dry:
        return {"action": "would-register", **st}
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists():
        shutil.copy2(cfg, cfg.with_suffix(cfg.suffix + ".findinfo.bak"))
    _write_text_keep_eol(cfg, new_text, eol)
    return {"action": "registered", **_codex_state()}


def codex_set_instructions(enabled: bool, dry: bool = False) -> dict:
    """Flip [skills].include_instructions in Codex's config.

    This is a GLOBAL switch: with false, Codex registers the skill but does not
    put its instructions into context, so the agent cannot actually use it.
    Only the user should decide to change it, hence an explicit flag.
    """
    cfg = _codex_config()
    if not cfg.exists():
        return {"action": "no-config", "config": str(cfg)}
    text, eol = _read_text_keep_eol(cfg)
    want = "true" if enabled else "false"
    if re.search(r"(?m)^include_instructions\s*=\s*" + want + r"\s*$", text):
        return {"action": "unchanged", "include_instructions": enabled}
    if re.search(r"(?m)^include_instructions\s*=", text):
        text = re.sub(r"(?m)^include_instructions\s*=\s*(true|false)\s*$",
                      "include_instructions = " + want, text)
    elif re.search(r"(?m)^\[skills\]\s*$", text):
        text = re.sub(r"(?m)^\[skills\]\s*$", "[skills]\ninclude_instructions = " + want, text)
    else:
        text = text.rstrip("\n") + "\n\n[skills]\ninclude_instructions = " + want + "\n"
    if dry:
        return {"action": "would-set", "include_instructions": enabled}
    shutil.copy2(cfg, cfg.with_suffix(cfg.suffix + ".findinfo.bak"))
    _write_text_keep_eol(cfg, text, eol)
    return {"action": "set", "include_instructions": enabled}


def codex_unregister(dry: bool = False) -> dict:
    cfg = _codex_config()
    st = _codex_state()
    if not st["registered"]:
        return {"action": "unchanged", **st}
    want = _codex_entry_path().lower()
    text, eol = _read_text_keep_eol(cfg)
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        if s.startswith("path") and "=" in s:
            val = s.split("=", 1)[1].strip().strip("'\"")
            if val.lower() == want:
                # drop the whole entry: [[skills.config]] + path + enabled + blank
                while out and not out[-1].strip():
                    out.pop()
                if out and out[-1].strip() == "[[skills.config]]":
                    out.pop()
                i += 1
                while i < len(lines):
                    nxt = lines[i].strip()
                    if not nxt:
                        i += 1
                        continue
                    if nxt.startswith(("enabled", "name", "description")):
                        i += 1
                        continue
                    break
                continue
        out.append(ln)
        i += 1
    if dry:
        return {"action": "would-unregister", **st}
    if cfg.exists():
        shutil.copy2(cfg, cfg.with_suffix(cfg.suffix + ".findinfo.bak"))
    _write_text_keep_eol(cfg, "\n".join(out).rstrip("\n") + "\n", eol)
    return {"action": "unregistered", **_codex_state()}


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
    out = {"source": str(SOURCE), "targets": rows, "codex_config": _codex_state()}
    if out["codex_config"].get("include_instructions") is False:
        out["codex_config"]["warning"] = ("[skills].include_instructions = false，"
                                          "Codex 不会把 skill 说明注入上下文")
    print(json.dumps(out, ensure_ascii=False, indent=2))
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

    # copy mode: a self-contained skill directory.
    # The membership rule is scripts/shipped.py, the same one the release zip
    # uses -- src/shipped_files(). A private ignore list here is how a copy
    # install came to miss eight config.yaml files the bundle shipped: the
    # glob "config.yaml" matched every tool directory, not just bin/.
    cur_platform = _shipped.host_platform()
    files = shipped_files()
    for rel in files:
        src = SOURCE / rel
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
    (dst / MARKER).write_text(json.dumps(
        {"skill": SKILL_NAME, "source": str(SOURCE), "mode": "copy",
         "bin_platform_included": cur_platform},
        ensure_ascii=False, indent=2), encoding="utf-8")
    result["action"] = "copied"
    result["bin_platform_included"] = cur_platform
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

    # Codex 只认 config.toml 里的 [[skills.config]]，链接不够
    codex_reg = None
    if any(k in ("codex", "project-codex") for k in all_targets) and _selected("codex", targets_wanted, project):
        codex_reg = codex_register(dry=dry)

    refused = [r for r in results if r.get("action") == "refused"]
    print(json.dumps({"source": str(SOURCE), "mode": mode, "dry_run": dry,
                      "results": results, "codex_config": codex_reg},
                     ensure_ascii=False, indent=2))
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
    codex_reg = None
    if _selected("codex", wanted, project):
        codex_reg = codex_unregister(dry=dry)
    print(json.dumps({"results": removed, "codex_config": codex_reg},
                     ensure_ascii=False, indent=2))
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
    # Codex 的可用性取决于 config.toml 里的注册，不是目录是否存在
    cs = _codex_state()
    codex_ok = (not cs["exists"]) or cs["registered"]
    checks.append({"client": "codex-config", "ok": codex_ok,
                   "config": cs["config"], "registered": cs["registered"],
                   "include_instructions": cs["include_instructions"]})
    print(json.dumps({"checks": checks}, ensure_ascii=False, indent=2))
    return 0 if all(c["ok"] for c in checks) else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="install", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default="",
                    help="comma list: agents,claude,codex,project-agents,project-claude")
    ap.add_argument("--project", default="", help="project dir for project-level install")
    ap.add_argument("--mode", choices=["link", "copy"], default="link")
    ap.add_argument("--copy", action="store_true",
                    help="shorthand for --mode copy (docstring mentioned it; "
                         "the flag did not exist)")
    ap.add_argument("--force", action="store_true", help="replace a non-managed directory")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--enable-instructions", action="store_true",
                    help="Codex: set [skills].include_instructions = true "
                         "(global switch; without it Codex registers but does not "
                         "read skill instructions)")
    args = ap.parse_args(argv)

    wanted = [t.strip() for t in args.targets.split(",") if t.strip()]
    project = args.project or None
    mode = "copy" if args.copy else args.mode

    if args.status:
        return cmd_status(project)
    if args.verify:
        return cmd_verify(project)
    if args.enable_instructions:
        res = codex_set_instructions(True, dry=args.dry_run)
        print(json.dumps({"codex_config": res}, ensure_ascii=False, indent=2))
        return 0
    if args.uninstall:
        return cmd_uninstall(project, wanted, args.dry_run)
    return cmd_install(project, wanted, mode, args.force, args.dry_run)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
