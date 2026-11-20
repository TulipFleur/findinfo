"""Pure offline bootstrap: no config, no directory creation, no runtime import.

The CLI used to import lib.core (which resolves HOME at import time and
`mkdir`s cache/runs/data/config, then loads config.json and .env) BEFORE it
could know whether the caller asked for a read-only mode. So `run --dry-run`
and `doctor --offline` -- documented as side-effect free -- still created the
home layout and read credentials (F09).

This module is standard library only and imports nothing from the runtime.
Everything here answers from:

* the parsed CLI (already available before runtime import), and
* file METADATA (existence, size, mtime) under a path the caller names.

No configuration is loaded, no credential is read, no directory is created and
no tool or socket is touched. Capabilities are reported as not_checked -- never
false, because false means "checked and failed".
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Tool names the runtime looks up; listed here so an offline answer can say
# "present/absent" without importing the resolver.
_TOOL_NAMES = ("enscan", "subfinder", "httpx", "dnsx", "naabu", "cdncheck",
               "uncover", "katana", "chaos", "ksubdomain", "onepass",
               "hostCollision")


def resolve_root() -> Path:
    """The skill root (this file's parent's parent) -- no config involved."""
    return Path(__file__).resolve().parent.parent


def _bin_dir(root: Path, platform: str | None = None) -> Path:
    if platform is None:
        platform = "windows" if os.name == "nt" else "linux"
    return root / "bin" / platform


def _presence(root: Path, name: str) -> dict:
    """File metadata only: does the bundled binary exist, and how big is it?"""
    exe = _bin_dir(root) / (name + (".exe" if os.name == "nt" else ""))
    if not exe.exists():
        return {"present": False}
    try:
        st = exe.stat()
        return {"present": True, "path": str(exe), "size": st.st_size,
                "executable": os.access(str(exe), os.X_OK),
                "health": "not_checked",
                "note": "presence only; running it is not part of an offline check"}
    except OSError:
        return {"present": False}


def doctor_offline() -> dict:
    """doctor with zero execution, network or credential access (F09).

    Egress, fake-IP verdict and credentials are None/not_checked, never false.
    Paths are reported with metadata only; a path that does not exist is
    reported as absent WITHOUT creating it.
    """
    root = resolve_root()
    home_env = os.environ.get("FINDINFO_HOME")
    home = Path(home_env).expanduser() if home_env else (Path.home() / ".findinfo")
    tools = {n: _presence(root, n) for n in _TOOL_NAMES}
    present = [n for n, v in tools.items() if v.get("present")]
    missing = [n for n, v in tools.items() if not v.get("present")]
    paths = {}
    for label, p in (("home", home), ("root", root),
                     ("config", root / "config"),
                     ("wordlists", root / "wordlists")):
        entry = {"path": str(p), "exists": p.exists()}
        try:
            if p.exists():
                st = p.stat()
                entry.update({"is_dir": p.is_dir(), "size": st.st_size,
                              "mtime": int(st.st_mtime)})
        except OSError:
            pass
        paths[label] = entry
    return {
        "schema": "findinfo.doctor/offline",
        "mode": "offline",
        "note": ("offline: no tool execution, no DNS/HTTP, no credential read, "
                 "no directory creation; unknown checks stay unknown"),
        "python": {"version": sys.version.split()[0],
                   "executable": sys.executable,
                   "ok": sys.version_info >= (3, 10)},
        "platform": {"system": sys.platform, "os_name": os.name},
        "paths": paths,
        "tools": tools,
        "tools_summary": {"present": present, "missing": missing,
                          "all_in_bin": None, "checked": False,
                          "note": "presence only; health is not_checked"},
        "api_keys": {k: "not_checked" for k in
                     ("fofa", "quake", "hunter", "shodan", "censys", "chaos",
                      "securitytrails", "virustotal", "urlscan")},
        "environment": {
            "net_egress": {"checked": False, "any_reachable": None,
                           "note": "an offline check never probes egress"},
            "fake_ip_dns": {"checked": False, "fake_ip_dns": None,
                            "note": "an offline check never resolves a name"},
        },
    }


def plan_preview(run_spec, planned_stages, active: bool, disabled: list,
                 identity_questions: list, limits: dict,
                 background: bool, resume: str | None,
                 effective: dict | None = None) -> dict:
    """The `run --dry-run` answer, built WITHOUT the runtime.

    `run_spec` is a lib.spec.RunSpec (pure data). Everything that would need
    live facts -- credentials, tool health, egress, requestability -- is
    reported as unverified rather than guessed.
    """
    return {
        "run_id": None,
        "spec_hash": run_spec.dedupe_identity(),
        "dry_run": True,
        "target": run_spec.target_label,
        "scope": list(run_spec.domain),
        "planned_stages": planned_stages,
        "active": active,
        "disabled_stages": disabled,
        "identity_questions": identity_questions,
        "limits": dict(limits),
        "possible_requests": {
            "note": "network requestability is not checked in a dry run; "
                    "counts are unknown"},
        "capabilities": {
            "checked": False,
            "note": "tool presence, egress and credentials are not verified by "
                    "a dry run"},
        "background_requested": bool(background),
        "resume_requested": resume or None,
        "effective": effective or None,
        "note": ("plan only: no job was started, no database or home directory "
                 "was created, no credential was read"),
    }
