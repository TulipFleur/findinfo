#!/usr/bin/env python
"""Build a clean, reproducible release bundle for findinfo.

The manual bundles that started this (0.7.x) shipped bytecode, Linux-only
units, the developer agent-record tool, and a dozen tool config.yaml files
nobody reads. This script makes the contents a rule instead of a memory:

    python scripts/build-release.py                        # both platforms
    python scripts/build-release.py --platform windows
    python scripts/build-release.py --out _rel/next --version 0.7.3

What goes in (one rule, shared with install.py --copy via shipped_files()):

  * tracked files only (git ls-files)  -> no __pycache__, no .env, no state
  * plus this platform's bin/<platform>/* (the binaries are not in git);
    another platform's binaries never travel with a bundle
  * minus developer-only material (tests/, agent-records/, rust/ sources,
    the agent-record tool)
  * minus files that only apply to the other platform / are only useful when
    working on the source tree, as listed in PLATFORM_ONLY

Secrets are never shipped: excluded_paths() drops bin/config.yaml and
config/.env regardless of platform.

After zipping it writes SHA256SUMS, then unpacks the archive into a temp dir
and audits it (no .pyc / __pycache__ / .env / bin/config.yaml, doctor runs).
A network probe failing inside doctor is not a build failure; a bundle that
cannot import its own CLI is.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = ("windows", "linux")

# ------------------------------------------------------------ file selection

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

# Single developer files.
DEV_FILES = (
    "scripts/agent-record.py",   # dev record tool, unrelated to using the skill
    "scripts/build-onepass.sh",  # build script, superseded by DEV_DIRS for both
    "scripts/build-enscan.sh",
)

# Files that must never leave the author's machine, in any platform.
SECRETS = (
    "bin/config.yaml",       # ENScan cookie
    "config/.env",           # API keys
    "config/config.json",
    "config/scope.json",
)

# Runtime/packaging leftovers that should not exist in a bundle. A tracked
# file that matches one of these is a bug, so the audit fails on them.
FORBIDDEN_SUFFIXES = (".pyc", ".pyo")
FORBIDDEN_PARTS = ("__pycache__", ".git")
# Bare names that must never appear anywhere in a bundle. config.yaml is
# deliberately NOT here: the PD tools own <tool>/config.yaml files are
# auto-generated defaults, while our ENScan cookie lives at the different
# path bin/config.yaml (SECRETS is path based).
FORBIDDEN_NAMES = (".env", ".gitignore")
# .gitignore is repo bookkeeping, not skill content.
DEV_FILES = (*DEV_FILES, ".gitignore")


def _norm(rel: str) -> str:
    return rel.replace(os.sep, "/").lstrip("./") if rel.startswith("./") else rel.replace(os.sep, "/")


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


def platform_tool_names(platform: str, root: Path = ROOT) -> list:
    """Every tool the bundle for `platform` must contain and run."""
    names = []
    for rel in platform_binaries(platform, root):
        if not rel.startswith("bin/" + platform + "/"):
            continue
        name = rel.rsplit("/", 1)[-1]
        if name.startswith("."):
            continue
        names.append(name.replace(".exe", "") if platform == "windows" else name)
    return sorted(names)


def platform_binaries(platform: str, root: Path = ROOT) -> list:
    """This platform's binaries: bin/<platform>/* (not tracked in git).

    Hidden support files (e.g. bin/linux/.installed-versions, the manifest
    setup-linux.sh keeps for --check) are part of a working install, so they
    travel too; only secrets and bytecode are filtered by excluded_paths().
    """
    d = root / "bin" / platform
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.rglob("*")):
        if not p.is_file():
            continue
        rel = _norm(str(p.relative_to(root)))
        # bin/<platform>/config.yaml is the ENScan cookie the author filled
        # in locally; the .example next to it is what ships
        if rel in SECRETS or p.name in ("config.yaml", ".env"):
            continue
        out.append(rel)
    return out


def excluded_paths(platform: str) -> list:
    """Absolute-in-bundle paths that must never be packed, for this platform."""
    bad = list(SECRETS)
    wrong = "linux" if platform == "windows" else "windows"
    bad += platform_binaries(wrong)          # other platform's binaries
    bad += list(PLATFORM_ONLY[platform])
    bad += [p for p in DEV_FILES]
    return bad


def shipped_files(platform: str, root: Path = ROOT) -> list:
    """The bundle manifest: sorted, slash-separated, relative paths.

    This is the single rule shared with install.py --copy. If a file is not
    here, it is not in the bundle, and nothing else decides membership.
    """
    if platform not in PLATFORMS:
        raise SystemExit("unknown platform " + platform
                         + " (choose from " + ", ".join(PLATFORMS) + ")")
    keep = set(tracked_files(root)) | set(platform_binaries(platform, root))
    excluded = set(excluded_paths(platform))

    result = []
    for rel in sorted(keep):
        if rel in excluded:
            continue
        if _under(rel, DEV_DIRS):
            continue
        # never ship the other platform's binaries even if they were tracked
        if rel.startswith("bin/") and rel.count("/") >= 1:
            parts = rel.split("/")
            if len(parts) > 1 and parts[1] in PLATFORMS and parts[1] != platform:
                continue
        if _under(rel, ("docs/",)) and rel.endswith(".pyc"):
            continue
        result.append(rel)
    return result


def is_forbidden(rel: str) -> bool:
    """True for anything the audit must never find in a bundle."""
    parts = rel.split("/")
    if any(s in rel for s in FORBIDDEN_PARTS):
        return True
    if rel.endswith(FORBIDDEN_SUFFIXES):
        return True
    if parts[-1] in FORBIDDEN_NAMES:
        return True
    return False


# ------------------------------------------------------------------- packing

def _zip_name(prefix: str, rel: str) -> str:
    return prefix + "/" + rel


def build(platform: str, version: str, out: Path, root: Path = ROOT) -> dict:
    files = shipped_files(platform, root)
    if not files:
        raise SystemExit("nothing to ship for " + platform)
    bad = [f for f in files if is_forbidden(f)]
    if bad:
        raise SystemExit("refusing to pack forbidden paths: " + repr(bad[:10]))

    prefix = "findinfo-" + version + "-" + platform
    out.mkdir(parents=True, exist_ok=True)
    archive = out / (prefix + ".zip")

    raw = 0
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for rel in files:
            src = root / rel
            data = src.read_bytes()
            raw += len(data)
            info = zipfile.ZipInfo(_zip_name(prefix, rel), date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            # entry dates are pinned so two runs on the same tree produce the
            # same archive bytes (a release must be reproducible)
            mode = _bundle_mode(rel, src)
            info.external_attr = (mode & 0xFFFF) << 16
            z.writestr(info, data)

    digest = sha256(archive)
    return {
        "file": str(archive),
        "name": archive.name,
        "sha256": digest,
        "files": len(files),
        "bytes_raw": raw,
        "bytes_zip": archive.stat().st_size,
        "prefix": prefix,
        "manifest": files,
        "tools": platform_tool_names(platform, root),
    }


# ELF binaries must unpack executable. The build usually runs on Windows,# where an NTFS mount reports every file as 0644 and no exec bit exists at
# all, so mode cannot be read off the source tree -- it is decided by path.
EXEC_PREFIXES = ("bin/linux/", "bin/windows/", "scripts/")
EXEC_SUFFIXES = (".sh", ".py")


def _bundle_mode(rel: str, src: Path) -> int:
    """File mode to store in the archive for this entry."""
    if rel.startswith(EXEC_PREFIXES):
        # setup-linux.sh keeps a .installed-versions manifest beside it
        return 0o644 if rel.endswith(".installed-versions") else 0o755
    if rel.endswith(EXEC_SUFFIXES):
        return 0o755
    if os.name != "nt" and (src.stat().st_mode & 0o111):
        return 0o755
    return 0o644


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sums(out: Path, results) -> Path:
    """SHA256SUMS with one '<sha>  <name>' line per archive, stable order."""
    path = out / "SHA256SUMS"
    lines = [r["sha256"] + "  " + r["name"] for r in sorted(results, key=lambda r: r["name"])]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


# -------------------------------------------------------------------- audit

def _net_ok(host: str = "crt.sh", port: int = 443, timeout: float = 3.0) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _is_os_payload(entry: str) -> bool:
    """True for entries whose exec bit matters: binaries, not support files."""
    rel = entry.split("/", 1)[-1]
    if "/bin/" not in entry and not rel.startswith("scripts/"):
        return False
    return not rel.endswith((".installed-versions", ".yaml", ".yml", ".json",
                             ".example.yaml"))


def audit(archive: Path, prefix: str, version: str, run_doctor: bool = True,
          cross_checkable: bool = True, expect=()) -> dict:
    """Unpack and prove the bundle is clean and its CLI actually starts."""
    problems = []
    notes = []
    with tempfile.TemporaryDirectory(prefix="findinfo-audit-") as tmp:
        tmp_path = Path(tmp)
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            for n in names:
                rel = n.split("/", 1)[1] if "/" in n else n
                if rel and is_forbidden(rel):
                    problems.append("forbidden entry: " + n)
            if any(".." in n.split("/") or n.startswith("/") for n in names):
                problems.append("absolute or traversing entry name")
            z.extractall(tmp_path)

        base = tmp_path / prefix
        platform = prefix.rsplit("-", 1)[-1]
        # doctor resolves from real ROOT, so its exec probe always hits the
        # build checkout even when run inside the unpacked copy: the launch
        # is just a cross-check that the CLI imports and reads its own VERSION.
        local_bin = ROOT / "bin" / platform
        expected = base / "findinfo.py"
        if not expected.is_file():
            problems.append("findinfo.py missing at archive root")
        stored = base / "VERSION"
        if stored.is_file():
            got = stored.read_text(encoding="utf-8").strip()
            if got != version:
                problems.append("VERSION says " + got + ", expected " + version)

        if run_doctor and expected.is_file():
            env = dict(os.environ)
            env["FINDINFO_HOME"] = str(tmp_path / "home")
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            proc = subprocess.run([sys.executable, "findinfo.py", "doctor"],
                                  cwd=str(base), capture_output=True,
                                  text=True, encoding="utf-8", errors="replace",
                                  env=env, timeout=600)
            try:
                reporter = json.loads(proc.stdout or "{}")
            except ValueError:
                reporter = {}
            tools = (reporter.get("tools") or {}) if isinstance(reporter, dict) else {}
            # doctor's real shape is {python, skill_version, environment, tools}.
            # The run itself is a smoke test: the bundled CLI imported, read its
            # own VERSION and reported an inventory. Its per-tool verdicts are
            # NOT taken as proof of what the zip carries -- doctor resolves
            # from the real ROOT, so the binaries it probes are the build
            # checkout's, not this copy's.
            if not tools:
                problems.append("doctor produced no tool inventory (rc="
                                + str(proc.returncode) + "): "
                                + (proc.stderr or proc.stdout or "")[:400])
            elif reporter.get("skill_version") != version:
                problems.append("doctor reports version "
                                + repr(reporter.get("skill_version"))
                                + ", expected " + version)
            # What the bundle carries is read off the unpacked tree instead:
            # every expected tool must be a file here (a defect on any host),
            # and -- only where the host is the target -- runnable.
            unpacked_missing, not_runnable, untestable = [], [], []
            for name in expect:
                carried = (base / "bin" / platform
                           / (name + (".exe" if platform == "windows" else "")))
                if not carried.is_file():
                    unpacked_missing.append(name)
                elif not _runnable_here(carried):
                    untestable.append(name)
                elif not cross_checkable and not tools.get(name, {}).get("executable"):
                    not_runnable.append(name)
            if unpacked_missing:
                problems.append("binaries absent from the bundle: "
                                + repr(sorted(unpacked_missing)))
            if not_runnable:
                problems.append("binaries not runnable on this host: "
                                + repr(sorted(not_runnable)))
            if untestable:
                notes.append(str(len(untestable)) + " binaries are for another "
                             "platform and were not executed here; verify the "
                             "bundle on its own OS: " + repr(sorted(untestable)))
            egress = ((reporter.get("environment") or {}).get("net_egress") or {})
            if not egress.get("any_reachable"):
                print("note: no outbound network during audit; doctor's egress "
                      "checks failed (not a build failure)", file=sys.stderr)

        # Windows cannot represent a POSIX mode: os.stat() there reports
        # 0666 for everything and ZipFile.extractall() ignores the stored
        # attribute, so the exec bit can only be verified where the OS
        # models one (the Linux side of a release check).
        if os.name != "nt":
            lost = []
            for p in (base.rglob("*") if base.is_dir() else []):
                if not p.is_file():
                    continue
                rel = p.relative_to(base).as_posix()
                if rel.endswith(".installed-versions"):
                    continue
                if not rel.startswith(("bin/", "scripts/")):
                    continue
                if not (p.stat().st_mode & 0o111):
                    lost.append(rel)
            if lost:
                problems.append("not executable after unpack: " + repr(lost[:5]))
        else:
            # still assert the archive STORES the bit correctly
            with zipfile.ZipFile(archive) as z:
                plain = [i.filename for i in z.infolist()
                         if _is_os_payload(i.filename)
                         and not (i.external_attr >> 16) & 0o111]
                if plain:
                    problems.append("exec bit not stored for: " + repr(plain[:5]))

        # nothing the audit could not see
        for p in base.rglob("*") if base.is_dir() else []:
            rel = p.relative_to(base).as_posix()
            if p.is_dir() and p.name == "__pycache__":
                problems.append("__pycache__ left behind: " + rel)
            if p.is_file() and p.suffix in FORBIDDEN_SUFFIXES:
                problems.append("bytecode in bundle: " + rel)
    return {"ok": not problems, "problems": problems, "notes": notes}


# ---------------------------------------------------------------------- main

def _version(root: Path, want: str) -> str:
    if want:
        return want.lstrip("v")
    f = root / "VERSION"
    if not f.is_file():
        raise SystemExit("no VERSION file and no --version given")
    return f.read_text(encoding="utf-8").strip()


def host_platform() -> str:
    """The platform whose binaries this interpreter can actually run."""
    return "windows" if os.name == "nt" else "linux"


def _runnable_here(path: Path) -> bool:
    """Can this host execute the file? Judges the FORMAT, not the exec bit.

    A Linux bundle built on Windows carries perfect ELF binaries that this
    machine simply cannot start; the Python-3.6 interpreter on the WSL side
    cannot read the zip either, so the only honest verdict here is "not
    testable" -- reported as a note for whoever verifies on Linux. The exec
    bit is checked separately, straight off the archive, on every host.
    """
    head = path.read_bytes()[:4]
    if path.suffix == ".exe" or head[:2] == b"MZ":
        return True
    return head == b"\x7fELF" and host_platform() != "windows"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="build clean findinfo release bundles")
    ap.add_argument("--platform", default="all", choices=(*PLATFORMS, "all"))
    ap.add_argument("--version", default="", help="defaults to the VERSION file")
    ap.add_argument("--out", default="_rel", help="output directory (default _rel)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the file list and stop; writes nothing")
    ap.add_argument("--skip-audit", action="store_true",
                    help="skip the unpack + doctor self-check (not for releases)")
    ap.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    version = _version(root, args.version)
    platforms = list(PLATFORMS) if args.platform == "all" else [args.platform]
    out = (root / args.out) if not Path(args.out).is_absolute() else Path(args.out)

    if args.dry_run:
        for platform in platforms:
            files = shipped_files(platform, root)
            print(platform + ": " + str(len(files)) + " files")
            for rel in files:
                print("  " + rel)
        return 0

    results = []
    for platform in platforms:
        info = build(platform, version, out, root)
        result = {"version": version, "platform": platform,
                  "files": info["files"],
                  "bytes_raw": info["bytes_raw"],
                  "bytes_zip": info["bytes_zip"],
                  "sha256": info["sha256"],
                  "zip": str(Path(info["file"]))}
        if not args.skip_audit:
            verdict = audit(Path(info["file"]), info["prefix"], version,
                             cross_checkable=(platform == host_platform()),
                             expect=info.get("tools") or ())
            result["audit_ok"] = verdict["ok"]
            result["audit_problems"] = verdict["problems"]
            result["audit_notes"] = verdict["notes"]
            for note in verdict["notes"]:
                print("note: " + note, file=sys.stderr)
        else:
            result["audit_ok"] = None
        results.append(result)
        # one JSON line per platform, on stdout, for the release notes
        print(json.dumps(result, ensure_ascii=False))

    sums = write_sums(out, [{"sha256": r["sha256"],
                             "name": Path(r["zip"]).name} for r in results])
    print(json.dumps({"SHA256SUMS": str(sums),
                      "archives": [Path(r["zip"]).name for r in results]},
                     ensure_ascii=False))
    return 0 if all(r["audit_ok"] in (True, None) for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
