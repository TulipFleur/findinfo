#!/usr/bin/env python
"""Materialise a release as a plain DIRECTORY (no zip) next to _rel/<version>/.

    python scripts/build-release-dir.py                       # both platforms + source
    python scripts/build-release-dir.py --platform windows
    python scripts/build-release-dir.py --out _rel --version 0.8.0

Why this exists
---------------
build-release.py produces reproducible ZIPs. Reviewing a bundle then means
unzipping it somewhere else, and comparing a bundle against the working tree
means diffing an archive. This script writes the SAME manifest as an unpacked
tree, so a bundle can be inspected, diffed, run and hashed in place:

    <out>/<version>/findinfo-<version>-<platform>/
    <out>/<version>/findinfo-<version>-source/      (code+docs, no binaries)

The contents are decided by scripts/shipped.py and nothing else -- the same
rule build-release.py and install.py --copy use. There is deliberately no
second ignore list here: a private list is exactly how the three drifted
before.

Reproducibility: file bytes are copied verbatim and the write order is the
manifest order, so two runs over the same tree produce identical content.
SHA256SUMS is written beside the platform directories, one line per file:

    <sha256>  <platform>/<relative path>

Exit 0 on success. A bundle that cannot import its own CLI fails the run:
this script audits the tree it just wrote instead of trusting the copy.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import shipped as _shipped                                    # noqa: E402

# build-release.py owns the platform tool list and the forbidden-path
# predicate; the file name has a dash, so it is imported by path.
import importlib.util as _ilu                                 # noqa: E402

_spec = _ilu.spec_from_file_location(
    "build_release", str(Path(__file__).resolve().parent / "build-release.py"))
_build = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_build)

PLATFORMS = _shipped.PLATFORMS
platform_tool_names = _build.platform_tool_names
is_forbidden = _build.is_forbidden


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _mode_for(rel: str, src: Path) -> int:
    """Same mode rule the archive uses (ELF must stay executable)."""
    if rel.startswith(("bin/linux/", "bin/windows/", "scripts/")):
        return 0o644 if rel.endswith(".installed-versions") else 0o755
    if rel.endswith((".sh", ".py")):
        return 0o755
    if os.name != "nt" and (src.stat().st_mode & 0o111):
        return 0o755
    return 0o644


def build_source_dir(version: str, out: Path, root: Path = ROOT) -> dict:
    """A code+docs-only tree: everything shippable EXCEPT the platform binaries.

    For reviewing what a bundle contains without carrying the native tools,
    and for comparing repo shape against a platform bundle. Built from the
    same manifest, with every bin/<platform>/ entry removed.
    """
    files = list(_shipped.shipped_files("windows", root))
    for f in _shipped.shipped_files("linux", root):
        if f not in files:
            files.append(f)
    files = sorted({f for f in files
                    if not f.startswith(("bin/windows/", "bin/linux/"))})
    if not files:
        raise SystemExit("nothing to ship for source")

    name = "findinfo-" + version + "-source"
    dest = out / version / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    sums: list = []
    for rel in files:
        src = root / rel
        if not src.is_file():
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(src.read_bytes())
        try:
            os.chmod(target, _mode_for(rel, src))
        except OSError:
            pass
        sums.append((_sha256(target), "source/" + rel))

    sums_path = out / version / "SHA256SUMS-source"
    sums_path.write_text("\n".join("%s  %s" % s for s in sums) + "\n",
                         encoding="utf-8", newline="\n")
    return {"dir": str(dest), "name": name, "files": len(sums),
            "bytes": sum(p.stat().st_size for p in dest.rglob("*")
                         if p.is_file()),
            "sums": str(sums_path), "manifest": files, "tools": []}


def build_dir(platform: str, version: str, out: Path,
              root: Path = ROOT) -> dict:
    files = _shipped.shipped_files(platform, root)
    if not files:
        raise SystemExit("nothing to ship for " + platform)
    bad = [f for f in files if is_forbidden(f)]
    if bad:
        raise SystemExit("refusing to write forbidden paths: " + repr(bad[:10]))

    name = "findinfo-" + version + "-" + platform
    dest = out / version / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    sums: list = []
    copied = 0
    for rel in files:                       # manifest order == write order
        src = root / rel
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        target.write_bytes(data)
        copied += 1
        try:
            os.chmod(target, _mode_for(rel, src))
        except OSError:
            pass
        sums.append((_sha256(target), platform + "/" + rel))

    sums_path = out / version / ("SHA256SUMS-" + platform)
    sums_path.write_text("\n".join("%s  %s" % s for s in sums) + "\n",
                         encoding="utf-8", newline="\n")
    return {"dir": str(dest), "name": name, "files": copied,
            "bytes": sum(p.stat().st_size for p in dest.rglob("*")
                         if p.is_file()),
            "sums": str(sums_path),
            "manifest": files,
            "tools": platform_tool_names(platform, root)}


def audit(result: dict) -> list:
    """Problems found in the tree that was just written (empty == clean)."""
    problems: list = []
    dest = Path(result["dir"])
    for rel in result["manifest"]:
        p = dest / rel
        if not p.is_file():
            problems.append("missing: " + rel)
    for p in dest.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(dest).as_posix()
        if rel.endswith(".pyc") or "__pycache__" in rel:
            problems.append("bytecode shipped: " + rel)
        if rel in _shipped.SECRETS:
            problems.append("secret shipped: " + rel)
    # the bundle must be able to import its own CLI and print a version
    cli = dest / "findinfo.py"
    if cli.is_file():
        try:
            # -B + PYTHONDONTWRITEBYTECODE: the audit must not write .pyc into
            # the bundle it is checking (importing findinfo.py creates
            # lib/__pycache__/ otherwise -- bytecode that would appear in the
            # tree because WE ran it, not because the manifest shipped it).
            env = dict(os.environ)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            proc = subprocess.run(
                [sys.executable, "-B", str(cli), "--help"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=120, cwd=str(dest), env=env)
            if proc.returncode != 0:
                problems.append("CLI --help failed rc=" + str(proc.returncode) +
                                ": " + (proc.stderr or "")[-300:])
        except Exception as exc:
            problems.append("CLI did not run: " + repr(exc)[:200])
    # belt and braces: drop any bytecode the audit itself may have produced
    for p in dest.rglob("__pycache__"):
        shutil.rmtree(p, ignore_errors=True)
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="write an unpacked release tree (no zip) beside _rel/<version>/")
    ap.add_argument("--platform", default="all",
                    choices=(*PLATFORMS, "all"))
    ap.add_argument("--version", default="",
                    help="defaults to the VERSION file")
    ap.add_argument("--out", default="_rel",
                    help="output root (default _rel); the tree lands in <out>/<version>/")
    ap.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    ap.add_argument("--skip-audit", action="store_true",
                    help="write the tree but do not verify it")
    ap.add_argument("--no-source", action="store_true",
                    help="skip the code+docs-only findinfo-<ver>-source tree")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    version = (args.version or (root / "VERSION").read_text(
        encoding="utf-8").strip())
    out = Path(args.out)
    if not out.is_absolute():
        out = root / out

    results = []
    if not args.no_source:
        res = build_source_dir(version, out, root)
        res["problems"] = [] if args.skip_audit else audit(res)
        results.append(res)
    platforms = PLATFORMS if args.platform == "all" else (args.platform,)
    for platform in platforms:
        res = build_dir(platform, version, out, root)
        res["problems"] = [] if args.skip_audit else audit(res)
        results.append(res)

    for r in results:
        print("%-34s %5d files  %8.1f KiB  %s" % (
            r["name"], r["files"], r["bytes"] / 1024.0, r["dir"]))
        if r["problems"]:
            for p in r["problems"]:
                print("  PROBLEM " + p, file=sys.stderr)
    bad = [r for r in results if r["problems"]]
    if bad:
        return 1
    print("OK: " + ", ".join(r["name"] for r in results) +
          " (unpacked; no archive)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
