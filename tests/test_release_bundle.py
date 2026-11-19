"""Release bundle contents are a rule, not a memory.

The 0.7.x bundles were assembled by hand: they shipped cpython bytecode,
systemd units to Windows users, the developer agent-record tool, and a
bin/windows/config.yaml holding a real ENScan cookie. These tests pin the
manifest so a rebuild cannot silently regress to "whatever was in the tree".

They import scripts/build-release.py as a module (file name has a dash, so
importlib is used) and never build a real archive.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import tests.util  # noqa: F401  (isolate FINDINFO_HOME before lib.* imports)

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build-release.py"


def _mod():
    spec = importlib.util.spec_from_file_location("build_release", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_release"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_windows_manifest_has_no_bytecode_or_dev_material():
    m = _mod()
    files = m.shipped_files("windows", ROOT)
    assert files, "windows manifest is empty"
    bad = [f for f in files if m.is_forbidden(f)]
    assert not bad, "forbidden files in the windows bundle: " + repr(bad)
    for prefix in ("tests/", "agent-records/", "rust/", "deploy/"):
        leaked = [f for f in files if f.startswith(prefix)]
        assert not leaked, prefix + " must not ship: " + repr(leaked[:5])
    assert "scripts/agent-record.py" not in files
    assert ".gitignore" not in files


def test_windows_manifest_drops_the_posix_installer():
    m = _mod()
    files = m.shipped_files("windows", ROOT)
    assert "scripts/setup-linux.sh" not in files, (
        "setup-linux.sh installs ELF binaries; a Windows bundle cannot use it")
    # the cross-client installer is not platform bound and must stay
    assert "scripts/install.py" in files
    assert "scripts/findinfo.sh" in files


def test_windows_manifest_keeps_docs_and_only_exe_binaries():
    m = _mod()
    files = m.shipped_files("windows", ROOT)
    for doc in ("docs/LINUX.md", "docs/TOOLS.md", "docs/report-preview.png",
                "prompts/AGENT.txt", "SKILL.md", "README.md"):
        assert doc in files, doc + " must ship (README links to it)"
    binaries = [f for f in files if f.startswith("bin/windows/")]
    assert binaries, "no windows binaries in the manifest"
    assert all(b.endswith(".exe") for b in binaries), (
        "non-exe in bin/windows: " + repr([b for b in binaries
                                           if not b.endswith(".exe")]))


def test_linux_manifest_has_elf_binaries_and_no_exe():
    m = _mod()
    files = m.shipped_files("linux", ROOT)
    assert files
    exe = [f for f in files if f.endswith(".exe")]
    assert not exe, "an .exe cannot run on Linux: " + repr(exe[:5])
    binaries = [f for f in files if f.startswith("bin/linux/")]
    assert binaries, "no linux binaries in the manifest"
    assert not [f for f in binaries if f.endswith(".exe")]
    # a Linux bundle keeps its POSIX installer
    assert "scripts/setup-linux.sh" in files


def test_no_platform_ships_a_config_yaml_or_env():
    m = _mod()
    for platform in ("windows", "linux"):
        files = m.shipped_files(platform, ROOT)
        for secret in ("bin/config.yaml", "config/.env"):
            assert secret not in files, platform + " bundle leaks " + secret
        named = [f for f in files if f.rsplit("/", 1)[-1] == ".env"]
        assert not named, (platform + " bundle ships an .env: "
                           + repr(named[:5]))
        # a bin/**/config.yaml is an ENScan cookie: exclude by path
        assert not [f for f in files if f.startswith("bin/") and f.endswith("config.yaml")]
        # the templates people copy from DO ship
        assert "bin/config.example.yaml" in files
        assert "config/.env.example" in files


def test_manifest_is_stable_and_sorted():
    m = _mod()
    a = m.shipped_files("windows", ROOT)
    b = m.shipped_files("windows", ROOT)
    assert a == b, "manifest is not deterministic between calls"
    assert a == sorted(a), "manifest must be sorted so diffs are meaningful"


def test_zip_entry_names_are_posix_and_rooted_at_a_prefix():
    m = _mod()
    assert m._zip_name("findinfo-0.7.2-windows", "lib/core.py") == (
        "findinfo-0.7.2-windows/lib/core.py")


def test_audit_flags_a_planted_pyc(tmp_path=None):
    """The audit must fail on the exact defect the manual bundles shipped."""
    m = _mod()
    import zipfile
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="fi-reltest-"))
    prefix = "findinfo-0.0.0-test"
    archive = tmp / (prefix + ".zip")
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(prefix + "/findinfo.py", "print('{}')\n")
        z.writestr(prefix + "/lib/__pycache__/core.cpython-310.pyc", "x")
    verdict = m.audit(archive, prefix, "0.0.0-test", run_doctor=False)
    assert not verdict["ok"], "audit accepted a bundle containing a .pyc"
    assert any("forbidden" in p or "bytecode" in p for p in verdict["problems"])


def test_audit_accepts_a_minimal_clean_bundle():
    m = _mod()
    import zipfile
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="fi-reltest-"))
    prefix = "findinfo-0.0.0-test"
    archive = tmp / (prefix + ".zip")
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(prefix + "/findinfo.py", "print('{}')\n")
        z.writestr(prefix + "/VERSION", "0.0.0-test\n")
    verdict = m.audit(archive, prefix, "0.0.0-test", run_doctor=False)
    assert verdict["ok"], repr(verdict["problems"])
