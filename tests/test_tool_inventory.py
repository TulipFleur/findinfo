"""Cross-source consistency: the tool inventory must agree everywhere.

A tool list lives in several places (the doctor canon, the setup-linux.sh
--check loop, the setup-linux.sh download table, and the actual
bin/<platform>/ contents). They drifted apart before: tlsx/gau/ffuf sat in
bin/ with no call site, while chaos and ksubdomain were listed for download
but missing from bin/linux. These tests turn any future drift into a hard
failure instead of a silent surprise.
"""

import os
import re

from lib import core


ROOT = core.ROOT
SETUP = ROOT / "scripts" / "setup-linux.sh"


def _setup_text():
    return SETUP.read_text(encoding="utf-8")


def _doctor_names():
    """The canonical list doctor tracks (lib/tools.py: doctor())."""
    src = (ROOT / "lib" / "tools.py").read_text(encoding="utf-8")
    m = re.search(r"def doctor\(\).*?names = \[(.*?)\]", src, re.S)
    assert m, "could not locate the doctor tool list"
    # hostCollision is camelCase; keep the character class wide enough
    return sorted(re.findall('"([A-Za-z][A-Za-z0-9_]*)"', m.group(1)))


def _download_names():
    """Tools setup-linux.sh actually downloads from a release."""
    blocks = re.findall('TOOLS="(.*?)"', _setup_text(), re.S)
    assert blocks, "could not locate the TOOLS download tables"
    names = set()
    for block in blocks:
        for line in block.strip().splitlines():
            if "|" in line:
                names.add(line.split("|")[0].strip())
    return names


def _check_loop_names():
    m = re.search(r"for t in ([a-zA-Z0-9 _]+); do", _setup_text())
    assert m, "could not locate the --check loop"
    return set(m.group(1).split())


# jsluice ships no release binary: docs/TOOLS.md tells the user to go install
# it themselves, so it is in the doctor list but never in the download table.
USER_PROVIDED = {"jsluice"}

# onepass is built from rust/ and enscan from go source, so neither appears in
# the release-download table; both have dedicated build steps instead.
BUILT_FROM_SOURCE = {"onepass", "enscan"}


def test_doctor_list_is_reasonable():
    names = _doctor_names()
    assert len(names) >= 10, names
    assert "httpx" in names and "subfinder" in names


def test_download_table_matches_doctor_list():
    # Everything doctor tracks that ships a release binary must be downloadable.
    # jsluice is user-provided (no release); onepass/enscan are built from source.
    download = _download_names()
    doctor = set(_doctor_names())
    expected = doctor - USER_PROVIDED - BUILT_FROM_SOURCE
    missing = expected - download
    extra = download - doctor
    assert not missing, "setup-linux.sh never downloads: " + str(sorted(missing))
    assert not extra, "setup-linux.sh downloads untracked tools: " + str(sorted(extra))


def test_check_loop_covers_every_doctor_tool():
    loop = _check_loop_names()
    doctor = set(_doctor_names())
    missing = doctor - loop
    assert not missing, "--check never inspects: " + str(sorted(missing))


def test_no_extra_tools_in_check_loop():
    loop = _check_loop_names()
    doctor = set(_doctor_names())
    extra = loop - doctor
    assert not extra, "--check inspects tools doctor does not track: " + str(sorted(extra))


def test_windows_and_linux_bin_dirs_agree():
    """Both platforms must ship the same tool set when present.

    A platform directory may be absent (a fresh clone on the other OS), but
    when both exist their contents must match the doctor list exactly.
    """
    doctor = set(_doctor_names())
    win_dir = ROOT / "bin" / "windows"
    lin_dir = ROOT / "bin" / "linux"
    if not win_dir.is_dir() or not lin_dir.is_dir():
        return  # nothing to compare on a single-platform checkout
    win = {f[:-4] for f in os.listdir(win_dir) if f.endswith(".exe")}
    lin = {f for f in os.listdir(lin_dir) if not f.startswith(".")}
    assert win == doctor, "bin/windows mismatch: " + str(sorted(win ^ doctor))
    assert lin == doctor, "bin/linux mismatch: " + str(sorted(lin ^ doctor))