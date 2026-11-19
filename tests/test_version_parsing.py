"""doctor version recognition: never mistake a path for a version number.

doctor is the pre-flight every agent runs, and its version strings end up in
delivery notes. The old parser took the first x.y.z-looking token in the whole
output, so a usage banner that echoed its own install path reported the
directory name as the tool version:

    enscan -> "0.7.2-windows" (from E:\...\findinfo-0.7.2-windows\...)
    hostCollision -> "0.7.2-windows" (same)
    ksubdomain -> "" (its version is "2.4", only two components)

The fixtures below are verbatim samples captured from the shipped binaries, so
the parser is tested against what the tools really print.
"""
import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools


FIXTURE_PD = (
    "[INF] Current Version: v2.17.0\n"
    "[INF] Subfinder Config Directory: C:\\Users\\x\\AppData\\Roaming\\subfinder\n"
)
FIXTURE_PD_LOWER = (
    "\n  / /_____ _/ /____ ____  ___ _\n"
    "[INF] Current version: v1.8.0\n"
    "[INF] Katana config directory: C:\\Users\\x\\AppData\\Roaming\\katana\n"
)
FIXTURE_PD_BARE = (
    "\n      _             __  __\n"
    "   __| | _ __   ___ \\ \\/ /\n"
    "[INF] Current Version: 1.3.1\n"
)
FIXTURE_USAGE_WITH_PATH = (
    "Usage of E:\\AI\\skills\\findinfo\\bin\\windows\\hostCollision.exe:\n"
    "  -df string\n    \tdomain file path\n"
    "  -o string\n    \toutput file name\n"
    "  -r int\n    \trate limit (default 100)\n"
)
FIXTURE_USAGE_SLASH_PATH = (
    "Usage of /opt/findinfo-0.7.2-linux/bin/hostCollision:\n"
    "  -silent\n    \tsilent mode\n"
)
FIXTURE_KSUBDOMAIN = "KSubdomain version 2.4\n"
FIXTURE_ONEPASS = '{"ok":true,"version":"0.1.0"}\n'
FIXTURE_ENSCAN_EMPTY = (
    "Go Version: \n"
    "Author: \n"
    "Build SHA: \n"
    "Version: \n"
    "\nhttps://github.com/wgpsec/ENScan_GO\n"
)
FIXTURE_NO_VERSION = "  -silent\n    \tsilent mode\n  -t int\n    \tthreads\n"


def test_pd_banner_versions_are_read():
    tools = fresh_tools(fresh_core())
    assert tools.parse_version("subfinder", FIXTURE_PD) == ("v2.17.0", True)
    assert tools.parse_version("katana", FIXTURE_PD_LOWER) == ("v1.8.0", True)
    assert tools.parse_version("dnsx", FIXTURE_PD_BARE) == ("1.3.1", True)


def test_install_path_is_never_a_version():
    """The whole bug: findinfo-0.7.2-windows is a directory, not a version."""
    tools = fresh_tools(fresh_core())
    ver, found = tools.parse_version("hostCollision", FIXTURE_USAGE_WITH_PATH)
    assert found is False
    assert ver == "", "path fragment leaked as a version: " + repr(ver)
    ver2, found2 = tools.parse_version("hostCollision", FIXTURE_USAGE_SLASH_PATH)
    assert found2 is False
    assert ver2 == "", "path fragment leaked as a version: " + repr(ver2)
    ver3, found3 = tools.parse_version("onepass", FIXTURE_USAGE_WITH_PATH)
    assert found3 is False and ver3 == ""


def test_ksubdomain_two_component_version():
    """ksubdomain prints "2.4", which an x.y.z regex could never match."""
    tools = fresh_tools(fresh_core())
    assert tools.parse_version("ksubdomain", FIXTURE_KSUBDOMAIN) == ("2.4", True)


def test_onepass_json_version():
    tools = fresh_tools(fresh_core())
    assert tools.parse_version("onepass", FIXTURE_ONEPASS) == ("0.1.0", True)


def test_empty_version_field_is_unknown_not_a_path():
    """ENScan leaves the field blank; the trailing URL must not be harvested."""
    tools = fresh_tools(fresh_core())
    ver, found = tools.parse_version("enscan", FIXTURE_ENSCAN_EMPTY)
    assert found is False
    assert ver == "", "empty Version: field produced " + repr(ver)


def test_no_version_anywhere_is_unknown():
    tools = fresh_tools(fresh_core())
    for name in ("hostCollision", "enscan", "katana"):
        ver, found = tools.parse_version(name, FIXTURE_NO_VERSION)
        assert found is False, name
        assert ver == "", name + " -> " + repr(ver)


def test_strip_paths_removes_both_separators():
    tools = fresh_tools(fresh_core())
    text = ("Usage of E:\\AI\\skills\\findinfo\\bin\\windows\\x.exe:\n"
            "also /opt/findinfo-0.7.2-linux/bin/x\n")
    cleaned = tools._strip_paths(text)
    assert "0.7.2" not in cleaned, cleaned


def test_every_doctor_tool_has_a_version_recipe():
    """A tool added to doctor without a recipe reports four flags of noise as
    its version -- that is how this bug reached a release."""
    tools = fresh_tools(fresh_core())
    names = ["enscan", "subfinder", "httpx", "dnsx", "naabu", "cdncheck",
             "uncover", "katana", "chaos", "ksubdomain", "onepass",
             "hostCollision"]
    missing = [n for n in names if n not in tools._VERSION_SPECS]
    assert not missing, ("these doctor tools have no version recipe: "
                         + repr(missing))

def test_release_bundle_path_is_not_a_version():
    """The reported failure verbatim: findinfo-0.7.2-windows is a directory."""
    import re
    banner = ("Usage of E:\\AI\\skills\\findinfo\\_rel\\findinfo-0.7.2-windows"
              "\\bin\\windows\\hostCollision.exe:\n"
              "  -df string\n    \tdomain file path\n")
    # the old parser really did return the directory name -- keep a witness
    old = re.search(r"(v?\d+\.\d+\.\d+[\w.\-]*)", banner)
    assert old and old.group(1) == "0.7.2-windows", (
        "fixture no longer reproduces the original bug: "
        + repr(old.group(1) if old else None))
    tools = fresh_tools(fresh_core())
    ver, found = tools.parse_version("hostCollision", banner)
    assert found is False, "parsed a version out of a usage banner: " + repr(ver)
    assert ver == "", "reported the bundle directory as a version: " + repr(ver)
