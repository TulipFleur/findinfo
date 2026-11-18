"""doctor's environment self-check: python, executability, network egress.

A consumer-grade agent host may not satisfy the pipeline's preconditions:
Python < 3.10 chokes on PEP 604 syntax, sandboxes strip the exec bit or
block unknown binaries, and some containers have no egress at all. doctor
used to hardcode "python": "ok" and probe none of this, so an agent inside
a restricted sandbox learned about the problem only when a stage failed
mid-run. These tests pin the new contract.
"""
import json
import os
import sys
from pathlib import Path

import tests.util  # noqa: F401  (isolated FINDINFO_HOME before lib import)
from tests.util import fresh_core


def _tools_mod():
    return __import__("lib.tools", fromlist=["tools"])


def test_core_run_returns_126_on_non_executable():
    """A binary the OS refuses to run must map to rc=126, not an exception.
    This is what keeps doctor alive inside a sandbox that blocks binaries."""
    core = fresh_core()
    tools = _tools_mod()
    fake = Path(core.HOME) / "fake-tool"
    fake.write_bytes(b"#!/bin/sh\n")            # no exec bit, not a real binary
    if os.name == "nt":
        fake = fake.with_suffix(".exe")
        fake.write_bytes(b"this is not a PE file")
    rc, _out, err = core.run([str(fake), "-version"], timeout=10)
    assert rc == 126, (rc, err)
    assert err, "the failure reason must survive for doctor's hint"


def test_doctor_flags_non_executable_binary():
    """A broken binary in bin/ must show executable=false and land in
    tools_summary.not_executable instead of crashing doctor."""
    core = fresh_core()
    tools = _tools_mod()
    from lib import core as real_core
    real_core.BIN_PLATFORM = Path(core.HOME) / "bin" / real_core.PLATFORM
    real_core.BIN_PLATFORM.mkdir(parents=True, exist_ok=True)
    (real_core.BIN_PLATFORM / ("httpx" + (".exe" if os.name == "nt" else ""))) \
        .write_bytes(b"definitely not an executable image")
    d = tools.doctor()
    entry = d["tools"]["httpx"]
    assert entry["present"] is True
    assert entry.get("executable") is False, entry
    assert "httpx" in d["tools_summary"]["not_executable"]
    assert d["tools_summary"]["all_in_bin"] is False
    assert d["python"], "doctor must still complete and emit JSON"


def test_doctor_environment_block_shape():
    """The environment block must exist and carry the three preconditions:
    a real python version check (not the old hardcoded 'ok'), a >=3.10
    requirement statement, and egress probe results."""
    core = fresh_core()
    tools = _tools_mod()
    d = tools.doctor()
    env = d["environment"]
    assert env["python_version"] == ".".join(map(str, sys.version_info[:3]))
    assert env["python_required"] == ">=3.10"
    assert isinstance(env["python_ok"], bool)
    assert env["python_ok"] == (sys.version_info >= (3, 10))
    net = env["net_egress"]
    assert set(net["probes"].keys()) == {"crt.sh", "rapiddns", "hackertarget"}
    assert all(isinstance(v, bool) for v in net["probes"].values())
    assert net["any_reachable"] == any(net["probes"].values())
    # the top-level python field must AGREE with the version check now
    if env["python_ok"]:
        assert d["python"] == "ok"
    else:
        assert d["python"].startswith("incompatible:")


def test_doctor_python_field_is_not_hardcoded_ok():
    """The old doctor returned the literal 'ok' without looking at the
    interpreter. On an incompatible python the field must say so."""
    tools = _tools_mod()
    src = Path(tools.__file__).read_text(encoding="utf-8")
    assert '"python": "ok" if env["python_ok"]' in src, \
        "the python field must be derived from the version check, not hardcoded"


def test_probe_url_treats_http_error_as_reachable():
    """A probe that gets an HTTP error answer (403/429 from a WAF) proves the
    egress works; only transport failures mean 'no egress'."""
    tools = _tools_mod()

    class _Boom(Exception):
        pass

    import urllib.error
    import urllib.request
    req = urllib.request.Request("https://example.invalid/")
    orig = urllib.request.urlopen
    def _fail(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)
    urllib.request.urlopen = _fail
    try:
        assert tools._probe_url(req) is True
    finally:
        urllib.request.urlopen = orig
