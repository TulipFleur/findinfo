"""Contract tests for tool resolution: one directory, no ambient fallbacks.

These guard the decision that every tool must live in bin/<platform>/. A
regression here is silent and expensive: results would start depending on
whatever happened to be installed on the machine the agent ran on.
"""

import os
import sys

import pytest

from lib import core


def test_platform_is_windows_or_linux():
    assert core.PLATFORM in ("windows", "linux")


def test_darwin_is_rejected(monkeypatch):
    """macOS must fail loudly instead of trying to run linux binaries."""
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(RuntimeError) as exc:
        core._platform_tag()
    assert "macOS" in str(exc.value)


def test_tool_resolves_from_bin_platform(monkeypatch):
    monkeypatch.setattr(core, "BIN_PLATFORM", core.BIN_PLATFORM)
    # a tool that ships with the repo on every platform it supports
    path = core.tool("subfinder")
    assert os.path.dirname(path) == str(core.BIN_PLATFORM)


def test_tool_does_not_fall_back_to_path(monkeypatch, tmp_path):
    """A same-named binary elsewhere on PATH must NOT be picked up."""
    fake = tmp_path / ("findinfo-no-such-tool" + (".exe" if os.name == "nt" else ""))
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    if os.name != "nt":
        fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(core, "BIN_PLATFORM", tmp_path / "empty-bin")
    with pytest.raises(core.ToolMissing):
        core.tool("findinfo-no-such-tool")


def test_tool_does_not_fall_back_to_flat_bin(monkeypatch, tmp_path):
    """The legacy flat bin/ layout is gone; only bin/<platform>/ counts."""
    flat = tmp_path / "bin"
    flat.mkdir()
    exe = flat / ("findinfo-flat-only" + (".exe" if os.name == "nt" else ""))
    exe.write_text("x", encoding="utf-8")
    monkeypatch.setattr(core, "BIN", flat)
    monkeypatch.setattr(core, "BIN_PLATFORM", tmp_path / "bin" / "missing-platform")
    with pytest.raises(core.ToolMissing):
        core.tool("findinfo-flat-only")


def test_missing_tool_message_points_at_bin_platform(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "BIN_PLATFORM", tmp_path / "nothing-here")
    with pytest.raises(core.ToolMissing) as exc:
        core.tool("definitely-absent-tool")
    msg = str(exc.value)
    assert "nothing-here" in msg
    assert "doctor" in msg