"""Offline wait-cursor regression: real state files, no runtime config/processes."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import types
from unittest.mock import patch


def _load_jobs(tmp_path, monkeypatch):
    """Load the real jobs module with a small core, never lib.core/config."""
    def forbidden(*args, **kwargs):
        raise AssertionError("wait cursor tests must not use network or processes")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    for name in ("kill", "system", "startfile"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden)

    package = types.ModuleType("_findinfo_wait_test")
    package.__path__ = []
    core = types.ModuleType(package.__name__ + ".core")
    core.RUNS_DIR = tmp_path / "runs"
    core.RUNS_DIR.mkdir()
    core.FindInfoError = RuntimeError
    core.now = lambda: "2026-11-22T00:00:00Z"
    package.core = core
    path = Path(__file__).resolve().parents[1] / "lib" / "jobs.py"
    spec = importlib.util.spec_from_file_location(package.__name__ + ".jobs", path)
    jobs = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {package.__name__: package, core.__name__: core}):
        spec.loader.exec_module(jobs)
    # Derive liveness from a fixture, never inspect or signal host processes.
    monkeypatch.setattr(jobs, "pid_alive", lambda pid: True)
    return jobs, core


def _running(wait_jobs):
    jobs, core = wait_jobs
    rd = core.RUNS_DIR / "20261122-cursor"
    rd.mkdir()
    jobs.update_state(rd, state="running", pid=12345, stage="dns")
    return jobs, rd


def test_changed_wait_returns_new_cursor_and_next_wait_does_not_repeat(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    first = jobs.wait(rd, timeout=0)
    assert first["changed"] is False and first["timed_out"] is True
    jobs.update_state(rd, stage="probe")

    second = jobs.wait(rd, timeout=0, since_seq=first["cursor"])
    assert second["changed"] is True and second["timed_out"] is False
    assert second["cursor"] == second["progress_seq"] > first["cursor"]

    third = jobs.wait(rd, timeout=0, since_seq=second["cursor"])
    assert third["changed"] is False and third["timed_out"] is True
    assert third["cursor"] == second["cursor"]


def test_heartbeat_keeps_progress_cursor_stable(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    cursor = jobs.wait(rd, timeout=0)["cursor"]
    jobs.update_state(rd, beat=1)
    jobs.update_state(rd, beat=2)
    result = jobs.wait(rd, timeout=0, since_seq=cursor)
    assert result["seq"] > result["progress_seq"] == result["cursor"] == cursor
    assert result["changed"] is False and result["timed_out"] is True


def test_legacy_raw_seq_after_heartbeat_is_not_new_progress(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    jobs.update_state(rd, beat=1)
    raw_seq = jobs.read_state(rd)["seq"]
    result = jobs.wait(rd, timeout=0, since_seq=raw_seq)
    assert result["changed"] is False and result["timed_out"] is True
    assert result["cursor"] == result["progress_seq"] < raw_seq


def test_progress_after_legacy_raw_seq_returns_latest_marker(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    jobs.update_state(rd, beat=1)
    raw_seq = jobs.read_state(rd)["seq"]
    jobs.update_state(rd, stage="probe")
    result = jobs.wait(rd, timeout=0, since_seq=raw_seq)
    assert result["changed"] is True
    assert result["cursor"] == result["progress_seq"] > raw_seq


def test_default_wait_uses_current_progress_as_baseline(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    jobs.update_state(rd, stage="probe")
    jobs.update_state(rd, beat=1)
    result = jobs.wait(rd, timeout=0)
    assert result["changed"] is False and result["timed_out"] is True
    assert result["cursor"] == result["progress_seq"] < result["seq"]


def test_default_wait_returns_progress_that_arrives_during_wait(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    before = jobs.read_state(rd)["progress_seq"]
    sleeps = []

    def advance(_delay):
        sleeps.append(_delay)
        jobs.update_state(rd, stage="probe")

    monkeypatch.setattr(jobs.time, "sleep", advance)
    result = jobs.wait(rd, timeout=1)
    assert sleeps, "default wait must start from the current marker"
    assert result["changed"] is True and result["timed_out"] is False
    assert result["cursor"] == result["progress_seq"] > before


def test_default_wait_does_not_wake_for_heartbeat_during_wait(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    ticks = [0.0]
    monkeypatch.setattr(jobs.time, "time", lambda: ticks[0])

    def heartbeat(delay):
        ticks[0] += delay
        jobs.update_state(rd, beat=ticks[0])

    monkeypatch.setattr(jobs.time, "sleep", heartbeat)
    result = jobs.wait(rd, timeout=0.2)
    assert result["changed"] is False and result["timed_out"] is True
    assert result["seq"] > result["cursor"] == result["progress_seq"]


def test_terminal_result_acknowledges_current_marker(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    before = jobs.wait(rd, timeout=0)["cursor"]
    jobs.update_state(rd, state="completed", result={"status": "partial"})
    result = jobs.wait(rd, timeout=30, since_seq=before)
    assert result["terminal"] is True and result["changed"] is True
    assert result["timed_out"] is False
    assert result["cursor"] == result["progress_seq"] > before
    again = jobs.wait(rd, timeout=30, since_seq=result["cursor"])
    assert again["terminal"] is True and again["changed"] is False
    assert again["timed_out"] is False


def test_legacy_state_without_progress_marker_returns_raw_seq_cursor(tmp_path, monkeypatch):
    jobs, core = _load_jobs(tmp_path, monkeypatch)
    rd = core.RUNS_DIR / "20261122-legacy"
    rd.mkdir()
    (rd / "status.json").write_text(json.dumps({
        "state": "completed", "seq": 4, "updated_ts": jobs.now_ts()}),
        encoding="utf-8")
    result = jobs.wait(rd, timeout=0, since_seq=3)
    assert result["changed"] is True and result["cursor"] == result["seq"] == 4
    assert result["resync_recommended"] is True


def test_returned_cursor_survives_a_fresh_state_reader(tmp_path, monkeypatch):
    jobs, rd = _running(_load_jobs(tmp_path, monkeypatch))
    first = jobs.wait(rd, timeout=0)
    jobs.update_state(rd, counts={"domain": 10})
    second = jobs.wait(str(rd), timeout=0, since_seq=first["cursor"])
    # Only the serialized cursor and on-disk state are needed for the next call.
    next_cursor = json.loads(json.dumps(second))["cursor"]
    third = jobs.wait(rd.name, timeout=0, since_seq=next_cursor)
    assert third["changed"] is False and third["timed_out"] is True
