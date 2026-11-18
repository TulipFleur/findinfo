"""Fake pipeline entry used by tests/test_jobs.py and end-to-end checks.

Only sleeps, writes state through lib.jobs and touches marker files: no
tools, no network, no real collection. It stands in for cmd_run so the job
lifecycle (spawn / poll / wait / cancel / interrupt / resume) can be exercised
with a controlled, short-running process.

It lives in its own module (not in a heredoc) because the worker imports the
entry by name: an entry defined in a stdin script is not importable by a
child process.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from lib import jobs


def _heartbeat(run_dir: Path, stage: str, n: int, total: int) -> None:
    jobs.update_state(run_dir, stage=stage, stage_state="running",
                      stage_index=n, stage_total=total,
                      counts={"domain": n * 10})


def run(args) -> int:
    """args: run_dir, stages, sleep, fail_at, first_delay, result_status."""
    run_dir = Path(args.run_dir)
    stages = int(getattr(args, "stages", 3) or 3)
    sleep = float(getattr(args, "sleep", 0.4) or 0.4)
    fail_at = int(getattr(args, "fail_at", 0) or 0)
    first_delay = float(getattr(args, "first_delay", 0) or 0)
    status = getattr(args, "result_status", "complete") or "complete"
    if first_delay:
        # simulate a stage that produces nothing for a while (long idle window)
        time.sleep(first_delay)
    for i in range(1, stages + 1):
        (run_dir / ("stage%d.done" % i)).write_text(str(os.getpid()), encoding="utf-8")
        _heartbeat(run_dir, "stage-%d" % i, i - 1, stages)
        time.sleep(sleep)
    if fail_at:
        raise RuntimeError("injected failure at stage %d" % fail_at)
    result = {"status": status, "reason": "all_stages_done",
              "counts": {"domain": stages * 10}}
    coverage = {"planned_stages": ["stage-%d" % i for i in range(1, stages + 1)],
                "done_stages": ["stage-%d" % i for i in range(1, stages + 1)],
                "failed_stages": [], "not_run_stages": [],
                "stop_reason": "no_new_assets", "complete": status == "complete"}
    jobs.update_state(run_dir, counts={"domain": stages * 10}, result=result,
                      coverage=coverage, stage="done", stage_state="done",
                      stage_index=stages, stage_total=stages)
    with open(run_dir / "summary.jsonl", "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"stages": [], "result": result, "coverage": coverage},
                            ensure_ascii=False) + chr(10))
    return 0
