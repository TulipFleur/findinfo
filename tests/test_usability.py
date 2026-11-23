"""Small CLI contracts a real run tripped over (2026-11-23 report).

* `--domain a,b` reached the worker as one value and failed there, leaving
  only "worker finished state=failed" on stderr;
* `--top-ports 200` was accepted and handed to naabu, which refuses anything
  but its presets ("invalid top ports option");
* a failed naabu or a failed run did not say why where an agent looks first.
No socket, no binary, no real worker process.
"""
import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools, import_findinfo


def _payload(buf):
    return json.loads([ln for ln in buf.getvalue().splitlines() if ln.startswith("{")][-1])


def test_a_comma_list_of_domains_is_several_seeds():
    fresh_tools(fresh_core())
    fi = import_findinfo()
    seen = {}

    def _pipeline(args):
        seen["domain"] = list(args.domain)
        return 0

    with mock.patch.object(fi, "_run_pipeline", _pipeline):
        fi.main(["run", "--domain", "a.example.com,b.example.com",
                 "--domain", "c.example.com"])
    assert seen["domain"] == ["a.example.com", "b.example.com", "c.example.com"], seen


def test_a_bad_seed_is_refused_before_any_worker_starts():
    fresh_tools(fresh_core())
    fi = import_findinfo()
    spawned = []
    buf = io.StringIO()
    with mock.patch.object(fi.jobs, "spawn", lambda rd: spawned.append(rd) or 4242), \
            redirect_stdout(buf):
        rc = fi.main(["run", "--domain", "bad..example.com", "--background"])
    assert rc == 2, rc
    assert "invalid domain" in _payload(buf).get("message", ""), buf.getvalue()
    assert spawned == [], spawned


def test_top_ports_takes_only_the_naabu_presets():
    fresh_tools(fresh_core())
    fi = import_findinfo()
    ok = fi.build_parser().parse_args(["run", "--domain", "a.example.com",
                                       "--top-ports", "100"])
    assert ok.top_ports == 100
    for argv in (["run", "--domain", "a.example.com", "--top-ports", "200"],
                 ["ports", "--ip", "203.0.113.5", "--top-ports", "200"]):
        try:
            with redirect_stderr(io.StringIO()):
                fi.build_parser().parse_args(argv)
            raised = None
        except SystemExit as exc:
            raised = exc.code
        assert raised == 2, argv


def test_a_failed_naabu_names_its_reason():
    core = fresh_core()
    tools = fresh_tools(core)
    from lib import pipeline
    store = core.Store()
    try:
        rd = core.new_run_dir("ports-why")
        summary = {"stages": [], "_run_public_id": rd.name, "attempt": 1,
                   "_stage_total": 1}
        ctx = pipeline.RunContext(
            args=SimpleNamespace(top_ports=1000), store=store, run_id=None,
            run_dir=rd, summary=summary, active=True, attempt=1, target_label="t",
            planned=["ports"], ledger=None, rounds=1, time_budget=0.0,
            tool_timeout=0, max_seed=0, t_start=0.0, scope=["example.com"],
            ipagg={"candidates": [{"ip": "203.0.113.5", "domains": []}]})
        why = "[FTL] Could not parse ports: invalid top ports option"
        with mock.patch.object(tools, "t_ports", lambda *a, **kw: {
                "count": 0, "ok": False, "rc": 1, "error": why}):
            pipeline._stage_ports(ctx)
    finally:
        store.close()
    entry = summary["stages"][-1]
    assert entry.get("failed") is True, entry
    assert "invalid top ports option" in entry.get("error", ""), entry


def test_a_failed_run_says_why_on_stderr():
    fresh_tools(fresh_core())
    fi = import_findinfo()
    args = fi.build_parser().parse_args(["run", "--domain", "bad..example.com"])
    err = io.StringIO()
    raised = None
    with redirect_stderr(err):
        try:
            fi._run_pipeline(args)
        except Exception as exc:  # noqa: BLE001 - the refusal is the point
            raised = exc
    assert raised is not None
    assert "run failed:" in err.getvalue() and "invalid domain" in err.getvalue(), \
        err.getvalue()[-400:]


def _failing_entry(args):
    """What _run_pipeline leaves behind when it stops on bad input."""
    from lib import pipeline
    pipeline._write_status(Path(args.run_dir), state="failed",
                           last_error={"type": "FindInfoError",
                                       "message": "invalid domain: bad..example.com"})
    return 2


def test_the_worker_result_names_why_the_run_stopped():
    core = fresh_core()
    from lib import jobs
    rd = core.new_run_dir("why-failed")
    jobs.write_spec(rd, entry="tests.test_usability:_failing_entry",
                    args={"run_dir": str(rd)}, target="example.com",
                    scope=["example.com"], dedupe_key="why",
                    root=str(core.ROOT), home=str(core.HOME),
                    env={"FINDINFO_HOME": str(core.HOME)})
    jobs.update_state(rd, state="queued")
    # the worker publishes its identity in the environment: keep it local,
    # and start from none (an earlier in-process worker may have left its
    # launch token, which would fence this run's status writes out)
    with mock.patch.dict(os.environ, {}), redirect_stderr(io.StringIO()):
        for k in ("FINDINFO_LAUNCH_TOKEN", "FINDINFO_RUN_DIR", "FINDINFO_ATTEMPT"):
            os.environ.pop(k, None)
        jobs.worker_main(rd)
    result = jobs.read_state(rd).get("result") or {}
    assert result.get("error", "").startswith("invalid domain"), result
