"""Mapping opt-out/replay flags survive every Agent entry point.

All collectors/spawn are faked. Cold CLI plans install their own audit guard
before loading findinfo, so a runtime import, credential read or dispatch is
a test failure rather than an accidental request.
"""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from unittest import mock

import tests.util  # noqa: F401
from lib import spec
from tests.util import fresh_core, import_findinfo


def _args(fi, *flags):
    argv = ["run", "--domain", "mt-a.example.com", *flags]
    args = fi.build_parser().parse_args(argv)
    fi._mark_explicit(args, argv)
    return args


def _offline_cli(home, *argv):
    code = r'''
import os, runpy, sys
def guard(event, args):
    if event.startswith("socket.") or event in ("subprocess.Popen", "os.system"):
        raise AssertionError("offline dispatch: " + event)
    if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        name = os.fsdecode(args[0]).replace("\\", "/").split("/")[-1]
        if name in (".env", "config.json"):
            raise AssertionError("offline credential/config read: " + name)
sys.addaudithook(guard)
path, *argv = sys.argv[1:]
sys.argv = [path, *argv]
try:
    runpy.run_path(path, run_name="__main__")
except SystemExit as exc:
    assert "lib.core" not in sys.modules, "cold plan imported runtime"
    raise
'''
    env = dict(os.environ, FINDINFO_HOME=str(home), FINDINFO_TASK="")
    env.pop("FINDINFO_RUN_DIR", None)
    return subprocess.run(
        [sys.executable, "-c", code, str(tests.util.ROOT / "findinfo.py"),
         "--home", str(home), *argv],
        cwd=str(tests.util.ROOT), env=env, capture_output=True, timeout=30)


def _payload(proc):
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return json.loads(proc.stdout)


def test_mapping_flags_round_trip_and_legacy_defaults():
    fi = import_findinfo()
    for no_mapping, remap in ((False, False), (True, False),
                              (False, True), (True, True)):
        flags = (["--no-mapping"] if no_mapping else [])
        flags += ["--remap"] if remap else []
        original = spec.from_cli(_args(fi, *flags))
        restored = spec.RunSpec.from_json(original.to_json())
        replay = spec.from_cli(fi.build_parser().parse_args(
            restored.to_worker_argv()))
        assert replay == original
        assert replay.no_mapping is no_mapping and replay.remap is remap
    legacy = json.loads(original.to_json())
    legacy.pop("no_mapping")
    legacy.pop("remap")
    restored = spec.RunSpec.from_json(json.dumps(legacy))
    assert not restored.no_mapping and not restored.remap


def test_background_persists_mapping_policy_without_spawning():
    fresh_core()
    fi = import_findinfo()
    args = _args(fi, "--no-mapping", "--remap", "--background")
    launched = []

    def fake_spawn(rd):
        launched.append(fi.jobs.read_spec(rd))
        return os.getpid()

    with mock.patch.object(fi.jobs, "spawn", fake_spawn), \
            mock.patch.object(fi.jobs, "find_inflight", lambda key: None), \
            redirect_stdout(io.StringIO()):
        assert fi._start_background(args) == 0
    assert len(launched) == 1
    job = launched[0]
    assert job["run_spec"]["no_mapping"] and job["run_spec"]["remap"]
    assert "--no-mapping" in job["argv"] and "--remap" in job["argv"]
    assert job["params"]["no_mapping"] and job["params"]["remap"]
    replay = fi.build_parser().parse_args(job["argv"])
    assert replay.no_mapping and replay.remap


def test_mapping_policy_changes_do_not_reuse_the_other_job():
    fresh_core()
    fi = import_findinfo()
    variants = [_args(fi), _args(fi, "--no-mapping"), _args(fi, "--remap")]
    keys = {fi.jobs.dedupe_key(fi._dedupe_payload(a)) for a in variants}
    assert len(keys) == 3
    assert "no_mapping" not in fi._dedupe_payload(variants[0])
    assert "remap" not in fi._dedupe_payload(variants[0])
    assert set(spec.from_cli(variants[1]).diff(spec.from_cli(variants[0]))) == {
        "no_mapping"}
    assert set(spec.from_cli(variants[2]).diff(spec.from_cli(variants[0]))) == {
        "remap"}


def test_resume_preserves_policy_and_checks_only_explicit_identity():
    fi = import_findinfo()
    stored = spec.from_cli(_args(fi, "--name", "美团", "--no-mapping", "--remap"))
    job = {"run_spec": json.loads(stored.to_json()),
           "argv": stored.to_worker_argv()}
    args = _args(fi, "--resume", "R", "--no-mapping", "--remap", "--rounds", "4")
    effective = fi._resume_effective_spec(job, args)["_effective_spec"]
    assert effective.name == "美团" and effective.rounds == 4
    assert effective.no_mapping and effective.remap
    assert job["run_spec"]["rounds"] == 1, "preview mutated the stored object"
    legacy = {"argv": stored.to_worker_argv()}
    replay = fi._resume_effective_spec(legacy, _args(fi, "--resume", "R"))
    assert "--no-mapping" in replay["argv"] and "--remap" in replay["argv"]
    plain = spec.from_cli(_args(fi))
    for flag in ("--no-mapping", "--remap"):
        try:
            fi._resume_effective_spec(
                {"run_spec": json.loads(plain.to_json())},
                _args(fi, "--resume", "R", flag))
        except fi.core.FindInfoError as exc:
            assert "resume rejected" in str(exc)
        else:
            raise AssertionError("resume silently changed " + flag)


def test_cold_plan_honors_mapping_opt_out_without_runtime():
    with tempfile.TemporaryDirectory(prefix="fi-map-plan-") as td:
        home = Path(td) / "not-created"
        p = _payload(_offline_cli(home, "run", "--domain", "mt-a.example.com",
                                  "--no-mapping", "--remap", "--dry-run"))
        assert "mapping" not in p["planned_stages"]
        assert not home.exists()


def test_cold_resume_plan_replays_flags_and_explicit_limits_read_only():
    with tempfile.TemporaryDirectory(prefix="fi-map-resume-") as td:
        home = Path(td)
        for legacy in (False, True):
            rd = home / "runs" / ("legacy" if legacy else "current")
            rd.mkdir(parents=True)
            stored = spec.RunSpec(name="美团", domain=("mt-a.example.com",),
                                  no_mapping=True, remap=True, rounds=2,
                                  task_timeout=100)
            job = {"argv": stored.to_worker_argv(), "run_id": rd.name}
            if not legacy:
                job["run_spec"] = json.loads(stored.to_json())
            path = rd / "job.json"
            path.write_text(json.dumps(job), encoding="utf-8")
            before = path.read_bytes()
            p = _payload(_offline_cli(
                home, "run", "--resume", rd.name, "--domain", "mt-a.example.com",
                "--rounds", "7", "--task-timeout", "0", "--dry-run"))
            assert p["target"] == p["effective"]["target"] == "美团"
            assert p["limits"]["rounds"] == p["effective"]["limits"]["rounds"] == 7
            assert p["effective"]["limits"]["task_timeout_sec"] == 0
            assert "mapping" not in p["planned_stages"]
            assert "mapping" not in p["effective"]["planned_stages"]
            assert "--remap" in p["effective"]["argv"]
            assert path.read_bytes() == before and list(rd.iterdir()) == [path]


def test_legacy_resume_preserves_implicit_five_seed_cap_in_both_entries():
    fi = import_findinfo()
    assert spec.from_cli(_args(fi)).max_seed == 0
    with tempfile.TemporaryDirectory(prefix="fi-map-legacy-cap-") as td:
        home = Path(td)
        for legacy_json in (False, True):
            rd = home / "runs" / ("json" if legacy_json else "argv")
            rd.mkdir(parents=True)
            job = {"run_id": rd.name,
                   "argv": ["run", "--domain", "mt-a.example.com", "--no-mapping"]}
            if legacy_json:
                old = json.loads(spec.RunSpec(domain=("mt-a.example.com",),
                                              no_mapping=True).to_json())
                old.pop("max_seed")
                job["run_spec"] = old
            path = rd / "job.json"
            path.write_text(json.dumps(job), encoding="utf-8")
            effective = fi._resume_effective_spec(
                job, _args(fi, "--resume", rd.name))["_effective_spec"]
            assert effective.max_seed == 5
            before = path.read_bytes()
            payload = _payload(_offline_cli(
                home, "run", "--resume", rd.name, "--dry-run"))
            assert payload["limits"]["max_seed"] == 5
            argv = payload["effective"]["argv"]
            assert argv[argv.index("--max-seed") + 1] == "5"
            assert path.read_bytes() == before
    for cap in (0, 5, 9):
        job = {"run_spec": json.loads(spec.RunSpec(max_seed=cap).to_json())}
        assert spec.from_stored(job, lambda argv: None).max_seed == cap


def test_cold_resume_refuses_mapping_policy_changes_without_writing():
    with tempfile.TemporaryDirectory(prefix="fi-map-policy-change-") as td:
        home = Path(td)
        rd = home / "runs" / "R"
        rd.mkdir(parents=True)
        path = rd / "job.json"
        stored = spec.RunSpec(domain=("mt-a.example.com",))
        path.write_text(json.dumps({"run_id": "R", "argv": stored.to_worker_argv(),
                                    "run_spec": json.loads(stored.to_json())}),
                        encoding="utf-8")
        before = path.read_bytes()
        for flag in ("--no-mapping", "--remap"):
            payload = _payload(_offline_cli(
                home, "run", "--resume", "R", flag, "--dry-run"))
            assert payload["effective"]["source"] == "rejected"
            assert "resume rejected" in payload["effective"]["error"]
            assert path.read_bytes() == before and list(rd.iterdir()) == [path]


class _StopAfterStage(BaseException):
    pass


def _dispatch_forbidden(*args, **kwargs):
    raise AssertionError("a real collector was reached")


def test_no_mapping_blocks_name_fallback_and_remap_reaches_enabled_fallback():
    for disabled in (False, True):
        fresh_core()
        fi = import_findinfo()
        calls = []
        args = _args(fi, "--name", "美团", "--remap",
                     *(["--no-mapping"] if disabled else []))

        def stage(store, rd, summary, name, inputs, args, fn, entry, **kw):
            assert name == "entity"
            assert inputs["remap"] is True
            assert bool(inputs.get("no_mapping")) is disabled
            fn()
            raise _StopAfterStage()

        def probe(*a, **kw):
            calls.append(kw)
            return {"domains": [], "answered": 1}

        with mock.patch.object(fi.pipeline, "_stage", stage), \
                mock.patch.object(fi.tools, "t_enscan", lambda *a, **kw: {
                    "anchor_failed": True, "companies": [], "domains": [], "rc": 0}), \
                mock.patch.object(fi.tools, "resolve_entity_identity", lambda **kw: {
                    "status": "identified"}), \
                mock.patch.object(fi.mapdispatch, "resolve_by_name", probe), \
                mock.patch.object(fi.core, "run", _dispatch_forbidden), \
                mock.patch.object(fi.core, "curl", _dispatch_forbidden):
            try:
                fi._run_pipeline(args)
            except _StopAfterStage:
                pass
        assert len(calls) == (0 if disabled else 1)
        if calls:
            assert calls[0]["remap"] is True


def test_no_icp_skips_filing_questions_but_keeps_domain_mapping():
    for disabled in (False, True):
        core = fresh_core()
        fi = import_findinfo()
        s = core.Store()
        s.upsert_asset("icp", "京ICP证000001号", source="enscan", parent="美团")
        s.close()
        calls, stage_inputs = [], []
        args = _args(fi, "--name", "美团", *(["--no-icp"] if disabled else []))

        def stage(store, rd, summary, name, inputs, args, fn, entry, **kw):
            if name == "entity":
                return True, {"companies": ["美团"], "domains": [], "icp": []}
            if name == "mapping":
                stage_inputs.append(inputs)
                fn()
                raise _StopAfterStage()
            return True, {}

        def ask(store, run_id, kind, values, **kw):
            calls.append((kind, list(values)))
            return {"results": [], "dispatched": 0, "reused": 0}

        with mock.patch.object(fi.pipeline, "_stage", stage), \
                mock.patch.object(fi.mapdispatch, "ask_all", ask), \
                mock.patch.object(fi.mapdispatch, "engines_for", lambda *a: (["fofa"], [])), \
                mock.patch.object(fi.core, "run", _dispatch_forbidden), \
                mock.patch.object(fi.core, "curl", _dispatch_forbidden):
            try:
                fi._run_pipeline(args)
            except _StopAfterStage:
                pass
        assert [kind for kind, _ in calls] == (["domain"] if disabled else ["domain", "icp"])
        assert bool(stage_inputs[0]["codes"]) is (not disabled)


def test_name_fallback_forwards_remap_to_the_paid_adapter():
    fresh_core()
    from lib import mapdispatch, metered
    calls = []

    def ask(*a, **kw):
        calls.append(kw)
        return {"status": metered.ST_EMPTY, "results": []}

    with mock.patch.object(mapdispatch, "engines_for_task", lambda *a: (["fofa"], [])), \
            mock.patch.object(mapdispatch, "ask", ask):
        mapdispatch.resolve_by_name(object(), "R", "美团", remap=True)
    assert len(calls) == 1 and calls[0]["remap"] is True
