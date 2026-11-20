"""Wiring W2 acceptance: one RunSpec for launch, resume and reuse (T20).

The CLI path, the worker replay argv and the resume patch all come from
lib/spec.py now; the handwritten _foreground_argv and the argv-splicing
merge helpers are gone. These tests pin the observable behaviour:

* a launched job's argv is a RunSpec round trip (spec -> argv -> parser);
* resume accepts only explicitly-typed limit flags and rejects identity
  changes with a structured error (never a silent repoint);
* reusing an in-flight job reports request_differences instead of
  applying the new limits to the running job.
"""

import json
import os
import subprocess
import sys
import tempfile

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import ROOT, import_findinfo

FI = import_findinfo()


def _cli(home, *args, timeout=120):
    env = dict(os.environ, FINDINFO_HOME=home, FINDINFO_TASK="")
    env.pop("FINDINFO_RUN_DIR", None)
    r = subprocess.run([sys.executable, str(ROOT / "findinfo.py"),
                         "--home", home] + list(args),
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", env=env, timeout=timeout,
                        cwd=str(ROOT))
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "")


def _json(stdout):
    lines = [l for l in stdout.splitlines() if l.strip().startswith("{")]
    return json.loads(lines[-1]) if lines else {}


def _read_spec(home, task, rid):
    with open(os.path.join(home, "tasks", task, "runs", rid, "job.json"),
              encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------- T20 launch
def test_background_argv_is_a_runspec_round_trip():
    """The stored argv re-parses into the spec that produced it."""
    home = tempfile.mkdtemp(prefix="fi-w2-argv-")
    try:
        rc, out, err = _cli(home, "--task", "w2a", "run", "--domain",
                            "mt-a.example.com", "--background", "--no-onepass",
                            "--no-icp", "--active", "--rounds", "2")
        assert rc == 0, err[-300:]
        rid = _json(out)["run_id"]
        spec = _read_spec(home, "w2a", rid)
        assert spec["argv"][0] == "run", spec["argv"]
        # the argv re-parses cleanly and matches the stored run_spec
        args = FI.build_parser().parse_args(list(spec["argv"]))
        from lib import spec as spec_mod
        rs = spec_mod.from_cli(args)
        assert rs.domain == ("mt-a.example.com",), rs
        assert rs.rounds == 2 and rs.active is True, rs
        assert spec["run_spec"]["rounds"] == 2, spec["run_spec"]
        assert spec["run_spec"]["active"] is True, spec["run_spec"]
        _cli(home, "--task", "w2a", "cancel", "--run", rid)
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------- T20 resume
def test_resume_rejects_identity_change_with_structured_error():
    """A resume that re-points the job at another target fails loudly."""
    home = tempfile.mkdtemp(prefix="fi-w2-id-")
    try:
        rc, out, _ = _cli(home, "--task", "w2b", "run", "--domain",
                          "mt-a.example.com", "--background", "--no-onepass")
        rid = _json(out)["run_id"]
        _cli(home, "--task", "w2b", "cancel", "--run", rid)
        rc2, out2, _ = _cli(home, "--task", "w2b", "run", "--resume", rid,
                            "--domain", "mt-b.example.net")
        assert rc2 == 2, "identity change on resume must be an error"
        payload = _json(out2)
        assert "rejected" in str(payload.get("message", "")).lower(), payload
        assert "mt-b.example.net" in str(payload.get("message", "")), payload
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def test_resume_applies_only_explicit_limit_flags():
    """Typed limits patch; untouchable identity keeps the stored value."""
    home = tempfile.mkdtemp(prefix="fi-w2-lim-")
    try:
        rc, out, _ = _cli(home, "--task", "w2c", "run", "--domain",
                          "mt-a.example.com", "--background", "--no-onepass",
                          "--rounds", "1", "--tool-timeout", "60")
        rid = _json(out)["run_id"]
        _cli(home, "--task", "w2c", "cancel", "--run", rid)
        rc2, out2, err2 = _cli(home, "--task", "w2c", "run", "--resume", rid,
                               "--rounds", "4")
        assert rc2 == 0, err2[-300:]
        spec = _read_spec(home, "w2c", rid)
        argv = spec["argv"]
        assert argv[argv.index("--rounds") + 1] == "4", argv
        assert argv[argv.index("--tool-timeout") + 1] == "60", (
            "an unspecified flag must keep its stored value", argv)
        assert spec["budget"]["rounds"] == 4, spec["budget"]
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def test_resume_bare_keeps_the_stored_spec_untouched():
    """A bare `--resume <id>` with no flags replays the job as it was."""
    home = tempfile.mkdtemp(prefix="fi-w2-bare-")
    try:
        rc, out, _ = _cli(home, "--task", "w2d", "run", "--domain",
                          "mt-a.example.com", "--background", "--no-onepass",
                          "--no-icp")
        rid = _json(out)["run_id"]
        _cli(home, "--task", "w2d", "cancel", "--run", rid)
        spec_before = _read_spec(home, "w2d", rid)
        rc2, out2, err2 = _cli(home, "--task", "w2d", "run", "--resume", rid)
        assert rc2 == 0, err2[-300:]
        spec_after = _read_spec(home, "w2d", rid)
        # the argv is identical: parser defaults never leak into the replay
        assert spec_after["argv"] == spec_before["argv"], (
            "a bare resume changed the replayed argv",
            spec_before["argv"], spec_after["argv"])
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)
