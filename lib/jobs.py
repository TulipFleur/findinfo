"""Background jobs: a pure-Python worker, per-run state, bounded waiting.

A "job" is one run directory under RUNS_DIR:

    job.json      immutable spec  (argv, target, scope, budgets, dedupe_key)
    status.json   mutable state   (state, stage, counters, heartbeat, seq)
    stdout.log    worker stdout   (the final one-line JSON summary)
    stderr.log    worker stderr   (human progress)
    summary.jsonl result          (written by cmd_run / the entry point)
    cancel        marker          (cancellation was requested)

One worker process owns one job and is the only writer of status.json. The
worker is an ordinary Python child process started in its own session
(POSIX setsid / Windows DETACHED_PROCESS), so it does not depend on the
terminal or the agent call that started it. That is the *only* liveness
guarantee this module makes: it cannot keep a job alive across a machine
reboot, and it cannot wake a finished agent session (see docs).

State machine: queued -> running -> completed | failed | cancelled.
'queued' exists for the short window between create and worker start; a page
of truth that says 'running' with a dead pid is reported as interrupted, which
is derived, not stored.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from . import core

SCHEMA = "findinfo.job/1"
TERMINAL = ("completed", "failed", "cancelled")
# A queued job with no pid is legitimate only for the instant between writing
# state=queued and spawn() publishing the pid. Anything longer than this is a
# failed launch, and must stop reporting alive=True (see derive()).
QUEUE_GRACE = 20.0
ACTIVE = ("queued", "running")


# ---------------------------------------------------------------- basics
def now_ts() -> float:
    return round(time.time(), 3)


def resolve(ref) -> Path:
    """Accept a run id, a run directory path, or a prefix of a run id."""
    if isinstance(ref, Path):
        return ref
    raw = str(ref or "").strip()
    if not raw:
        raise core.FindInfoError("run id is required (see: python findinfo.py runs)")
    p = Path(raw)
    if p.is_dir() and (p / "status.json").exists():
        return p
    direct = core.RUNS_DIR / raw
    if (direct / "status.json").exists() or (direct / "job.json").exists():
        return direct
    # prefix match, newest first: ids carry a timestamp so sorting is meaningful
    cands = sorted([d for d in core.RUNS_DIR.glob(raw + "*")
                    if d.is_dir() and ((d / "status.json").exists() or (d / "job.json").exists())])
    if len(cands) == 1:
        return cands[0]
    if len(cands) > 1:
        raise core.FindInfoError("ambiguous run id " + raw + ": " +
                                 ", ".join(d.name for d in cands[-5:]))
    raise core.FindInfoError("run not found: " + raw)


def _atomic_write(path: Path, obj) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(str(tmp), str(path))


class _Lock:
    """Cross-platform exclusive lock built on O_CREAT|O_EXCL.

    status.json is a read-modify-write file; the worker's heartbeat thread and
    its main thread both update it, so a lock is required to keep the seq
    monotonic and to avoid losing fields.

    Stale recovery must not become "steal from a live holder". A writer that
    is merely SLOW (a GC pause, an antivirus scan, a stalled disk) leaves an
    old mtime while still running; the old rule broke the lock on mtime alone,
    so a second writer removed the live holder's file, took the name, and then
    the holder's exit unlinked the INTRUDER's lock -- both writes were lost.
    The lock file records the owner pid, so a steal is allowed only when that
    pid is provably gone (or the file carries no readable pid and is old).
    """

    def __init__(self, path: Path, timeout: float = 10.0):
        self.path = path
        self.timeout = timeout
        self.fd = None
        self._owned = False

    def _holder_gone(self) -> bool:
        """True only when the recorded owner cannot be alive any more."""
        try:
            raw = self.path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return False           # vanished/racy: let the loop retry the open
        try:
            pid = int(raw or 0)
        except ValueError:
            pid = 0
        if pid > 0:
            # the owner writes its pid on acquisition; a live pid is a live
            # holder, no matter how stale the mtime looks
            return not pid_alive(pid)
        # no usable pid (very old writer, or a torn write): fall back to mtime
        try:
            return time.time() - self.path.stat().st_mtime > 30
        except OSError:
            return False

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self.fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, str(os.getpid()).encode())
                self._owned = True
                return self
            except FileExistsError:
                if self._holder_gone():
                    try:
                        self.path.unlink()
                        continue
                    except OSError:
                        pass
                if time.time() > deadline:
                    raise core.FindInfoError("state lock timeout: " + str(self.path))
                time.sleep(0.02)

    def __exit__(self, *exc):
        try:
            if self.fd is not None:
                os.close(self.fd)
        except OSError:
            pass
        if self._owned:
            # Only the owner removes the file. A lock we never acquired, or
            # one that was stolen and re-created under us, must not be
            # unlinked here -- deleting an intruder's lock is the other half
            # of the corruption this class now prevents.
            try:
                if self.path.read_text(encoding="utf-8",
                                       errors="replace").strip() == str(os.getpid()):
                    self.path.unlink()
            except OSError:
                pass
        self._owned = False
        return False


# ---------------------------------------------------------------- state
def read_state(ref) -> dict:
    rd = resolve(ref)
    p = rd / "status.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    data.setdefault("run_id", rd.name)
    data["run_dir"] = str(rd)
    return data


# Fields whose change is a REAL fact an agent acts on. Anything else
# (updated/updated_ts/seq/beat) is a heartbeat: it must not move the progress
# cursor, or `wait --since` would report progress every 30 seconds.
_SUBSTANTIVE_FIELDS = ("state", "stage", "stage_state", "stage_index",
                       "stage_total", "counts", "endpoints", "result",
                       "coverage", "last_error", "attempt", "pid",
                       "planned_stages", "round", "rounds")


def _substantive_fingerprint(state: dict) -> str:
    """Stable hash of the substantive projection of a state document."""
    import hashlib
    blob = json.dumps([state.get(k) for k in _SUBSTANTIVE_FIELDS],
                      sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]


def _write_locked(rd: Path, p: Path, mutate) -> dict:
    """Read-modify-write status.json with the whole cycle under the state lock.

    `mutate(data)` returns the fields to merge, or None to abort (a fenced
    write that lost its token). Reading the token OUTSIDE the lock and writing
    inside it is the exact race F05 describes: a fresh attempt can install its
    token between the check and the write, and the stale writer then clobbers
    it. Here the check sees the same bytes it merges into.
    """
    with _Lock(rd / "state.lock"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        fields = mutate(data)
        if fields is None:
            return data
        data.update(fields)
        data["run_id"] = rd.name
        data["seq"] = int(data.get("seq") or 0) + 1
        data["updated"] = core.now()
        data["updated_ts"] = now_ts()
        # Persist the progress cursor: the seq of the last SUBSTANTIVE change.
        # A heartbeat-only write leaves it where it was.
        fp = _substantive_fingerprint(data)
        if data.get("progress_fingerprint") != fp:
            data["progress_fingerprint"] = fp
            data["progress_seq"] = data["seq"]
        _atomic_write(p, data)
    return data


def update_state(ref, **kw) -> dict:
    """Unfenced state write (CLI / host-side control entries only)."""
    rd = resolve(ref)
    p = rd / "status.json"
    return _write_locked(rd, p, lambda data: dict(kw))


def pid_alive(pid) -> bool:
    """True when a process with this pid exists (best effort, no false negatives)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, 0, pid)
        if handle:
            # OpenProcess succeeds for zombies too: ask for the exit code, which
            # is STILL_ACTIVE (259) only while the process really runs.
            code = ctypes.c_ulong(0)
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            kernel32.CloseHandle(handle)
            return bool(ok) and code.value == 259
        # ERROR_INVALID_PARAMETER means "no such process"; access denied = exists
        return ctypes.get_last_error() == 5
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass                       # exists but not ours
    except OSError:
        return False
    # A terminated child that has not been reaped yet still answers kill(0)
    # (zombie). On Linux /proc/<pid>/stat reports state Z for those, which is
    # the difference between "dead" and "still running".
    try:
        stat = Path("/proc/" + str(pid) + "/stat").read_text(encoding="utf-8", errors="replace")
        state = stat.rsplit(")", 1)[1].split()[0]
        if state in ("Z", "X"):
            return False
    except (OSError, IndexError):
        pass
    return True


def derive(state: dict) -> dict:
    """Add alive / interrupted / terminal / stalled to a raw state snapshot."""
    st = dict(state or {})
    name = str(st.get("state") or "unknown")
    pid = st.get("pid")
    alive = False
    if name == "running":
        alive = pid_alive(pid)
    elif name == "queued":
        # A queued job either has a worker already spawned (spawn() publishes
        # the pid immediately) or is still waiting to get one. Trust the pid
        # when present: a queued row whose worker died must not look alive.
        #
        # No pid at all is only legitimate for the few milliseconds between
        # "state=queued" and "spawn returned". Keeping it alive forever is how
        # a failed spawn turns into a job an agent waits on until the heat death
        # of the universe. Past QUEUE_GRACE the absence of a pid IS the failure.
        alive = pid_alive(pid) if pid else (now_ts() - float(st.get("updated_ts") or 0)) < QUEUE_GRACE
    age = None
    if st.get("updated_ts"):
        age = round(now_ts() - float(st["updated_ts"]), 1)
    # A dead pid is conclusive on its own. The 15 s heartbeat grace only exists
    # for platforms where a pid can look dead right after spawn; once the worker
    # has published at least one heartbeat, no grace is needed.
    # A worker publishes its pid synchronously in spawn(), so a dead pid is
    # conclusive immediately. The 15 s grace only covers rows written by an
    # older process that never published one.
    grace = 0 if st.get("pid") or st.get("beat") else 15
    interrupted = bool(name in ACTIVE and not alive and age is not None
                       and age >= grace)
    stalled = bool(name == "running" and alive and age is not None and age >= 180)
    st["alive"] = alive
    st["interrupted"] = interrupted
    st["stalled"] = stalled
    st["terminal"] = name in TERMINAL
    st["heartbeat_age_sec"] = age
    if interrupted:
        # Distinguish "the host reaped the worker before it ran any Python"
        # from an ordinary crash. The worker writes its '[worker] entered'
        # breadcrumb as its very first action, so an interrupted job whose
        # stderr.log is EMPTY never reached the interpreter: the detached
        # process was killed by the host (sandbox / session-scoped process
        # reaping). Remediation differs from a crash: retrying --background
        # dies the same way, so the caller must switch execution modes.
        reaped = False
        try:
            log = Path(str(st.get("run_dir") or "")) / "stderr.log"
            # spawn() opens stderr.log in append mode BEFORE starting the child,
            # so a backgrounded run dir always has the file. An ABSENT file
            # means the snapshot was hand-built (tests) or the dir predates
            # the job system: absent evidence is not evidence of reaping.
            reaped = log.is_file() and not log.read_text(
                encoding="utf-8", errors="replace").strip()
        except OSError:
            reaped = False
        st["reaped_by_host"] = reaped
        if reaped:
            st["hint"] = ("worker was killed by the host before it ran any Python "
                          "(empty stderr.log): this environment reaps detached "
                          "processes. Do NOT retry --background; run the same "
                          "command in the foreground with --task-timeout, or hold "
                          "the worker under a live parent process")
        else:
            st["hint"] = ("worker process " + str(pid) + " is gone; the job stopped "
                          "unexpectedly. Resume with: python findinfo.py run --resume " + st.get("run_id", ""))
    elif stalled:
        st["hint"] = "worker is alive but has not reported progress for a while; keep waiting"
    if "reaped_by_host" not in st:
        st["reaped_by_host"] = False
    return st


def progress(state: dict) -> dict:
    """Structured progress for agents. Never invents a percentage."""
    st = state or {}
    idx = st.get("stage_index")
    total = st.get("stage_total")
    pct = None
    if isinstance(idx, int) and isinstance(total, int) and total > 0:
        # A resumed run can have executed more stage entries than the original
        # plan; the index is then larger than the total. Report the real
        # progress of the PLAN (never > 100), and keep the raw index visible.
        pct = round(min(idx, total) * 100.0 / total, 1)
    return {
        "stage": st.get("stage"),
        "stage_state": st.get("stage_state"),
        "stage_index": idx,
        "stage_total": total,
        "percent": pct,              # None when the stage budget is unknown
        "counts": st.get("counts") or {},
        "endpoints": st.get("endpoints"),
        "elapsed_sec": (round(now_ts() - st["started_ts"], 1)
                        if st.get("started_ts") else None),
        "last_error": st.get("last_error"),
    }


# ---------------------------------------------------------------- job spec
def write_spec(run_dir: Path, **spec) -> dict:
    spec.setdefault("schema", SCHEMA)
    spec.setdefault("run_id", run_dir.name)
    spec.setdefault("created", core.now())
    spec.setdefault("created_ts", now_ts())
    _atomic_write(run_dir / "job.json", spec)
    return spec


def read_spec(ref) -> dict:
    rd = resolve(ref)
    try:
        return json.loads((rd / "job.json").read_text(encoding="utf-8"))
    except Exception:
        return {"run_id": rd.name}


def start_lock(key: str, timeout: float = 30.0):
    """Cross-process critical section for "check dedupe, then create the job".

    Two agents submitting the same target at the same time both call
    find_inflight() before either has written job.json, so both see "no
    inflight job" and both spawn a worker. The lock is per dedupe key, so
    unrelated targets do not serialise against each other.

    Reuses the O_CREAT|O_EXCL primitive from _Lock; a stale lock older than
    the timeout is stolen so a crashed process cannot wedge submissions.
    """
    safe = "".join(ch if ch.isalnum() else "_" for ch in (key or "nokey"))[:32]
    return _Lock(core.HOME / ("start-" + safe + ".lock"), timeout=timeout)


def dedupe_key(payload: dict) -> str:
    import hashlib
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]


def find_inflight(key: str) -> Path | None:
    """Return the run dir of an in-flight job with the same key, if any."""
    if not key:
        return None
    for rd in sorted(core.RUNS_DIR.glob("*")):
        jp = rd / "job.json"
        if not jp.exists():
            continue
        try:
            spec = json.loads(jp.read_text(encoding="utf-8"))
        except Exception:
            continue
        if spec.get("dedupe_key") != key:
            continue
        st = read_state(rd)
        state = st.get("state")
        if state not in ACTIVE:
            continue
        # Treat a job as in flight unless we are sure it is dead: a just-spawned
        # worker has not written its pid yet, and a slow machine may not have
        # started it at all. Re-using a live run is cheap; starting a duplicate
        # collection is not.
        if derive(st).get("interrupted"):
            continue
        return rd
    return None


# ---------------------------------------------------------------- worker
def _kill_children() -> None:
    """Terminate every descendant of this worker, leaving the worker alive.

    os._exit() on the timer thread leaves orphaned tool processes behind: a
    naabu/katana child keeps scanning (and consuming quota) after the job has
    already been reported as timed out. Walk the tree and kill bottom-up.
    """
    me = os.getpid()
    try:
        import psutil  # optional; stdlib fallback below
        victims = []
        for p in psutil.Process(me).children(recursive=True):
            victims.append(p)
        for p in reversed(victims):
            try:
                p.kill()
            except Exception:
                pass
        return
    except Exception:
        pass
    # stdlib fallback (Windows: taskkill /T walks the tree itself; POSIX: /proc)
    # WMIC used to be the child-lister here, but Windows 11 24H2 ships without
    # it: the wmic call failed silently and a task_timeout left naabu/katana
    # children running -- still probing the target after the authorized window
    # had closed. taskkill /T /PID <me> kills the whole descendant tree and is
    # present on every Windows install; killing our own pid is avoided by
    # listing children first only when wmic exists, else we let taskkill /T
    # terminate the tree and rely on the worker's own os._exit afterwards.
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        children = []
        # Prefer listing children so we do not taskkill ourselves: try wmic
        # (present on older Windows), then PowerShell CIM (24H2+), then fall
        # back to taskkill /T which takes the whole tree including us -- the
        # caller of _kill_children always follows with os._exit, so dying here
        # is acceptable, just noisier.
        for probe in (
            ["wmic", "process", "where", "ParentProcessId=%d" % me,
             "get", "ProcessId"],
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Process -Filter "
             "'ParentProcessId=%d').ProcessId" % me],
        ):
            try:
                # errors=replace: PowerShell's banner on a Chinese Windows is
                # GBK and would raise UnicodeDecodeError mid-probe, turning a
                # kill-path fallback into a silent no-op (the exact bug this
                # function exists to prevent).
                out = subprocess.run(probe, capture_output=True, text=True,
                                     errors="replace", timeout=15,
                                     creationflags=flags)
                for tok in (out.stdout or "").split():
                    if tok.isdigit() and int(tok) != me:
                        children.append(int(tok))
                if children or out.returncode == 0:
                    break
            except Exception:
                continue
        try:
            if children:
                for pid in children:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                   capture_output=True, timeout=10,
                                   creationflags=flags)
            else:
                # No child list available: take the whole tree. The worker
                # exits immediately after (os._exit), so this only races by
                # milliseconds.
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(me)],
                               capture_output=True, timeout=10,
                               creationflags=flags)
        except Exception:
            pass
    else:
        try:
            for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
                try:
                    with open("/proc/%s/stat" % pid) as fh:
                        fields = fh.read().split()
                    if len(fields) > 3 and int(fields[3]) == me:
                        os.kill(int(pid), 15)
                except Exception:
                    continue
        except Exception:
            pass


def _worker_flags() -> int:
    if os.name == "nt":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NO_WINDOW = 0x08000000
        return DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    return 0


def _windowless_python() -> str:
    """The interpreter to run the detached worker under.

    `sys.executable` is usually python.exe, a CONSOLE program. Started with
    DETACHED_PROCESS on Windows, a console program still gets a console of its
    own, so every `--background` run flashed a black cmd window on the user's
    desktop and left it there for the length of the run. pythonw.exe is the
    same interpreter without a console.
    """
    if os.name != "nt":
        return sys.executable
    exe = Path(sys.executable)
    if exe.name.lower() == "python.exe":
        cand = exe.with_name("pythonw.exe")
        if cand.exists():
            return str(cand)
    return sys.executable

def spawn(ref) -> int:
    """Start the detached worker for a prepared run dir; returns its pid."""
    rd = resolve(ref)
    spec = read_spec(rd)
    root = str(spec.get("root") or core.ROOT)
    env = dict(os.environ)
    env.update(spec.get("env") or {})
    env["PYTHONIOENCODING"] = "utf-8"
    env["FINDINFO_JOB_ID"] = rd.name
    cmd = [_windowless_python(), str(Path(root) / "findinfo.py"), "__worker", str(rd)]
    out = open(rd / "stdout.log", "ab")
    err = open(rd / "stderr.log", "ab")
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = _worker_flags()
    else:
        kw["start_new_session"] = True
    try:
        proc = subprocess.Popen(cmd, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err, close_fds=True, **kw)
    except BaseException as exc:              # noqa: BLE001 - must not stay queued
        # The job row already says state=queued and the dedupe key is taken.
        # Leaving that as-is is the worst outcome: every later submission sees
        # an "in flight" job, reuses it, and waits for a worker that was never
        # started. Record a terminal failure with an actionable message so the
        # next submission starts fresh (find_inflight ignores terminal rows).
        msg = (type(exc).__name__ + ": " + str(exc))[:300]
        try:
            update_state(rd, state="failed", exit_code=127, pid=None,
                         finished_ts=now_ts(), finished=core.now(),
                         stage_state="failed",
                         last_error={"type": "spawn_failed", "message": msg,
                                     "hint": "worker could not be started; "
                                             "check python/exe paths and retry "
                                             "with: python findinfo.py run --resume <run_id>"})
        except Exception:
            pass
        raise core.FindInfoError("failed to start worker: " + msg +
                                 " (run dir: " + str(rd) + ")")
    finally:
        out.close()
        err.close()
    pid = int(proc.pid)
    # Publish the pid immediately: the worker may still be importing modules, and
    # callers (and liveness checks) must not have to poll to learn it.
    try:
        update_state(rd, pid=pid, worker_started_ts=now_ts())
    except Exception:
        pass
    return pid


def claim_launch(rd, spec: dict) -> str | None:
    """Atomically claim the CURRENT launch token of a run.

    The resume path publishes a fresh token while holding the resume lock;
    a worker (or a stale attempt writing state) must match it to publish or
    update anything (docs/RELIABILITY-PLAN.md par.11: a superseded attempt
    cannot update state, acknowledge work, or publish a verdict). Returns the
    token when this worker owns the launch, None when it is superseded.
    """
    token = spec.get("launch_token")
    if not token:
        return ""            # legacy spec: nothing to fence, keep old behaviour
    current = read_state(rd)
    if (current.get("launch_token") or "") != token:
        return None
    return token


def fenced_write(rd, token, **fields) -> bool:
    """update_state that validates the launch token INSIDE the state lock.

    The token comparison and the merge happen in the same critical section:
    a resume that installs a new token between a stale reader's check and its
    write can no longer be clobbered (F05). A write without a token is allowed
    only while the state carries no token at all (legacy job): an empty token
    is not a universal bypass once a token exists.
    """
    rd = resolve(rd)
    accepted = {"ok": False}

    def mutate(data):
        current = data.get("launch_token") or ""
        if token:
            if current != token:
                return None
        elif current:
            # legacy/empty writer against a fenced job: refuse
            return None
        accepted["ok"] = True
        return dict(fields)

    _write_locked(rd, rd / "status.json", mutate)
    return accepted["ok"]


def worker_main(ref) -> int:
    """Entry point of the detached worker process (called by __worker)."""
    rd = resolve(ref)
    spec = read_spec(rd)
    argv = list(spec.get("argv") or [])
    # Leave a breadcrumb the instant the worker starts: a child that dies during
    # interpreter/module startup (bad env, missing DLL, blocked by policy) writes
    # nothing at all, and "empty stderr + dead pid" is indistinguishable from a
    # launch that never happened. This line makes the difference observable.
    try:
        with open(rd / "stderr.log", "a", encoding="utf-8") as _fh:
            _fh.write("[worker] entered pid=" + str(os.getpid()) +
                      " exe=" + sys.executable + chr(10))
    except Exception:
        pass
    timeout = float(spec.get("task_timeout") or 0)
    # Tell the pipeline which attempt it is, so summary.jsonl carries the
    # provenance of THIS execution (the pipeline cannot read job.json itself
    # without re-resolving the run dir).
    os.environ["FINDINFO_ATTEMPT"] = str(int(spec.get("attempt") or 1))
    # The pipeline's status writes are fenced by the SAME token this worker
    # claimed. Publishing it here (not re-reading job.json later) keeps the
    # identity immutable for the life of the process: a late resume that
    # rewrites job.json cannot hand this worker a different identity.
    _spec_token = spec.get("launch_token") or ""
    if _spec_token:
        os.environ["FINDINFO_LAUNCH_TOKEN"] = str(_spec_token)
    token = claim_launch(rd, spec)
    if token is None:
        core.log("[job] superseded attempt (launch token mismatch); exiting "
                 "without touching state")
        return 4                     # fenced out: a newer attempt owns the job
    # Every state mutation this worker performs goes through fenced_write
    # (par.11): a superseded attempt can never publish progress, a timeout
    # verdict or a terminal state over a newer attempt's.
    fenced_write(rd, token, state="running", pid=os.getpid(), started_ts=now_ts(),
                 attempt=int(spec.get("attempt") or 1),
                 launch_token=token or None,
                 target=spec.get("target"), scope=spec.get("scope") or [],
                 budget=spec.get("budget") or {})
    core.log("[job] worker started pid=" + str(os.getpid()) + " argv=" + " ".join(argv))

    timer = None
    if timeout > 0:
        def _timeout():
            # A hard deadline must actually stop the work. The old path wrote
            # state=failed and called os._exit(124) immediately: the collector
            # child processes kept running (still scanning, still spending
            # quota) and status kept showing the previous attempt's
            # result.status=complete / coverage.complete=true next to a failed
            # job. Kill the tree first, then overwrite the result for THIS
            # attempt, then leave.
            try:
                # Order matters: kill_tree() on our own pid group would take
                # this process down before the state write. Persist first, then
                # terminate the children, then exit.
                try:
                    summary = _last_summary(rd, int(spec.get("attempt") or 1))
                except Exception:
                    summary = None
                upd = {"state": "failed", "exit_code": 124,
                       "finished_ts": now_ts(), "finished": core.now(),
                       "stage_state": "failed",
                       "last_error": {"type": "task_timeout",
                                      "message": "task timeout after " +
                                                 str(int(timeout)) + "s"}}
                if summary is None or (summary.get("result") or {}).get("status") != "failed":
                    # No summary of our own (or one that still claims success):
                    # never let the previous attempt's success stand.
                    upd["result"] = {"status": "failed",
                                     "reason": "task_timeout",
                                     "attempt": int(spec.get("attempt") or 1),
                                     "message": "hard deadline hit at " +
                                                str(int(timeout)) + "s"}
                    upd["coverage"] = {"complete": False,
                                       "reason": "task_timeout",
                                       "attempt": int(spec.get("attempt") or 1)}
                # The deadline fires from THIS worker's timer, so it must also
                # respect the fence: a superseded attempt timing out must not
                # overwrite the newer attempt's state.
                fenced_write(rd, token, **upd)
                try:
                    _kill_children()
                except Exception:
                    pass
            finally:
                os._exit(124)
        timer = threading.Timer(timeout, _timeout)
        timer.daemon = True
        timer.start()

    rc = 1
    err = None
    try:
        if str(spec.get("entry") or "findinfo:main").endswith(":main"):
            # The worker IS findinfo.py, so a *script* child already finds
            # lib/ next to it and needs nothing. Keeping the entry unconditionally
            # put the skill root ahead of the caller's own sys.path for every
            # in-process launch (tests, embeddings), which shadowed same-named
            # modules; only add it when the start module cannot supply it.
            _root = str(spec.get("root") or core.ROOT)
            try:
                _have = __import__("lib.core", fromlist=["x"]).__file__ or ""
            except Exception:
                _have = ""
            if os.path.dirname(os.path.dirname(os.path.abspath(_have))) != os.path.abspath(_root):
                sys.path.insert(0, _root)
            # The worker IS findinfo.py, so its own module object already holds
            # any in-process patches (tests) and the same process-wide state.
            # Importing "findinfo" again would create a second module whose
            # "tools" reference points at pristine library functions.
            mod = sys.modules.get("__main__")
            if mod is None or not hasattr(mod, "main"):
                mod = importlib.import_module("findinfo")
            rc = int(mod.main(argv) or 0)
        else:                                  # custom entry (tests / extensions)
            mod_name, _, fn_name = str(spec["entry"]).partition(":")
            sys.path.insert(0, str(spec.get("root") or core.ROOT))
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name)
            args = argparse.Namespace(**spec["args"]) if spec.get("args") is not None else None
            rc = int(fn(args) or 0)
    except SystemExit as exc:                  # entry raised instead of returning
        rc = int(exc.code or 0) if isinstance(exc.code, int) else 1
    except BaseException:                      # noqa: BLE001 - worker must record it
        err = traceback.format_exc()[-4000:]
        rc = 1
    finally:
        if timer is not None:
            timer.cancel()

    cancelled = (rd / "cancel").exists()
    if cancelled:
        state, exit_code = "cancelled", 130
    elif rc == 0:
        state, exit_code = "completed", 0
    elif rc == 5:
        state, exit_code = "completed", 5      # finished, coverage incomplete
    else:
        state, exit_code = "failed", rc
    summary = _last_summary(rd, int(spec.get("attempt") or 1))
    upd = {"state": state, "exit_code": exit_code, "finished_ts": now_ts(),
           "finished": core.now(), "stage_state": state, "pid": os.getpid()}
    if summary is not None:
        upd["result"] = summary.get("result")
        upd["coverage"] = summary.get("coverage")
    else:
        # This attempt produced no summary of its own. Publishing the previous
        # attempt's result/coverage would let state=failed coexist with
        # result.status=complete. Say "no result for this attempt" explicitly;
        # the earlier entry stays in summary.jsonl for forensics, and `assets`
        # still shows the collected data.
        upd["result"] = {"status": ("cancelled" if cancelled else "failed"),
                         "reason": ("cancelled" if cancelled else "no_summary_for_attempt"),
                         "attempt": int(spec.get("attempt") or 1),
                         "note": "this attempt ended before publishing a summary; "
                                 "earlier attempts remain in summary.jsonl"}
        upd["coverage"] = {"complete": False,
                           "reason": "no_summary_for_attempt",
                           "attempt": int(spec.get("attempt") or 1)}
    if err:
        upd["last_error"] = {"type": "unexpected", "message": err.splitlines()[-1][:300],
                             "traceback_tail": err}
    # Terminal write is fenced too (par.11): if a newer attempt already
    # claimed the launch, this one exits without publishing anything over it.
    if not fenced_write(rd, token, **upd):
        core.log("[job] terminal write fenced out (superseded attempt); "
                 "state left to the newer attempt")
        return exit_code
    core.log("[job] worker finished state=" + state + " rc=" + str(exit_code))
    return exit_code


def _last_summary(rd: Path, attempt: int | None = None):
    """The newest summary, but ONLY if it belongs to `attempt`.

    summary.jsonl is append-only across attempts: a resume that dies in its very
    first stage writes nothing, so the last line is still the previous run's
    successful summary. Publishing that as this attempt's result produces the
    most misleading state possible -- state=failed with result.status=complete
    and coverage.complete=true. When an attempt is known, a summary stamped with
    a different attempt is not ours and must not be adopted.

    A summary without an attempt field (older installs, foreground runs) is
    accepted only when no attempt was requested.
    """
    p = rd / "summary.jsonl"
    try:
        lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except Exception:
        return None
    for ln in reversed(lines):
        try:
            rec = json.loads(ln)
        except Exception:
            continue
        if attempt is None:
            return rec
        if int(rec.get("attempt") or 0) == int(attempt):
            return rec
        # Newest record is from another attempt: keep looking only if it is
        # older-format (no attempt key at all) and this is attempt 1.
        if "attempt" not in rec and int(attempt) == 1:
            return rec
    return None


# ---------------------------------------------------------------- control
def wait_status(ref, states, timeout: float = 30.0, poll: float = 0.05) -> dict:
    """Event-driven wait: return as soon as one of `states` is reached.

    Polls at `poll` (50 ms) rather than sleeping a fixed slice, so a caller that
    only cares about one transition (e.g. "the worker published its pid") pays no
    artificial latency. Same contract as wait(): a timeout is reported, not raised.
    """
    rd = resolve(ref)
    wanted = tuple(states or ())
    start = time.time()
    deadline = start + max(0.0, float(timeout))
    while True:
        st = derive(read_state(rd))
        state = st.get("state")
        if wanted:
            hit = (state in wanted) or (bool(st.get("terminal")) and "terminal" in wanted)
        else:
            hit = bool(st.get("terminal"))
        if hit:
            return {"run_id": st.get("run_id"), "state": state, "matched": True,
                    "state_doc": st, "waited_sec": round(time.time() - start, 3)}
        if time.time() >= deadline:
            return {"run_id": st.get("run_id"), "state": state, "matched": False,
                    "timed_out": True, "state_doc": st,
                    "waited_sec": round(time.time() - start, 3)}
        time.sleep(min(poll, max(0.0, deadline - time.time())))


def _wait_payload(st, changed, timed_out, waited, start) -> dict:
    """One decision payload for BOTH wait modes.

    compact and full differ only by the bulky echoes (coverage/run_dir); every
    field an agent needs to choose the next action is produced here, at the
    bottom, so a compact projection can never drop attempt, terminal,
    reaped_by_host or the coverage gaps (F13).
    """
    cov = st.get("coverage") if isinstance(st.get("coverage"), dict) else {}
    gap = cov.get("not_run_stages") or []
    return {
        "run_id": st.get("run_id"), "state": st.get("state") or "unknown",
        "attempt": st.get("attempt"), "pid": st.get("pid"),
        "terminal": bool(st.get("terminal")),
        "changed": bool(changed), "timed_out": bool(timed_out),
        "waited_sec": waited, "seq": st.get("seq"),
        "progress_seq": st.get("progress_seq"),
        "alive": st.get("alive"), "interrupted": st.get("interrupted"),
        "stalled": st.get("stalled"),
        "reaped_by_host": st.get("reaped_by_host"),
        "retryable": st.get("retryable"),
        "next_action": st.get("next_action"),
        "gap_count": len(gap),
        "gaps": gap,
        "result": st.get("result"),
        "coverage": st.get("coverage"),
        "progress": progress(st),
        "run_dir": st.get("run_dir"),
    }


def wait(ref, timeout: float = 30.0, since_seq=None, poll: float = 0.05) -> dict:
    """Bounded wait: return early on progress or terminal state.

    A timed-out wait means "nothing changed within this window"; it is NOT a
    failure signal, and the caller must keep waiting on the same run id.

    The cursor is the PERSISTED progress marker (`progress_seq`: the seq of the
    last substantive change), not a snapshot taken when this call started:

    * `--since N` compares N with the persisted marker, so a change that
      happened BETWEEN two waits is reported on the next call (F13: the old
      code compared N with the CURRENT snapshot's seq, so a caller that passed
      the previous call's cursor never saw the change);
    * without `--since`, the call blocks until a substantive change happens
      after it started.

    A heartbeat bumps seq but neither the marker nor `changed`.
    """
    rd = resolve(ref)
    timeout = max(0.0, float(timeout if timeout is not None else 30.0))
    start = time.time()
    baseline = read_state(rd)
    base_marker = baseline.get("progress_seq")
    if base_marker is None:
        # legacy state without the persisted marker: fall back to the seq seen
        # now, and say so (never silently drop a change)
        base_marker = baseline.get("seq")
        legacy_marker = True
    else:
        legacy_marker = False
    if since_seq is None:
        cursor = base_marker
    else:
        cursor = since_seq
    while True:
        st = derive(read_state(rd))
        marker = st.get("progress_seq")
        if marker is None:
            marker = st.get("seq")
        changed = (marker is not None and cursor is not None
                   and marker != cursor)
        if st.get("terminal"):
            out = _wait_payload(st, changed, False,
                                round(time.time() - start, 1), start)
            if legacy_marker:
                out["note"] = ("this job predates the persisted progress cursor; "
                               "the comparison used seq as a one-time fallback")
            out["cursor"] = cursor
            out["resync_recommended"] = bool(legacy_marker)
            return out
        if changed:
            out = _wait_payload(st, True, False,
                                round(time.time() - start, 1), start)
            out["cursor"] = cursor
            return out
        if time.time() - start >= timeout:
            out = _wait_payload(st, False, True,
                                round(time.time() - start, 1), start)
            out["cursor"] = cursor
            out["note"] = ("wait timeout means this wait window ended, not that "
                           "the job failed; keep waiting on the same run_id")
            return out
        time.sleep(min(poll, max(0.0, timeout - (time.time() - start))))


def kill_tree(pid) -> None:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return
    if pid <= 0:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, timeout=20,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
        return
    import signal
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(pid), sig)
        except Exception:
            try:
                os.kill(pid, sig)
            except Exception:
                return
        for _ in range(25):
            if not pid_alive(pid):
                return
            time.sleep(0.1)


def cancel(ref, reason: str = "user") -> dict:
    rd = resolve(ref)
    st = derive(read_state(rd))
    (rd / "cancel").write_text(reason + " " + core.now() + chr(10), encoding="utf-8")
    pid = st.get("pid")
    if st.get("state") in ACTIVE and pid:
        kill_tree(pid)
    st = derive(read_state(rd))
    if st.get("state") in ACTIVE:
        st = derive(update_state(rd, state="cancelled", exit_code=130,
                                 finished_ts=now_ts(), finished=core.now(),
                                 last_error={"type": "cancelled", "message": reason}))
    return {"run_id": st.get("run_id"), "state": st.get("state"),
            "run_dir": str(rd), "exit_code": st.get("exit_code")}


def list_runs(limit: int = 20, state_filter: str = "", active_only: bool = False) -> list:
    rows = []
    for rd in sorted(core.RUNS_DIR.glob("*"), reverse=True):
        if not rd.is_dir() or not (rd / "job.json").exists():
            continue
        st = derive(read_state(rd))
        spec = read_spec(rd)
        if active_only and st.get("state") not in ACTIVE:
            continue
        if state_filter and st.get("state") != state_filter:
            continue
        rows.append({"run_id": rd.name, "state": st.get("state"),
                     "stage": st.get("stage"), "alive": st.get("alive"),
                     "interrupted": st.get("interrupted"),
                     "target": spec.get("target"), "created": spec.get("created"),
                     "updated": st.get("updated"), "exit_code": st.get("exit_code"),
                     "run_dir": str(rd)})
        if len(rows) >= max(1, limit):
            break
    return rows