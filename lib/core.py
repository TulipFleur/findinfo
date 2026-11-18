"""findinfo core: paths, config, store, normalize, cache, rate-limit, exec helpers."""
from __future__ import annotations

import base64
import collections
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import quote
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Code lives next to this package (bin/, wordlists/); mutable state lives in a
# user-level home so that the same skill can be linked into several clients
# without splitting the asset graph or writing into a read-only install.
ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"


def _platform_tag() -> str:
    """Directory name used to keep per-platform binaries apart under bin/."""
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


PLATFORM = _platform_tag()
BIN_PLATFORM = BIN / PLATFORM


def _safe_task_name(task: str) -> str:
    """Stable filesystem token for a task (engagement) name.

    Plain [A-Za-z0-9_-]+ names keep their directory verbatim (existing
    installs stay where they are). Anything else -- Chinese, spaces,
    punctuation -- would collide after sanitizing (both "美团" and "百度"
    used to collapse into tasks/default), so a hash of the original name is
    mixed in. Same name always maps to the same token; different names never
    share a token.
    """
    safe = re.sub(r"[^A-Za-z0-9_\-]+", "_", task).strip("_")
    digest = hashlib.sha1(task.encode("utf-8", "replace")).hexdigest()
    if not safe:
        return "task-" + digest[:12]
    if safe != task:
        return safe[:40] + "-" + digest[:8]
    return safe


def _resolve_home() -> Path:
    """State root. Order: FINDINFO_TASK > FINDINFO_HOME > ~/.findinfo > legacy.

    FINDINFO_TASK names a per-engagement subdirectory ("tasks/<name>/") under
    whichever home applies. Each task gets its own findinfo.db + runs + cache,
    which is how cross-engagement pollution is prevented at the storage layer:
    one company's asset graph can never leak into another's `--from-store`.

    Idempotent: when FINDINFO_HOME already points AT that task directory (which
    is what a background worker receives from its job spec), the task segment
    is not appended a second time -- otherwise the worker writes into
    "tasks/<name>/tasks/<name>/" and the parent sees an empty database.
    """
    base = _resolve_home_base()
    task = (os.environ.get("FINDINFO_TASK") or "").strip()
    if not task:
        return base
    safe = _safe_task_name(task)
    if base.name == safe and base.parent.name == "tasks":
        return base                      # already the task root
    return base / "tasks" / safe


def _resolve_home_base() -> Path:
    env = os.environ.get("FINDINFO_HOME")
    if env:
        return Path(env).expanduser().resolve()
    user_home = Path.home() / ".findinfo"
    if (user_home / "findinfo.db").exists():
        return user_home
    if (ROOT / "data" / "findinfo.db").exists():
        return ROOT          # keep an existing in-tree database where it is
    return user_home


HOME = _resolve_home()
_LEGACY = HOME == ROOT          # existing install that keeps state in-tree
DATA = ROOT / "data" if _LEGACY else HOME
CACHE_DIR = ROOT / "cache" if _LEGACY else HOME / "cache"
RUNS_DIR = ROOT / "runs" if _LEGACY else HOME / "runs"
# Config stays with the code on purpose: existing installs already keep their
# .env here, and a silent move would break configured API keys.
CONF_DIR = ROOT / "config"

for _d in (BIN, BIN_PLATFORM, DATA, CACHE_DIR, RUNS_DIR, CONF_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass   # read-only install: only commands that need to write will fail


# ---------------------------------------------------------------- logging / output
# ---------------------------------------------------------------- outcomes
# One vocabulary for "what happened in this collection step", shared by every
# adapter, the stage runner, the run result and coverage. Agents branch on
# these strings, so they must not drift per-tool:
#
#   ok         success, produced at least one asset
#   empty      success, genuinely found nothing (a valid answer)
#   partial    some sources worked, others failed; the assets kept are real
#   failed     every source failed -- NOT the same as empty
#   timeout    a source or the tool hit its deadline
#   unavailable a required capability/key is missing
#   budget     stopped because a budget (rounds/time) ran out
#
# The distinction that matters to an agent is empty vs failed: "no subdomains
# exist" and "subfinder crashed" look identical in a count, but lead to
# opposite next actions.
OUTCOME_OK = "ok"
OUTCOME_EMPTY = "empty"
OUTCOME_PARTIAL = "partial"
OUTCOME_FAILED = "failed"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_UNAVAILABLE = "unavailable"
OUTCOME_BUDGET = "budget"

_OUTCOME_RANK = {
    OUTCOME_OK: 0, OUTCOME_EMPTY: 1, OUTCOME_BUDGET: 2,
    OUTCOME_PARTIAL: 3, OUTCOME_TIMEOUT: 4,
    OUTCOME_UNAVAILABLE: 5, OUTCOME_FAILED: 6,
}


def combine_outcome(*outcomes: str) -> str:
    """Worst outcome wins, so one dead source cannot hide behind a live one.

    ok+empty -> empty (a real "nothing found"), partial+ok -> partial, any
    failed with no success -> failed. Unknown values are ignored.
    """
    seen = [o for o in outcomes if o in _OUTCOME_RANK]
    if not seen:
        return OUTCOME_OK
    return max(seen, key=lambda o: _OUTCOME_RANK[o])


def outcome_from_rc(rc: int, count: int, *, ok: bool | None = None) -> str:
    """Classify one child process result.

    rc==124 is core.run's timeout code. A non-zero rc with no assets is a
    failure, never an empty success; a non-zero rc that still produced rows is
    partial (keep the rows, report the gap).
    """
    if ok is False and count == 0:
        return OUTCOME_FAILED
    if rc == 124:
        return OUTCOME_TIMEOUT
    if rc not in (0, None) and count == 0:
        return OUTCOME_FAILED
    if rc not in (0, None) and count > 0:
        return OUTCOME_PARTIAL
    return OUTCOME_OK if count > 0 else OUTCOME_EMPTY


def outcome_hint(outcome: str) -> str:
    """A short, actionable sentence for the agent (logs keep the detail)."""
    return {
        OUTCOME_FAILED: "all sources failed; check the tool and retry the stage",
        OUTCOME_PARTIAL: "some sources failed; results are real but coverage is incomplete",
        OUTCOME_TIMEOUT: "hit a deadline; raise the timeout or narrow the input",
        OUTCOME_UNAVAILABLE: "required capability missing; see doctor / set the API key",
        OUTCOME_BUDGET: "stopped on budget; raise rounds/time-budget to continue",
        OUTCOME_EMPTY: "sources answered and found nothing",
        OUTCOME_OK: "",
    }.get(outcome, "")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    sys.stderr.write("[" + now() + "] " + str(msg) + chr(10))
    sys.stderr.flush()


def emit(obj: Any) -> None:
    """Machine-readable result goes to stdout; everything else to stderr.

    A background job accumulates progress in status.json and its final summary
    in summary.jsonl, so when we are not the ones publishing those (i.e. we are
    just checking progress) repeating them on every call is pure token cost.
    FINDINFO_EMIT=minimal drops the bulky echo fields; behaviour of the data
    itself is unchanged.
    """
    if (os.environ.get("FINDINFO_EMIT") or "").lower() == "minimal" and isinstance(obj, dict):
        drop = ("progress", "coverage", "summary", "params", "paths")
        obj = {k: v for k, v in obj.items() if k not in drop}
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + chr(10))
    sys.stdout.flush()


class FindInfoError(Exception):
    pass


class ToolMissing(FindInfoError):
    pass


class StageError(FindInfoError):
    """A pipeline stage failed at the tool level (non-zero rc, timeout, ...).

    Carrying `result` makes a PARTIAL failure possible: whatever the stage
    produced before dying still feeds downstream stages and the summary, but
    no "done" checkpoint is written, so the next run retries it. Distinguish
    from FindInfoError (bad input/config), which aborts the run.
    """

    def __init__(self, message: str, result: dict | None = None):
        super().__init__(message)
        self.result = result


# ---------------------------------------------------------------- config
DEFAULT_CONFIG = {
    "engagements": {},
    "apis": {
        "fofa": {"email": "", "key": "", "base": ""},
        "quake": {"key": ""},
        "hunter": {"key": ""},
        "securitytrails": {"key": ""},
        "virustotal": {"key": ""},
        "urlscan": {"key": ""},
        "shodan": {"key": ""},
        "chaos": {"key": ""},
    },
    "http": {"timeout": 25, "user_agent": "Mozilla/5.0 findinfo"},
    "limits": {
        "dns_concurrency": 100,
        "http_concurrency": 50,
        "per_host_rps": 5,
        "source_retries": 2,
        "vhost_threads": 20,
        "crawl_timeout": 2700,
    },
    "paths": {"resolvers": "", "subwordlist": "", "vhostwordlist": ""},
}


ENV_MAP = {
    # env var -> (section, key)
    "FOFA_EMAIL": ("apis", "fofa.email"),
    "FOFA_KEY": ("apis", "fofa.key"),
    "FOFA_BASE": ("apis", "fofa.base"),
    "QUAKE_TOKEN": ("apis", "quake.key"),
    "HUNTER_KEY": ("apis", "hunter.key"),
    "SHODAN_KEY": ("apis", "shodan.key"),
    "CENSYS_ID": ("apis", "censys.id"),
    "CENSYS_SECRET": ("apis", "censys.secret"),
    "SECURITYTRAILS_KEY": ("apis", "securitytrails.key"),
    "VIRUSTOTAL_KEY": ("apis", "virustotal.key"),
    "URLSCAN_KEY": ("apis", "urlscan.key"),
    "CHAOS_KEY": ("apis", "chaos.key"),
    "GITHUB_TOKEN": ("apis", "github.token"),
    "ZOOMEYE_KEY": ("apis", "zoomeye.key"),
    "MAPPING_API_INTERVAL_MS": ("limits", "mapping_interval_ms"),
}


def _set_dotted(cfg: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = cfg
    for p in parts[:-1]:
        if not isinstance(cur.get(p), dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def load_env_file(p: Path) -> dict:
    """Tiny .env parser (KEY=VALUE, # comments), no external dependency."""
    out: dict[str, str] = {}
    if not p.exists():
        return out
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and v:
            out[k] = v
    return out


def load_config(path: str | None = None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    p = Path(path) if path else CONF_DIR / "config.json"
    if p.exists():
        try:
            user = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            raise FindInfoError("config parse error: " + str(exc))
        _deep_merge(cfg, user)
    # .env wins over config.json for secrets (matches the /redtools convention)
    for env_file in (CONF_DIR / ".env", ROOT / ".env"):
        for k, v in load_env_file(env_file).items():
            if k in ENV_MAP:
                section, key = ENV_MAP[k]
                _set_dotted(cfg, section + "." + key, int(v) if v.isdigit() else v)
    # real environment variables win over files (CI / one-off runs)
    for k, (section, key) in ENV_MAP.items():
        v = os.environ.get(k)
        if v:
            _set_dotted(cfg, section + "." + key, int(v) if str(v).isdigit() else v)
    return cfg


def _deep_merge(base: dict, extra: dict) -> None:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


CFG = load_config()


def api_key(name: str) -> str:
    v = CFG.get("apis", {}).get(name, {})
    if isinstance(v, dict):
        return v.get("key") or ""
    return ""


def api_email(name: str) -> str:
    v = CFG.get("apis", {}).get(name, {})
    return v.get("email", "") if isinstance(v, dict) else ""


def api_base(name: str) -> str:
    """Custom API base URL (e.g. a third-party FOFA mirror gateway).

    Official FOFA lives at https://fofa.info; a self-hosted or relay gateway
    speaks a different protocol (AK header + POST JSON), so the address has to
    be configurable rather than hardcoded.
    """
    v = CFG.get("apis", {}).get(name, {})
    return (v.get("base") or "").rstrip("/") if isinstance(v, dict) else ""


# ProjectDiscovery binaries (uncover, subfinder, ...) only read keys from the
# environment, never from our config/. Without this bridge a configured FOFA key
# shows up as `api_keys.fofa = true` in doctor while `uncover` still dies with
# "requires keys but no keys were found".
_ENV_KEY_MAP = {
    "fofa": [("FOFA_EMAIL", api_email("fofa")), ("FOFA_KEY", api_key("fofa"))],
    "quake": [("QUAKE_TOKEN", api_key("quake"))],
    "hunter": [("HUNTER_TOKEN", api_key("hunter"))],
    "chaos": [("CHAOS_KEY", api_key("chaos"))],
    "securitytrails": [("SECURITYTRAILS_API_KEY", api_key("securitytrails"))],
    "virustotal": [("VIRUSTOTAL_API_KEY", api_key("virustotal"))],
    "urlscan": [("URLSCAN_API_KEY", api_key("urlscan"))],
    "shodan": [("SHODAN_API_KEY", api_key("shodan"))],
    "censys": [("CENSYS_API_KEY", api_key("censys"))],
}


def tool_env() -> dict:
    """Env vars that expose configured API keys to child binaries.

    Only non-empty values are injected so an existing shell environment still
    wins for anything we do not have.
    """
    env: dict = {}
    for pairs in _ENV_KEY_MAP.values():
        for k, v in pairs:
            if v:
                env[k] = v
    return env


# ---------------------------------------------------------------- tool lookup
def tool(name: str) -> str:
    """Resolve a bundled binary for this platform, else fall back to PATH.

    Search order:
      1. bin/<platform>/<name>[.exe]   per-platform, the recommended layout
      2. bin/<name>[.exe]             legacy flat layout (still supported)
      3. PATH                         system-installed (Linux via setup-linux.sh --prefix)
    """
    for base in (BIN_PLATFORM, BIN):
        for cand in (name, name + ".exe"):
            p = base / cand
            if p.exists():
                return str(p)
    found = shutil.which(name)
    if found:
        return found
    raise ToolMissing(
        "tool not found in bin/" + PLATFORM + "/, bin/ or PATH: " + name +
        " -- run: python findinfo.py doctor"
    )


def has_tool(name: str) -> bool:
    try:
        tool(name)
        return True
    except ToolMissing:
        return False


def run(cmd: list[str], timeout: int = 300, input_text: str | None = None,
        cwd: str | None = None, env: dict | None = None,
        progress=None, progress_every: float = 30.0) -> tuple[int, str, str]:
    """Run a child process.

    timeout <= 0 means "no upper bound": the child runs to completion no matter
    how long it takes. Tools that page through a slow upstream (ENScan, brute
    force over a big wordlist) can otherwise be killed mid-run and look like
    they failed when they simply had not finished.
    """
    e = dict(os.environ)
    e.setdefault("PYTHONIOENCODING", "utf-8")
    # API keys live in config/.env; ProjectDiscovery tools only read env vars.
    for k, v in tool_env().items():
        e.setdefault(k, v)
    if env:
        e.update(env)
    lim = None if not timeout or timeout <= 0 else timeout
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        # Popen + poll (not subprocess.run) so a slow tool can publish a
        # heartbeat: a 20-minute ENScan with no output looks like a hang, and an
        # agent has no way to tell "working" from "stuck" without this.
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", cwd=cwd, env=e,
            creationflags=creation,
        )
        if input_text is not None and p.stdin is not None:
            try:
                p.stdin.write(input_text)
                p.stdin.close()
            except Exception:
                pass
        start = time.time()
        next_beat = float(progress_every or 0)
        while True:
            try:
                out, err = p.communicate(timeout=1.0)
                return p.returncode, out or "", err or ""
            except subprocess.TimeoutExpired:
                elapsed = time.time() - start
                if lim is not None and elapsed > lim:
                    _kill_tree(p)
                    return 124, "", "timeout after " + str(timeout) + "s"
                if progress is not None and next_beat and elapsed >= next_beat:
                    try:
                        progress(int(elapsed))
                    except Exception:
                        pass
                    next_beat += float(progress_every)
    except FileNotFoundError as exc:
        return 127, "", str(exc)


# ---------------------------------------------------------------- streaming exec
def _row_limit() -> int:
    env = os.environ.get("FINDINFO_ROW_LIMIT")
    if env and str(env).isdigit():
        return max(1, int(env))
    return max(1, int((CFG.get("limits") or {}).get("row_limit") or 500))


ROW_LIMIT = _row_limit()


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the child and everything it spawned (katana/httpx can fork helpers).

    The kill is addressed by pid, not by Popen state: katana exits on its own
    while the chrome it spawned keeps running, and Popen-only paths used to
    return early ("the child is already gone") leaving those helpers alive.
    """
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15)
        else:
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def stream_store_writer(store_method, build):
    """Build a run_stream collector that never touches the DB off-thread.

    SQLite connections are thread-bound: a callback invoked from run_stream's
    reader thread cannot write to the caller's store ("SQLite objects created
    in a thread can only be used in that same thread"). Earlier this failed
    silently -- the log said "stream line skipped" for every record while the
    stage still reported success, so dns stored 0 of 7373 hosts.

    This wrapper parses on the reader thread (pure Python) and applies the
    store writes afterwards, on the caller's thread, via .flush().
    """
    staged: list = []
    lock = threading.Lock()

    def on_line(line: str) -> None:
        item = build(line)
        if item is not None:
            with lock:
                staged.append(item)

    def flush() -> int:
        with lock:
            items, staged[:] = list(staged), []
        for item in items:
            store_method(item)
        return len(items)

    return on_line, flush


def run_stream(cmd: list[str], on_line=None, timeout: int = 300,
               cwd: str | None = None, env: dict | None = None) -> tuple[int, int, str]:
    """Run a child and hand every stdout line to on_line instead of buffering it.

    This is the memory-safe path for tools that emit tens of thousands of JSONL
    records: peak memory stays flat no matter how big the output is, because the
    text is consumed line by line and dropped. Returns (rc, lines, stderr_tail).
    """
    e = dict(os.environ)
    e.setdefault("PYTHONIOENCODING", "utf-8")
    for k, v in tool_env().items():
        e.setdefault(k, v)
    if env:
        e.update(env)
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    kwargs: dict = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True       # so the whole group can be killed
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace", bufsize=1, cwd=cwd, env=e,
        creationflags=creation, **kwargs)

    tail: collections.deque = collections.deque(maxlen=60)
    timed_out = threading.Event()

    def drain_err() -> None:
        try:
            for line in proc.stderr:
                tail.append(line.rstrip())
        except Exception:
            pass

    def on_timeout() -> None:
        timed_out.set()
        _kill_tree(proc)

    err_thread = threading.Thread(target=drain_err, daemon=True)
    err_thread.start()
    # timeout <= 0 disables the watchdog: the child runs until it finishes.
    timer = None
    if timeout and timeout > 0:
        timer = threading.Timer(timeout, on_timeout)
        timer.daemon = True
        timer.start()

    # A plain "for line in proc.stdout" blocks until EOF, and EOF never comes
    # when the tool forked helpers that inherited the pipe: katana -jc spawns
    # chrome, so killing katana left the workers holding the write end and
    # run_stream hung past its deadline (observed: crawl stayed "running" 18s+
    # past a 2700s ceiling). Worse, a readline() already blocked in the main
    # thread could not be interrupted at all, so the deadline was only checked
    # between lines -- and a stalled child emits no lines at all (observed:
    # elapsed 3169s against a 2700s ceiling, rc still unset).
    # So: read on a helper thread, and have the CALLER join it with a deadline.
    lines = 0

    def read_loop() -> None:
        nonlocal lines
        try:
            if proc.stdout is None:
                return
            while not timed_out.is_set():
                chunk = proc.stdout.readline()
                if not chunk:
                    return                # real EOF
                line = chunk.strip()
                if not line:
                    continue
                lines += 1
                if on_line is not None:
                    try:
                        on_line(line)
                    except Exception as exc:  # a bad record must not kill the run
                        log("stream line skipped: " + repr(exc))
        except Exception:
            pass

    reader = threading.Thread(target=read_loop, daemon=True)
    reader.start()
    try:
        # The reader is the only owner of the stdout pipe, so this join is the
        # real timeout authority: expiry here means "stop waiting", whether the
        # child is silent, stuck behind a child that holds the pipe, or gone
        # but not reaped. No in-flight readline() is ever abandoned mid-call.
        join_for = (timeout + 5) if (timeout and timeout > 0) else None
        reader.join(join_for)
        if reader.is_alive():
            log("stream: deadline passed, stopping read (children may hold the pipe)")
            timed_out.set()
            _kill_tree(proc)
            reader.join(5)
    finally:
        if timer is not None:
            timer.cancel()
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass
        try:
            rc = proc.wait(timeout=15)
        except Exception:
            _kill_tree(proc)
            rc = 124
        err_thread.join(timeout=2)

    if timed_out.is_set():
        rc = 124
    return rc, lines, chr(10).join(tail)[-8000:]


def iter_json_array(path: str | Path, chunk: int = 1 << 20):
    """Yield the items of a JSON array file incrementally (no full load).

    ksubdomain writes its hits as one big JSON array; a 100k-hit run would
    otherwise need hundreds of MB to parse.
    """
    dec = json.JSONDecoder()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        buf = ""
        while True:
            piece = fh.read(chunk)
            if not piece:
                return
            buf += piece
            i = buf.find("[")
            if i >= 0:
                buf = buf[i + 1:]
                break
        while True:
            buf = buf.lstrip()
            while buf.startswith(","):
                buf = buf[1:].lstrip()
            if not buf:
                piece = fh.read(chunk)
                if not piece:
                    return
                buf += piece
                continue
            if buf.startswith("]"):
                return
            try:
                obj, end = dec.raw_decode(buf)
            except ValueError:
                piece = fh.read(chunk)
                if not piece:
                    raise FindInfoError("truncated json array: " + str(path))
                buf += piece
                continue
            yield obj
            buf = buf[end:]


CURL = "curl"


def curl(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    base = [CURL, "-sS", "-L", "--max-time", str(timeout),
            "--retry", "2", "--retry-delay", "2",
            "-A", CFG.get("http", {}).get("user_agent", "findinfo")]
    # Windows schannel aborts with CRYPT_E_REVOCATION_OFFLINE (0x80092013) when
    # the CA's revocation server is unreachable through a proxy/TUN, which
    # would kill every HTTPS API call (FOFA/Quake/...) on such hosts. Using
    # curl's own CA bundle sidesteps schannel entirely; if this curl build has
    # no OpenSSL backend the flag is simply ignored.
    base += ["--ssl-no-revoke"] if os.name == "nt" else []
    return run(base + args, timeout=timeout + 15)


def fetch_with_retry(fetch, *args, attempts: int = 3, backoff: float = 1.5,
                     **kwargs):
    """Call fetch() until it returns non-None, with bounded retries + backoff.

    Source calls (CT mirrors, mapping APIs) fail transiently all the time:
    rate limits, 502s, a dropped tunnel. Retrying a couple more times with
    growing delays turns most of those into a result, and when every attempt
    fails the caller still knows it was a transient failure (not "no assets")
    because the return value stays None. Never retries past `attempts`: a
    source that is really down must not eat the whole run budget.
    """
    delay = backoff
    for i in range(max(1, attempts)):
        try:
            res = fetch(*args, **kwargs)
        except Exception as exc:          # noqa: BLE001 - retrying is the point
            log("fetch attempt " + str(i + 1) + " raised: " + repr(exc)[:120])
            res = None
        if res is not None:
            return res
        if i + 1 < attempts:
            log("fetch attempt " + str(i + 1) + " failed; retrying in " +
                str(round(delay, 1)) + "s")
            time.sleep(delay)
            delay *= 2
    return None


def curl_json(url: str, headers: dict | None = None, timeout: int = 60,
              body: str | None = None) -> Any:
    args: list[str] = []
    for k, v in (headers or {}).items():
        args += ["-H", k + ": " + v]
    if body is not None:
        args += ["-X", "POST", "-H", "Content-Type: application/json",
                 "--data-binary", body]
    rc, out, err = curl(args + [url], timeout=timeout)
    if rc != 0 or not out.strip():
        log("curl failed rc=" + str(rc) + " " + url[:120] + " " + err[:160])
        return None
    try:
        return json.loads(out)
    except Exception:
        log("json parse failed " + url[:120])
        return None


# ---------------------------------------------------------------- FOFA gateway
def fofa_query(query: str, fields: str = "ip,port,domain,title,server",
               size: int = 100, page: int = 1, timeout: int = 60) -> dict:
    """Run one FOFA query against whichever endpoint is configured.

    Two protocols exist:
      * official  https://fofa.info  — GET /api/v1/search/all?key=..&qbase64=..
      * gateway   custom base        — POST /api/v1/query with `X-Ak` header
    A third-party relay (FofaViewer-style) speaks the latter; its AK is only
    valid there, which is why pointing an AK at fofa.info returns -700.
    """
    base = api_base("fofa")
    key = api_key("fofa")
    if not key:
        return {"ok": False, "error": "no fofa key configured", "results": []}
    if base:
        body = json.dumps({"query": query, "fields": fields,
                           "size": size, "page": page}, ensure_ascii=False)
        d = curl_json(base + "/api/v1/query", headers={"X-Ak": key},
                      timeout=timeout, body=body)
        if not isinstance(d, dict):
            return {"ok": False, "error": "gateway unreachable", "results": []}
        return {"ok": bool(d.get("ok")), "total": d.get("total"),
                "count": d.get("count"), "remaining": d.get("remaining"),
                "error": d.get("error"), "results": d.get("results") or [],
                "base": base}
    q = base64.b64encode(query.encode("utf-8")).decode("ascii")
    url = ("https://fofa.info/api/v1/search/all?key=" + quote(key) +
           "&qbase64=" + quote(q) + "&size=" + str(size) + "&page=" + str(page) +
           "&fields=" + quote(fields))
    d = curl_json(url, timeout=timeout)
    if not isinstance(d, dict):
        return {"ok": False, "error": "fofa.info unreachable", "results": []}
    if d.get("error"):
        return {"ok": False, "error": d.get("errmsg") or "fofa error",
                "results": [], "base": "https://fofa.info"}
    rows = d.get("results") or []
    cols = (d.get("fields") or fields.split(","))
    out = []
    for r in rows:
        if isinstance(r, list):
            out.append(dict(zip(cols, r)))
        elif isinstance(r, dict):
            out.append(r)
    return {"ok": True, "total": d.get("size"), "count": len(out),
            "results": out, "base": "https://fofa.info"}


def parse_jsonl(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


# ---------------------------------------------------------------- normalize
_DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
# Filenames from crawl/JS extraction look exactly like hostnames (ajax.js,
# index.vsb.css) and would otherwise be stored as domains, then fed to dns.
_FILE_TLDS = frozenset("""
js mjs css scss less map json xml txt html htm shtml php php3 php5 phtml
jsp jspx asp aspx ashx cgi pl py rb sh bat exe dll bin so dylib apk ipa
jpg jpeg png gif bmp svg webp ico tif tiff psd
mp3 mp4 avi mov wmv flv mkv webm wav ogg flac
pdf doc docx xls xlsx ppt pptx csv zip rar 7z gz tgz bz2 tar iso dmg
woff woff2 ttf eot otf
css? _ inc bak old log tmp swp sql db
""".split())

# JS expressions also look like hostnames: `window.top`, `popover.style.top`,
# `t.top-i.top` are property accesses, not domains. `.top` is a real TLD, so a
# suffix blacklist cannot catch them; instead reject labels that are JS object
# names, and reject 1-char leading labels (a real public host virtually never
# uses a single letter as its first label, while minified JS constantly does).
# A JS-looking first label only disqualifies a TWO-label host: "window.top" and
# "length.name" are property chains, but "host.ai" / "data.cn" are real hosts
# (the TLD guard above already rejects the bogus suffixes).
_JS_OBJECT_LABELS = frozenset("""
window document parent self this top style popover prototype constructor
length name value data type size text html body head element target
""".split())


# Suffixes a real asset can plausibly use. Anything else is treated as a
# JS/HTML artifact rather than a domain (see canon_domain).
_KNOWN_TLDS = frozenset("""
com net org edu gov mil int info biz name pro aero coop museum mobi asia tel
travel jobs cat xxx post io co ai app dev cloud tech site online store shop
xyz top club vip work ltd group inc plus live life world today space website
fun host press rocks social media news blog page network systems solutions
services digital agency studio design software tools codes run build zone
link click fit games wiki email art band cafe city company center email
cn us uk jp kr de fr ru br in au ca nl se no fi dk pl cz at ch be ie it es
pt gr tr il ae sa sg my th vn id ph hk tw mo eu su cc tv me la fm gg ly
to ws pw am so sh st nu ac cr cx gy hn ht im is kg ki kz lt lu lv md mg
mk mn mt mu mv nz pe pk pr py qa re ro rs rw sc sd sg si sk sm sn sv sz
tg tj tn tz ua ug uy uz ve za zm zw
""".split())


def canon_domain(value: str) -> str | None:
    if not value:
        return None
    v = str(value).strip().lower().rstrip(".")
    v = re.sub(r"^[a-z]+://", "", v)
    v = v.split("/")[0]
    v = v.split("@")[-1]
    if ":" in v and not v.count(":") > 2:
        v = v.split(":")[0]
    if v.startswith("*."):
        v = v[2:]
    if not v or len(v) > 253:
        return None
    if not _DOMAIN_RE.match(v):
        return None
    # Reject "ajax.js" / "index.vsb.css": crawl and JS extraction emit file
    # names that pass the hostname grammar. Real TLDs are never these.
    last = v.rsplit(".", 1)[-1]
    if last in _FILE_TLDS:
        return None
    # A hostname needs a REAL public suffix. JS/HTML extraction keeps producing
    # property chains whose last label is a plausible-looking word
    # (arguments.length, avalon.router.go, e.env.need). Only accept a known
    # suffix: the common gTLDs plus any ccTLD (2 letters), which covers every
    # host a recon run legitimately sees while rejecting method/property names.
    if last not in _KNOWN_TLDS and not (len(last) == 2 and last.isalpha()):
        return None
    # Reject JS property chains: window.top, popover.style.top, t.top-i.top
    labels = v.split(".")
    if len(labels) == 2 and labels[0] in _JS_OBJECT_LABELS:
        return None
    # `t.top` / `e.top` / `f.top` are minified-JS property accesses. Only reject
    # the 2-label shape (single letter + TLD); `a.example.com` and
    # `hr.lh.rendd.cn` stay valid.
    if len(labels) == 2 and len(labels[0]) == 1:
        return None
    # `t.top-i.top` comes from arithmetic in JS (`a.top - i.top`). A hostname's
    # second-level label never contains one of these operator-prone patterns.
    if re.search(r"\.(top|left|right|bottom)-", v):
        return None
    return v


def canon_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except Exception:
        return None


def is_ip(value: str) -> bool:
    return canon_ip(value) is not None


def path_template(path: str) -> str:
    segs = []
    for s in path.split("/"):
        if not s:
            continue
        if s.isdigit():
            segs.append("{n}")
        elif _UUID_RE.match(s):
            segs.append("{uuid}")
        elif _HEX_RE.match(s):
            segs.append("{hex}")
        else:
            segs.append(s)
    return "/" + "/".join(segs)


def split_url(url: str) -> tuple[str | None, str, list[str]]:
    """url -> (host, path, param_names)"""
    m = re.match(r"^[a-z]+://([^/?#]+)([^?#]*)\??([^#]*)", url.strip(), re.I)
    if not m:
        return None, "/", []
    host = canon_domain(m.group(1))
    path = m.group(2) or "/"
    params = []
    for kv in (m.group(3) or "").split("&"):
        if "=" in kv:
            params.append(kv.split("=")[0])
    return host, path, sorted(set(params))


# ---------------------------------------------------------------- scope
# Multi-label public suffixes. Deriving a base domain by "last two labels"
# expands customer.co.uk to co.uk (a public suffix) and would accept every
# unrelated *.co.uk site as in scope. This table covers the suffixes a CN/EN
# recon run realistically hits; anything not listed falls back to two labels,
# which is correct for com/net/org/io/... and all plain ccTLDs.
_PUBLIC_SUFFIXES = frozenset("""
com.cn net.cn org.cn gov.cn edu.cn ac.cn mil.cn ah.cn bj.cn cq.cn fj.cn gd.cn
gs.cn gz.cn ha.cn hb.cn he.cn hi.cn hl.cn hn.cn jl.cn js.cn jx.cn ln.cn nm.cn
nx.cn qh.cn sc.cn sd.cn sn.cn sx.cn tj.cn xj.cn xz.cn yn.cn zj.cn
com.hk net.hk org.hk edu.hk gov.hk idv.hk
com.tw net.tw org.tw edu.tw gov.tw idv.tw
com.sg net.sg org.sg edu.sg gov.sg per.sg com.mx net.mx org.mx gob.mx edu.mx
com.au net.au org.au edu.au gov.au id.au asn.au net.nz org.nz govtn.nz ac.nz
co.nz school.nz geek.nz gen.nz maori.nz
co.uk org.uk ac.uk gov.uk me.uk net.uk ltd.uk plc.uk sch.uk
co.jp ne.jp or.jp go.jp ac.jp ad.jp ed.jp gr.jp lg.jp
co.kr ne.jp or.kr go.kr ac.kr re.kr pe.kr co.za net.za org.za web.za
com.br net.br org.br gov.br edu.br com.ar net.ar org.ar gob.ar edu.ar
com.tr net.tr org.tr gov.tr edu.tr com.ru net.ru org.ru com.ua net.ua org.ua
com.my net.my org.my edu.my gov.my com.in net.in org.in edu.in gov.in res.in
co.in firm.in gen.in ind.in net.in org.in ac.in
com.pk com.eg com.ng com.gh co.id or.id web.id ac.id sch.id go.id my.id
com.ph com.vn com.th co.th in.th or.th ac.th go.th net.th
com.co net.co org.co edu.co gov.co nom.co com.pe com.ve com.ec com.do com.gt
com.py com.uy com.bo com.sv com.ni com.pa com.cr com.hn
""".split())


def registrable_domain(host: str) -> str | None:
    """Registrable (base) domain via the public-suffix table above.

    Only used to DERIVE a scope from observed hosts when the caller gave none:
    an explicit --domain/--scope always wins and is never widened. Plain
    "last two labels" would turn customer.co.uk into co.uk.
    """
    h = canon_domain(host)
    if not h:
        return None
    labels = h.split(".")
    if len(labels) >= 3 and (labels[-2] + "." + labels[-1]) in _PUBLIC_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return h


def canon_scope(entries: Iterable[str]) -> list[str]:
    """Canonical, deduped scope list: [canon_domain(e) for e if valid]."""
    out: list[str] = []
    for e in entries or []:
        d = canon_domain(e)
        if d and d not in out:
            out.append(d)
    return out


def in_scope(host: str | None, scope: list[str] | None) -> bool:
    """True when host equals or sits under one of the scope domains.

    An EMPTY scope means "no restriction" (whole shared graph) -- callers that
    must not act on unknown assets have to treat an empty scope as empty
    candidate sets themselves.
    """
    if not scope:
        return True
    h = canon_domain(host or "")
    if not h:
        return False
    for s in scope:
        s2 = canon_domain(s or "")
        if s2 and (h == s2 or h.endswith("." + s2)):
            return True
    return False


# ---------------------------------------------------------------- provenance
# A sources cell names either a collector ("dnsx") or a collector plus the
# upstream it relayed ("onepass:crt.sh"). Confidence counts DISTINCT upstreams:
# re-running a collector, reordering tokens, or reaching the same upstream via
# a different entry point must not change the score.
ONEPASS_UPSTREAMS = frozenset((
    "crtsh", "certspotter", "hackertarget", "rapiddns", "anubis",
    "alienvault", "threatminer", "subdomain_center", "urlscan",
    "virustotal", "securitytrails", "chaos", "fofa", "quake", "hunter",
))
_UPSTREAM_ALIASES = {
    "crtsh": "crt.sh",       # onepass source id -> canonical upstream id
    "fofa-gateway": "fofa",  # the self-hosted gateway relays fofa.info
    "icp-gateway": "fofa",
}


def split_source_token(token: str) -> tuple[str, str | None]:
    """'onepass:crt.sh' -> ('onepass', 'crt.sh'); 'dnsx' -> ('dnsx', None).

    Bare tokens that are onepass upstream ids are attributed back to onepass:
    older rows were written as "onepass:crt.sh,rapiddns" where only the first
    token carried the prefix.
    """
    tok = (token or "").strip().lower()
    if not tok:
        return "", None
    tool, _, detail = tok.partition(":")
    tool = tool.strip()
    detail = detail.strip() or None
    if tool == "crawl":
        tool = "katana"
    if detail is None and tool in ONEPASS_UPSTREAMS:
        return "onepass", tool
    return tool, detail


def upstream_id(tool: str, detail: str | None) -> str:
    """Stable identity of the evidence ORIGIN, independent of the collector.

    crt.sh queried directly (t_certs, "certs:crt.sh") and crt.sh reached
    through onepass ("onepass:crtsh") both resolve to 'crt.sh': one upstream,
    one confidence vote.
    """
    if detail:
        return _UPSTREAM_ALIASES.get(detail, detail)
    return _UPSTREAM_ALIASES.get(tool, tool)


def source_upstreams(raw: str) -> set[str]:
    """All distinct upstream ids in a sources cell (order-independent)."""
    out: set[str] = set()
    for tok in (raw or "").split(","):
        if not tok.strip():
            continue
        tool, detail = split_source_token(tok)
        if tool:
            out.add(upstream_id(tool, detail))
    return out


def source_tools(raw: str) -> set[str]:
    """All distinct collector ids in a sources cell."""
    out: set[str] = set()
    for tok in (raw or "").split(","):
        if not tok.strip():
            continue
        tool, _ = split_source_token(tok)
        if tool:
            out.add(tool)
    return out


def merge_confidence(stored: float, declared: float, distinct_upstreams: int) -> float:
    """Deterministic asset confidence from its evidence.

    floor: 3+ independent upstreams corroborate to 0.95, 2 to 0.7.
    cap:   fewer than 3 upstreams can never justify more than 0.9.
    A stored score ABOVE the cap is provably not backed by the current
    evidence (the retired alias bug double-counted onepass upstreams into
    "3+ tools"), so it is ignored instead of being preserved via max().
    Everything else keeps the strongest legitimate claim (max) -- an ENScan
    0.9 anchor survives a later 0.8 dnsx observation.
    """
    floor = 0.95 if distinct_upstreams >= 3 else (0.7 if distinct_upstreams == 2 else 0.0)
    cap = 0.95 if distinct_upstreams >= 3 else 0.9
    base = min(max(float(declared or 0.0), 0.0), 0.95)
    if stored is not None and stored <= cap:
        base = max(base, min(float(stored), 0.95))
    return round(min(max(base, floor), cap), 3)


# ---------------------------------------------------------------- cache
class Cache:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, ns: str, key: str) -> Path:
        h = hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()
        d = self.root / ns
        d.mkdir(parents=True, exist_ok=True)
        return d / (h + ".json")

    def get(self, ns: str, key: str, ttl: int) -> Any:
        p = self._path(ns, key)
        if not p.exists():
            return None
        try:
            blob = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        if time.time() - blob.get("t", 0) > ttl:
            return None
        return blob.get("d")

    def put(self, ns: str, key: str, data: Any) -> None:
        p = self._path(ns, key)
        try:
            p.write_text(json.dumps({"t": time.time(), "d": data}, ensure_ascii=False),
                         encoding="utf-8")
        except Exception:
            pass


CACHE = Cache(CACHE_DIR)


# ---------------------------------------------------------------- rate limit
class TokenBucket:
    def __init__(self, rate: float, burst: int = 3):
        self.rate = max(rate, 0.001)
        self.burst = max(burst, 1)
        self.tokens = float(self.burst)
        self.ts = time.time()
        self.lock = threading.Lock()

    def acquire(self, n: float = 1.0) -> None:
        with self.lock:
            while True:
                t = time.time()
                self.tokens = min(self.burst, self.tokens + (t - self.ts) * self.rate)
                self.ts = t
                if self.tokens >= n:
                    self.tokens -= n
                    return
                time.sleep(min(0.5, (n - self.tokens) / self.rate))


_BUCKETS: dict[str, TokenBucket] = {
    "crtsh": TokenBucket(2, 3),
    "certspotter": TokenBucket(1, 2),
    "fofa": TokenBucket(2, 3),
    "quake": TokenBucket(2, 3),
    "hunter": TokenBucket(1, 2),
    "securitytrails": TokenBucket(0.5, 2),
    "virustotal": TokenBucket(0.25, 1),
    "urlscan": TokenBucket(1, 2),
    "dns": TokenBucket(200, 200),
}


def throttle(name: str) -> None:
    b = _BUCKETS.get(name)
    if b:
        b.acquire()


_MAPPING_LOCK = threading.Lock()
_MAPPING_LAST = [0.0]


def mapping_wait() -> None:
    """Serialize space-mapping API calls (FOFA/Quake/Hunter via uncover).

    The interval is the documented MAPPING_API_INTERVAL_MS knob (default
    1500ms); every call site shares the same gate so parallel seeds cannot
    burst a key into a rate-limit ban.
    """
    interval = float(CFG.get("limits", {}).get("mapping_interval_ms") or 0) / 1000.0
    if interval <= 0:
        return
    with _MAPPING_LOCK:
        wait = _MAPPING_LAST[0] + interval - time.time()
        if wait > 0:
            time.sleep(wait)
        _MAPPING_LAST[0] = time.time()


# ---------------------------------------------------------------- store
SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  canonical TEXT NOT NULL,
  parent TEXT,
  sources TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 0.4,
  passivity TEXT NOT NULL DEFAULT 'passive',
  attrs TEXT NOT NULL DEFAULT '{}',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(kind, canonical)
);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  path TEXT NOT NULL,
  params TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  status INTEGER,
  title TEXT,
  first_seen TEXT NOT NULL,
  UNIQUE(asset, method, path, params)
);
CREATE TABLE IF NOT EXISTS steps (
  engagement TEXT NOT NULL,
  step TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  artifact TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (engagement, step)
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement TEXT,
  target TEXT,
  started TEXT,
  finished TEXT,
  summary TEXT
);
-- Many-to-many evidence between an asset and the thing it belongs to.
-- assets.parent is a single COALESCE'd column: the FIRST writer wins, so
-- "1.2.3.4 belongs to old.com" permanently hid that it also serves
-- example.com, and a scoped ipagg/report for example.com could not find it.
-- A row per (kind, canonical, relation, owner) keeps every association without
-- rewriting the assets table; INSERT OR IGNORE makes the migration idempotent.
CREATE TABLE IF NOT EXISTS asset_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,           -- asset kind being linked (ip / domain / url)
  canonical TEXT NOT NULL,      -- the asset
  relation TEXT NOT NULL,       -- e.g. 'resolved_from' / 'serves'
  owner TEXT NOT NULL,          -- the domain/engagement it relates to
  source TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  UNIQUE(kind, canonical, relation, owner)
);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent);
CREATE INDEX IF NOT EXISTS idx_endpoints_asset ON endpoints(asset);
CREATE INDEX IF NOT EXISTS idx_links_owner ON asset_links(owner);
CREATE INDEX IF NOT EXISTS idx_links_asset ON asset_links(kind, canonical);
-- JS work items: a bundle URL is discovered, queued, attempted, then either
-- done or failed. Re-runs pick up `pending`/`failed` rows instead of fetching
-- the same first N candidates again, which is what made "40 of 41 processed"
-- repeat forever and read as convergence.
CREATE TABLE IF NOT EXISTS js_queue (
  url TEXT PRIMARY KEY,
  state TEXT NOT NULL,          -- pending / done / failed / skipped
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  discovered_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jsq_state ON js_queue(state);
"""


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = str(path or (DATA / "findinfo.db"))
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        # Several agents may write into one asset graph at the same time:
        # WAL keeps readers running during a write, busy_timeout absorbs the
        # writer lock instead of failing after 30s, and every mutation below
        # takes a BEGIN IMMEDIATE transaction so a read-modify-write upsert
        # cannot silently drop a source merged by another process.
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.Error:
            pass
        self.conn.isolation_level = None      # explicit transactions only
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    @contextlib.contextmanager
    def _write(self):
        """BEGIN IMMEDIATE ... COMMIT, with backoff while other agents write."""
        delay = 0.05
        last: Exception | None = None
        for _ in range(10):
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                last = exc
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 1.0)
        else:
            raise FindInfoError("database is locked by another findinfo process: " +
                                str(last))
        try:
            yield self.conn
        except Exception:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    # -- assets
    @staticmethod
    def _merge_sources(existing: str, incoming: str, limit: int = 24) -> str:
        """Append a source to the comma-joined column, token by token.

        Callers sometimes hand over a pre-joined string (onepass writes
        "onepass:crt.sh,rapiddns,subfinder"), so both sides are split and
        deduped. Without this a compound value is appended wholesale on every
        re-upsert and the column grows into a repeated blob.
        """
        out, seen = [], set()
        for chunk in ((existing or "") + "," + (incoming or "")).split(","):
            tok = chunk.strip()
            if not tok or tok in seen:
                continue
            seen.add(tok)
            out.append(tok)
            if len(out) >= limit:
                break
        return ",".join(out)

    def link_asset(self, kind: str, canonical: str, relation: str,
                   owner: str, source: str = "") -> bool:
        """Record that `canonical` relates to `owner` (idempotent).

        INSERT OR IGNORE on (kind, canonical, relation, owner): re-observing the
        same pairing is a no-op, so re-runs and migrations cannot fan the table
        out. Old databases get the table via CREATE TABLE IF NOT EXISTS on open.
        """
        if not canonical or not owner or not relation:
            return False
        with self._write():
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO asset_links"
                "(kind,canonical,relation,owner,source,first_seen)"
                " VALUES(?,?,?,?,?,?)",
                (kind, canonical, relation, owner, source or "", now()))
            return bool(cur.rowcount)

    def linked_owners(self, kind: str, canonical: str,
                      relation: str | None = None) -> list[str]:
        """All owners ever recorded for an asset, oldest first."""
        sql = "SELECT owner FROM asset_links WHERE kind=? AND canonical=?"
        args: list[Any] = [kind, canonical]
        if relation:
            sql += " AND relation=?"
            args.append(relation)
        return [r["owner"] for r in self.conn.execute(
            sql + " ORDER BY id", args)]

    def assets_linked_to(self, kind: str, owners: list[str],
                         relation: str | None = None) -> list[str]:
        """Canonicals of `kind` linked to any of `owners` (scope-aware reads)."""
        want = [o for o in (owners or []) if o]
        if not want:
            return []
        sql = "SELECT DISTINCT canonical FROM asset_links WHERE kind=?"
        args: list[Any] = [kind]
        sql += " AND (" + " OR ".join(["owner=?"] * len(want)) + ")"
        args += want
        if relation:
            sql += " AND relation=?"
            args.append(relation)
        return [r["canonical"] for r in self.conn.execute(sql, args)]

    def upsert_asset(self, kind: str, canonical: str, source: str,
                     confidence: float = 0.4, passivity: str = "passive",
                     parent: str | None = None, attrs: dict | None = None) -> tuple[str, bool]:
        """Insert or merge an asset row.

        passivity merge rule: one observation from an active stage
        (probe/scan/crawl/vhost) permanently marks the asset 'active';
        later passive observations never downgrade it. The column therefore
        answers "was this asset ever actively confirmed", which is what the
        report shows.
        confidence merge rule: recomputed from the merged evidence via
        merge_confidence() -- deterministic in token order and re-runs.
        """
        if not canonical:
            return "", False
        ts = now()
        with self._write():
            row = self.conn.execute(
                "SELECT id, sources, confidence, passivity, attrs FROM assets WHERE kind=? AND canonical=?",
                (kind, canonical)).fetchone()
            if row is None:
                merged = self._merge_sources("", source)
                distinct = len(source_upstreams(merged))
                conf = merge_confidence(0.0, confidence, distinct)
                self.conn.execute(
                    "INSERT INTO assets(kind,canonical,parent,sources,confidence,passivity,attrs,first_seen,last_seen)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (kind, canonical, parent, merged, conf, passivity,
                     json.dumps(attrs or {}, ensure_ascii=False), ts, ts))
                if parent:
                    try:
                        self.conn.execute(
                            "INSERT OR IGNORE INTO asset_links"
                            "(kind,canonical,relation,owner,source,first_seen)"
                            " VALUES(?,?,?,?,?,?)",
                            (kind, canonical, "resolved_from", parent, source or "", ts))
                    except Exception:
                        pass
                return canonical, True
            merged = self._merge_sources(row["sources"], source)
            distinct = len(source_upstreams(merged))
            conf = merge_confidence(float(row["confidence"] or 0.4), confidence, distinct)
            pvn = row["passivity"] or "passive"
            if pvn != "active" and passivity == "active":
                pvn = "active"
            attrs_old = {}
            try:
                attrs_old = json.loads(row["attrs"] or "{}")
            except Exception:
                pass
            attrs_old.update(attrs or {})
            self.conn.execute(
                "UPDATE assets SET sources=?, confidence=?, passivity=?, attrs=?, last_seen=?,"
                " parent=COALESCE(parent, ?) WHERE id=?",
                (merged, conf, pvn, json.dumps(attrs_old, ensure_ascii=False),
                 ts, parent, row["id"]))
            if parent:
                # Keep the many-to-many side in step with the single-valued
                # parent column: parent tells you one owner, asset_links tells
                # you every owner ever seen (see the SCHEMA note).
                try:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO asset_links"
                        "(kind,canonical,relation,owner,source,first_seen)"
                        " VALUES(?,?,?,?,?,?)",
                        (kind, canonical, "resolved_from", parent, source or "", ts))
                except Exception:
                    pass
        return canonical, False

    # -- JS work queue -----------------------------------------------------
    def js_enqueue(self, urls: list[str]) -> int:
        """Add newly discovered bundles as pending; existing rows keep state."""
        n = 0
        ts = now()
        with self._write():
            for u in urls:
                if not u:
                    continue
                cur = self.conn.execute(
                    "INSERT OR IGNORE INTO js_queue"
                    "(url,state,attempts,last_error,discovered_at,updated_at)"
                    " VALUES(?,?,?,?,?,?)", (u, "pending", 0, "", ts, ts))
                n += cur.rowcount or 0
        return n

    def js_claim(self, limit: int) -> list[str]:
        """Oldest pending first, then retryable failures; never re-claim done."""
        if limit <= 0:
            return []
        rows = self.conn.execute(
            "SELECT url FROM js_queue WHERE state IN ('pending','failed')"
            " ORDER BY CASE state WHEN 'pending' THEN 0 ELSE 1 END,"
            " updated_at, url LIMIT ?", (limit,)).fetchall()
        return [r["url"] for r in rows]

    def js_finish(self, url: str, ok: bool, error: str = "") -> None:
        ts = now()
        with self._write():
            self.conn.execute(
                "UPDATE js_queue SET state=?, attempts=attempts+1, last_error=?,"
                " updated_at=? WHERE url=?",
                ("done" if ok else "failed", (error or "")[:300], ts, url))

    def js_stats(self) -> dict:
        """Everything an agent needs to decide "keep going or stop"."""
        row = self.conn.execute(
            "SELECT state, COUNT(*) c FROM js_queue GROUP BY state").fetchall()
        by = {r["state"]: r["c"] for r in row}
        return {"discovered": sum(by.values()),
                "succeeded": by.get("done", 0),
                "failed": by.get("failed", 0),
                "pending": by.get("pending", 0),
                "skipped": by.get("skipped", 0)}

    def get_assets(self, kind: str | None = None, min_conf: float = 0.0,
                   limit: int = 100000, match: list[str] | None = None) -> list[dict]:
        """Query assets.

        `match` restricts results to rows whose canonical OR parent equals/sits
        under one of the given suffixes (e.g. ["hniu.cn"]). The store is a
        shared, cross-engagement graph, so any caller that feeds results back
        into an active stage must scope the query or it will drag another
        target's assets along. Scope lists longer than 50 entries are applied
        in Python (SQLite's bound-parameter limit).
        """
        sql = "SELECT * FROM assets WHERE confidence>=?"
        args: list[Any] = [min_conf]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        match = canon_scope(match or [])
        sql_match = match if len(match) <= 50 else []
        if sql_match:
            sql += " AND (" + " OR ".join(
                ["(canonical=? OR canonical LIKE ? OR parent=? OR parent LIKE ?)"] * len(sql_match)) + ")"
            for m in sql_match:
                args += [m, "%." + m, m, "%." + m]
        sql += " ORDER BY confidence DESC, first_seen ASC LIMIT ?"
        args.append(limit)
        out = []
        for r in self.conn.execute(sql, args):
            d = dict(r)
            try:
                d["attrs"] = json.loads(d.get("attrs") or "{}")
            except Exception:
                d["attrs"] = {}
            if match and len(match) > 50:
                # scope too large for SQL params: same predicate in Python
                if not (in_scope(d.get("canonical"), match) or
                        in_scope(d.get("parent"), match)):
                    continue
            out.append(d)
        return out

    def count_assets(self) -> dict:
        out = {}
        for r in self.conn.execute("SELECT kind, COUNT(*) c FROM assets GROUP BY kind"):
            out[r["kind"]] = r["c"]
        return out

    # -- endpoints
    def upsert_endpoint(self, asset: str, method: str, path: str, params: list[str] | str,
                        source: str, status: int | None = None, title: str | None = None) -> bool:
        if isinstance(params, list):
            params = ",".join(sorted(set(params)))
        ts = now()
        with self._write():
            row = self.conn.execute(
                "SELECT id FROM endpoints WHERE asset=? AND method=? AND path=? AND params=?",
                (asset, method, path, params)).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE endpoints SET status=COALESCE(?,status), title=COALESCE(?,title) WHERE id=?",
                    (status, title, row["id"]))
                return False
            self.conn.execute(
                "INSERT INTO endpoints(asset,method,path,params,source,status,title,first_seen)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (asset, method, path, params, source, status, title, ts))
        return True

    def get_endpoints(self, asset: str | None = None, limit: int = 100000) -> list[dict]:
        if asset:
            rows = self.conn.execute("SELECT * FROM endpoints WHERE asset=? LIMIT ?", (asset, limit))
        else:
            rows = self.conn.execute("SELECT * FROM endpoints LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    # -- housekeeping
    def purge(self, match: list[str] | None = None, keep: list[str] | None = None,
              kinds: list[str] | None = None, dry_run: bool = False) -> dict:
        """Delete assets (and their endpoints) either by suffix or all-but-suffix.

        match:   delete only rows equal/under these suffixes
        keep:    delete everything except rows equal/under these suffixes
        kinds:   limit ASSET deletion to these asset kinds (default: all)
        dry_run: count exactly what would be deleted, delete nothing. The same
                 filter is built either way, so a preview cannot disagree with
                 the real run.

        Endpoint semantics: the endpoints table is keyed by hostname, not by
        an assets row, and has no kind column. Endpoint rows follow the
        suffix filter alone, and are deleted only when host-keyed assets are
        being deleted (kinds is None, or includes "domain"/"endpoint").
        `--kind ip` therefore never touches another host's endpoints.
        """
        where, args = [], []
        if kinds:
            where.append("kind IN (" + ",".join("?" * len(kinds)) + ")")
            args += kinds
        suffix_clause = []
        suffix_args: list[Any] = []
        scope = match if match else keep
        if scope:
            for m in canon_scope(scope):
                suffix_clause.append("(canonical=? OR canonical LIKE ? OR parent=? OR parent LIKE ?)")
                suffix_args += [m, "%." + m, m, "%." + m]
        if not suffix_clause:
            # No filter: refuse to nuke the whole graph by accident.
            return {"error": "no filter given; pass match= or keep=", "assets": 0, "endpoints": 0}
        joined = " OR ".join(suffix_clause)
        suffix_where = ("NOT (" + joined + ")") if keep else ("(" + joined + ")")
        # endpoints are keyed by hostname (asset), not canonical/parent
        ep_where = suffix_where.replace("canonical", "asset").replace("parent", "asset")
        w = " AND ".join(where + [suffix_where]) if where else suffix_where
        ep_touched = kinds is None or any(k in kinds for k in ("domain", "endpoint"))
        if dry_run:
            # Same SELECTs as the real path, no DELETEs: a preview derived from
            # a different query could claim a different count than the wipe.
            doomed = [r["canonical"] for r in self.conn.execute(
                "SELECT canonical FROM assets WHERE " + w, args + suffix_args)]
            ep = 0
            if ep_touched:
                cur = self.conn.execute(
                    "SELECT COUNT(*) c FROM endpoints WHERE " + ep_where, suffix_args)
                ep = cur.fetchone()["c"] if cur else 0
            return {"assets": len(doomed), "endpoints": ep, "filter": w,
                    "endpoints_touched": ep_touched, "dry_run": True}
        with self._write():
            doomed = [r["canonical"] for r in self.conn.execute(
                "SELECT canonical FROM assets WHERE " + w, args + suffix_args)]
            ep = 0
            if ep_touched:
                cur = self.conn.execute(
                    "SELECT COUNT(*) c FROM endpoints WHERE " + ep_where, suffix_args)
                ep = cur.fetchone()["c"] if cur else 0
                self.conn.execute("DELETE FROM endpoints WHERE " + ep_where, suffix_args)
            cur = self.conn.execute("DELETE FROM assets WHERE " + w, args + suffix_args)
            n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else len(doomed)
        return {"assets": n, "endpoints": ep, "filter": w,
                "endpoints_touched": ep_touched}

    def vacuum(self) -> None:
        """Reclaim disk after a big purge (WAL is checkpointed first)."""
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass
        try:
            self.conn.execute("VACUUM")
        except Exception:
            pass

    # -- steps / runs
    def step_done(self, engagement: str, step: str, input_hash: str) -> bool:
        """True only for a stage that succeeded with exactly these inputs.

        'failed'/'skipped' rows never count as done, so a re-run retries them.
        """
        row = self.conn.execute(
            "SELECT status, input_hash FROM steps WHERE engagement=? AND step=?",
            (engagement, step)).fetchone()
        return bool(row and row["status"] == "done" and row["input_hash"] == input_hash)

    def set_step(self, engagement: str, step: str, input_hash: str, status: str,
                 artifact: str | None = None) -> None:
        with self._write():
            self.conn.execute(
                "INSERT INTO steps(engagement,step,input_hash,status,artifact,updated_at)"
                " VALUES(?,?,?,?,?,?) ON CONFLICT(engagement,step) DO UPDATE SET"
                " input_hash=excluded.input_hash, status=excluded.status,"
                " artifact=excluded.artifact, updated_at=excluded.updated_at",
                (engagement, step, input_hash, status, artifact, now()))

    def start_run(self, engagement: str, target: str) -> int:
        with self._write():
            cur = self.conn.execute("INSERT INTO runs(engagement,target,started) VALUES(?,?,?)",
                                    (engagement, target, now()))
            run_id = int(cur.lastrowid)
        return run_id

    def finish_run(self, run_id: int, summary: dict) -> None:
        with self._write():
            self.conn.execute("UPDATE runs SET finished=?, summary=? WHERE id=?",
                              (now(), json.dumps(summary, ensure_ascii=False), run_id))


def new_run_dir(tag: str) -> Path:
    """Unique run directory; two agents starting in the same second must not
    clobber each other's artifacts."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    # Keep the label readable: a Chinese target name collapsed to "___" makes
    # run ids indistinguishable in `runs` output. Prefer the ASCII part of the
    # tag, else a short hash of it, so every run id stays unique AND legible.
    raw = (tag or "").strip()
    safe = re.sub(r"[^0-9a-zA-Z_.\-]+", "-", raw).strip("-.")
    if len(safe) < 3:
        import hashlib
        safe = "job-" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:6]
    safe = safe[:40]
    for n in range(1, 1000):
        name = stamp + "-" + safe + ("" if n == 1 else "-" + str(n))
        p = RUNS_DIR / name
        try:
            p.mkdir(parents=True, exist_ok=False)
            return p
        except FileExistsError:
            continue
    raise FindInfoError("cannot create run dir under " + str(RUNS_DIR))


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + chr(10))
            n += 1
    return n
