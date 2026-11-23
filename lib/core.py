"""findinfo core: paths, config, store, normalize, cache, rate-limit, exec helpers."""
from __future__ import annotations

import base64
import codecs
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
        raise RuntimeError(
            "findinfo does not ship macOS binaries: supported platforms are "
            "windows (bin/windows/*.exe) and linux (bin/linux/*). "
            "Run on Windows or Linux."
        )
    return "linux"


PLATFORM = _platform_tag()
BIN_PLATFORM = BIN / PLATFORM


def skill_version() -> str:
    """Skill version string, read from the VERSION file at the repo root.

    Surfaced through `doctor` so an agent can tell which build it is talking
    to. Falls back to "unknown" rather than raising: a missing VERSION file
    must never break a diagnostic command.
    """
    try:
        return (ROOT / "VERSION").read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def _safe_task_name(task: str) -> str:
    """Stable filesystem token for a task (engagement) name.

    Plain [A-Za-z0-9_-]+ names keep their directory verbatim (existing
    installs stay where they are). Anything else -- Chinese, spaces,
    punctuation -- would collide after sanitizing (both "Example Corp" and "Acme Inc."
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

# Severity used when merging per-source outcomes. "unavailable" is
# deliberately BELOW partial: a source we never had a key for is a coverage gap
# (it goes to coverage.unavailable), not evidence that the stage broke. Ranking
# it above partial made "subfinder worked, no mapping key configured" report as
# worse than "subfinder worked, a keyed source crashed", and pushed an agent
# into --resume loops over a problem retrying can never fix.
_OUTCOME_RANK = {
    OUTCOME_OK: 0, OUTCOME_EMPTY: 1, OUTCOME_UNAVAILABLE: 2,
    OUTCOME_BUDGET: 3, OUTCOME_PARTIAL: 4, OUTCOME_TIMEOUT: 5,
    OUTCOME_FAILED: 6,
}


def combine_outcome(*outcomes: str) -> str:
    """Merge per-source outcomes, never letting a gap masquerade as success.

    Rules (see tests/test_outcome_and_evidence.py for the contract):
      - no source at all usable -> unavailable (a coverage gap, not a failure)
      - every usable source failed -> failed
      - every usable source timed out -> timeout, never failed: the fix is a
        bigger deadline, and "the tool is broken" sends an agent retrying
        something that only needed more time
      - some usable succeeded, some broke -> partial (timeout if one of the
        broken ones timed out: the results are real but a deadline was hit)
      - otherwise the worst remaining outcome wins (timeout > partial > budget)
    Unknown values are ignored so a new adapter cannot poison the merge.
    """
    seen = [o for o in outcomes if o in _OUTCOME_RANK]
    if not seen:
        return OUTCOME_OK
    usable = [o for o in seen if o != OUTCOME_UNAVAILABLE]
    if not usable:
        return OUTCOME_UNAVAILABLE
    if all(o in (OUTCOME_FAILED, OUTCOME_TIMEOUT) for o in usable):
        if all(o == OUTCOME_TIMEOUT for o in usable):
            return OUTCOME_TIMEOUT
        return OUTCOME_FAILED
    succeeded = [o for o in usable
                 if o in (OUTCOME_OK, OUTCOME_EMPTY, OUTCOME_PARTIAL, OUTCOME_BUDGET)]
    broken = [o for o in usable if o in (OUTCOME_FAILED, OUTCOME_TIMEOUT)]
    if succeeded and broken:
        return OUTCOME_TIMEOUT if OUTCOME_TIMEOUT in broken else OUTCOME_PARTIAL
    return max(usable, key=lambda o: _OUTCOME_RANK[o])


# Marker for "we could not tell what the last run did". A brief that shows an
# empty gap list because it read the wrong run is worse than one that admits
# ignorance: the agent reads "no gaps" and reports a clean result.
COVERAGE_SOURCE_NONE = "none"


def select_coverage(coverage: dict | None, source: str) -> dict:
    """Wrap a run coverage block with where it came from.

    `source` is the run id it was read from, or COVERAGE_SOURCE_NONE when no
    run matched at all. known=False tells the brief "this is not evidence of
    zero gaps" -- report and brief must call this identically, or the same
    question gets two different answers depending on the command.
    """
    out = dict(coverage) if isinstance(coverage, dict) else {}
    src = str(source or "").strip()
    # "known" needs an actual run id AND something recorded in it. Copying the
    # source key into `out` first would make bool(out) always true, which is
    # exactly the "no gaps found" lie this function exists to prevent.
    known = bool(src) and src != COVERAGE_SOURCE_NONE and bool(out)
    out["source"] = src or COVERAGE_SOURCE_NONE
    out["known"] = known
    return out


def empty_coverage() -> dict:
    """The honest answer when no run matched: known=False, not a clean bill.
    """
    return select_coverage(None, COVERAGE_SOURCE_NONE)


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


def emit_ascii_default() -> bool:
    """Whether stdout JSON is ASCII-escaped (the default) or raw UTF-8."""
    return (os.environ.get("FINDINFO_EMIT_UTF8") or "").lower() not in (
        "1", "true", "yes")


def encode_json_line(obj, ascii_safe: bool | None = None) -> str:
    """THE one encoder for stdout: compact separators plus the final newline.

    Everything that MEASURES a payload or prints it must go through this, or
    the declared size and the real stdout bytes disagree (F14: the brief was
    measured as compact UTF-8 while stdout wrote ASCII-escaped text, so a
    declared 32749 bytes became 32845 on the wire).
    """
    if ascii_safe is None:
        ascii_safe = emit_ascii_default()
    return json.dumps(obj, ensure_ascii=ascii_safe,
                      separators=(",", ":")) + chr(10)


def emit(obj: Any) -> None:
    """Machine-readable result goes to stdout; everything else to stderr.

    A background job accumulates progress in status.json and its final summary
    in summary.jsonl, so when we are not the ones publishing those (i.e. we are
    just checking progress) repeating them on every call is pure token cost.
    FINDINFO_EMIT=minimal drops the bulky echo fields; behaviour of the data
    itself is unchanged -- except that a brief keeps the fields it is REQUIRED
    to carry (a minimal mode must not strip a brief's decision surface).

    stdout is ASCII-escaped by default (ensure_ascii=True): the JSON line is
    consumed by scripts and agents, and pure ASCII decodes identically under
    EVERY console code page -- including PowerShell 5.1 on a Chinese Windows
    default (code page 936), where raw UTF-8 bytes make ConvertFrom-Json fail
    on the first CJK string. Set FINDINFO_EMIT_UTF8=1 to emit raw UTF-8 (for
    humans piping to a UTF-8-aware terminal); the JSON value content is the
    same either way. Both paths share encode_json_line(), so a caller that
    measured these bytes sees the same number on stdout.

    The bytes are written through the BINARY buffer on purpose: a text-mode
    write on Windows translates '\\n' to '\\r\\n', which would make stdout one
    byte longer than the measured payload -- exactly the off-by-one that made a
    declared brief_bytes disagree with the real stdout. A caller that measures
    encode_json_line() now sees that exact byte count.
    """
    if (os.environ.get("FINDINFO_EMIT") or "").lower() == "minimal" and isinstance(obj, dict):
        if obj.get("schema") == "findinfo.brief/1":
            # never strip a brief's required fields under minimal mode
            pass
        else:
            drop = ("progress", "coverage", "summary", "params", "paths")
            obj = {k: v for k, v in obj.items() if k not in drop}
    data = encode_json_line(obj).encode("utf-8", "replace")
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        sys.stdout.flush()
        buf.write(data)
        buf.flush()
    else:                                  # a replaced stdout (tests, embedding)
        sys.stdout.write(data.decode("utf-8", "replace"))
        sys.stdout.flush()


class FindInfoError(Exception):
    pass


class ToolMissing(FindInfoError):
    pass


class ScopeRequired(FindInfoError):
    """A command would take its targets from the whole shared asset store.

    The store is shared across engagements (and across tasks when --task is
    omitted), so an unscoped read hands one target's assets to another
    target's stage. `code` is the stable error key on stdout; `hint` says
    how to scope the command.

    `candidates` carries the scopes the store itself suggests, so a caller
    being refused does not have to guess a name and re-run.
    `scope_source` names how scope was decided: "explicit", "inferred",
    "whole_store", or "refused" when no read happened at all.
    """
    code = "scope_required"

    def __init__(self, message: str, hint: str = "",
                 candidates: list | None = None,
                 scope_source: str = "refused"):
        super().__init__(message)
        self.hint = hint
        self.candidates = list(candidates or [])
        self.scope_source = scope_source or "refused"


class SeedDomainRequired(FindInfoError):
    """The run anchored a subject but has no domain to seed discovery with.

    Distinct from a plain refusal because the caller CAN act on it: the
    company name is what the mapping engines want, so `queries` carries the
    exact strings to try (`icp="<name>"`, `domain="<name>"`) and `candidates`
    the names themselves. The operator rule this implements: when ENScan gives
    an asset name and no domain, the agent goes to the internet engines -- it
    is not left with "no seed".
    """

    code = "seed_domain_required"

    def __init__(self, message: str, hint: str = "",
                 candidates: list | None = None, queries: list | None = None):
        super().__init__(message)
        self.hint = hint
        self.candidates = list(candidates or [])
        self.queries = list(queries or [])


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
        # Censys Platform authenticates with a token + organization id (the
        # old "key" field never existed, so CENSYS_API_KEY was always empty).
        "censys": {"token": "", "org_id": "", "id": "", "secret": ""},
        "zoomeye": {"key": ""},
    },
    "http": {"timeout": 25, "user_agent": "Mozilla/5.0 findinfo"},
    "dns": {
        # "auto" probes the OS resolver with a non-existent name at run time;
        # "on"/"off" force the DoH path. See lib/doh.py.
        "fake_ip": "auto",
        "doh_url": "https://cloudflare-dns.com/dns-query",
        "doh_concurrency": 20,
        "doh_timeout": 8,
        "doh_retry": 1,
    },
    # Mapping query templates, per question kind and engine. Only the entries
    # listed here are dispatched: uncover passes -q through verbatim, so a
    # guessed syntax yields a silent zero. Evidence: docs/MAPPING-QUERIES.md.
    "mapping": {"queries": {"domain": {}, "icp": {}}},
    "limits": {
        "dns_concurrency": 100,
        "http_concurrency": 50,
        "per_host_rps": 5,
        "source_retries": 2,
        "vhost_threads": 20,
        "crawl_timeout": 2700,
        # NOT set by default: each engine has its own ceiling in
        # mapdispatch.ENGINE_LIMITS, because uncover pages at 100 rows on
        # every engine and the cost of "one page" differs wildly (fofa bills
        # per query with a 10000-row page; quake bills 100 credits a page and
        # its whole free month is 3000 credits). Setting a global default here
        # would override every engine with one number. Operators who want a
        # single cap for all of them can still write
        # "limits": {"mapping_rows": N} in config.json.
        # Pages followed per onepass source that supports paging
        # (VirusTotal links.next, urlscan search_after). onepass's own
        # default is 4 and it clamps at 20; asking for the clamp means
        # "collect everything the free source will give", and a source
        # that still has more is reported truncated.
        "mapping_pages": 20,
        # JS bundles fetched and scanned per extract invocation. It is a
        # WORK budget, not a discovery cap: every bundle is queued, the
        # rest stay pending and are reported as such (js_pending /
        # js_budget_hit). A real target easily has thousands, so the old
        # hard-coded 40 scanned 24 of 3202 and called the stage partial.
        "js_fetch_limit": 2000,
    },
    # How a store-reading command with NO scope flag is resolved:
    #   infer  (default) derive the scope when the store makes it unambiguous;
    #   refuse          never infer (the strict behaviour);
    #   legacy          read the whole store, loudly, for old scripts.
    # Every choice is published as `scope_source` in the command's output.
    "scope": {"unscoped_reads": "infer"},
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
    "CENSYS_API_TOKEN": ("apis", "censys.token"),
    "CENSYS_ORGANIZATION_ID": ("apis", "censys.org_id"),
    "SECURITYTRAILS_KEY": ("apis", "securitytrails.key"),
    "VIRUSTOTAL_KEY": ("apis", "virustotal.key"),
    "URLSCAN_KEY": ("apis", "urlscan.key"),
    "CHAOS_KEY": ("apis", "chaos.key"),
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


# The credential field differs per provider: Censys issues a token (+ org id),
# everyone else uses "key". api_key() reads the field the provider actually
# uses, so a configured Censys token is not reported as "no key" forever.
_KEY_FIELD = {"censys": "token"}


def api_key(name: str) -> str:
    v = CFG.get("apis", {}).get(name, {})
    if not isinstance(v, dict):
        return ""
    field = _KEY_FIELD.get(name, "key")
    return v.get(field) or v.get("key") or ""


# Which config key each uncover engine needs. An engine with no key can only
# fail, so it must never be handed to uncover: one dead engine out of five
# turns a successful stage into "every source failed".
UNCOVER_ENGINE_KEYS = {
    "fofa": "fofa",
    "quake": "quake",
    "hunter": "hunter",
    "shodan": "shodan",
    "censys": "censys",
    "zoomeye": "zoomeye",
    "securitytrails": "securitytrails",
    "virustotal": "virustotal",
    "chaos": "chaos",
}


def engine_has_key(engine: str) -> bool:
    """True when the mapping engine has a usable credential configured."""
    name = UNCOVER_ENGINE_KEYS.get((engine or "").strip().lower())
    if not name:
        return False
    if name == "fofa":
        # FOFA needs the email too, and a relay gateway can stand in for the
        # official API entirely (see api_base).
        return bool(api_key("fofa") or api_base("fofa"))
    if name == "censys":
        # uncover reads CENSYS_API_TOKEN and CENSYS_ORGANIZATION_ID; a token
        # without the org id is still a usable credential (uncover falls back
        # to the token's own organization), but neither means "no key".
        return bool(api_key("censys"))
    return bool(api_key(name))


# uncover hands `-q` to every engine VERBATIM -- it does not translate between
# query languages -- so one query string sent to five engines is right for at
# most one of them. uncover also reports an upstream syntax or auth error as
# rc=0 with no rows, so the other engines used to look like "found nothing".
# Every engine is asked in its own language, one dispatch per engine, so each
# answer (and each failure) is attributed to the engine that gave it.
# fofa/quake/hunter mirror rust/onepass/src/sources.rs, which queries the same
# APIs directly. An engine missing from a table is never asked: guessing its
# syntax would only manufacture another silent zero.
# Per-engine query templates. EVIDENCE for each default (docs/MAPPING-QUERIES.md):
#   * strings of bin/windows/uncover.exe show the field tokens the agents build
#     with: `domain=`, `domain:"..."`, `hostname:"..."`, `icp:"..."`;
#   * GitHub projectdiscovery/uncover agents/* construct exactly these forms.
# uncover hands -q to the engine VERBATIM -- it does not translate between
# query languages -- so one template per engine is mandatory; an engine with no
# template is never asked (a guessed syntax yields a silent zero).
# Overridable via config `mapping.queries.<kind>.<engine>`; a template MUST
# contain the placeholder `{value}` (validated on load).
_DEFAULT_DOMAIN_QUERY = {
    "fofa": 'domain="{value}"',
    "quake": 'domain:"{value}"',
    "hunter": 'domain="{value}"',
    "shodan": 'hostname:"{value}"',
}
_DEFAULT_ICP_QUERY = {
    "fofa": 'icp="{value}"',
    "quake": 'icp:"{value}"',
    "hunter": 'icp.number="{value}"',
}


def _query_table(kind: str) -> dict:
    """The effective templates for one question kind: config over defaults."""
    defaults = (_DEFAULT_DOMAIN_QUERY if kind == "domain"
                else _DEFAULT_ICP_QUERY)
    out = dict(defaults)
    raw = ((CFG.get("mapping") or {}).get("queries") or {}).get(kind) or {}
    if isinstance(raw, dict):
        for engine, tpl in raw.items():
            e = str(engine).strip().lower()
            t = str(tpl or "")
            if not e or not t:
                continue
            if "{value}" not in t:
                raise FindInfoError(
                    "mapping.queries." + kind + "." + e +
                    " must contain the {value} placeholder: " + t[:80])
            out[e] = t
    return out


UNCOVER_DOMAIN_QUERY = _DEFAULT_DOMAIN_QUERY
UNCOVER_ICP_QUERY = _DEFAULT_ICP_QUERY
_QUERY_TABLES = {"domain": UNCOVER_DOMAIN_QUERY, "icp": UNCOVER_ICP_QUERY}


def uncover_query(kind: str, engine: str, value: str) -> str | None:
    """`value` asked of `engine` in that engine's own syntax, or None.

    Quotes and backslashes are stripped from the value: it is interpolated
    inside a quoted term, and a stray quote would turn one term into a
    different query.
    """
    tpl = _query_table(kind).get((engine or "").strip().lower())
    if not tpl:
        return None
    clean = str(value or "").replace('"', "").replace("\\", "").strip()
    return tpl.replace("{value}", clean)


def uncover_query_identity(kind: str, engines: list[str]) -> dict:
    """{engine: template} for the engines that will actually be asked.

    Part of a stage's checkpoint inputs: when a template changes, a stage that
    asked the old question re-runs instead of hitting its checkpoint.
    """
    table = _query_table(kind)
    return {e: table[e] for e in engines if e in table}


def split_engines(engines: str) -> tuple[list[str], list[str]]:
    """Split a requested engine list into (usable, missing-key)."""
    usable, missing = [], []
    for raw in (engines or "").split(","):
        e = raw.strip().lower()
        if not e:
            continue
        (usable if engine_has_key(e) else missing).append(e)
    return usable, missing


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


# ProjectDiscovery binaries only read keys from the environment, never from our
# config/. But the variable NAME differs per consumer, and the old table used
# one name per engine for every consumer, so several configured keys never
# reached the tool that wanted them:
#
#   engine          .env key            tool              variable the tool reads
#   hunter          HUNTER_KEY          uncover           HUNTER_API_KEY
#                                       onepass           HUNTER_KEY
#   securitytrails  SECURITYTRAILS_KEY  uncover/onepass   SECURITYTRAILS_API_KEY
#   virustotal      VIRUSTOTAL_KEY      uncover/onepass   VIRUSTOTAL_API_KEY
#   urlscan         URLSCAN_KEY         uncover/onepass   URLSCAN_API_KEY
#   censys          CENSYS_ID/SECRET    uncover           CENSYS_API_TOKEN
#                                                         + CENSYS_ORGANIZATION_ID
#   zoomeye         ZOOMEYE_KEY         uncover           ZOOMEYE_API_KEY
#
# The uncover names come from the upstream agent sources
# (github.com/projectdiscovery/uncover/agents/*) and from a string scan of the
# bundled binary; the onepass names come from rust/onepass/src/sources.rs
# (`Auth::Header(_, "HUNTER_KEY")` etc). A name is listed only when a consumer
# is known to read it -- a guess would look configured while silently failing.
# Evaluated AT CALL TIME, not import time: api_key() reads the live config, and
# a module-level dict froze whatever was configured when the process started
# (so a test that overrides a key still saw the old one).
def _consumer_env(consumer: str) -> dict:
    if consumer == "uncover":
        return {
            "fofa": [("FOFA_EMAIL", api_email("fofa")),
                     ("FOFA_KEY", api_key("fofa"))],
            "quake": [("QUAKE_TOKEN", api_key("quake"))],
            "hunter": [("HUNTER_API_KEY", api_key("hunter"))],
            "shodan": [("SHODAN_API_KEY", api_key("shodan"))],
            "censys": [("CENSYS_API_TOKEN", api_key("censys")),
                       ("CENSYS_ORGANIZATION_ID",
                        str((CFG.get("apis", {}).get("censys") or {})
                            .get("org_id") or ""))],
            "zoomeye": [("ZOOMEYE_API_KEY", api_key("zoomeye"))],
        }
    if consumer == "onepass":
        return {
            "fofa": [("FOFA_EMAIL", api_email("fofa")),
                     ("FOFA_KEY", api_key("fofa"))],
            "quake": [("QUAKE_TOKEN", api_key("quake"))],
            "hunter": [("HUNTER_KEY", api_key("hunter"))],
            "chaos": [("CHAOS_KEY", api_key("chaos"))],
            "securitytrails": [("SECURITYTRAILS_KEY",
                                api_key("securitytrails"))],
            "virustotal": [("VIRUSTOTAL_KEY", api_key("virustotal"))],
            "urlscan": [("URLSCAN_KEY", api_key("urlscan"))],
        }
    return {}


# The engine names each consumer can be asked about (values come from
# _consumer_env() at call time).
CONSUMER_ENV = {
    "uncover": {k: [] for k in ("fofa", "quake", "hunter", "shodan",
                                "censys", "zoomeye")},
    "onepass": {k: [] for k in ("fofa", "quake", "hunter", "chaos",
                                "securitytrails", "virustotal", "urlscan")},
}

# Variable NAMES per consumer (for stripping and for documentation).
_CONSUMER_VARS = {
    "uncover": ("FOFA_EMAIL", "FOFA_KEY", "QUAKE_TOKEN", "HUNTER_API_KEY",
                "SHODAN_API_KEY", "CENSYS_API_TOKEN",
                "CENSYS_ORGANIZATION_ID", "ZOOMEYE_API_KEY"),
    "onepass": ("FOFA_EMAIL", "FOFA_KEY", "QUAKE_TOKEN", "HUNTER_KEY",
                "CHAOS_KEY", "SECURITYTRAILS_KEY", "VIRUSTOTAL_KEY",
                "URLSCAN_KEY"),
}

# Every variable any consumer might read. A child that is NOT a mapping
# dispatch has these stripped, including values inherited from the ambient
# environment: httpx and naabu have no business holding paid API keys, and an
# exported key is one more thing a compromised tool can leak.
_ALL_KEY_VARS = frozenset(k for names in _CONSUMER_VARS.values()
                          for k in names)


def tool_env(consumer: str | None = None,
             engines=None) -> dict:
    """API-key env vars for ONE consumer ("uncover" / "onepass"), or none.

    `consumer=None` returns {} on purpose: the default for any child process is
    NO key. Mapping dispatch passes the consumer it is actually calling, so
    httpx/naabu/katana/dnsx never see a key and a paid tool gets exactly its
    own variables under the names it reads.
    """
    if not consumer:
        return {}
    table = _consumer_env(consumer)
    if engines is None:
        chosen = table
    else:
        want = {str(e).strip().lower() for e in (engines or [])}
        chosen = {k: v for k, v in table.items() if k in want}
    env: dict = {}
    for pairs in chosen.values():
        for k, v in pairs:
            if v:
                env[k] = v
    return env


def strip_key_env(env: dict) -> dict:
    """Remove known API-key variables from a child environment.

    Applied to every child that is not a mapping dispatch, so a key exported in
    the user's shell (or inherited from a parent mapping process) is not handed
    to a tool that never needs it.
    """
    for k in _ALL_KEY_VARS:
        env.pop(k, None)
    return env


# ---------------------------------------------------------------- tool lookup
def tool(name: str) -> str:
    """Resolve a bundled binary. Only bin/<platform>/ is searched.

    There is deliberately NO PATH fallback and NO flat bin/ fallback. A
    same-named binary from the ambient environment may be a different build,
    a different version, or an unrelated tool that happens to share the
    name; resolving it silently made every result depend on whichever machine
    the agent ran on. Bundling all tools under one directory is what makes a
    run repeatable.

    Repair is always the same action: install the missing binary into
    bin/<platform>/ (Windows: drop the .exe there; Linux: run
    scripts/setup-linux.sh), then re-run doctor.
    """
    for ext in ("", ".exe"):
        p = BIN_PLATFORM / (name + ext)
        if p.exists():
            return str(p)
    raise ToolMissing(
        "tool not found in " + str(BIN_PLATFORM) + ": " + name +
        " -- install it into bin/" + PLATFORM + "/, then run: " 
        "python findinfo.py doctor"
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
    e = strip_key_env(dict(os.environ))
    e.setdefault("PYTHONIOENCODING", "utf-8")
    # No key is injected by default (see tool_env): a child gets the exact
    # variables its tool reads only when a mapping dispatch passes them.
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
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            cwd=cwd, env=e,
            creationflags=creation,
        )
        if input_text is not None and p.stdin is not None:
            try:
                p.stdin.write(input_text.encode("utf-8", "replace"))
                p.stdin.close()
            except Exception:
                pass
        start = time.time()
        next_beat = float(progress_every or 0)
        while True:
            try:
                out_b, err_b = p.communicate(timeout=1.0)
                # A native tool may answer in GBK on a Chinese Windows console;
                # decoding it as UTF-8 with "replace" silently destroyed CJK
                # titles (see decode_tool_bytes).
                return (p.returncode, decode_tool_bytes(out_b or b""),
                        decode_tool_bytes(err_b or b""))
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
    except OSError as exc:
        # Not executable in this environment: a binary without the exec bit
        # (Linux PermissionError), a non-PE file on Windows (WinError 193),
        # or a blocked-by-policy sandbox. Callers (doctor above all) turn
        # this into a suspect entry instead of crashing on the very machine
        # they are asked to diagnose.
        return 126, "", type(exc).__name__ + ": " + str(exc)


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
                           capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
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


def decode_tool_bytes(raw: bytes) -> str:
    """Decode a native tool's stdout/stderr bytes without losing CJK text.

    Windows collector binaries (httpx and friends) do NOT always emit UTF-8:
    a Chinese-locale console or a Go program writing through the ANSI code
    page produces GBK/CP936 bytes. Decoding those as UTF-8 with
    errors="replace" turned every CJK title into U+FFFD -- irreversible, and
    the store then held '������Ϣְҵ����ѧԺ' instead of 湖南信息职业技术学院
    (observed on mail.mail.hniu.cn, xs.hniu.cn, mail.xs.hniu.cn).

    Order matters: strict UTF-8 first (the documented/normal case, and it
    never succeeds on GBK CJK), then the platform's ANSI code page, then
    cp936 explicitly (so a Windows box with a non-Chinese ANSI page still
    recovers Chinese titles), and only then lossy UTF-8 as the last resort.
    """
    if not raw:
        return ""
    candidates = ["utf-8"]
    try:
        import locale as _locale
        enc = (_locale.getpreferredencoding(False) or "").lower()
        if enc and enc.replace("-", "") not in ("utf8", "ascii"):
            candidates.append(enc)
    except Exception:
        pass
    if os.name == "nt":
        candidates += ["cp936", "gb18030"]
    for enc in candidates:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


class _LineDecoder:
    """Incremental byte->text decoder with the same fallback ladder.

    A process stream is not a single byte blob: a chunk can end mid-character,
    so this keeps the chosen decoder and buffers a partial tail. The codec is
    decided on the FIRST chunk that carries a high byte; ASCII-only output
    stays on UTF-8 (identical semantics) and downloads never switch.
    """

    def __init__(self):
        self._enc = None
        self._dec = None
        self._pending = b""

    def _pick(self, raw: bytes) -> str:
        for enc in ("utf-8", "cp936", "gb18030"):
            try:
                raw.decode(enc)
                return enc
            except (UnicodeDecodeError, LookupError):
                continue
        return "utf-8"

    def feed(self, raw: bytes) -> str:
        if not raw:
            return ""
        data = self._pending + raw
        self._pending = b""
        if self._enc is None:
            if data.isascii():
                return data.decode("ascii")
            self._enc = self._pick(data)
            try:
                self._dec = codecs.getincrementaldecoder(self._enc)("strict")
            except LookupError:
                self._enc = "utf-8"
                self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            return self._dec.decode(data)
        except UnicodeDecodeError:
            # an incomplete tail: keep it for the next chunk
            dec = codecs.getincrementaldecoder(self._enc)("replace")
            text = dec.decode(data)
            self._pending = b""
            return text

    def close(self) -> str:
        if self._dec is None:
            return ""
        try:
            return self._dec.decode(b"", True)
        except Exception:
            return ""


def run_stream(cmd: list[str], on_line=None, timeout: int = 300,
               cwd: str | None = None, env: dict | None = None) -> tuple[int, int, str]:
    """Run a child and hand every stdout line to on_line instead of buffering it.

    This is the memory-safe path for tools that emit tens of thousands of JSONL
    records: peak memory stays flat no matter how big the output is, because the
    text is consumed line by line and dropped. Returns (rc, lines, stderr_tail).
    """
    e = strip_key_env(dict(os.environ))
    e.setdefault("PYTHONIOENCODING", "utf-8")
    if env:
        e.update(env)
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    kwargs: dict = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True       # so the whole group can be killed
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        bufsize=0, cwd=cwd, env=e,
        creationflags=creation, **kwargs)

    tail: collections.deque = collections.deque(maxlen=60)
    timed_out = threading.Event()
    err_dec = _LineDecoder()

    def drain_err() -> None:
        try:
            if proc.stderr is None:
                return
            while True:
                chunk = proc.stderr.read(4096)
                if not chunk:
                    return
                text = err_dec.feed(chunk)
                for line in text.splitlines():
                    if line.strip():
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
        dec = _LineDecoder()
        buf = b""
        try:
            if proc.stdout is None:
                return
            while not timed_out.is_set():
                chunk = proc.stdout.read(8192)
                if not chunk:
                    break                 # real EOF
                buf += chunk
                # emit on newlines only: a JSONL record must be decoded whole
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = dec.feed(raw).strip()
                    if not line:
                        continue
                    lines += 1
                    if on_line is not None:
                        try:
                            on_line(line)
                        except Exception as exc:  # a bad record must not kill the run
                            log("stream line skipped: " + repr(exc))
            tail_line = dec.feed(buf).strip() if buf else ""
            if tail_line:
                lines += 1
                if on_line is not None:
                    try:
                        on_line(tail_line)
                    except Exception as exc:
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
    # 0 is "the default", as --tool-timeout 0 is documented. It used to reach
    # curl as `--max-time 0` (no limit) while the process was killed after
    # 0 + 15 s: every answer slower than 15 s (crt.sh on a large domain) was
    # lost, and a dead upstream still cost the full 15 s per try. The connect
    # timeout makes a black-holed host fail fast without cutting a slow body.
    timeout = int(timeout) if timeout and int(timeout) > 0 else 60
    connect = int((CFG.get("limits") or {}).get("http_connect_timeout") or 15)
    base = [CURL, "-sS", "-L", "--max-time", str(timeout),
            "--connect-timeout", str(max(1, min(connect, timeout))),
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
# Interior labels that only ever appear inside a JS property chain, never in
# a hostname a recon run legitimately sees: jQuery UI widgets, ECharts
# internals, DOM geometry and event plumbing. Matched against lower-cased
# labels of every position except the last.
# TLDs that are ALSO everyday JS/DOM property names. jQuery/ECharts bundles
# yield i.find.id, ge.td, xt.host, li.eq, thumbobj.click, ex.name, ce.fn: every
# label is a property word and the last one happens to be a real suffix, so the
# public-suffix check in canon_domain passes it. Enumerating every property
# name cannot work (i.find.id uses "find"), so the test is inverted: for these
# suffixes require POSITIVE evidence that the second-level label is a real
# organisation name -- a hyphen, a digit, or a word that is not a known
# property/object word. hniu.cn, mail.example.com and my-api.example.cn are
# unaffected because .cn/.com are not in this set.
_AMBIGUOUS_TLDS = frozenset("""
id td th fn eq on is host name click top run build link live life world
today space website fun press rocks social media news blog page network
systems solutions services digital agency studio design software tools codes
zone fit games wiki email art band cafe city company center
""".split())

# Words that appear as property/object names in minified JS and are never a
# registrable organisation label on their own.
_JS_WORDS = frozenset("""
find filter name names eq lt gt fn td th tr host hosts id ids obj opt opts t e i
o a b c el els ev e v k p s n m x y z key keys data item items val value index
len length text html node nodes type target style class list map set get add
remove push pop each this self window document prototype constructor
""".split())


def _looks_like_js_chain(labels: list) -> bool:
    """True when a .tld-shaped label list reads as an object property chain."""
    if len(labels) < 2:
        return False
    if labels[-1] not in _AMBIGUOUS_TLDS:
        return False
    second = labels[-2]
    if "-" in second or any(ch.isdigit() for ch in second):
        return False            # my-api.example / api2.example: a real label
    if second not in _JS_WORDS and len(second) >= 5:
        return False            # a plausible word: hniu, school, example
    return True


_JS_DOM_PROPERTY_LABELS = frozenset("""
style options animation clienty clientx offset position overflowoffset
browserinfo osinfo activegroup pagey pagex railpadding axispointer boundaries
componentoptions selectiondrag pseudos rail value size
""".split())

# Names that look like the above but are also legitimate registrable domains.
_JS_PROPERTY_DOMAINS = frozenset("""
tr
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


def canon_user_domain(value: str) -> str | None:
    """Validate a domain the USER explicitly typed (CLI --domain, --match...).

    canon_domain() doubles as the de-noising filter for crawl/JS extraction,
    so it rejects anything without a known public suffix -- which silently
    threw away legitimate user input: 127.0.0.1:18765, *.test, dev.corp.local,
    IDN names. This function validates USER INTENT instead: strip scheme/
    port/wildcard like canon_domain, accept any syntactically valid hostname
    (including private TLDs like .local/.test and punycode-able IDN), and let
    the CALLER decide what to do with a rejection (the CLI surfaces it in
    rejected_inputs instead of dropping it silently).

    Returns the normalized hostname, or None for a rejection the caller must
    report -- never a silent drop.
    """
    if not value:
        return None
    v = str(value).strip().lower().rstrip(".")
    # IDN (e.g. Chinese-label names) -> punycode so downstream tools get ASCII
    if any(ord(c) > 127 for c in v):
        try:
            v = v.encode("idna").decode("ascii")
        except Exception:
            return None
    v = re.sub(r"^[a-z]+://", "", v)
    v = v.split("/")[0]
    v = v.split("@")[-1]
    if ":" in v and not v.count(":") > 2:
        v = v.split(":")[0]
    if v.startswith("*."):
        v = v[2:]
    if not v or len(v) > 253:
        return None
    # A user-supplied hostname: any dot-separated labels that look like a
    # DNS name (letters/digits/hyphen), a bare IPv4, or a bracketed IPv6
    # handled above by the port strip. NO public-suffix check here.
    if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", v):
        if canon_ip(v) is None:
            return None
    return v


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
    # Property chains whose LAST label is a real TLD word. jQuery/ECharts
    # bundles produce `e.animation.on`, `options.name`, `abel.tr`: every label
    # is a DOM/JS property and the final one happens to be a real TLD
    # (.top/.name/.on/.tr), so the suffix guard above lets it through. A real
    # host never has an interior label that is a JS property word; when one
    # does, and the name is not a known registrable domain, drop it.
    # `e.clienty-n.top`: a JS subtraction inside a label. Split on the
    # hyphen and test the pieces against the same property vocabulary.
    if any(part in _JS_DOM_PROPERTY_LABELS
           for lbl in labels[:-1] if "-" in lbl
           for part in lbl.split("-") if part):
        return None
    if v not in _JS_PROPERTY_DOMAINS:
        if any(lbl in _JS_DOM_PROPERTY_LABELS for lbl in labels[:-1]):
            return None
        if _looks_like_js_chain(labels):
            return None
    return v


def canon_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except Exception:
        return None


def is_ip(value: str) -> bool:
    return canon_ip(value) is not None


# A path that came out of a JS string concatenation is not a URL: katana sees
# `'/_upload/tpl/' + tecUrl + '/x.js'` inside a bundle and reports the pieces
# as paths. A real target produced 25k such fragments, burying the 492 real
# API endpoints. These patterns say "this is source code, not a location".
_PATH_JUNK_PATTERNS = (
    r"\+\s*[A-Za-z_$][\w$]*\s*\+",     # 'a' + name + 'b'
    r"%27", r"%22",                       # encoded quote = literal text
    r"\$\{[^}]*\}",                      # JS template interpolation
    r"\{\{[^}]*\}\}",                     # framework template
    r"['\"]\s*\+",                      # quote then concatenation
)
_PATH_JUNK_RE = re.compile("|".join(_PATH_JUNK_PATTERNS), re.I)


def is_junk_path(path: str) -> bool:
    """True when a claimed path is really a fragment of JavaScript source.

    Used before anything is stored as an endpoint: a path like
    `/_upload/tpl/{n}/template1/js/'+tecUrl+'` can never be requested, and
    storing thousands of them makes the endpoint table useless for triage.
    """
    p = str(path or "")
    if not p or p == "/":
        return False
    return bool(_PATH_JUNK_RE.search(p))


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


def canon_match(entries: Iterable[str]) -> list[str]:
    """Scope entries for MATCHING stored assets: strict where possible, but a
    user-typed private name (dev.corp.local, *.test) is kept, never dropped.

    canon_scope() is the crawl/JS de-noiser and drops such names; used to
    build a query filter it turned "--scope dev.corp.local" into no filter at
    all, i.e. the whole shared store.
    """
    out: list[str] = []
    for e in entries or []:
        d = canon_domain(e) or canon_user_domain(e)
        if d and d not in out:
            out.append(d)
    return out


def is_public_ip(value: str) -> bool:
    """True for a globally routable unicast address.

    Private, loopback, link-local, CGNAT, benchmark (198.18.0.0/15, the
    Clash/TUN fake-IP range), documentation, reserved and multicast addresses
    are not: an address like that taken from the store came out of a page,
    JS bundle or internal DNS answer, and probing it reaches whatever network
    the operator happens to sit in, not the target.
    """
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return bool(addr.is_global and not addr.is_multicast)


def canon_user_scope(entries: Iterable[str]) -> tuple[list[str], list[str]]:
    """Scope from USER-TYPED input, with rejections surfaced.

    Returns (accepted, rejected): accepted uses canon_user_domain (validates
    intent -- private TLDs, IPs, IDN are fine), rejected carries the raw input
    the caller must report in rejected_inputs. The strict canon_domain filter
    stays in place for de-noising crawl/JS output; this is the version for
    flags a human or agent deliberately typed.
    """
    accepted: list[str] = []
    rejected: list[str] = []
    for e in entries or []:
        d = canon_user_domain(e)
        if not d:
            rejected.append(str(e))
        elif d not in accepted:
            accepted.append(d)
        # an exact duplicate of an already-accepted value is neither a new
        # acceptance nor a rejection -- reporting it as rejected would be
        # worse than dropping it silently (a repeated --domain flag is
        # normal argparse usage, not a user error).
    return accepted, rejected


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


# --- scope of an unscoped store read ----------------------------------
# The store is shared, so a read with no scope flag used to be either a
# silent whole-store read (old behaviour) or a hard refusal. Neither is
# right for every caller: a single-target store reads fine without a flag,
# and an old script must still be able to say "all of it".
# `scope.unscoped_reads` picks the policy, and every read publishes how its
# scope was decided as `scope_source` so a caller can never mistake an
# inferred scope for an explicit one.
SCOPE_MODES = ("infer", "refuse", "legacy")


def scope_mode() -> str:
    """The configured policy for a store read that carries no scope flag.

    Unknown values fall back to "infer" with a log line rather than raising:
    a typo in a config file must not make every command fail, and the
    fallback is the SAFE one (never a silent whole-store read).
    """
    raw = str(((CFG.get("scope") or {}).get("unscoped_reads")) or "").strip().lower()
    if raw in SCOPE_MODES:
        return raw
    if raw:
        log("scope.unscoped_reads=" + raw + " is not one of " +
            "/".join(SCOPE_MODES) + "; using infer")
    return "infer"


def scope_candidates(store, kind: str = "domain", limit: int = 12) -> list[str]:
    """Registrable domains the store itself contains, most-supported first.

    This is what a refusal offers instead of "guess a name and re-run". It
    reads only the local database and never widens anything by itself.
    """
    counts: dict[str, int] = {}
    try:
        rows = store.get_assets(kind=kind)
    except Exception:
        return []
    for a in rows:
        base = registrable_domain(a.get("canonical") or "")
        if base:
            counts[base] = counts.get(base, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [name for name, _n in ordered[:max(1, limit)]]


def infer_scope(store, kind: str = "domain") -> list[str]:
    """The ONE registrable domain this store holds, or [] when ambiguous.

    "Unambiguous" means every stored domain collapses to the same base
    domain. Two or more bases means the store mixes targets, and guessing
    would hand one target's assets to another -- exactly what the scope
    gate exists to prevent. So the caller refuses instead.
    """
    names = scope_candidates(store, kind=kind, limit=2)
    return names if len(names) == 1 else []


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
    if b is None and name == "fofa-gateway":
        # A FOFA relay publishes its own pace (the one seen in a real run:
        # 10 questions a minute); asking faster only earns "请求过于频繁".
        per_min = float((CFG.get("limits") or {}).get("fofa_gateway_per_minute") or 10)
        b = _BUCKETS[name] = TokenBucket(per_min / 60.0, 1)
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
  last_seen TEXT,
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
  last_seen TEXT,
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
        self._migrate_seen_columns()
        self.conn.commit()

    def _migrate_seen_columns(self) -> None:
        """Add last_seen to older databases that predate it.

        CREATE TABLE IF NOT EXISTS never touches an existing table, so a
        store created before last_seen existed would keep the old shape and
        every write would fail. The migration is idempotent: PRAGMA reports
        the columns already present and nothing is altered twice.
        """
        for table in ("endpoints", "asset_links"):
            try:
                cols = [r[1] for r in self.conn.execute(
                    "PRAGMA table_info(" + table + ")").fetchall()]
            except sqlite3.Error:
                continue
            if not cols or "last_seen" in cols:
                continue
            try:
                self.conn.execute(
                    "ALTER TABLE " + table + " ADD COLUMN last_seen TEXT")
                # Backfill: an asset discovered before this column existed
                # was last observed at least at first_seen, never earlier.
                self.conn.execute(
                    "UPDATE " + table + " SET last_seen=first_seen WHERE last_seen IS NULL")
            except sqlite3.Error:
                pass

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

        Keyed on (kind, canonical, relation, owner): re-observing the same
        pairing does not fan the table out, but it DOES move last_seen forward
        (see _link). Returns True when the edge is new.
        """
        if not canonical or not owner or not relation:
            return False
        with self._write():
            before = self.conn.execute(
                "SELECT id FROM asset_links"
                " WHERE kind=? AND canonical=? AND relation=? AND owner=?",
                (kind, canonical, relation, owner)).fetchone()
            self._link(kind, canonical, relation, owner, source or "", now())
            return before is None

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

    def _link(self, kind: str, canonical: str, relation: str, owner: str,
              source: str, ts: str) -> None:
        """Record one (asset, relation, owner) edge, refreshing last_seen.

        A re-observation is the whole point of last_seen: an edge that is
        still being seen must move forward instead of staying pinned to the
        first time it was discovered. The source token is merged rather than
        overwritten, so the row keeps every upstream that ever reported it.
        """
        if not (canonical and owner):
            return
        try:
            row = self.conn.execute(
                "SELECT id, source FROM asset_links"
                " WHERE kind=? AND canonical=? AND relation=? AND owner=?",
                (kind, canonical, relation, owner)).fetchone()
            if row is None:
                self.conn.execute(
                    "INSERT INTO asset_links"
                    "(kind,canonical,relation,owner,source,first_seen,last_seen)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (kind, canonical, relation, owner, source or "", ts, ts))
            else:
                merged = self._merge_sources(row["source"] or "", source or "")
                self.conn.execute(
                    "UPDATE asset_links SET last_seen=?, source=? WHERE id=?",
                    (ts, merged, row["id"]))
        except sqlite3.Error:
            pass


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
                    self._link(kind, canonical, "resolved_from", parent, source, ts)
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
                self._link(kind, canonical, "resolved_from", parent, source, ts)
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

    def js_claim(self, limit: int, allow_urls: list[str] | None = None,
                 scope: list[str] | None = None) -> list[str]:
        """Oldest pending first, then retryable failures; never re-claim done.

        The queue is shared across targets. Claiming globally meant a run for
        example.com fetched and scanned bundles queued by a previous, unrelated
        target -- widening the active scope without anybody asking. Callers
        pass the exact work set (`allow_urls`) or a `scope`; only matching rows
        are claimable.
        """
        if limit <= 0:
            return []
        rows = self.conn.execute(
            "SELECT url FROM js_queue WHERE state IN ('pending','failed')"
            " ORDER BY CASE state WHEN 'pending' THEN 0 ELSE 1 END,"
            " updated_at, url").fetchall()
        urls = [r["url"] for r in rows]
        if allow_urls is not None:
            allow = set(allow_urls)
            urls = [u for u in urls if u in allow]
        if scope:
            sc = canon_scope(scope)
            urls = [u for u in urls if in_scope(split_url(u)[0] or "", sc)]
        return urls[:limit]

    def js_finish(self, url: str, ok: bool, error: str = "") -> None:
        ts = now()
        with self._write():
            self.conn.execute(
                "UPDATE js_queue SET state=?, attempts=attempts+1, last_error=?,"
                " updated_at=? WHERE url=?",
                ("done" if ok else "failed", (error or "")[:300], ts, url))

    def js_stats(self, scope: list[str] | None = None) -> dict:
        """Everything an agent needs to decide "keep going or stop".

        `scope` restricts the counts to bundles under those domains, so another
        target's leftovers cannot make this run look unfinished (or hide work
        that really is this run's).
        """
        rows = self.conn.execute("SELECT url, state FROM js_queue").fetchall()
        sc = canon_scope(scope or [])
        if sc:
            rows = [r for r in rows
                    if in_scope(split_url(r["url"])[0] or "", sc)]
        by: dict[str, int] = {}
        for r in rows:
            by[r["state"]] = by.get(r["state"], 0) + 1
        return {"discovered": sum(by.values()),
                "succeeded": by.get("done", 0),
                "failed": by.get("failed", 0),
                "pending": by.get("pending", 0),
                "skipped": by.get("skipped", 0)}

    def get_assets(self, kind: str | None = None, min_conf: float = 0.0,
                   limit: int = 100000, match: list[str] | None = None) -> list[dict]:
        """Query assets.

        `match` restricts results to rows whose canonical OR parent equals/sits
        under one of the given suffixes (e.g. ["example.com"]). The store is a
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
        requested = bool(match)
        match = canon_match(match or [])
        if requested and not match:
            # The caller asked for a scope and none of it is a usable name:
            # that is an empty scope, never "no scope" (the whole store).
            return []
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
                # Re-observing an endpoint moves last_seen forward; first_seen
                # stays put so "when did we first see this path" survives a
                # rerun that merely confirms it again.
                self.conn.execute(
                    "UPDATE endpoints SET status=COALESCE(?,status),"
                    " title=COALESCE(?,title), last_seen=? WHERE id=?",
                    (status, title, ts, row["id"]))
                return False
            self.conn.execute(
                "INSERT INTO endpoints"
                "(asset,method,path,params,source,status,title,first_seen,last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (asset, method, path, params, source, status, title, ts, ts))
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

    def clear_steps(self, canon: list[str] | None = None) -> int:
        """Forget stage checkpoints whose inputs were just deleted.

        Dropping assets while `steps` still says done is self-contradictory:
        the next run skips the stage and every downstream stage starves for
        input (seen with `clean --all` before an ENScan re-run). canon=None
        clears every checkpoint, which is what an unfiltered wipe means.
        """
        with self._write():
            if not canon:
                cur = self.conn.execute("DELETE FROM steps")
                return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            n = 0
            for m in canon_scope(canon):
                cur = self.conn.execute(
                    "DELETE FROM steps WHERE input_hash LIKE ?",
                    ("%" + m + "%",))
                n += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            return n

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
