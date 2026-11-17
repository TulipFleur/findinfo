"""findinfo core: paths, config, store, normalize, cache, rate-limit, scope, exec helpers."""
from __future__ import annotations

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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Code lives next to this package (bin/, wordlists/); mutable state lives in a
# user-level home so that the same skill can be linked into several clients
# without splitting the asset graph or writing into a read-only install.
ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"


def _resolve_home() -> Path:
    """State root. Order: FINDINFO_HOME > ~/.findinfo > legacy in-tree data/."""
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
# scope.json and .env here, and a silent move would turn scope checks off.
CONF_DIR = ROOT / "config"

for _d in (BIN, DATA, CACHE_DIR, RUNS_DIR, CONF_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass   # read-only install: only commands that need to write will fail


# ---------------------------------------------------------------- logging / output
def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    sys.stderr.write("[" + now() + "] " + str(msg) + chr(10))
    sys.stderr.flush()


def emit(obj: Any) -> None:
    """Machine-readable result goes to stdout; everything else to stderr."""
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + chr(10))
    sys.stdout.flush()


class FindInfoError(Exception):
    pass


class ScopeError(FindInfoError):
    pass


class ToolMissing(FindInfoError):
    pass


# ---------------------------------------------------------------- config
DEFAULT_CONFIG = {
    "engagements": {},
    "apis": {
        "fofa": {"email": "", "key": ""},
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
        "vhost_threads": 20,
    },
    "paths": {"resolvers": "", "subwordlist": "", "vhostwordlist": ""},
}


ENV_MAP = {
    # env var -> (section, key)
    "FOFA_EMAIL": ("apis", "fofa.email"),
    "FOFA_KEY": ("apis", "fofa.key"),
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


# ---------------------------------------------------------------- tool lookup
def tool(name: str) -> str:
    """Resolve a binary: bundled bin/ first, then PATH (non-Windows installs)."""
    for cand in (name, name + ".exe"):
        p = BIN / cand
        if p.exists():
            return str(p)
    found = shutil.which(name)
    if found:
        return found
    raise ToolMissing(
        "tool not found in bin/ or PATH: " + name + " -- run: python findinfo.py doctor"
    )


def has_tool(name: str) -> bool:
    try:
        tool(name)
        return True
    except ToolMissing:
        return False


def run(cmd: list[str], timeout: int = 300, input_text: str | None = None,
        cwd: str | None = None, env: dict | None = None) -> tuple[int, str, str]:
    e = dict(os.environ)
    e.setdefault("PYTHONIOENCODING", "utf-8")
    if env:
        e.update(env)
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, cwd=cwd, env=e,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after " + str(timeout) + "s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)


CURL = "curl"


def curl(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    base = [CURL, "-sS", "-L", "--max-time", str(timeout),
            "--retry", "2", "--retry-delay", "2",
            "-A", CFG.get("http", {}).get("user_agent", "findinfo")]
    return run(base + args, timeout=timeout + 15)


def curl_json(url: str, headers: dict | None = None, timeout: int = 60) -> Any:
    args: list[str] = []
    for k, v in (headers or {}).items():
        args += ["-H", k + ": " + v]
    rc, out, err = curl(args + [url], timeout=timeout)
    if rc != 0 or not out.strip():
        log("curl failed rc=" + str(rc) + " " + url[:120] + " " + err[:160])
        return None
    try:
        return json.loads(out)
    except Exception:
        log("json parse failed " + url[:120])
        return None


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
    "http": TokenBucket(50, 50),
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


# ---------------------------------------------------------------- scope
class Scope:
    """Authorization gate. Active tools must call require(); the rule lives in code."""

    def __init__(self, spec: dict | None = None):
        spec = spec or {}
        self.engagement = spec.get("engagement", "default")
        self.domains = [d.lower().lstrip("*").lstrip(".") for d in spec.get("domains", [])]
        self.cidrs = []
        for c in spec.get("cidrs", []):
            try:
                self.cidrs.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                pass
        self.deny = [d.lower() for d in spec.get("deny", [])]
        self.enabled = bool(self.domains or self.cidrs)
        self.checked = 0
        self.blocked = 0

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Scope":
        p = Path(path) if path else CONF_DIR / "scope.json"
        if not p.exists():
            return cls({})
        try:
            return cls(json.loads(p.read_text(encoding="utf-8")))
        except Exception as exc:
            raise FindInfoError("scope parse error: " + str(exc))

    def check(self, host: str) -> tuple[bool, str]:
        self.checked += 1
        h = (host or "").strip().lower()
        if not h:
            return False, "empty"
        for d in self.deny:
            if h == d or h.endswith("." + d):
                self.blocked += 1
                return False, "deny:" + d
        ip = canon_ip(h)
        if ip:
            addr = ipaddress.ip_address(ip)
            for net in self.cidrs:
                if addr in net:
                    return True, "cidr:" + str(net)
            self.blocked += 1
            return False, "ip-not-in-scope"
        for d in self.domains:
            if h == d or h.endswith("." + d):
                return True, "domain:" + d
        self.blocked += 1
        return False, "not-in-scope"

    def require(self, host: str) -> None:
        ok, rule = self.check(host)
        if not ok:
            raise ScopeError("scope denied for " + host + " (" + rule + ")")

    def summary(self) -> dict:
        return {"engagement": self.engagement, "enabled": self.enabled,
                "domains": self.domains, "cidrs": [str(c) for c in self.cidrs],
                "deny": self.deny, "checked": self.checked, "blocked": self.blocked}


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
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent);
CREATE INDEX IF NOT EXISTS idx_endpoints_asset ON endpoints(asset);
"""


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = str(path or (DATA / "findinfo.db"))
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    # -- assets
    def upsert_asset(self, kind: str, canonical: str, source: str,
                     confidence: float = 0.4, passivity: str = "passive",
                     parent: str | None = None, attrs: dict | None = None) -> tuple[str, bool]:
        if not canonical:
            return "", False
        ts = now()
        row = self.conn.execute(
            "SELECT id, sources, confidence, attrs FROM assets WHERE kind=? AND canonical=?",
            (kind, canonical)).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO assets(kind,canonical,parent,sources,confidence,passivity,attrs,first_seen,last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (kind, canonical, parent, source, confidence, passivity,
                 json.dumps(attrs or {}, ensure_ascii=False), ts, ts))
            self.conn.commit()
            return canonical, True
        sources = [s for s in (row["sources"] or "").split(",") if s]
        if source and source not in sources:
            sources.append(source)
        conf = max(float(row["confidence"] or 0.4), confidence)
        if len(sources) >= 2:
            conf = max(conf, 0.7)
        if len(sources) >= 3:
            conf = max(conf, 0.95)
        attrs_old = {}
        try:
            attrs_old = json.loads(row["attrs"] or "{}")
        except Exception:
            pass
        attrs_old.update(attrs or {})
        self.conn.execute(
            "UPDATE assets SET sources=?, confidence=?, attrs=?, last_seen=?,"
            " parent=COALESCE(parent, ?) WHERE id=?",
            (",".join(sources), conf, json.dumps(attrs_old, ensure_ascii=False),
             ts, parent, row["id"]))
        self.conn.commit()
        return canonical, False

    def get_assets(self, kind: str | None = None, min_conf: float = 0.0,
                   limit: int = 100000) -> list[dict]:
        sql = "SELECT * FROM assets WHERE confidence>=?"
        args: list[Any] = [min_conf]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        sql += " ORDER BY confidence DESC, first_seen ASC LIMIT ?"
        args.append(limit)
        out = []
        for r in self.conn.execute(sql, args):
            d = dict(r)
            try:
                d["attrs"] = json.loads(d.get("attrs") or "{}")
            except Exception:
                d["attrs"] = {}
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
        row = self.conn.execute(
            "SELECT id FROM endpoints WHERE asset=? AND method=? AND path=? AND params=?",
            (asset, method, path, params)).fetchone()
        if row:
            self.conn.execute(
                "UPDATE endpoints SET status=COALESCE(?,status), title=COALESCE(?,title) WHERE id=?",
                (status, title, row["id"]))
            self.conn.commit()
            return False
        self.conn.execute(
            "INSERT INTO endpoints(asset,method,path,params,source,status,title,first_seen)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (asset, method, path, params, source, status, title, ts))
        self.conn.commit()
        return True

    def get_endpoints(self, asset: str | None = None, limit: int = 100000) -> list[dict]:
        if asset:
            rows = self.conn.execute("SELECT * FROM endpoints WHERE asset=? LIMIT ?", (asset, limit))
        else:
            rows = self.conn.execute("SELECT * FROM endpoints LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    # -- steps / runs
    def step_done(self, engagement: str, step: str, input_hash: str) -> bool:
        row = self.conn.execute(
            "SELECT status, input_hash FROM steps WHERE engagement=? AND step=?",
            (engagement, step)).fetchone()
        return bool(row and row["status"] == "done" and row["input_hash"] == input_hash)

    def set_step(self, engagement: str, step: str, input_hash: str, status: str,
                 artifact: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO steps(engagement,step,input_hash,status,artifact,updated_at)"
            " VALUES(?,?,?,?,?,?) ON CONFLICT(engagement,step) DO UPDATE SET"
            " input_hash=excluded.input_hash, status=excluded.status,"
            " artifact=excluded.artifact, updated_at=excluded.updated_at",
            (engagement, step, input_hash, status, artifact, now()))
        self.conn.commit()

    def start_run(self, engagement: str, target: str) -> int:
        cur = self.conn.execute("INSERT INTO runs(engagement,target,started) VALUES(?,?,?)",
                                (engagement, target, now()))
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, summary: dict) -> None:
        self.conn.execute("UPDATE runs SET finished=?, summary=? WHERE id=?",
                          (now(), json.dumps(summary, ensure_ascii=False), run_id))
        self.conn.commit()


def new_run_dir(tag: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^0-9a-zA-Z_.\-]+", "_", tag)[:40]
    p = RUNS_DIR / (stamp + "-" + safe)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + chr(10))
            n += 1
    return n
