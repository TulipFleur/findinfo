"""findinfo tools: thin, typed wrappers around bundled binaries + APIs.

Every function:
  - takes explicit inputs
  - returns structured dicts (never raw HTML)
  - writes normalized records into the store
"""
from __future__ import annotations

import atexit
import json
import os
import urllib.error
import urllib.request
import uuid
import re
import socket
import tempfile
import threading
import time
import concurrent.futures as futures
from pathlib import Path
from typing import Any

from . import core

# ---------------------------------------------------------------- helpers
BASE_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.I)
ICP_RE = re.compile(r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-Za-z]ICP[备证]\d+号(?:-\d+)?")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


_TMP_FILES: list[str] = []


def _cleanup_tmp() -> None:
    for p in _TMP_FILES:
        try:
            os.remove(p)
        except Exception:
            pass
    _TMP_FILES.clear()


atexit.register(_cleanup_tmp)


def _tmp_lines(rows: list[str], suffix: str = ".txt") -> str:
    """Write a temp input list; auto-deleted at process exit."""
    tmpdir = core.DATA / "_tmp"
    tmpdir.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(suffix=suffix, dir=str(tmpdir))
    with open(fd, "w", encoding="utf-8") as fh:
        fh.write(chr(10).join([r for r in rows if r]))
        fh.write(chr(10))
    _TMP_FILES.append(path)
    return path


def _uniq(seq) -> list:
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _looks_public(domain: str) -> bool:
    return bool(BASE_RE.match(domain or "")) and "." in domain


BARE_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$", re.I)


def expand_host_words(words: list[str], bases: list[str]) -> list[str]:
    """vhost wordlist -> hostnames that can actually be sent as a Host header.

    wordlists/vhost.txt holds bare labels ("jenkins", "uat"). A bare label alone
    is not a hostname, so qualifying it against every known base domain is what
    turns the bundled wordlist into real candidates. Entries that already look
    like a domain are kept verbatim.
    """
    clean_bases = [b for b in _uniq([core.canon_domain(b) or "" for b in bases]) if b]
    out: list[str] = []
    for raw in words:
        w = (raw or "").strip().lower().lstrip("*.")
        if not w or w.startswith("#"):
            continue
        d = core.canon_domain(w)
        if d:
            out.append(d)
            continue
        if not BARE_LABEL_RE.match(w):
            core.log("vhost wordlist: skip invalid entry " + str(raw))
            continue
        if not clean_bases:
            core.log("vhost wordlist: bare label '" + w +
                     "' needs a base domain (pass --domain or seed a domain first)")
            continue
        out.extend(w + "." + b for b in clean_bases)
    return _uniq(out)


# ---------------------------------------------------------------- 1. entity (ENScan)
def harvest_entity(obj: Any, depth: int = 0) -> dict:
    """Format-tolerant harvest: pull companies / ICP / domains out of any ENScan JSON."""
    out = {"companies": [], "icp": [], "domains": [], "apps": []}
    if depth > 12:
        return out
    if isinstance(obj, dict):
        for key, val in obj.items():
            k = str(key).lower()
            if isinstance(val, str):
                if "icp" in k:
                    for m in ICP_RE.findall(val):
                        out["icp"].append(m)
                if "domain" in k:
                    d = core.canon_domain(val)
                    if d and _looks_public(d):
                        out["domains"].append(d)
                if any(x in k for x in ("company", "name", "enterprise")) and "domain" not in k:
                    out["companies"].append(val.strip())
                if "app" in k and len(val) < 200:
                    out["apps"].append(val.strip())
                for m in ICP_RE.findall(val):
                    out["icp"].append(m)
                for m in DOMAIN_RE.findall(val):
                    d = core.canon_domain(m)
                    if d and _looks_public(d):
                        out["domains"].append(d)
            elif isinstance(val, (dict, list)):
                sub = harvest_entity(val, depth + 1)
                for kk in out:
                    out[kk].extend(sub[kk])
    elif isinstance(obj, list):
        for it in obj:
            sub = harvest_entity(it, depth + 1)
            for kk in out:
                out[kk].extend(sub[kk])
    for kk in out:
        out[kk] = _uniq([x for x in out[kk] if x])
    return out


# ENScan keeps its own working state next to the process: two concurrent
# instances answer with the SAME company, silently giving one engagement
# another company domains. It must run one at a time, process-wide and
# across tasks/workers, so a lock file is used.
_ENSCAN_LOCK = threading.Lock()


class _FileLock:
    """Exclusive lock file with wait (O_CREAT|O_EXCL) and stale recovery."""

    def __init__(self, path, timeout: float = 1800.0, stale: float = 1800.0):
        self.path = Path(path)
        self.timeout = timeout
        self.stale = stale
        self.fd = None

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self.fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, str(os.getpid()).encode())
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale:
                        core.log("enscan lock stale, stealing: " + str(self.path))
                        self.path.unlink()
                        continue
                except OSError:
                    pass
                if time.time() > deadline:
                    raise core.FindInfoError("enscan lock timeout: " + str(self.path))
                time.sleep(0.2)

    def __exit__(self, *exc):
        try:
            if self.fd is not None:
                os.close(self.fd)
        except OSError:
            pass
        try:
            self.path.unlink()
        except OSError:
            pass
        return False


def t_enscan(store, name: str, invest: int = 51, deep: int = 2,
             outdir: Path | None = None, timeout: int = 0,
             field: str = "icp,app,wx_app,wechat,copyright,supplier,invest,enterprise_info",
             delay: int = 2) -> dict:
    exe = core.tool("enscan")
    outdir = outdir or (core.RUNS_DIR / "enscan")
    outdir.mkdir(parents=True, exist_ok=True)
    # Snapshot existing outputs so a re-run cannot harvest stale JSON from a
    # previous target/time (that silently merged another company's domains in).
    before = {p.resolve() for p in outdir.rglob("*.json")}
    cmd = [exe, "-n", name, "-invest", str(invest), "-deep", str(deep),
           "-json", "-out-dir", str(outdir), "-type", "aqc",
           "-branch", "-supplier", "-delay", str(delay)]
    if field:
        cmd += ["-field", field]
    core.log("enscan: " + " ".join(cmd[1:]))
    # ENScan is the slowest stage in practice: a deep query with every field can
    # run for tens of minutes against aiqicha. Say so up front and keep a beat,
    # so a waiting agent can tell "working" from "stuck".
    core.log("enscan: deep=" + str(deep) + " fields=" +
             str(len(field.split(",")) if field else 0) + " — this can take 10+ min")
    # serialized: two enscan.exe at once return the first query's entity
    with _ENSCAN_LOCK, _FileLock(core.DATA / "enscan.lock", timeout=1800):
        rc, out, err = core.run(cmd, timeout=timeout, cwd=str(core.BIN),
                                progress=lambda secs: core.log(
                                    "enscan: still running (" + str(secs) + "s)"))
    # ENScan is a Go program that tears its own process down at the end of a page
    # walk. Under a wrapper it can die before flushing the JSON writers, and on
    # a 20-minute deep query it may also finish its work but never exit. Either
    # way the only trustworthy signal is the artifacts on disk, so "no new JSON"
    # is NOT the same as "the tool failed": when a human-readable table was
    # printed but no JSON landed, say exactly that instead of blaming the target.
    if rc == 124:
        core.log("enscan: timed out after " + str(timeout) +
                 "s — partial output kept, stage will be retried")
    table = bool((out or "").strip())
    blob = (out or "") + (err or "")
    if "cookie" in blob.lower() or "Cookie" in blob:
        core.log("enscan: no cookie configured; put the aiqicha Cookie into bin/config.yaml")
    merged = {"companies": [], "icp": [], "domains": [], "apps": []}
    files = 0
    for p in sorted(outdir.rglob("*.json")):
        if p.resolve() in before:      # stale file from an earlier run
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        files += 1
        got = harvest_entity(data)
        for k in merged:
            merged[k].extend(got[k])
        store.upsert_asset("company", got_name(p, name), source="enscan",
                           confidence=0.9, passivity="passive")
    for k in merged:
        merged[k] = _uniq(merged[k])
    for d in merged["domains"]:
        store.upsert_asset("domain", d, source="enscan", confidence=0.9,
                           passivity="passive", parent=name)
    # Keep ICP numbers as first-class assets: `icp --from-store` and later
    # reverse-lookup rounds read them back, so a run must not be the only place
    # they exist.
    for code in merged["icp"]:
        store.upsert_asset("icp", code, source="enscan", confidence=0.9,
                           passivity="passive", parent=name)
    if files == 0 and table:
        core.log("enscan: printed a report table but wrote no JSON to " +
                 str(outdir) + " — entity data could not be parsed; treat as a "
                 "coverage gap, not as 'this company has no assets'")
    return {"rc": rc, "json_files": files, "stderr": err[-800:],
            "table_only": files == 0 and table,
            "companies": merged["companies"][:200],
            "icp": merged["icp"], "domains": merged["domains"],
            "apps": merged["apps"][:100]}


def got_name(p: Path, fallback: str) -> str:
    return p.stem or fallback


# ---------------------------------------------------------------- 2. certificate transparency
def t_certs(store, domain: str, timeout: int = 0) -> dict:
    """CT lookup via crt.sh, falling back to CertSpotter.

    The result names the upstream that actually answered (`upstream`): a
    CertSpotter fallback must not be reported as crt.sh evidence.
    `ok=False` means BOTH upstreams were unreachable -- the caller records
    the stage as failed instead of mistaking it for "no certificates".
    """
    raw = domain
    domain = core.canon_domain(domain)
    if not domain:
        raise core.FindInfoError("invalid domain: " + str(raw))
    cache_key = "ct:" + domain
    upstream = "crt.sh"
    cached = core.CACHE.get("certs", cache_key, ttl=7 * 86400)
    # The cache must remember WHICH upstream answered. Storing the payload alone
    # meant a certspotter result replayed from cache was relabelled "crt.sh",
    # inventing a second independent witness for the same evidence (confidence
    # counts distinct upstreams). Records written before this change have no
    # upstream field; keep them unknown rather than guessing.
    if isinstance(cached, dict) and "data" in cached:
        data = cached.get("data")
        upstream = str(cached.get("upstream") or "unknown")
    elif cached is not None:
        data = cached                      # legacy: bare payload
        upstream = "unknown"
    else:
        data = None
    if data is None:
        ok = False
        # transient failures (429/502/dropped tunnel) get bounded retries;
        # `attempts` stays small so a dead source cannot eat the run budget
        attempts = 1 + max(0, int((core.CFG.get("limits") or {}).get("source_retries") or 0))
        core.throttle("crtsh")
        data = core.fetch_with_retry(
            core.curl_json,
            "https://crt.sh/?q=%25." + domain + "&output=json",
            headers={"Accept": "application/json"}, timeout=timeout,
            attempts=attempts)
        if data is not None:
            ok = True
        else:
            core.throttle("certspotter")
            data = core.fetch_with_retry(
                core.curl_json,
                "https://api.certspotter.com/v1/issuances?domain=" + domain +
                "&include_subdomains=true&expand=dns_names",
                headers={"Accept": "application/json"}, timeout=timeout,
                attempts=attempts)
            if data is not None:
                ok = True
                upstream = "certspotter"
            else:
                data = []
        # never cache a failed fetch as "no certificates"
        if ok:
            core.CACHE.put("certs", cache_key,
                           {"schema": "certs/2", "upstream": upstream,
                            "data": data})
    else:
        ok = True
    names: list[str] = []
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            for key in ("name_value", "common_name"):
                v = item.get(key)
                if isinstance(v, str):
                    names.extend(v.split(chr(10)))
            for dn in item.get("dns_names", []) or []:
                if isinstance(dn, str):
                    names.append(dn)
    out = []
    for n in names:
        d = core.canon_domain(n.strip())
        if d and (d == domain or d.endswith("." + domain)):
            out.append(d)
    out = _uniq(out)
    for d in out:
        # collector "certs" is findinfo's own CT lookup; the upstream that
        # actually answered is named explicitly so it groups with the same
        # upstream reached through onepass (one confidence vote, not two).
        # A bare upstream id would be ambiguous with legacy onepass rows.
        store.upsert_asset("domain", d, source="certs:" + upstream,
                           confidence=0.5, passivity="passive", parent=domain)
    return {"domain": domain, "count": len(out), "records": len(data or []),
            "domains": out, "upstream": upstream, "ok": ok}


# ---------------------------------------------------------------- 2.5 third-party FOFA gateway
def fofa_gateway_query(query: str, fields: str = "ip,port,protocol,domain,link,title",
                       size: int = 100, page: int = 1, timeout: int = 0) -> dict | None:
    """Query a self-hosted FOFA relay (POST /api/v1/query + X-Ak header).

    Official FOFA uses GET /api/v1/search/all with email+key, so a mirror has to
    be addressed explicitly. Returns the parsed JSON body, or None when no
    gateway is configured or the call fails.
    """
    base = core.api_base("fofa")
    key = core.api_key("fofa")
    if not base or not key:
        return None
    body = json.dumps({"query": query, "fields": fields, "page": page, "size": size})
    tfile = core.DATA / "_tmp"
    tfile.mkdir(parents=True, exist_ok=True)
    tmp = tfile / ("fofa_" + str(os.getpid()) + "_" + str(abs(hash(query)) % 100000) + ".json")
    try:
        tmp.write_text(body, encoding="utf-8")
    except Exception:
        return None
    rc, out, err = core.curl(
        ["-X", "POST", "-H", "X-Ak: " + key, "-H", "Content-Type: application/json",
         "--data-binary", "@" + str(tmp), base + "/api/v1/query"], timeout=timeout)
    try:
        tmp.unlink()
    except Exception:
        pass
    if rc != 0 or not (out or "").strip():
        core.log("fofa gateway failed rc=" + str(rc) + " " + (err or "")[:160])
        return None
    try:
        data = json.loads(out)
    except Exception:
        core.log("fofa gateway: non-JSON response")
        return None
    if not data.get("ok"):
        msg = str(data.get("error") or data.get("message") or "")[:200]
        # A relay that is out of quota answers with an error too. Losing that
        # distinction made "quota exhausted" look exactly like "no collection
        # happened": both end up as None, and the caller records an empty
        # source instead of a coverage gap. Mark it so the caller can tell the
        # two apart (requirement: never disguise an exhausted quota as
        # "no assets found").
        low = msg.lower()
        exhausted = any(k in low for k in ("quota", "exhaust", "limit", "余额",
                                           "额度", "超出", "不足", "used up"))
        core.log("fofa gateway error" + (" (quota_exhausted)" if exhausted else "") +
                 ": " + msg)
        if exhausted:
            return {"ok": False, "quota_exhausted": True, "error": msg}
        return None
    # A successful body also carries the remaining quota; surface an exhausted
    # one so the caller can stop asking before it burns more errors.
    if data.get("usable") is False or data.get("remaining") == 0:
        core.log("fofa gateway: quota exhausted (remaining=" +
                 str(data.get("remaining")) + ")")
        data = dict(data)
        data["quota_exhausted"] = True
    return data


def fofa_gateway_usage(timeout: int = 0) -> dict | None:
    """Remaining quota for the configured AK (does not consume a query)."""
    base = core.api_base("fofa")
    key = core.api_key("fofa")
    if not base or not key:
        return None
    rc, out, err = core.curl(["-H", "X-Ak: " + key, base + "/api/v1/usage"], timeout=timeout)
    if rc != 0 or not (out or "").strip():
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def _gateway_rows_to_domains(res: dict) -> tuple[list[str], list[str]]:
    """Pull subdomains out of a gateway result set.

    The relay only exposes the *registered* domain in `domain`; the real
    hostname appears in `link` (e.g. https://ehall.example.com:8080/). Parse it
    out and keep only hostnames that are actually subdomains.
    """
    doms: list[str] = []
    ips: list[str] = []
    for r in res.get("results") or []:
        link = r.get("link") or ""
        host = ""
        if link:
            m = re.match(r"https?://([^/:]+)", link)
            if m:
                host = core.canon_domain(m.group(1)) or ""
        if not host:
            host = core.canon_domain(r.get("domain") or "") or ""
        if host:
            doms.append(host)
        ip = core.canon_ip(r.get("ip") or "")
        if ip and ip != "0.0.0.0":
            ips.append(ip)
    return _uniq(doms), _uniq(ips)


# ---------------------------------------------------------------- 3. ICP reverse lookup
def t_icp(store, codes: list[str], engines: str = "fofa,quake,hunter",
          timeout: int = 0) -> dict:
    try:
        exe = core.tool("uncover")
    except core.ToolMissing:
        # A configured FOFA gateway does not need uncover at all; only the
        # official-protocol fallback path does.
        if not core.api_base("fofa"):
            raise
        exe = ""
    domains: list[str] = []
    ips: list[str] = []
    rows = 0
    errors: list[dict] = []
    for code in codes:
        code = code.strip()
        if not code:
            continue
        store.upsert_asset("icp", code, source="icp-seed", confidence=0.9,
                           passivity="passive")
        # A self-hosted FOFA relay covers ICP reverse lookup without uncover.
        if core.api_base("fofa"):
            res = fofa_gateway_query('icp="' + code + '"', size=10000, timeout=timeout)
            if res:
                gd, gip = _gateway_rows_to_domains(res)
                for d in gd:
                    domains.append(d)
                    store.upsert_asset("domain", d, source="icp-gateway", confidence=0.9,
                                       passivity="passive", parent=code)
                for ip in gip:
                    ips.append(ip)
                    store.upsert_asset("ip", ip, source="icp-gateway", confidence=0.5,
                                       passivity="passive", parent=code)
                rows += res.get("count") or 0
                core.log("icp gateway " + code + ": total=" + str(res.get("total")) +
                         " hosts=" + str(len(gd)))
                continue
        if not exe:
            core.log("icp " + code + ": no uncover binary and gateway returned no rows")
            errors.append({"code": code, "rc": -1, "stderr": "no uncover, gateway empty"})
            continue
        usable, missing = core.split_engines(engines)
        if not usable:
            # No engine has a key: running uncover would only produce rc!=0 and
            # turn a coverage gap into a stage failure. Record it as unavailable.
            core.log("icp " + code + ": no api key for engines: " +
                     ",".join(missing))
            errors.append({"code": code, "rc": None, "unavailable": True,
                           "stderr": "no api key for engines: " +
                                     ",".join(missing)})
            continue
        q = 'icp="' + code + '"'
        core.throttle("fofa")
        core.mapping_wait()
        rc, out, err = core.run([exe, "-q", q, "-e", ",".join(usable), "-json",
                                 "-silent"], timeout=timeout)
        if rc != 0 or not (out or "").strip():
            # uncover swallows upstream API errors (bad key -> empty stdout with
            # rc=0), so a silent zero is indistinguishable from "no results".
            # Surface it instead of returning a clean-looking empty list.
            core.log("icp " + code + ": uncover rc=" + str(rc) + " empty "
                     + ("; " + err.strip()[:200] if err.strip() else ""))
            errors.append({"code": code, "rc": rc, "stderr": err.strip()[:300]})
        for r in core.parse_jsonl(out):
            rows += 1
            host = r.get("host") or ""
            d = core.canon_domain(host)
            if d:
                domains.append(d)
                store.upsert_asset("domain", d, source="icp:" + code.split("备")[-1][:12],
                                   confidence=0.9, passivity="passive", parent=code)
            ip = core.canon_ip(r.get("ip") or "")
            if ip:
                ips.append(ip)
                store.upsert_asset("ip", ip, source="icp:" + code.split("备")[-1][:12],
                                   confidence=0.5, passivity="passive", parent=code)
    domains, ips = _uniq(domains), _uniq(ips)
    return {"codes": codes, "rows": rows, "domains": domains, "ips": ips,
            "errors": errors}


# ---------------------------------------------------------------- 4. passive subdomains
def t_subs(store, domain: str, engines: str = "fofa,quake,hunter,shodan,censys",
           timeout: int = 0) -> dict:
    raw = domain
    domain = core.canon_domain(domain)
    if not domain:
        raise core.FindInfoError("invalid domain: " + str(raw))
    found: dict[str, set] = {}

    def add(d: str, src: str) -> None:
        cd = core.canon_domain(d)
        if not cd:
            return
        if not (cd == domain or cd.endswith("." + domain)):
            return
        found.setdefault(cd, set()).add(src)

    # Third-party FOFA relay first: it returns real hostnames from the `link`
    # field, which official-protocol endpoints and uncover would miss.
    quota_exhausted = False
    if core.api_base("fofa"):
        core.log("fofa gateway " + domain)
        res = fofa_gateway_query('domain="' + domain + '"', size=10000, timeout=timeout)
        if res and res.get("quota_exhausted"):
            # Reported, not silent: the source produced nothing because its
            # budget ran out, which is a coverage gap, not "no assets exist".
            quota_exhausted = True
            core.log("fofa gateway: skipped for " + domain +
                     " — quota exhausted, recorded as a coverage gap")
        elif res:
            gd, gip = _gateway_rows_to_domains(res)
            for d in gd:
                add(d, "fofa-gateway")
            for ip in gip:
                store.upsert_asset("ip", ip, source="fofa-gateway", confidence=0.6,
                                   passivity="passive", parent=domain)
            core.log("fofa gateway: total=" + str(res.get("total")) +
                     " rows=" + str(res.get("count")) +
                     " hosts=" + str(len(gd)) +
                     " remaining=" + str(res.get("remaining")))
            quota_exhausted = bool(res.get("quota_exhausted"))

    # Every source records its own outcome. A dead source used to be invisible:
    # the function returned count=0 and the stage checkpointed "done", so
    # "subfinder crashed" and "this domain has no subdomains" were the same
    # string to the agent. Each entry below is (id, outcome, found, error).
    per_source: list[dict] = []

    def run_source(sid: str, cmd: list[str], *, key: str, tool: str) -> None:
        core.log(tool + " " + domain)
        rc, out, err = core.run(cmd, timeout=timeout)
        before = len(found)
        for r in core.parse_jsonl(out):
            add(r.get(key, "") or r.get("host", ""), sid)
        n = sum(1 for srcs in found.values() if sid in srcs)
        outcome = core.outcome_from_rc(rc, n)
        per_source.append({"id": sid, "outcome": outcome, "found": n,
                           "rc": rc,
                           "error": ("timeout" if rc == 124 else
                                     (err or "")[-200:].strip() if rc not in (0, None) else "")})
        if outcome in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT):
            core.log(sid + ": " + outcome + " rc=" + str(rc))

    if core.has_tool("subfinder"):
        run_source("subfinder",
                   [core.tool("subfinder"), "-d", domain, "-all",
                    "-recursive", "-silent", "-json"], key="host", tool="subfinder")
    else:
        per_source.append({"id": "subfinder", "outcome": core.OUTCOME_UNAVAILABLE,
                           "found": 0, "rc": None, "error": "binary not found"})

    if core.has_tool("chaos") and core.api_key("chaos"):
        run_source("chaos",
                   [core.tool("chaos"), "-d", domain, "-silent", "-json",
                    "-key", core.api_key("chaos")], key="domain", tool="chaos")

    # Only hand uncover the engines we actually have credentials for: an engine
    # with no key can only fail, and one dead engine out of five used to turn a
    # successful stage into "every source failed" -> partial run -> an agent
    # that resumes forever against a problem retrying can never fix.
    usable_engines, missing_engines = core.split_engines(engines)
    if core.has_tool("uncover") and usable_engines:
        core.throttle("fofa")
        core.mapping_wait()
        run_source("uncover",
                   [core.tool("uncover"), "-q", 'domain:"' + domain + '"',
                    "-e", ",".join(usable_engines), "-json", "-silent"],
                   key="host", tool="uncover")
    elif not core.has_tool("uncover"):
        per_source.append({"id": "uncover", "outcome": core.OUTCOME_UNAVAILABLE,
                           "found": 0, "rc": None, "error": "binary not found"})
    else:
        per_source.append({"id": "uncover", "outcome": core.OUTCOME_UNAVAILABLE,
                           "found": 0, "rc": None,
                           "error": "no api key for engines: " +
                                    ",".join(missing_engines)})

    rows = []
    for d, srcs in found.items():
        conf = 0.5 if len(srcs) == 1 else (0.75 if len(srcs) == 2 else 0.95)
        store.upsert_asset("domain", d, source=",".join(sorted(srcs)),
                           confidence=conf, passivity="passive", parent=domain)
        rows.append({"domain": d, "sources": sorted(srcs), "confidence": conf})
    rows.sort(key=lambda x: x["domain"])

    outcomes = [p["outcome"] for p in per_source]
    if quota_exhausted:
        outcomes.append(core.OUTCOME_BUDGET)
    tried = [p for p in per_source if p["outcome"] != core.OUTCOME_UNAVAILABLE]
    if tried and all(p["outcome"] in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT)
                     for p in tried):
        # A stage where every source hit its deadline is a timeout, not a
        # failure: the caller has to raise the timeout, not debug the tools.
        if all(p["outcome"] == core.OUTCOME_TIMEOUT for p in tried):
            outcome = core.OUTCOME_TIMEOUT
        else:
            outcome = core.OUTCOME_FAILED
    else:
        outcome = core.combine_outcome(*(outcomes or [core.OUTCOME_OK]))
        if outcome == core.OUTCOME_OK and not rows:
            outcome = core.OUTCOME_EMPTY
    out = {"domain": domain, "count": len(rows), "domains": rows,
           "outcome": outcome, "per_source": per_source,
           "ok": outcome in (core.OUTCOME_OK, core.OUTCOME_EMPTY,
                             core.OUTCOME_PARTIAL, core.OUTCOME_BUDGET),
           "hint": core.outcome_hint(outcome)}
    if quota_exhausted:
        # Never let "the budget ran out" read as "this source found nothing".
        out["quota_exhausted"] = True
        out["sources_unavailable"] = ["fofa-gateway:quota_exhausted"]
    return out


# ---------------------------------------------------------------- 5. DNS resolve + wildcard
def t_dns(store, domains: list[str], timeout: int = 0) -> dict:
    """Resolve domains with wildcard filtering.

    The wildcard filter is keyed on the REGISTRABLE parent (public-suffix
    aware), not "last two labels" -- customer.co.uk must not collapse to
    co.uk. Both resolvers (dnsx + system fallback) apply the SAME filter: the
    fallback used to accept every name a wildcard zone answered, which turned
    random subdomains into "trusted assets".
    `ok=False` means dnsx itself failed (rc!=0); partial results may still be
    present and the caller must not checkpoint the stage as done.
    """
    domains = _uniq([core.canon_domain(d) for d in domains if core.canon_domain(d)])
    if not domains:
        return {"count": 0, "domains": [], "wildcard": [], "ok": True, "rc": 0}
    # wildcard probe per registrable parent domain
    wildcard: dict[str, str] = {}
    parents = sorted({core.registrable_domain(d) for d in domains
                      if core.registrable_domain(d)})
    if core.has_tool("dnsx"):
        for p in parents[:20]:
            probe = "findinfo-wildcard-probe-9f3a." + p
            rc, out, err = core.run([core.tool("dnsx"), "-d", probe, "-a", "-resp",
                                     "-silent", "-json"], timeout=timeout)
            for r in core.parse_jsonl(out):
                for a in r.get("a", []) or []:
                    wildcard[p] = a
    exe = core.tool("dnsx")
    path = _tmp_lines(domains)
    core.log("dnsx resolving " + str(len(domains)) +
             " (wildcard parents: " + str(len(wildcard)) + ")")
    rows: list[dict] = []
    seen_dns: set[str] = set()
    pending: list[tuple[str, list, list]] = []   # parsed off-thread, stored here
    total = 0

    def accept(d: str, ips: list[str], cnames: list[str], source: str) -> None:
        """Store + count a resolved domain, unless it is a wildcard answer.

        Shared by dnsx output and the system-resolver fallback so both paths
        apply identical filtering rules.
        """
        nonlocal total
        wc = wildcard.get(core.registrable_domain(d) or "")
        if wc and wc in ips:
            return            # wildcard zone: random names resolve here too
        total += 1
        for ip in ips:
            store.upsert_asset("ip", ip, source=source, confidence=0.6,
                               passivity="passive", parent=d)
        store.upsert_asset("domain", d, source=source, confidence=0.8,
                           passivity="passive")
        if len(rows) < core.ROW_LIMIT:      # display cap only; store gets all
            rows.append({"domain": d, "a": ips, "cname": cnames})

    def handle(line: str) -> None:
        # run_stream hands lines to a READER THREAD. SQLite objects may only be
        # used from the thread that created them, and the store belongs to the
        # caller's thread, so a write here raised
        # "SQLite objects created in a thread can only be used in that same
        # thread" for EVERY resolved host: dns silently stored nothing while
        # reporting success (observed on 7373 hosts). Only parse here; the
        # caller's thread does the writes after the stream closes.
        try:
            r = json.loads(line)
        except Exception:
            return
        d = core.canon_domain(r.get("host", ""))
        if not d:
            return
        seen_dns.add(d)
        ips = [x for x in (core.canon_ip(x) for x in (r.get("a") or [])) if x]
        cnames = [x for x in (core.canon_domain(x) for x in (r.get("cname") or [])) if x]
        pending.append((d, ips, cnames))

    rc, lines, err = core.run_stream(
        [exe, "-l", path, "-a", "-cname", "-resp", "-silent", "-json",
         "-t", str(core.CFG["limits"]["dns_concurrency"])],
        handle, timeout=timeout)
    for d, ips, cnames in pending:
        accept(d, ips, cnames, "dnsx")
    # ---- system resolver fallback -------------------------------------
    # dnsx uses public resolvers (8.8.8.8 etc). In CN networks those are often
    # blocked or poisoned; fall back to the OS resolver for anything unresolved.
    missing = [d for d in domains if d not in seen_dns]
    sys_rows: list[dict] = []
    if missing:
        core.log("system-dns fallback for " + str(len(missing)) + " domains")

        def resolve_one(d: str):
            try:
                infos = socket.getaddrinfo(d, None)
                return d, sorted({core.canon_ip(i[4][0]) for i in infos} -
                                 {None})
            except Exception:
                return d, []

        with futures.ThreadPoolExecutor(max_workers=50) as pool:
            for d, ips in pool.map(resolve_one, missing):
                # 198.18.0.0/15 = Clash/TUN fake-IP benchmark range
                ips = [x for x in ips if x and not x.startswith("198.18.")]
                if not ips:
                    continue
                sys_rows.append((d, ips))
        for d, ips in sys_rows:
            accept(d, ips, [], "system-dns")
    ok = rc == 0
    return {"count": total, "domains": rows, "truncated": total > len(rows),
            "wildcard": [{"parent": k, "ip": v} for k, v in wildcard.items()],
            "system_fallback": len(sys_rows), "lines": lines, "rc": rc, "ok": ok}


# ---------------------------------------------------------------- 6. httpx probe
def t_httpx(store, hosts: list[str], timeout: int = 0) -> dict:
    hosts = _uniq([h for h in hosts if h])
    if not hosts:
        return {"count": 0, "rows": []}
    path = _tmp_lines(hosts)
    lim = core.CFG["limits"]
    cmd = [core.tool("httpx"), "-l", path, "-silent", "-json",
           "-sc", "-title", "-tech-detect", "-ip", "-cname", "-cdn", "-favicon",
           "-threads", str(lim["http_concurrency"]),
           "-timeout", "10", "-retries", "1"]
    core.log("httpx probing " + str(len(hosts)))
    rows: list[dict] = []          # only ROW_LIMIT of them: the rest live in the store
    staged: list = []              # store writes happen on the caller's thread
    total = 0

    def handle(line: str) -> None:
        nonlocal total
        try:
            r = json.loads(line)
        except Exception:
            return
        host = core.canon_domain(r.get("input", "") or r.get("host", ""))
        url = r.get("url", "")
        ip = core.canon_ip(r.get("host_ip", "")) or core.canon_ip(r.get("ip", ""))
        if not ip:
            for _a in (r.get("a") or []):
                ip = core.canon_ip(_a)
                if ip:
                    break
        if not host:
            h2, _p2, _params2 = core.split_url(url)
            host = h2
        if not host:
            return
        total += 1
        title = (r.get("title") or "")[:200]
        status = r.get("status_code")
        tech = r.get("tech") or []
        rec = {"host": host, "url": url, "status": status, "title": title,
               "tech": tech, "ip": ip, "cname": r.get("cname") or [],
               "port": r.get("port"), "length": r.get("content_length"),
               "cdn": r.get("cdn_name") or r.get("cdn"),
               "favicon": r.get("favicon"), "webserver": r.get("webserver")}
        if len(rows) < core.ROW_LIMIT:
            rows.append(rec)
        attrs = {"status": status, "title": title, "tech": tech, "url": url,
                 "ip": ip, "port": r.get("port"), "cdn": rec["cdn"],
                 "webserver": rec["webserver"]}
        # store writes are deferred to the caller's thread (SQLite is
        # thread-bound; run_stream calls this from its reader thread)
        staged.append((host, ip, url, attrs, status, title))

    staged: list = []

    def live(item) -> None:
        host, ip, url, attrs, status, title = item
        if ip:
            store.upsert_asset("ip", ip, source="httpx", confidence=0.7,
                               passivity="active", parent=host)
        store.upsert_asset("domain", host, source="httpx", confidence=0.9,
                           passivity="active", attrs=attrs)
        h2, p2, params2 = core.split_url(url)
        if h2 and p2:
            store.upsert_endpoint(h2, "GET", core.path_template(p2), params2,
                                  source="httpx", status=status if isinstance(status, int) else None,
                                  title=title)

    rc, lines, err = core.run_stream(cmd, handle, timeout=timeout)
    for item in staged:
        live(item)
    core.log("httpx: " + str(total) + " live hosts (" + str(lines) + " lines) rc=" + str(rc))
    return {"count": total, "rows": rows, "truncated": total > len(rows),
            "lines": lines, "rc": rc, "ok": rc == 0, "stderr": err[-400:]}


# ---------------------------------------------------------------- 7. IP aggregate + CDN
def t_ipagg(store, ips: list[str] | None = None, timeout: int = 0,
            scope: list[str] | None = None) -> dict:
    """Group domains by shared IP, dropping CDN fronts.

    `scope` restricts every read of the shared graph: candidate IPs come only
    from domains under the scope, and shared-ip groups are built only from
    in-scope hosts. Without it a second engagement's domains would drag that
    target's IPs into ports/vhost.
    """
    scope = core.canon_scope(scope or [])
    if not ips:
        if scope:
            ips = [a["canonical"] for a in store.get_assets(kind="ip", match=scope)]
        else:
            ips = [a["canonical"] for a in store.get_assets(kind="ip")]
    ips = _uniq([core.canon_ip(i) for i in ips if core.canon_ip(i)])
    if not ips and scope:
        # No IP rows directly under this scope, but asset_links may know about
        # IPs observed through another domain. Returning early here skipped the
        # very fallback added for that case.
        ips = _uniq(core.canon_ip(i) for i in store.assets_linked_to("ip", scope)
                    if core.canon_ip(i))
    if not ips:
        return {"ips": [], "candidates": [], "count_candidates": 0, "scope": scope}
    cdn_ips: dict[str, Any] = {}
    if core.has_tool("cdncheck"):
        path = _tmp_lines(ips)
        rc, out, err = core.run([core.tool("cdncheck"), "-i", path, "-json", "-silent"],
                                timeout=timeout)
        for r in core.parse_jsonl(out):
            ip = core.canon_ip(r.get("input", "") or r.get("ip", ""))
            if ip and (r.get("cdn") or r.get("waf")):
                cdn_ips[ip] = r.get("cdn_name") or r.get("waf_name") or "cdn"
    groups: dict[str, list[str]] = {}
    for a in store.get_assets(kind="domain", match=scope or None):
        d = a["canonical"]
        ip = (a.get("attrs") or {}).get("ip")
        if ip:
            groups.setdefault(ip, []).append(d)
    # Second source of truth: asset_links. attrs.ip is only written by httpx/dns,
    # so an IP observed through another path (or before this version) could be
    # invisible to a scoped aggregation even though the association exists.
    # Union, do not replace: attrs stays the fast path, links close the gap.
    if scope:
        for ip in store.assets_linked_to("ip", scope):
            for d in store.linked_owners("ip", ip):
                if core.in_scope(d, scope) and d not in groups.get(ip, []):
                    groups.setdefault(ip, []).append(d)
    candidates = []
    for ip, doms in groups.items():
        if ip in cdn_ips:
            continue
        if len(doms) >= 2:
            candidates.append({"ip": ip, "domains": sorted(set(doms)), "reason": "shared-ip"})
    return {"ips": ips, "cdn": cdn_ips, "candidates": candidates,
            "count_candidates": len(candidates), "scope": scope}


# ---------------------------------------------------------------- 8. port scan
def t_ports(store, ips: list[str], top_ports: int = 1000, timeout: int = 0) -> dict:
    targets = _uniq([core.canon_ip(i) for i in ips if core.canon_ip(i)])
    if not targets:
        raise core.FindInfoError("no valid ip for naabu")
    path = _tmp_lines(targets)
    rows: list[dict] = []
    staged: list = []              # store writes happen on the caller's thread
    total = 0

    def handle(line: str) -> None:
        nonlocal total
        try:
            r = json.loads(line)
        except Exception:
            return
        ip = core.canon_ip(r.get("ip") or r.get("host") or "")
        port = r.get("port")
        if not ip or not port:
            return
        total += 1
        if len(rows) < core.ROW_LIMIT:
            rows.append({"ip": ip, "port": int(port)})
        staged.append((ip, int(port)))   # stored on the caller's thread

    rc, lines, err = core.run_stream(
        [core.tool("naabu"), "-l", path, "-top-ports", str(top_ports),
         "-silent", "-json", "-rate", "1000"], handle, timeout=timeout)
    for ip, port in staged:
        store.upsert_asset("endpoint", ip + ":" + str(port), source="naabu",
                           confidence=0.8, passivity="active", parent=ip,
                           attrs={"port": port})
    return {"targets": targets, "count": total, "rows": rows,
            "truncated": total > len(rows), "lines": lines, "rc": rc, "ok": rc == 0}


# ---------------------------------------------------------------- 9. vhost collision
def _curl_probe(ip: str, port: int, scheme: str, host: str, timeout: int = 10) -> dict | None:
    """One HTTP probe straight at ip:port with a chosen Host header.

    hostCollision bails out on hosts that answer 3xx (its no-redirect client
    treats that as an error), which silently drops every login-gateway vhost.
    This curl path keeps 3xx and exposes status/length/title/location so the
    caller can run its own differential.
    """
    hostpart = host if host else ip
    url = scheme + "://" + ip + ":" + str(port) + "/"
    args = ["-k", "-sS", "--max-time", str(timeout), "-o", "-",
            "-w", chr(10) + "__META__%{http_code}|%{size_download}|%{redirect_url}",
            "--resolve", hostpart + ":" + str(port) + ":" + ip, url]
    if host:
        args += ["-H", "Host: " + host]
    out = core.curl(args, timeout=timeout + 8)[1]
    if "__META__" not in (out or ""):
        return None
    body, _, meta = out.rpartition("__META__")
    parts = meta.strip().split("|")
    try:
        status = int(parts[0])
    except Exception:
        return None
    if status == 0:
        return None
    try:
        length = int(parts[1])
    except Exception:
        length = len(body)
    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return {"status": status, "len": length,
            "title": (tm.group(1).strip()[:120] if tm else ""),
            "location": parts[2] if len(parts) > 2 else "",
            "via": "curl"}


def _curl_vhost_collide(ip: str, hosts: list[str], ports: list[int],
                        timeout: int = 10) -> list[dict]:
    """3-probe differential, mirroring hostCollision's logic but 3xx-safe.

    baseline A: no Host header
    baseline B: random label under the candidate's parent (catch-all check)
    candidate: the real name
    A hit needs B to look like A while the candidate differs in status, length,
    title or redirect target.
    """
    hits: list[dict] = []
    tls_ports = (443, 8443, 9443, 10443, 9083, 9028)
    for port in ports:
        scheme = "https" if port in tls_ports else "http"
        base_a = _curl_probe(ip, port, scheme, "", timeout)
        if not base_a:
            continue

        def same(a: dict, b: dict) -> bool:
            return (a["status"] == b["status"]
                    and abs(a["len"] - b["len"]) <= 32
                    and (a.get("title") or "") == (b.get("title") or ""))

        for host in hosts:
            parent = ".".join(host.split(".")[1:]) or host
            probe_b = _curl_probe(ip, port, scheme, "zzq7x9k2w1." + parent, timeout)
            if not probe_b:
                continue
            if not same(base_a, probe_b):
                continue          # unstable baseline / catch-all: skip, avoid FP
            cand = _curl_probe(ip, port, scheme, host, timeout)
            if not cand:
                continue
            if same(base_a, cand):
                continue          # identical to the invisible baseline
            hits.append({"ip": ip, "port": port, "scheme": scheme, "host": host,
                         "status": cand["status"], "len": cand["len"],
                         "title": cand["title"],
                         "location": cand.get("location", ""),
                         "baseline_status": base_a["status"],
                         "baseline_len": base_a["len"],
                         "via": "curl-diff"})
    return hits


def _live_domains(store, hosts: list[str]) -> set[str]:
    """Hosts already verified live by probe — no point colliding them again."""
    live: set[str] = set()
    want = set(hosts)
    for a in store.get_assets(kind="domain", min_conf=0.0):
        d = a["canonical"]
        if d not in want:
            continue
        st = (a.get("attrs") or {}).get("status")
        if isinstance(st, int) and 200 <= st < 500:
            live.add(d)
    return live


def t_vhost(store, ip: str, hosts: list[str], ports: list[int] | None = None,
            threads: int = 20, timeout: int = 0, rate: int = 100,
            skip_live: bool = True) -> dict:
    """Host collision via bundled hostCollision (3-probe differential).

    hostCollision probes: no-Host baseline, then a random-label Host, then the
    real candidate. A hit requires those two invisible probes to agree while
    the candidate differs, which kills most catch-all false positives that a
    single-baseline comparison would report. Bodies over 2000 chars are judged
    by edit-distance similarity instead of raw length.
    """
    ip = core.canon_ip(ip) or ip
    # The hosts a caller passes are deliberate input (candidates they named or
    # derived from scope): canon_user_domain validates them without the
    # public-suffix de-noiser. Rejections are reported, never dropped --
    # passing dev.corp.local used to yield tested:0 with ok:true.
    rejected = [h for h in hosts if not core.canon_user_domain(h)]
    hosts = _uniq([core.canon_user_domain(h) for h in hosts
                   if core.canon_user_domain(h)])
    ports = ports or [80, 443]
    live = _live_domains(store, hosts) if skip_live else set()
    todo = [h for h in hosts if h not in live]
    if not todo:
        return {"ip": ip, "tested": 0, "hits": 0, "results": [],
                "skipped_live": len(live), "tool": "hostCollision",
                **({"rejected_inputs": rejected} if rejected else {})}

    urls = [("https" if p in (443, 8443, 9443) else "http") + "://" + ip + ":" + str(p)
            for p in ports]
    url_path = _tmp_lines(urls)
    host_path = _tmp_lines(todo)
    outdir = core.DATA / "_tmp"
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / ("hc_" + str(os.getpid()) + "_" + str(abs(hash(ip)) % 100000) + ".txt")
    try:
        if outfile.exists():
            outfile.unlink()
    except Exception:
        pass

    exe = core.tool("hostCollision")
    cmd = [exe, "-uf", url_path, "-df", host_path, "-o", str(outfile),
           "-t", str(threads), "-r", str(rate), "-silent"]
    core.log("hostCollision " + ip + " hosts=" + str(len(todo)) + " ports=" + str(len(ports))
             + " skipped_live=" + str(len(live)))
    hc_rc, _hc_out, _hc_err = core.run(cmd, timeout=timeout)

    lines: list[str] = []
    try:
        if outfile.exists():
            lines = outfile.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        lines = []
    result_re = re.compile(r"url:(\S+)\s+host:(\S+)\s+title:\[(.*?)\]\s+Length:\s*(\d+)")
    hits: list[dict] = []
    for ln in lines:
        m = result_re.search(ln)
        if not m:
            continue
        url, host, title, length = m.groups()
        scheme = "https" if url.startswith("https") else "http"
        port = 443 if scheme == "https" else 80
        tail = url.rsplit(":", 1)
        if len(tail) == 2 and tail[1].isdigit():
            port = int(tail[1])
        hits.append({"ip": ip, "port": port, "scheme": scheme, "host": host,
                     "status": None, "len": int(length), "title": title,
                     "server": "", "via": "hostCollision"})
    for h in hits:
        store.upsert_asset("domain", h["host"], source="vhost", confidence=0.5,
                           passivity="active", parent=ip,
                           attrs={"ip": ip, "port": h["port"], "len": h["len"],
                                  "title": h["title"], "via": "hostCollision"})
    try:
        if outfile.exists():
            outfile.unlink()
    except Exception:
        pass

    # hostCollision drops any candidate that answers 3xx (its no-redirect client
    # reports those as errors), which blanks out login-gateway vhosts. When it
    # finds nothing, run the curl differential instead and keep whichever hits.
    tool_used = "hostCollision"
    if not hits and todo:
        core.log("hostCollision returned 0; falling back to curl differential")
        alt = _curl_vhost_collide(ip, todo, ports)
        if alt:
            hits = alt
            tool_used = "curl-diff"
            for h in hits:
                store.upsert_asset("domain", h["host"], source="vhost", confidence=0.5,
                                   passivity="active", parent=ip,
                                   attrs={"ip": ip, "port": h["port"],
                                          "status": h["status"], "len": h["len"],
                                          "title": h["title"], "via": "curl-diff"})
    return {"ip": ip, "tested": len(todo), "hits": len(hits),
            "results": hits[:500], "skipped_live": len(live),
            "tool": tool_used, "rc": hc_rc, "ok": hc_rc == 0 or bool(hits),
            **({"rejected_inputs": rejected} if rejected else {})}


# ---------------------------------------------------------------- 10. crawl + extract
def t_crawl(store, urls: list[str], depth: int = 3, timeout: int = 0,
            scope_domains: list[str] | None = None) -> dict:
    """Crawl with a two-layer domain allow-list.

    Layer 1 (request scope): katana gets `-fs rdn:<seed>` per input so the
    crawler itself never leaves the seed's registrable domain -- out-of-scope
    requests are not made, not merely filtered afterwards.
    Layer 2 (output scope): every emitted URL must sit under the allow-list
    before it enters the store, so even a scope-ignoring katana build cannot
    poison the asset graph.
    The allow-list is derived with the public-suffix table (registrable_domain),
    never "last two labels": customer.co.uk must not widen to co.uk.
    """
    targets = _uniq([u for u in urls if u])
    if not targets:
        raise core.FindInfoError("no url for katana")
    allow = core.canon_scope(scope_domains or [])
    if not allow:
        # derive from the crawl seeds themselves so the filter is never empty
        for u in targets:
            reg = core.registrable_domain(core.split_url(u)[0] or "")
            if reg and reg not in allow:
                allow.append(reg)

    def in_scope(url: str) -> bool:
        h = core.canon_domain(core.split_url(url)[0] or "")
        if not h:
            return False
        return core.in_scope(h, allow)

    path = _tmp_lines(targets)
    rows: list[dict] = []
    staged: list = []              # store writes happen on the caller's thread
    total = 0
    dropped = 0

    def add(url: str, method: str) -> None:
        # Called from run_stream's READER THREAD, so only classify here and let
        # the caller's thread do the SQLite writes (see live() below). Writing
        # the store here raised "SQLite objects created in a thread can only be
        # used in that same thread" for every crawled URL: katana reported
        # kept=70 while the store received nothing.
        nonlocal total, dropped
        if not in_scope(url):
            dropped += 1
            return
        h, p, params = core.split_url(url)
        if not h:
            return
        total += 1
        staged.append((url, h, p, params, method))
        if len(rows) < core.ROW_LIMIT:      # display cap only; store gets all
            rows.append({"url": url, "host": h, "path": p, "params": params})

    def live(item) -> None:
        url, h, p, params, method = item
        store.upsert_endpoint(h, method, core.path_template(p), params,
                              source="katana")
        store.upsert_asset("url", url, source="katana", confidence=0.7,
                           passivity="active", parent=h)

    def handle(line: str) -> None:
        try:
            r = json.loads(line)
        except Exception:
            # older katana builds emit plain URL lines
            if line.startswith("http"):
                add(line, "GET")
            return
        req = r.get("request") or {}
        url = req.get("endpoint") or req.get("url") or r.get("url")
        if not url:
            return
        method = (req.get("method") or r.get("method") or "GET").upper()
        add(url, method)

    # Request-level scope. A regex with one alternative per allowed domain blows
    # past the Windows command-line limit once a real engagement has thousands of
    # hosts (observed: 7163 domains -> WinError 206, the whole crawl stage died).
    # Over the budget, fall back to filtering by REGISTRABLE domain -- katana
    # takes a handful of -fs rdn: flags instead of one huge expression -- and let
    # the output-side in_scope() check below do the exact filtering.
    # Preserve the caller's order (named seeds first) when collapsing hosts to
    # registrable domains: sorting alphabetically once put unrelated anchors
    # ahead of the actual target and the crawl budget went to the wrong sites.
    rdn: list = []
    for a in allow:
        r = core.registrable_domain(a) or a
        if r not in rdn:
            rdn.append(r)
    fs_regex = "(^|\\.)(" + "|".join(re.escape(a) for a in allow) + ")$"
    cmd = [core.tool("katana"), "-list", path, "-jc", "-kf", "all",
           "-d", str(depth), "-silent", "-j", "-or", "-ob"]
    if len(fs_regex) <= 6000:
        cmd += ["-fs", fs_regex]
        core.log("katana scope: exact regex (" + str(len(allow)) + " domains)")
    else:
        # A very large allow-list cannot go into one regex (Windows caps the
        # command line) and -fs takes a REGEX, not "rdn:" prefixes -- passing
        # "-fs rdn:host" makes katana drop every result (verified: zero output
        # for a host that streams URLs without it). So an oversized scope is
        # filtered by a regex over the registrable domains instead, batched so
        # each -fs stays short. The output-side in_scope() check remains the
        # exact authority either way.
        batches, cur, cur_len = [], [], 0
        for r in rdn:
            alt = re.escape(r)
            if cur and cur_len + len(alt) + 1 > 3000:
                batches.append(cur)
                cur, cur_len = [], 0
            cur.append(alt)
            cur_len += len(alt) + 1
        if cur:
            batches.append(cur)
        for alts in batches:
            cmd += ["-fs", "(^|\\.)(" + "|".join(alts) + ")$"]
        core.log("katana scope: " + str(len(allow)) + " domains -> " +
                 str(len(rdn)) + " registrable domains in " + str(len(batches)) +
                 " -fs regex(es); output filter is exact")
    rc, lines, err = core.run_stream(cmd, handle, timeout=timeout)
    for item in staged:
        live(item)
    core.log("katana: kept=" + str(total) + " dropped_out_of_scope=" + str(dropped) +
             " allow=" + ",".join(allow[:6]) + " rc=" + str(rc))
    return {"count": total, "rows": rows, "truncated": total > len(rows),
            "lines": lines, "rc": rc, "ok": rc == 0, "dropped_out_of_scope": dropped,
            "scope": allow}


def extract_from_text(text: str, root_domains: list[str]) -> dict:
    domains, ips = [], []
    for m in DOMAIN_RE.finditer(text or ""):
        d = core.canon_domain(m.group(1))
        if d and _looks_public(d):
            domains.append(d)
    for m in IPV4_RE.finditer(text or ""):
        ip = core.canon_ip(m.group(0))
        if ip:
            ips.append(ip)
    return {"domains": _uniq(domains), "ips": _uniq(ips)}



def t_extract(store, crawl_rows: list[dict], urls: list[str] | None = None,
              timeout: int = 0, fetch_limit: int = 40) -> dict:
    """Extract leaked domains/IPs/paths/secrets from crawl output and fetched JS.

    Inputs are complete work sets, not display samples: `urls` should come
    from a scoped store query (see run's extract stage), and crawl_rows from
    the crawler's full output. fetch_limit caps how many bundles are fetched
    (a work budget, reported as such), never how many are discovered.
    """
    from . import jsleak

    # Scan a bounded slice of the crawl output: json.dumps() of 100k rows would
    # allocate hundreds of MB just to run a regex over it. Budget by bytes, not
    # rows, so a few very long URLs cannot blow past it either.
    SCAN_BUDGET = 4 << 20
    parts: list[str] = []
    used = 0
    for r in crawl_rows:
        piece = json.dumps(r, ensure_ascii=False)
        if used + len(piece) > SCAN_BUDGET:
            break
        parts.append(piece)
        used += len(piece)
    text = chr(10).join(parts)
    got = extract_from_text(text, [])
    hit = jsleak.extract(text, [])
    got["domains"].extend(hit["domains"])
    got["ips"].extend(hit["ips"])

    # fetch JS bundles and API-ish pages, extract paths / hosts / secrets
    candidates = []
    for u in _uniq(urls or []):
        if re.search(r"(\.js|\.json|\.map)(\?|$)", u or "", re.I):
            candidates.append(u)
    discovered_js = len(candidates)
    # Persist the candidate set as a work queue BEFORE truncating to the budget.
    # The old code took candidates[:fetch_limit] from a freshly rebuilt list on
    # every round, so items 41..N were never reached: the run looked converged
    # because "nothing new" while 1+ bundles had simply never been attempted.
    store.js_enqueue(candidates)
    before = store.js_stats()
    # Claim only from THIS work set: the queue is shared, and fetching another
    # target's bundles would widen the active scope.
    candidates = store.js_claim(fetch_limit, allow_urls=candidates)
    api_paths: list[str] = []                 # host unknown (extracted from crawl text)
    api_hits: list[tuple[str, str, str]] = []  # (host, path, method) from a bundle
    secrets: dict = {}

    def fetch_and_scan(u: str) -> dict | None:
        rc, body, err = core.curl([u], timeout=timeout)
        if rc != 0 or not body:
            return None
        hit = jsleak.extract(body, [])
        hit["_url"] = u
        return hit

    # parallel fetch: network dominates the cost (~95%), so concurrency is the
    # single biggest win. workers are bounded to stay polite.
    if candidates:
        with futures.ThreadPoolExecutor(max_workers=min(10, len(candidates))) as pool:
            results = list(pool.map(fetch_and_scan, candidates))
        for u, h in zip(candidates, results):
            store.js_finish(u, ok=h is not None,
                            error="" if h is not None else "fetch failed or empty body")
            if not h:
                continue
            # NOTE: this block used to sit INSIDE the "if not h" branch, after a
            # continue -- unreachable. Every fetched bundle was discarded, so
            # extract() only ever saw crawl-text, never the JS it downloaded.
            got["domains"].extend(h["domains"])
            got["ips"].extend(h["ips"])
            api_paths.extend(h["api_paths"])
            host = core.split_url(h.get("_url") or "")[0]
            if host:
                meta = h.get("path_meta") or {}
                for p in h["api_paths"]:
                    # keep the verb the AST reported (POST/PUT/DELETE matter far
                    # more than GET when triaging); regex-only runs stay GET
                    verb = ((meta.get(p) or {}).get("method") or "GET").upper()
                    api_hits.append((host, p, verb if verb in
                                     ("GET", "POST", "PUT", "DELETE", "PATCH") else "GET"))
            for k, v in h["secrets"].items():
                secrets.setdefault(k, []).extend(v)
    # hostname validity gate: jsleak's regex accepts any alpha TLD shape, so
    # "service.example.com.au" survives intact while "ajax.js"-style names die
    got["domains"] = _uniq(d for d in got["domains"] if core.canon_domain(d))
    got["ips"] = _uniq(got["ips"])
    api_paths = _uniq(api_paths)[:500]
    # paths scraped from crawl text have no owner yet; keep them under the
    # explicit "leak" pseudo-asset so they are still queryable
    for p in api_paths:
        store.upsert_endpoint("leak", "GET", core.path_template(p), [], source="jsleak")
    # paths found inside a fetched bundle belong to that bundle's host
    seen_ep: set[tuple[str, str, str]] = set()
    for host, p, verb in api_hits:
        tpl = core.path_template(p)
        key = (host, tpl, verb)
        if key in seen_ep:
            continue
        seen_ep.add(key)
        store.upsert_endpoint(host, verb, tpl, [], source="jsleak")
    for d in got["domains"]:
        store.upsert_asset("domain", d, source="leak-extract", confidence=0.4,
                           passivity="passive")
    for ip in got["ips"]:
        store.upsert_asset("ip", ip, source="leak-extract", confidence=0.4,
                           passivity="passive")
    after = store.js_stats()
    attempted = len(candidates)
    pending = after["pending"] + after["failed"]
    budget_hit = pending > 0 or attempted >= fetch_limit
    return {"count_domains": len(got["domains"]), "count_ips": len(got["ips"]),
            # `fetched` used to be len(candidates) BEFORE the fetch ran, i.e. an
            # attempt count mislabelled as a success count. Keep the name for
            # compatibility but make it mean what it says, and expose the rest.
            "fetched": after["succeeded"] - before["succeeded"],
            "attempted": attempted,
            "js_discovered": after["discovered"],
            "js_succeeded": after["succeeded"],
            "js_failed": after["failed"],
            "js_pending": pending,
            "js_fetch_limit": fetch_limit,
            "js_budget_hit": budget_hit,
            # A non-empty pending queue is a coverage gap, not convergence.
            "outcome": (core.OUTCOME_PARTIAL if budget_hit and after["discovered"]
                        else core.OUTCOME_OK),
            "api_paths": api_paths[:300],
            "api_hosts": len(seen_ep),
            "secrets": _redact_secrets(secrets),
            "domains": got["domains"][:1000], "ips": got["ips"][:1000]}


def _redact_secrets(secrets: dict) -> dict:
    """Show that a secret exists without shipping it to the agent's context.

    A full AK/SK in a transcript is a leak with extra steps; the prefix plus
    length is enough for a human to recognise the credential family and for an
    agent to decide whether to escalate.
    """
    out: dict = {}
    for kind, values in (secrets or {}).items():
        masked = []
        for v in values[:10]:
            v = str(v)
            masked.append((v[:4] + "…" + str(len(v)) + "c") if len(v) > 8 else "…" + str(len(v)) + "c")
        if masked:
            out[kind] = masked
    return out


def resolve_wordlist(wordlist: str) -> Path:
    """Resolve a wordlist argument.

    Accepts an absolute path, a path relative to the skill root, or a bare
    name that lives in wordlists/ ("sub" -> wordlists/sub.txt). Agents get the
    short form; humans can still pass any path they like.
    """
    raw = (wordlist or "").strip()
    if not raw:
        raise core.FindInfoError("wordlist is empty")
    wl = Path(raw)
    if not wl.is_absolute():
        wl = core.ROOT / raw
    if wl.exists():
        return wl
    for cand in (core.ROOT / "wordlists" / raw,
                 core.ROOT / "wordlists" / (raw + ".txt")):
        if cand.exists():
            return cand
    raise core.FindInfoError("wordlist not found: " + raw +
                             " (try sub / submin / vhost)")


# ---------------------------------------------------------------- 11. brute force (ksubdomain)
def t_brute(store, domain: str, wordlist: str | None = None, bandwidth: str = "3m",
            wildcard: str = "basic", timeout: int = 0) -> dict:
    """Active DNS brute force via ksubdomain (stateless raw-socket engine).

    Requires Npcap (Windows) / libpcap (Linux) and usually admin rights.
    Much faster than dnsx-based brute force: 10k~100k queries/s.
    """
    raw = domain
    domain = core.canon_domain(domain)
    if not domain:
        raise core.FindInfoError("invalid domain: " + str(raw))
    exe = core.tool("ksubdomain")
    outdir = core.DATA / "_tmp"
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / ("ks_" + str(os.getpid()) + "_" +
                        str(abs(hash(domain)) % 100000) + ".json")
    cmd = [exe, "enum", "-d", domain, "-b", bandwidth,
           "--wild-filter-mode", wildcard,
           "-o", str(outfile), "--output-type", "json", "--silent"]
    if wordlist:
        cmd[4:4] = ["-f", str(resolve_wordlist(wordlist))]
    core.log("ksubdomain: " + " ".join(cmd[1:]))
    rc, out, err = core.run(cmd, timeout=timeout, cwd=str(core.BIN))

    rows: list[dict] = []
    total = 0

    def save(sub: str, ips: list[str]) -> None:
        # every hit is written to the store; only ROW_LIMIT are echoed back
        nonlocal total
        total += 1
        for ip in ips:
            store.upsert_asset("ip", ip, source="ksubdomain", confidence=0.6,
                               passivity="active", parent=sub)
        store.upsert_asset("domain", sub, source="ksubdomain", confidence=0.7,
                           passivity="active", parent=domain)
        if len(rows) < core.ROW_LIMIT:
            rows.append({"domain": sub, "a": ips})

    if outfile.exists():
        try:
            # incremental: a 100k-hit file must not be parsed into one list
            for item in core.iter_json_array(outfile):
                if not isinstance(item, dict):
                    continue
                sub = core.canon_domain(item.get("subdomain", ""))
                if not sub:
                    continue
                ips = [core.canon_ip(x) for x in (item.get("answers") or [])]
                save(sub, [x for x in ips if x])
        except Exception as exc:
            core.log("ksubdomain json parse failed: " + repr(exc))
        finally:
            try:
                outfile.unlink()
            except Exception:
                pass
    if total == 0:
        # fallback: parse "sub => ip => ip" lines from stdout
        for ln in (out or "").splitlines():
            m = re.search(r"([a-z0-9][a-z0-9.\-]*\." + re.escape(domain) + r")\s*=>\s*([0-9.,\s]+)", ln, re.I)
            if not m:
                continue
            sub = core.canon_domain(m.group(1))
            if not sub:
                continue
            ips = [core.canon_ip(x) for x in re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(2))]
            save(sub, [x for x in ips if x])
    return {"domain": domain, "rc": rc, "count": total, "ok": rc == 0,
            "records": rows, "truncated": total > len(rows), "stderr": err[-500:]}


# ---------------------------------------------------------------- 12. onepass (Rust passive collector)
def t_onepass(store, domain: str, sources: list[str] | None = None,
              timeout: int = 0, min_confidence: float = 0.0) -> dict:
    """Passive subdomain collection via the bundled Rust binary (bin/onepass.exe).

    onepass aggregates 15 sources (8 usable without any API key) and returns
    per-record provenance. It is the fastest cold-start collector in this skill.
    Every record is stored with one "onepass:<id>" token per upstream it was
    confirmed by -- the collector relays upstreams, it is not an upstream
    itself, and confidence counts upstreams.
    """
    raw = domain
    domain = core.canon_domain(domain)
    if not domain:
        raise core.FindInfoError("invalid domain: " + str(raw))
    exe = core.tool("onepass")
    cmd = [exe, "query", "--domain", domain]
    if sources:
        cmd += ["--sources", ",".join(sources)]
    core.log("onepass: " + " ".join(cmd[1:]))
    rc, out, err = core.run(cmd, timeout=timeout)
    try:
        data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except Exception:
        raise core.StageError("onepass returned non-JSON: " +
                               (out or "")[:200] + " " + (err or "")[:200])
    if not data.get("ok") and data.get("error"):
        raise core.StageError("onepass: " + str(data.get("error")) + " " +
                              str(data.get("message", "")))
    rows = []
    for rec in data.get("records", []):
        d = core.canon_domain(rec.get("domain", ""))
        if not d:
            continue
        conf = float(rec.get("confidence") or 0.5)
        if conf < min_confidence:
            continue
        srcs = [s for s in (rec.get("sources") or []) if s]
        # one prefixed token per upstream, in a stable order
        store.upsert_asset("domain", d, source=",".join("onepass:" + s for s in sorted(srcs)),
                           confidence=conf, passivity="passive", parent=domain,
                           attrs={"onepass_sources": srcs})
        rows.append({"domain": d, "sources": srcs, "confidence": conf})
    core.log("onepass: " + str(len(rows)) + " hosts from " +
             str(data.get("sources_ok", 0)) + " sources")

    # "ok": True was hardcoded, so an onepass run where every upstream failed
    # (or every key was missing) still looked like a successful empty result.
    # The binary already reports sources_ok / sources_error; derive the outcome
    # from them instead of assuming success.
    per_source = [{"id": s.get("id"), "status": s.get("status"),
                   "found": s.get("found"), "code": s.get("code")}
                  for s in data.get("sources", [])]
    try:
        n_ok = int(data.get("sources_ok") or 0)
        n_err = int(data.get("sources_error") or 0)
    except (TypeError, ValueError):
        n_ok, n_err = 0, 0
    if rc == 124:
        outcome = core.OUTCOME_TIMEOUT
    elif n_ok == 0 and (n_err > 0 or per_source):
        outcome = core.OUTCOME_FAILED
    elif n_err > 0:
        outcome = core.OUTCOME_PARTIAL
    elif rows:
        outcome = core.OUTCOME_OK
    else:
        outcome = core.OUTCOME_EMPTY
    return {
        "domain": domain,
        "count": len(rows),
        "elapsed_ms": data.get("elapsed_ms"),
        "sources_ok": data.get("sources_ok"),
        "sources_error": data.get("sources_error"),
        "per_source": per_source,
        "domains": rows[:2000],
        "outcome": outcome,
        "ok": outcome in (core.OUTCOME_OK, core.OUTCOME_EMPTY, core.OUTCOME_PARTIAL),
        "rc": rc,
        "hint": core.outcome_hint(outcome),
    }


# ---------------------------------------------------------------- doctor / versions
# Per-tool version recipe, derived from sampling each binary instead of
# guessing. The old code ran every tool with every flag and took the first
# x.y.z-looking token in the whole blob, so a usage banner echoing its own
# path ("Usage of E:\...\findinfo-0.7.3-windows\bin\...") was reported as
# that tool's version.
#
# Each entry: (args to try, regex whose group 1 is the version).
# Every regex is anchored on a version keyword or the tool's own name, so an
# unrelated number in the output cannot win.
VERSION_ARGS = ["-version", "--version", "-V", "-h"]

# ProjectDiscovery family prints "Current Version: v1.2.3" (capital V in older
# builds, lowercase in newer).
_PD_VERSION = re.compile(r"Current [Vv]ersion:\s*(v?\d+\.\d+[\w.\-]*)", re.I)

_VERSION_SPECS = {
    "subfinder": (["-version", "--version"], _PD_VERSION),
    "httpx":     (["-version", "--version"], _PD_VERSION),
    "dnsx":      (["-version", "--version"], _PD_VERSION),
    "naabu":     (["-version", "--version"], _PD_VERSION),
    "cdncheck":  (["-version", "--version"], _PD_VERSION),
    "uncover":   (["-version", "--version"], _PD_VERSION),
    "katana":    (["-version", "--version"], _PD_VERSION),
    "chaos":     (["-version", "--version"], _PD_VERSION),
    # "KSubdomain version 2.4" -- only two components, hence \d+\.\d+
    "ksubdomain": (["-version", "--version", "-h"],
                   re.compile(r"KSubdomain\s+version\s+(v?\d+(?:\.\d+)*)", re.I)),
    # onepass answers --version with JSON: {"ok":true,"version":"0.1.0"}
    "onepass":   (["--version"],
                  re.compile(r'"version"\s*:\s*"([^"]+)"')),
    # ENScan_GO prints a "Version:" field, but this build leaves it empty. The
    # regex only accepts a real dotted value, so an empty field yields "", not
    # the install path that follows it.
    "enscan":    (["-version", "--version", "-h"],
                  re.compile(r"^Version:\s*(v?\d+(?:\.\d+)+[\w.\-]*)\s*$",
                             re.M)),
    # hostCollision has no version flag: -h prints a Go flag usage banner
    # headed by the binary's absolute path. Nothing to parse.
    "hostCollision": (["-h"],
                      re.compile(r"^hostCollision\s+(v?\d+\.\d+[\w.\-]*)$",
                                 re.M | re.I)),
}

# Anything that looks like a filesystem location must never be mistaken for a
# version. Stripped before matching so a path cannot even reach a regex.
_PATH_NOISE = re.compile(
    r"""(?:[A-Za-z]:\\[^\s"']*          # C:\... (Windows absolute)
        |\\\\[^\s"']*                   # \\server\share
        |[\w.\-]*[\\/][\w.\-\\/]*      # any a\b or a/b fragment
    )""",
    re.I | re.X)



def _strip_paths(text: str) -> str:
    """Remove filesystem paths so a directory name cannot pose as a version.

    A release unpacks into a directory literally named after the version, so a
    usage banner echoing its own location caused the bogus
    ``enscan -> <version>-windows`` report.
    """
    out = text or ""
    for literal in (str(core.BIN_PLATFORM), str(core.ROOT), str(core.BIN)):
        if literal:
            out = out.replace(literal, " ")
            out = out.replace(literal.replace(chr(92), "/"), " ")
    return _PATH_NOISE.sub(" ", out)


def parse_version(tool: str, text: str) -> tuple[str, bool]:
    """Return (version, found) for one tool's raw output.

    found is False when the output carries no recognisable version, which is
    the honest answer for a tool with no version flag (hostCollision) or a
    build that leaves the field blank (this enscan binary).
    """
    spec = _VERSION_SPECS.get(tool)
    if not spec:
        return "", False
    _args, rx = spec
    m = rx.search(_strip_paths(text))
    if not m:
        return "", False
    val = (m.group(1) if m.groups() else m.group(0)).strip()
    if not val or "/" in val or chr(92) in val:
        return "", False
    return val, True


def _tool_version(name: str, exe: str) -> tuple[str, str, str]:
    """Run the tool's own version recipe; return (version, raw, exec_error).

    `raw` is the first 120 characters of the first non-empty invocation, so a
    human can see what the tool actually said when parsing fails. ANSI escape
    sequences and banner art are stripped: they carry zero diagnostic value
    and roughly doubled the doctor payload (a 4.7 KB stdout where a third was
    \x1b[32m banner art from the PD tools).
    """
    spec = _VERSION_SPECS.get(name)
    args_list = spec[0] if spec else VERSION_ARGS
    last_raw = ""
    for arg in args_list:
        rc, out, err = core.run([exe, arg], timeout=20)
        if rc == 126:
            # binary exists but the OS refuses to run it: report that instead
            # of pretending the version is unknown
            return "", "", (err or "")[:200]
        blob = (out or "") + (err or "")
        blob = _strip_ansi(blob)
        if blob and not last_raw:
            last_raw = blob[:120]
        ver, found = parse_version(name, blob)
        if found:
            return ver, blob[:120], ""
    return "", last_raw, ""


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|[\x00-\x08\x0b-\x1f]")


def _strip_ansi(blob: str) -> str:
    """Drop ANSI escapes, control chars, and banner-art lines.

    The PD tools and ENScan open with box-drawing logos; whole rows of those
    characters are pure decoration and were the bulk of the version_raw
    noise. Keep only lines with at least one alphanumeric character, then
    collapse the leftover spacing.
    """
    cleaned = _ANSI_RE.sub(" ", blob or "")
    lines = [ln.strip() for ln in cleaned.splitlines()]
    lines = [ln for ln in lines if re.search(r"[A-Za-z0-9]", ln)]
    return re.sub(r" {2,}", " ", "\n".join(lines)).strip()[:200]



# The only bundled binary that is built from in-repo source: if the binary is
# older than the source tree, a rebuild was forgotten and fixes silently
# never shipped (exactly how a UTF-8 panic fix stayed out of bin/ for a day).
_SOURCE_BUILT_TOOLS = {
    "onepass": core.ROOT / "rust" / "onepass" / "src",
}


def _stale_check(name: str, exe: str) -> dict | None:
    """Compare the binary's mtime against the source dir it is built from."""
    src = _SOURCE_BUILT_TOOLS.get(name)
    if not src or not src.exists():
        return None
    try:
        exe_mt = os.path.getmtime(exe)
        src_newest = exe_mt
        for p in src.rglob("*.rs"):
            src_newest = max(src_newest, os.path.getmtime(p))
        if src_newest > exe_mt + 60:      # 1min skew tolerance for copy tools
            return {"stale_binary": True,
                    "hint": ("binary is older than " + str(src) +
                             "; rebuild it: bash scripts/build-onepass.sh")}
    except OSError:
        return None
    return None


def _env_selfcheck() -> dict:
    """Environment preconditions a consumer-grade host may not satisfy.

    The pipeline assumes three things that are NOT true everywhere:
    (1) Python >= 3.10 (the codebase uses PEP 604 unions);
    (2) the bundled binaries can actually execute here (cloud sandboxes
        strip the exec bit or block unknown binaries by policy);
    (3) there is a network egress to the passive data sources.
    doctor used to hardcode "python": "ok" and had no probe for (2)/(3),
    so an agent inside a restricted sandbox learned about the problem only
    when a stage failed mid-run. This makes all three explicit up front.
    """
    import sys as _sys
    env = {"python_version": ".".join(map(str, _sys.version_info[:3])),
           "python_ok": _sys.version_info >= (3, 10),
           "python_required": ">=3.10"}
    if not env["python_ok"]:
        env["python_hint"] = ("findinfo uses PEP 604 syntax and needs Python "
                              ">= 3.10; stages will crash with SyntaxError on "
                              "this interpreter")
    # network egress: probe the actual passive sources, in parallel. Any one
    # reachable means the passive stages can produce something; zero means
    # this host has no usable egress and everything past `doctor` is moot.
    probes = {"crt.sh": "https://crt.sh/?output=json",
              "rapiddns": "https://rapiddns.io/",
              "hackertarget": "https://api.hackertarget.com/"}
    reach = {}
    with futures.ThreadPoolExecutor(max_workers=len(probes)) as ex:
        futs = {}
        for label, url in probes.items():
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "Mozilla/5.0 findinfo-doctor"})
            futs[ex.submit(_probe_url, req)] = label
        for fut, label in futs.items():
            reach[label] = fut.result()
    reachable = [k for k, v in reach.items() if v]
    env["net_egress"] = {"probes": reach, "any_reachable": bool(reachable)}
    if not reachable:
        env["net_hint"] = ("no passive source reachable from this host: passive "
                           "collection cannot produce data here; check egress "
                           "firewall / proxy before running any stage")
    return env


def _probe_url(req, timeout: float = 8.0) -> bool:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 100 <= int(r.status) < 500
    except urllib.error.HTTPError:
        return True          # got an HTTP answer: the egress works
    except Exception:
        return False


def doctor() -> dict:
    names = ["enscan", "subfinder", "httpx", "dnsx", "naabu", "cdncheck",
             "uncover", "katana", "chaos", "ksubdomain", "onepass",
             "hostCollision"]
    report = {}
    for n in names:
        try:
            exe = core.tool(n)
        except core.ToolMissing:
            report[n] = {"present": False}
            continue
        # Per-tool recipe (see _VERSION_SPECS): the old "first x.y.z in the
        # blob" approach reported the install directory name as a version
        # whenever a usage banner echoed its own path.
        ver, ver_raw, exec_error = _tool_version(n, exe)
        # core.tool() only resolves inside bin/<platform>/, so anything that
        # turns up here is a bundled binary by construction.
        entry = {"present": True, "path": exe, "version": ver,
                 "source": "bundle"}
        if ver_raw:
            # 120 chars of what the tool actually printed, so a human can see
            # why a version was not recognised instead of guessing
            entry["version_raw"] = ver_raw
        if not ver:
            # honest "we could not tell" -- never a path fragment posing as one
            entry["version_unknown"] = True
        report[n] = entry
        if exec_error:
            report[n].update({"executable": False, "hint": exec_error})
            continue
        report[n]["executable"] = True
        stale = _stale_check(n, exe)
        if stale:
            report[n].update(stale)
        if not ver:
            # A binary that cannot state its version is not necessarily wrong,
            # but if it also fails to identify itself it is worth flagging:
            # the file in bin/<platform>/ may be broken or a wrong build.
            _rc, _out, _err = core.run([exe, "-h"], timeout=15)
            _blob = ((_out or "") + (_err or "")).lower()
            if "projectdiscovery" not in _blob and n.lower() not in _blob:
                report[n]["suspect"] = True
                report[n]["hint"] = ("binary in bin/ does not identify itself as " + n +
                                     "; it may be broken or the wrong build -- reinstall "
                                     "it into bin/" + core.PLATFORM + "/")
    keys = {k: bool(api_key_or_empty(k)) for k in ["fofa", "quake", "hunter", "shodan",
                                                   "chaos", "securitytrails", "virustotal",
                                                   "urlscan"]}
    missing = [n for n, v in report.items() if not v.get("present")]
    # Every resolvable tool lives in bin/<platform>/ now: core.tool() has no
    # PATH fallback, so "outside bin" cannot happen. Kept in the output
    # shape so existing consumers of doctor keep parsing.
    outside = []
    suspects = [n for n, v in report.items() if v.get("suspect")]
    stale = [n for n, v in report.items() if v.get("stale_binary")]
    not_executable = [n for n, v in report.items() if v.get("present") and not v.get("executable")]
    gw_base = core.api_base("fofa")
    gw = None
    if gw_base and core.api_key("fofa"):
        u = fofa_gateway_usage(timeout=15)
        gw = {"base": gw_base, "reachable": bool(u and u.get("ok")),
              "remaining": (u or {}).get("remaining"),
              "max": (u or {}).get("maxQueries"),
              "usable": (u or {}).get("usable")}
    env = _env_selfcheck()
    return {"python": "ok" if env["python_ok"] else "incompatible:" + env["python_version"],
            "skill_version": core.skill_version(),
            "environment": env,
            "tools": report, "api_keys": keys,
            "fofa_gateway": gw,
            "tools_summary": {
                "total": len(names),
                "in_bin": len(names) - len(missing) - len(outside),
                "outside_bin": outside,
                "missing": missing,
                "suspect": suspects,
                "stale_binary": stale,
                "not_executable": not_executable,
                "all_in_bin": not missing and not outside and not not_executable,
            },
            "bin_dir": str(core.BIN_PLATFORM),
            "bin_platform": core.PLATFORM,
            "db": str(core.DATA / "findinfo.db"),
            "root": str(core.ROOT), "home": str(core.HOME)}


def api_key_or_empty(name: str) -> str:
    try:
        return core.api_key(name)
    except Exception:
        return ""
