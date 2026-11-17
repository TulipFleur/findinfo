"""findinfo tools: thin, typed wrappers around bundled binaries + APIs.

Every function:
  - takes explicit inputs
  - enforces scope where it generates traffic
  - returns structured dicts (never raw HTML)
  - writes normalized records into the store
"""
from __future__ import annotations

import atexit
import json
import os
import re
import socket
import ssl
import tempfile
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


def t_enscan(store, name: str, invest: int = 51, deep: int = 2,
             outdir: Path | None = None, timeout: int = 1200,
             field: str = "icp,app,wx_app,wechat,invest,enterprise_info") -> dict:
    exe = core.tool("enscan")
    outdir = outdir or (core.RUNS_DIR / "enscan")
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "-n", name, "-invest", str(invest), "-deep", str(deep),
           "-json", "-out-dir", str(outdir), "-type", "aqc"]
    if field:
        cmd += ["-field", field]
    core.log("enscan: " + " ".join(cmd[1:]))
    rc, out, err = core.run(cmd, timeout=timeout, cwd=str(core.BIN))
    blob = (out or "") + (err or "")
    if "cookie" in blob.lower() or "Cookie" in blob:
        core.log("enscan: 未配置 cookie，请在 bin/config.yaml 填入 aiqicha Cookie")
    merged = {"companies": [], "icp": [], "domains": [], "apps": []}
    files = 0
    for p in sorted(outdir.rglob("*.json")):
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
    return {"rc": rc, "json_files": files, "stderr": err[-800:],
            "companies": merged["companies"][:200],
            "icp": merged["icp"], "domains": merged["domains"],
            "apps": merged["apps"][:100]}


def got_name(p: Path, fallback: str) -> str:
    return p.stem or fallback


# ---------------------------------------------------------------- 2. certificate transparency
def t_certs(store, domain: str, timeout: int = 90) -> dict:
    raw = domain
    domain = core.canon_domain(domain)
    if not domain:
        raise core.FindInfoError("invalid domain: " + str(raw))
    cache_key = "ct:" + domain
    data = core.CACHE.get("certs", cache_key, ttl=7 * 86400)
    if data is None:
        core.throttle("crtsh")
        data = core.curl_json(
            "https://crt.sh/?q=%25." + domain + "&output=json",
            headers={"Accept": "application/json"}, timeout=timeout)
        if data is None:
            core.throttle("certspotter")
            data = core.curl_json(
                "https://api.certspotter.com/v1/issuances?domain=" + domain +
                "&include_subdomains=true&expand=dns_names",
                headers={"Accept": "application/json"}, timeout=timeout) or []
        core.CACHE.put("certs", cache_key, data)
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
        store.upsert_asset("domain", d, source="crt.sh", confidence=0.5,
                           passivity="passive", parent=domain)
    return {"domain": domain, "count": len(out), "records": len(data or []), "domains": out}


# ---------------------------------------------------------------- 3. ICP reverse lookup
def t_icp(store, codes: list[str], engines: str = "fofa,quake,hunter",
          timeout: int = 180) -> dict:
    exe = core.tool("uncover")
    domains: list[str] = []
    ips: list[str] = []
    rows = 0
    for code in codes:
        code = code.strip()
        if not code:
            continue
        store.upsert_asset("icp", code, source="icp-seed", confidence=0.9,
                           passivity="passive")
        q = 'icp="' + code + '"'
        core.throttle("fofa")
        core.mapping_wait()
        rc, out, err = core.run([exe, "-q", q, "-e", engines, "-json", "-silent"],
                                timeout=timeout)
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
    return {"codes": codes, "rows": rows, "domains": domains, "ips": ips}


# ---------------------------------------------------------------- 4. passive subdomains
def t_subs(store, domain: str, engines: str = "fofa,quake,hunter,shodan,censys",
           timeout: int = 300) -> dict:
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

    if core.has_tool("subfinder"):
        core.log("subfinder " + domain)
        rc, out, err = core.run([core.tool("subfinder"), "-d", domain, "-all",
                                 "-recursive", "-silent", "-json"], timeout=timeout)
        for r in core.parse_jsonl(out):
            add(r.get("host", ""), "subfinder")

    if core.has_tool("chaos") and core.api_key("chaos"):
        core.log("chaos " + domain)
        rc, out, err = core.run([core.tool("chaos"), "-d", domain, "-silent", "-json",
                                 "-key", core.api_key("chaos")], timeout=timeout)
        for r in core.parse_jsonl(out):
            add(r.get("domain", "") or r.get("host", ""), "chaos")

    if core.has_tool("uncover"):
        core.log("uncover space-mapping " + domain)
        core.throttle("fofa")
        core.mapping_wait()
        rc, out, err = core.run([core.tool("uncover"), "-q", 'domain:"' + domain + '"',
                                 "-e", engines, "-json", "-silent"], timeout=timeout)
        for r in core.parse_jsonl(out):
            add(r.get("host", ""), "uncover")

    rows = []
    for d, srcs in found.items():
        conf = 0.5 if len(srcs) == 1 else (0.75 if len(srcs) == 2 else 0.95)
        store.upsert_asset("domain", d, source=",".join(sorted(srcs)),
                           confidence=conf, passivity="passive", parent=domain)
        rows.append({"domain": d, "sources": sorted(srcs), "confidence": conf})
    rows.sort(key=lambda x: x["domain"])
    return {"domain": domain, "count": len(rows), "domains": rows}


# ---------------------------------------------------------------- 5. DNS resolve + wildcard
def t_dns(store, domains: list[str], timeout: int = 600) -> dict:
    domains = _uniq([core.canon_domain(d) for d in domains if core.canon_domain(d)])
    if not domains:
        return {"count": 0, "domains": [], "wildcard": []}
    # wildcard probe per parent domain
    wildcard: dict[str, str] = {}
    parents = sorted({".".join(d.split(".")[-2:]) for d in domains if d.count(".") >= 1})
    if core.has_tool("dnsx"):
        for p in parents[:20]:
            probe = "findinfo-wildcard-probe-9f3a." + p
            rc, out, err = core.run([core.tool("dnsx"), "-d", probe, "-a", "-resp",
                                     "-silent", "-json"], timeout=45)
            for r in core.parse_jsonl(out):
                for a in r.get("a", []) or []:
                    wildcard[p] = a
    exe = core.tool("dnsx")
    path = _tmp_lines(domains)
    core.log("dnsx resolving " + str(len(domains)))
    rc, out, err = core.run([exe, "-l", path, "-a", "-cname", "-resp", "-silent", "-json",
                             "-t", str(core.CFG["limits"]["dns_concurrency"])],
                            timeout=timeout)
    rows = []
    seen_dns: set[str] = set()
    for r in core.parse_jsonl(out):
        d = core.canon_domain(r.get("host", ""))
        if not d:
            continue
        seen_dns.add(d)
        ips = [core.canon_ip(x) for x in (r.get("a") or [])]
        ips = [x for x in ips if x]
        cnames = [core.canon_domain(x) for x in (r.get("cname") or [])]
        cnames = [x for x in cnames if x]
        parent = ".".join(d.split(".")[-2:])
        wc = wildcard.get(parent)
        is_wc = bool(wc and ips and wc in ips)
        if is_wc:
            continue
        for ip in ips:
            store.upsert_asset("ip", ip, source="dnsx", confidence=0.6, passivity="passive", parent=d)
        store.upsert_asset("domain", d, source="dnsx", confidence=0.8, passivity="passive")
        rows.append({"domain": d, "a": ips, "cname": cnames})
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
                ips = [x for x in ips if x and not x.startswith("198.18.")]
                if not ips:
                    continue
                for ip in ips:
                    store.upsert_asset("ip", ip, source="system-dns", confidence=0.6,
                                       passivity="passive", parent=d)
                store.upsert_asset("domain", d, source="system-dns", confidence=0.8,
                                   passivity="passive")
                sys_rows.append({"domain": d, "a": ips, "cname": []})
    rows.extend(sys_rows)
    return {"count": len(rows), "domains": rows,
            "wildcard": [{"parent": k, "ip": v} for k, v in wildcard.items()],
            "system_fallback": len(sys_rows)}


# ---------------------------------------------------------------- 6. httpx probe
def t_httpx(store, hosts: list[str], timeout: int = 1800) -> dict:
    hosts = _uniq([h for h in hosts if h])
    if not hosts:
        return {"count": 0, "rows": []}
    scope = core.Scope.load()
    safe = []
    for h in hosts:
        ok, _rule = scope.check(h)
        if ok or not scope.enabled:
            safe.append(h)
        else:
            core.log("scope skip " + h)
    if not safe:
        raise core.ScopeError("no host in scope for httpx")
    path = _tmp_lines(safe)
    lim = core.CFG["limits"]
    cmd = [core.tool("httpx"), "-l", path, "-silent", "-json",
           "-sc", "-title", "-tech-detect", "-ip", "-cname", "-cdn", "-favicon",
           "-threads", str(lim["http_concurrency"]), "-rate-limit", str(lim["per_host_rps"] * 10),
           "-timeout", "10", "-retries", "1"]
    core.log("httpx probing " + str(len(safe)))
    rc, out, err = core.run(cmd, timeout=timeout)
    rows = []
    for r in core.parse_jsonl(out):
        host = core.canon_domain(r.get("input", "") or r.get("host", ""))
        url = r.get("url", "")
        ip = core.canon_ip(r.get("host_ip", "")) or core.canon_ip(r.get("ip", ""))
        if not ip:
            for _a in (r.get("a") or []):
                ip = core.canon_ip(_a)
                if ip:
                    break
        if not host:
            h2, p2, params2 = core.split_url(url)
            host = h2
        if not host:
            continue
        title = (r.get("title") or "")[:200]
        status = r.get("status_code")
        tech = r.get("tech") or []
        rec = {"host": host, "url": url, "status": status, "title": title,
               "tech": tech, "ip": ip, "cname": r.get("cname") or [],
               "port": r.get("port"), "length": r.get("content_length"),
               "cdn": r.get("cdn_name") or r.get("cdn"),
               "favicon": r.get("favicon"), "webserver": r.get("webserver")}
        rows.append(rec)
        attrs = {"status": status, "title": title, "tech": tech, "url": url,
                 "ip": ip, "port": r.get("port"), "cdn": rec["cdn"],
                 "webserver": rec["webserver"]}
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
    return {"count": len(rows), "rows": rows}


# ---------------------------------------------------------------- 7. IP aggregate + CDN
def t_ipagg(store, ips: list[str] | None = None, timeout: int = 300) -> dict:
    if not ips:
        ips = [a["canonical"] for a in store.get_assets(kind="ip")]
    ips = _uniq([core.canon_ip(i) for i in ips if core.canon_ip(i)])
    if not ips:
        return {"ips": [], "candidates": []}
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
    for a in store.get_assets(kind="domain"):
        d = a["canonical"]
        ip = (a.get("attrs") or {}).get("ip")
        if ip:
            groups.setdefault(ip, []).append(d)
    candidates = []
    for ip, doms in groups.items():
        if ip in cdn_ips:
            continue
        if len(doms) >= 2:
            candidates.append({"ip": ip, "domains": sorted(set(doms)), "reason": "shared-ip"})
    return {"ips": ips, "cdn": cdn_ips, "candidates": candidates,
            "count_candidates": len(candidates)}


# ---------------------------------------------------------------- 8. port scan
def t_ports(store, ips: list[str], top_ports: int = 1000, timeout: int = 1800,
            check_scope: bool = True) -> dict:
    scope = core.Scope.load()
    targets = []
    for ip in _uniq([core.canon_ip(i) for i in ips if core.canon_ip(i)]):
        ok, rule = scope.check(ip)
        if ok or not scope.enabled:
            targets.append(ip)
        else:
            core.log("scope skip " + ip + " (" + rule + ")")
    if not targets:
        raise core.ScopeError("no ip in scope for naabu")
    path = _tmp_lines(targets)
    rc, out, err = core.run([core.tool("naabu"), "-l", path, "-top-ports", str(top_ports),
                             "-silent", "-json", "-rate", "1000"], timeout=timeout)
    rows = []
    for r in core.parse_jsonl(out):
        ip = core.canon_ip(r.get("ip") or r.get("host") or "")
        port = r.get("port")
        if not ip or not port:
            continue
        rows.append({"ip": ip, "port": int(port)})
        store.upsert_asset("endpoint", ip + ":" + str(port), source="naabu",
                           confidence=0.8, passivity="active", parent=ip,
                           attrs={"port": int(port)})
    return {"targets": targets, "count": len(rows), "rows": rows[:2000]}


# ---------------------------------------------------------------- 9. vhost collision
def _curl_probe(ip: str, port: int, scheme: str, host: str, timeout: float = 8.0) -> dict | None:
    """Fallback probe via curl --resolve: works through HTTP proxies / TUN setups
    where raw sockets to the target IP are not routable."""
    url = scheme + "://" + host + ":" + str(port) + "/"
    resolve = " --resolve " + host + ":" + str(port) + ":" + ip
    rc, out, err = core.run(
        [core.CURL, "-sS", "-k", "-L", "--max-time", str(int(timeout)),
         "--resolve", host + ":" + str(port) + ":" + ip,
         "-o", "-", "-w", chr(10) + "__META__%{http_code}|%{size_download}|%{redirect_url}" + chr(10),
         url], timeout=int(timeout) + 10)
    if rc != 0 or "__META__" not in out:
        return None
    body, _, meta = out.rpartition("__META__")
    parts = meta.strip().split("|")
    try:
        status = int(parts[0])
    except Exception:
        return None
    try:
        length = int(parts[1])
    except Exception:
        length = len(body)
    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return {"status": status, "len": length,
            "title": (tm.group(1).strip()[:120] if tm else ""),
            "server": "", "location": parts[2] if len(parts) > 2 else "",
            "hash": str(hash(body[:4096])), "via": "curl"}


def _http_probe(ip: str, port: int, scheme: str, host: str, timeout: float = 8.0) -> dict | None:
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return _curl_probe(ip, port, scheme, host, timeout)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        req = ("GET / HTTP/1.1" + chr(13) + chr(10) +
               "Host: " + host + chr(13) + chr(10) +
               "User-Agent: Mozilla/5.0 findinfo" + chr(13) + chr(10) +
               "Accept: */*" + chr(13) + chr(10) +
               "Connection: close" + chr(13) + chr(10) + chr(13) + chr(10))
        sock.settimeout(timeout)
        sock.sendall(req.encode("utf-8", "replace"))
        chunks = []
        total = 0
        while total < 65536:
            b = sock.recv(8192)
            if not b:
                break
            chunks.append(b)
            total += len(b)
        data = b"".join(chunks)
        sock.close()
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    text = head.decode("utf-8", "replace")
    lines = text.split("\r\n")
    status = None
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", lines[0] if lines else "")
    if m:
        status = int(m.group(1))
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    bt = body.decode("utf-8", "replace")
    tm = re.search(r"<title[^>]*>(.*?)</title>", bt, re.I | re.S)
    title = (tm.group(1).strip()[:120] if tm else "")
    return {"status": status, "len": len(body), "title": title,
            "server": hdrs.get("server", ""), "location": hdrs.get("location", ""),
            "hash": str(hash(body[:4096]))}


def t_vhost(store, ip: str, hosts: list[str], ports: list[int] | None = None,
            threads: int = 20, timeout: float = 8.0) -> dict:
    scope = core.Scope.load()
    ip = core.canon_ip(ip) or ip
    ok, rule = scope.check(ip)
    if not ok and scope.enabled:
        raise core.ScopeError("scope denied for " + ip + " (" + rule + ")")
    hosts = _uniq([core.canon_domain(h) for h in hosts if core.canon_domain(h)])
    ports = ports or [80, 443]
    baseline: dict = {}
    for port in ports:
        scheme = "https" if port in (443, 8443, 9443) else "http"
        base = _http_probe(ip, port, scheme, "findinfo-baseline-9f3a.invalid", timeout)
        baseline[(port, scheme)] = base
    hits = []

    def work(host: str) -> None:
        for port in ports:
            scheme = "https" if port in (443, 8443, 9443) else "http"
            core.throttle("http")
            r = _http_probe(ip, port, scheme, host, timeout)
            if not r:
                continue
            b = baseline.get((port, scheme)) or {}
            same = (r["status"] == b.get("status") and abs(r["len"] - (b.get("len") or 0)) < 32)
            if same:
                continue
            hits.append({"ip": ip, "port": port, "scheme": scheme, "host": host, **r})

    with futures.ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(work, hosts))
    for h in hits:
        store.upsert_asset("domain", h["host"], source="vhost", confidence=0.5,
                           passivity="active", parent=ip,
                           attrs={"ip": ip, "port": h["port"], "status": h["status"],
                                  "title": h["title"]})
    return {"ip": ip, "tested": len(hosts), "hits": len(hits), "results": hits[:500]}


# ---------------------------------------------------------------- 10. crawl + extract
def t_crawl(store, urls: list[str], depth: int = 3, timeout: int = 1800,
            check_scope: bool = True) -> dict:
    scope = core.Scope.load()
    targets = []
    for u in _uniq(urls):
        h, p, params = core.split_url(u)
        ok, rule = scope.check(h or "")
        if ok or not scope.enabled:
            targets.append(u)
        else:
            core.log("scope skip " + str(h))
    if not targets:
        raise core.ScopeError("no url in scope for katana")
    path = _tmp_lines(targets)
    rc, out, err = core.run([core.tool("katana"), "-list", path, "-jc", "-kf", "all",
                             "-d", str(depth), "-silent", "-j", "-or", "-ob"], timeout=timeout)
    rows = []
    for r in core.parse_jsonl(out):
        req = r.get("request") or {}
        url = req.get("endpoint") or req.get("url") or r.get("url") or req.get("endpoint")
        if not url:
            continue
        h, p, params = core.split_url(url)
        if not h:
            continue
        method = (req.get("method") or r.get("method") or "GET").upper()
        store.upsert_endpoint(h, method, core.path_template(p), params, source="katana")
        store.upsert_asset("url", url, source="katana", confidence=0.7,
                           passivity="active", parent=h)
        rows.append({"url": url, "host": h, "path": p, "params": params})
    if not rows:
        # older katana builds emit plain URL lines
        for line in (out or "").splitlines():
            u = line.strip()
            if not u.startswith("http"):
                continue
            h, p, params = core.split_url(u)
            if not h:
                continue
            store.upsert_endpoint(h, "GET", core.path_template(p), params, source="katana")
            store.upsert_asset("url", u, source="katana", confidence=0.7,
                               passivity="active", parent=h)
            rows.append({"url": u, "host": h, "path": p, "params": params})
    return {"count": len(rows), "rows": rows[:5000]}


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
              timeout: int = 300, fetch_limit: int = 40) -> dict:
    from . import jsleak

    text = json.dumps(crawl_rows, ensure_ascii=False)
    got = extract_from_text(text, [])
    hit = jsleak.extract(text, [])
    got["domains"].extend(hit["domains"])
    got["ips"].extend(hit["ips"])

    # fetch JS bundles and API-ish pages, extract paths / hosts / secrets
    candidates = []
    for u in _uniq(urls or []):
        if re.search(r"(\.js|\.json|\.map)(\?|$)", u or "", re.I):
            candidates.append(u)
    candidates = candidates[:fetch_limit]
    api_paths: list[str] = []                 # host unknown (extracted from crawl text)
    api_hits: list[tuple[str, str]] = []      # (host, path) from a fetched bundle
    secrets: dict = {}

    def fetch_and_scan(u: str) -> dict | None:
        core.throttle("http")
        rc, body, err = core.curl([u], timeout=25)
        if rc != 0 or not body:
            return None
        hit = jsleak.extract(body, [])
        hit["_url"] = u
        return hit

    # parallel fetch: network dominates the cost (~95%), so concurrency is the
    # single biggest win. workers are bounded to stay polite.
    if candidates:
        with futures.ThreadPoolExecutor(max_workers=min(10, len(candidates))) as pool:
            for h in pool.map(fetch_and_scan, candidates):
                if not h:
                    continue
                got["domains"].extend(h["domains"])
                got["ips"].extend(h["ips"])
                api_paths.extend(h["api_paths"])
                host = core.split_url(h.get("_url") or "")[0]
                if host:
                    api_hits.extend((host, p) for p in h["api_paths"])
                for k, v in h["secrets"].items():
                    secrets.setdefault(k, []).extend(v)
    got["domains"] = _uniq(got["domains"])
    got["ips"] = _uniq(got["ips"])
    api_paths = _uniq(api_paths)[:500]
    # paths scraped from crawl text have no owner yet; keep them under the
    # explicit "leak" pseudo-asset so they are still queryable
    for p in api_paths:
        store.upsert_endpoint("leak", "GET", core.path_template(p), [], source="jsleak")
    # paths found inside a fetched bundle belong to that bundle's host
    seen_ep: set[tuple[str, str]] = set()
    for host, p in api_hits:
        tpl = core.path_template(p)
        if (host, tpl) in seen_ep:
            continue
        seen_ep.add((host, tpl))
        store.upsert_endpoint(host, "GET", tpl, [], source="jsleak")
    for d in got["domains"]:
        store.upsert_asset("domain", d, source="leak-extract", confidence=0.4,
                           passivity="passive")
    for ip in got["ips"]:
        store.upsert_asset("ip", ip, source="leak-extract", confidence=0.4,
                           passivity="passive")
    return {"count_domains": len(got["domains"]), "count_ips": len(got["ips"]),
            "fetched": len(candidates), "api_paths": api_paths[:300],
            "api_hosts": len(seen_ep),
            "secrets": {k: v[:10] for k, v in secrets.items()},
            "domains": got["domains"][:1000], "ips": got["ips"][:1000]}


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
            wildcard: str = "basic", timeout: int = 1800) -> dict:
    """Active DNS brute force via ksubdomain (stateless raw-socket engine).

    Requires Npcap (Windows) / libpcap (Linux) and usually admin rights.
    Much faster than dnsx-based brute force: 10k~100k queries/s.
    """
    raw = domain
    domain = core.canon_domain(domain)
    if not domain:
        raise core.FindInfoError("invalid domain: " + str(raw))
    scope = core.Scope.load()
    ok, rule = scope.check(domain)
    if not ok and scope.enabled:
        raise core.ScopeError("scope denied for " + domain + " (" + rule + ")")
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
    blob = ""
    if outfile.exists():
        try:
            blob = outfile.read_text(encoding="utf-8", errors="replace")
            data = json.loads(blob) if blob.strip().startswith("[") else []
            for item in data:
                sub = core.canon_domain(item.get("subdomain", ""))
                ips = [core.canon_ip(x) for x in (item.get("answers") or [])]
                ips = [x for x in ips if x]
                if sub:
                    rows.append({"domain": sub, "a": ips})
        except Exception as exc:
            core.log("ksubdomain json parse failed: " + repr(exc))
        finally:
            try:
                outfile.unlink()
            except Exception:
                pass
    if not rows:
        # fallback: parse "sub => ip => ip" lines from stdout
        for ln in (out or "").splitlines():
            m = re.search(r"([a-z0-9][a-z0-9.\-]*\." + re.escape(domain) + r")\s*=>\s*([0-9.,\s]+)", ln, re.I)
            if not m:
                continue
            sub = core.canon_domain(m.group(1))
            ips = [core.canon_ip(x) for x in re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(2))]
            if sub:
                rows.append({"domain": sub, "a": [x for x in ips if x]})
    for r in rows:
        for ip in r["a"]:
            store.upsert_asset("ip", ip, source="ksubdomain", confidence=0.6,
                               passivity="active", parent=r["domain"])
        store.upsert_asset("domain", r["domain"], source="ksubdomain", confidence=0.7,
                           passivity="active", parent=domain)
    return {"domain": domain, "rc": rc, "count": len(rows),
            "records": rows[:2000], "stderr": err[-500:]}


# ---------------------------------------------------------------- 12. onepass (Rust passive collector)
def t_onepass(store, domain: str, sources: list[str] | None = None,
              timeout: int = 240, min_confidence: float = 0.0) -> dict:
    """Passive subdomain collection via the bundled Rust binary (bin/onepass.exe).

    onepass aggregates 15 sources (8 usable without any API key) and returns
    per-record provenance. It is the fastest cold-start collector in this skill.
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
        raise core.FindInfoError("onepass returned non-JSON: " + out[:200] + " " + err[:200])
    if not data.get("ok") and data.get("error"):
        raise core.FindInfoError("onepass: " + str(data.get("error")) + " " +
                                 str(data.get("message", "")))
    rows = []
    for rec in data.get("records", []):
        d = core.canon_domain(rec.get("domain", ""))
        if not d:
            continue
        conf = float(rec.get("confidence") or 0.5)
        if conf < min_confidence:
            continue
        srcs = rec.get("sources") or []
        store.upsert_asset("domain", d, source="onepass:" + ",".join(srcs),
                           confidence=conf, passivity="passive", parent=domain,
                           attrs={"onepass_sources": srcs})
        rows.append({"domain": d, "sources": srcs, "confidence": conf})
    core.log("onepass: " + str(len(rows)) + " hosts from " +
             str(data.get("sources_ok", 0)) + " sources")
    return {
        "domain": domain,
        "count": len(rows),
        "elapsed_ms": data.get("elapsed_ms"),
        "sources_ok": data.get("sources_ok"),
        "sources_error": data.get("sources_error"),
        "per_source": [{"id": s.get("id"), "status": s.get("status"),
                        "found": s.get("found"), "code": s.get("code")}
                       for s in data.get("sources", [])],
        "domains": rows[:2000],
    }


# ---------------------------------------------------------------- doctor
VERSION_ARGS = ["-version", "--version", "-V", "-h"]


def doctor() -> dict:
    names = ["enscan", "subfinder", "httpx", "dnsx", "naabu", "tlsx", "cdncheck",
             "uncover", "katana", "chaos", "gau", "ffuf", "ksubdomain", "onepass"]
    report = {}
    for n in names:
        try:
            exe = core.tool(n)
        except core.ToolMissing:
            report[n] = {"present": False}
            continue
        ver = ""
        for arg in VERSION_ARGS:
            rc, out, err = core.run([exe, arg], timeout=20)
            blob = (out or "") + (err or "")
            m = re.search(r"(v?\d+\.\d+\.\d+[\w.\-]*)", blob)
            if m:
                ver = m.group(1)
                break
        report[n] = {"present": True, "path": exe, "version": ver}
    keys = {k: bool(api_key_or_empty(k)) for k in ["fofa", "quake", "hunter", "chaos",
                                                   "securitytrails", "virustotal", "urlscan"]}
    return {"python": "ok", "tools": report, "api_keys": keys,
            "scope": core.Scope.load().summary(),
            "bin_dir": str(core.BIN), "db": str(core.DATA / "findinfo.db"),
            "root": str(core.ROOT), "home": str(core.HOME)}


def api_key_or_empty(name: str) -> str:
    try:
        return core.api_key(name)
    except Exception:
        return ""
