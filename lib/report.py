"""Final deliverables: one collection pass, two audiences.

    report.html      default human dashboard (self-contained, printable)
    report.md        optional text digest (chat / wiki / terminal)
    report.json      optional machine digest for scripts (stable schema)

Why scoping matters here: the asset graph is shared across engagements by
design (multi-agent merge), and a crawl is allowed to follow links it finds, so
a query without a scope suffix will happily render another target's hosts as
findings. Every read below is therefore scoped; out-of-scope rows are counted
but never presented as findings.

Why the report carries "gaps": a deliverable that only lists what was found
reads as complete when it is not. Stages that never ran, benchmark DNS
answers, and crawl pollution are part of the result.
"""
from __future__ import annotations

import html as _html
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from . import core

SCHEMA = "findinfo.report/1"

# ---------------------------------------------------------------- rules
# 198.18.0.0/15 is the benchmark range Clash/TUN fake-ip DNS hands out. An
# answer in this range means "the resolver is a proxy", not "the host is there".
BENCHMARK_NETS = [ipaddress.ip_network("198.18.0.0/15")]
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

SENSITIVE_PATHS = [
    (r"(^|/)\.git(/|$)", "exposed git repository", "high"),
    (r"(^|/)\.svn(/|$)", "exposed svn repository", "high"),
    (r"(^|/)\.hg(/|$)", "exposed mercurial repository", "medium"),
    (r"(^|/)\.env(\b|$)", "env file exposure", "high"),
    (r"(^|/)\.ds_store$", "directory index residue", "low"),
    (r"swagger|openapi|api-docs|swagger-ui", "API docs entry", "medium"),
    (r"actuator|/druid|jolokia|/metrics\b|heapdump|threaddump", "ops endpoint", "high"),
    (r"phpinfo|/server-status|/server-info|/trace\b", "info disclosure page", "medium"),
    (r"(backup|\.bak|\.sql|\.zip|\.tar\.gz|\.tgz|\.7z|\.rar|\.dump|\.old)(\?|$)",
     "backup/archive file", "high"),
    (r"(^|/)(admin|manage|manager|console|dashboard|backend|system)(/|$)", "admin entry", "medium"),
    (r"(^|/)(login|signin|sso|oauth|cas|auth)(/|$)", "auth entry", "low"),
    (r"upload|fileupload|attach", "file upload point", "medium"),
    (r"(^|/)(export|download|print)(/|$)", "export/download point", "low"),
    (r"graphql|/api/v[0-9]|/rest/|/internal/", "API surface", "low"),
]
SENSITIVE_PATHS = [(re.compile(p, re.I), label, sev) for p, label, sev in SENSITIVE_PATHS]

PARAM_RULES = [
    (r"^(url|uri|redirect|redirect_uri|next|return|returnurl|callback|target|dest|"
     r"destination|goto|jump|to|out|link|src|image|domain|host)$",
     "redirect param (SSRF / open redirect)", "medium"),
    (r"^(file|filename|path|dir|folder|page|template|include|require|load|read|"
     r"doc|document|download|attach)$",
     "path param (arbitrary file read)", "high"),
    (r"^(cmd|exec|command|shell|run|system|code|eval|func|method|function|class)$",
     "command param (command execution)", "high"),
    (r"^(id|uid|userid|user_id|account|orderid|order_id|no|num|key|token|sn|pid|sid)$",
     "identifier param (IDOR)", "medium"),
    (r"^(sql|query|where|order|sort|filter|search|keyword|q)$",
     "query param (injection surface)", "low"),
    (r"^(xml|data|json|payload|body|content|html|text)$",
     "content param (XXE / stored)", "low"),
]
PARAM_RULES = [(re.compile(p, re.I), label, sev) for p, label, sev in PARAM_RULES]

# Products that are interesting on their own: they either expose admin surfaces
# or have a long history of unauthenticated RCE / info leak.
TECH_INTEREST = {
    "weblogic": "WebLogic", "jboss": "JBoss", "tomcat": "Tomcat", "shiro": "Shiro",
    "struts": "Struts2", "thinkphp": "ThinkPHP", "spring": "Spring",
    "jenkins": "Jenkins", "gitlab": "GitLab", "confluence": "Confluence",
    "zabbix": "Zabbix", "nacos": "Nacos", "apollo": "Apollo", "kibana": "Kibana",
    "grafana": "Grafana", "elasticsearch": "Elasticsearch", "solr": "Solr",
    "rabbitmq": "RabbitMQ", "minio": "MinIO", "harbor": "Harbor", "druid": "Druid",
    "swagger": "Swagger", "jupyter": "Jupyter", "airflow": "Airflow",
    "superset": "Superset", "hadoop": "Hadoop", "yarn": "YARN", "hue": "Hue",
    "consul": "Consul", "etcd": "etcd", "rancher": "Rancher", "portainer": "Portainer",
    "php": "PHP", "asp.net": "ASP.NET", "iis": "IIS",
}

ADMIN_WORDS = ("后台", "管理", "登录", "运维", "监控", "控制", "平台", "系统", "门户",
               "admin", "manage", "console", "login", "dashboard", "portal", "system")


# ---------------------------------------------------------------- helpers
def _uniq(seq):
    out, seen = [], set()
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _as_int(value):
    try:
        if value is None or value == "":
            return None
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value).split(",") if x.strip()]


def _ip_kind(ip):
    """benchmark (fake-ip DNS) / private (real intranet leak) / public."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "unknown"
    for net in BENCHMARK_NETS:
        if addr in net:
            return "benchmark"
    for net in PRIVATE_NETS:
        if addr in net:
            return "private"
    return "public"


def _scope_suffixes(match):
    return [d for d in (core.canon_domain(m) for m in (match or [])) if d]


def _in_scope(host, suffixes):
    if not suffixes:
        return True
    h = (host or "").lower().strip(".")
    return any(h == s or h.endswith("." + s) for s in suffixes)


# Which binary produced an asset. The store keeps raw source ids
# ("onepass:crt.sh", "fofa-gateway", "vhost"); tokens are normalized through
# core.split_source_token (alias- and order-independent), and provenance is
# resolved to a label here for display only.
TOOL_LABELS = {
    "onepass": "onepass passive aggregation",
    "subfinder": "subfinder",
    "dnsx": "dnsx resolver",
    "httpx": "httpx liveness",
    "katana": "katana crawler",
    "crawl": "katana crawler",
    "fofa-gateway": "FOFA mapping",
    "icp-gateway": "ICP filing",
    "icp": "ICP filing",
    "icp-seed": "ICP reverse-lookup seed",
    "enscan": "ENScan equity/ICP",
    "vhost": "hostCollision differential",
    "leak-extract": "jsleak page/JS extraction",
    "jsleak": "jsleak page/JS extraction",
    "system-dns": "system DNS",
    "ksubdomain": "ksubdomain brute force",
    "naabu": "naabu port scan",
    "nmap": "nmap port scan",
    "crt.sh": "crt.sh certificates",
    "hackertarget": "HackerTarget",
    "rapiddns": "RapidDNS",
    "subdomain_center": "SubdomainCenter",
    "otx": "AlienVault OTX",
    "alienvault": "AlienVault OTX",
    "chaos": "Chaos",
    "uncover": "uncover",
    "passive": "passive source",
}


def _tool_label(tool):
    return TOOL_LABELS.get((tool or "").lower(), tool or "?")


def _provenance(raw):
    """Resolve a raw sources cell into (labels, upstream ids).

    Normalization lives in core (split_source_token + upstream_id), so the
    store and this report agree on what counts as an independent source:
    'onepass:crt.sh,subfinder,crt.sh' has ONE crt.sh upstream however it was
    wrapped, ordered or re-run.
    """
    labels, upstreams = [], []
    for tok in (raw or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        tool, detail = core.split_source_token(tok)
        if not tool:
            continue
        up = core.upstream_id(tool, detail)
        label = _tool_label(tool)
        if detail:
            label = label + "/" + _tool_label(core.upstream_id(tool, detail))
        if label not in labels:
            labels.append(label)
        if up and up not in upstreams:
            upstreams.append(up)
    return labels, upstreams


def _buckets(values, edges, labels):
    counts = [0] * len(labels)
    for v in values:
        for i, e in enumerate(edges):
            if v <= e:
                counts[i] += 1
                break
        else:
            counts[-1] += 1
    return list(zip(labels, counts))


def _now_label():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- collect
def _asset_in_scope(a: dict, suffixes: list[str]) -> bool:
    """Scope test per asset KIND, not one rule for everything.

    domain: hostname suffix on canonical.
    url:    parse the hostname out of the canonical URL first.
    ip:     the trusted attribution in this model is assets.parent (the
            in-scope domain that resolved to it). A shared IP is therefore
            reported as attributed-to-scope, never as exclusively owned --
            out-of-scope hosts on the same IP simply do not appear.
    Empty suffixes = whole shared library (caller warns about it).
    """
    if not suffixes:
        return True
    kind = a.get("kind")
    if kind == "ip":
        return _in_scope(a.get("parent") or "", suffixes)
    if kind == "url":
        host = core.split_url(a.get("canonical") or "")[0] or ""
        return _in_scope(host, suffixes)
    return _in_scope(a.get("canonical") or "", suffixes)


def collect(store, match=None, min_conf=0.4, limit=300, ep_limit=400,
            ep_scan=60000, engagement="default") -> dict:
    """Read the asset graph once and shape it into a report digest."""
    if match and not _scope_suffixes(match):
        # an explicit scope that canon_domain rejects is an ERROR, never a
        # silent fallback to the whole shared library
        raise core.FindInfoError(
            "no valid domain in match list: " + ",".join(str(m) for m in match))
    suffixes = _scope_suffixes(match)
    scope_auto = False
    target_label = ""
    if not suffixes:
        # Fall back to the last run's target so an agent can call report
        # without repeating the seeds; the DB itself has no notion of a target.
        try:
            row = store.conn.execute(
                "SELECT target FROM runs ORDER BY id DESC LIMIT 1").fetchone()
            if row and row["target"]:
                target_label = str(row["target"])
                suffixes = _scope_suffixes(target_label.split(","))
                scope_auto = bool(suffixes)
        except Exception:
            pass

    all_counts = store.count_assets()
    kept, dropped = [], 0
    for a in store.get_assets(kind=None, min_conf=min_conf, limit=10 ** 9):
        if _asset_in_scope(a, suffixes):
            kept.append(a)
        else:
            dropped += 1

    domains, ips, urls = [], [], []
    for a in kept:
        kind = a.get("kind")
        if kind == "domain":
            domains.append(a)
        elif kind == "ip":
            ips.append(a)
        elif kind == "url":
            urls.append(a)

    # -- endpoints: the table is shared across engagements too, filter first
    try:
        ep_rows = store.get_endpoints(limit=ep_scan)
    except Exception:
        ep_rows = []
    ep_scoped, ep_noise, ep_unattributed = [], 0, 0
    for e in ep_rows:
        host = (e.get("asset") or "").strip()
        if not host or host == "leak":
            ep_unattributed += 1
            continue
        if _in_scope(host, suffixes):
            ep_scoped.append(e)
        else:
            ep_noise += 1

    by_host = {}
    for e in ep_scoped:
        by_host.setdefault(e["asset"], []).append(e)

    signals = []
    hosts = []
    tech_counter = Counter()
    port_counter = Counter()
    status_counter = Counter()
    source_counter = Counter()
    passivity_counter = Counter()
    confidence_values = []
    ip_groups = {}
    fake_ip_count = 0

    for a in domains:
        host = a.get("canonical") or ""
        attrs = a.get("attrs") or {}
        status = _as_int(attrs.get("status"))
        tech = _as_list(attrs.get("tech"))
        title = (attrs.get("title") or "").strip()
        ip = (attrs.get("ip") or "").strip()
        port = _as_int(attrs.get("port"))
        cdn = attrs.get("cdn")
        provenance, upstreams = _provenance(a.get("sources"))
        sources = sorted(core.source_tools(a.get("sources") or ""))
        conf = float(a.get("confidence") or 0)
        passivity = a.get("passivity") or ""
        via = attrs.get("via") or ""
        internal = via in ("hostCollision", "curl-diff") or "vhost" in sources

        # Count each asset once per *upstream origin*: onepass relays 15
        # upstreams into the same column, crt.sh is reachable both directly
        # and through onepass -- counting wrappers would fake corroboration.
        for t in upstreams:
            source_counter[t] += 1
        if passivity:
            passivity_counter[passivity] += 1
        confidence_values.append(conf)
        for t in tech:
            tech_counter[t] += 1
        if port:
            port_counter[port] += 1
        if status is not None:
            status_counter[str(status)] += 1
        ip_kind = _ip_kind(ip) if ip else ""
        if ip_kind == "benchmark":
            fake_ip_count += 1
        elif ip_kind in ("public", "private"):
            ip_groups.setdefault(ip, []).append(host)

        eps = by_host.get(host, [])
        params = sorted({p for e in eps for p in _as_list(e.get("params"))})
        reasons = []
        score = 0

        if internal:
            score += 50
            reasons.append("internal service found via Host-header collision (" + (via or "vhost") + ")")
            signals.append({"severity": "high", "kind": "internal_service",
                            "host": host,
                            "detail": "internal service absent from public DNS, ip=" + (ip or "?")})
        if status in (401, 403):
            score += 12
            reasons.append("access restricted (" + str(status) + "): exists but needs credentials")
        elif status in (200, 201):
            score += 5
        elif status in (500, 502, 503):
            reasons.append("server error (" + str(status) + "): may leak stack traces")

        low_title = title.lower()
        if any(w in low_title for w in ADMIN_WORDS):
            score += 20
            reasons.append("title suggests an admin/login entry")
            if status in (200, 301, 302):
                signals.append({"severity": "medium", "kind": "admin_panel", "host": host,
                                "detail": "possible admin/auth page: " + (title[:60] or "(no title)")})

        for t in tech:
            low = t.lower()
            for probe, label in TECH_INTEREST.items():
                if probe in low:
                    score += 8
                    reasons.append("fingerprint: " + label)
                    break

        sensitive = []
        for e in eps:
            path = e.get("path") or ""
            for rx, label, sev in SENSITIVE_PATHS:
                if rx.search(path):
                    sensitive.append({"path": path[:120], "label": label, "severity": sev})
                    score += 25 if sev == "high" else 10
                    signals.append({"severity": sev, "kind": "sensitive_path", "host": host,
                                    "detail": label + " -> " + path[:120]})
                    break

        if params:
            score += 6
            reasons.append(str(len(params)) + " params: " + ", ".join(params[:5]))
            for p in params:
                for rx, label, sev in PARAM_RULES:
                    if rx.match(p):
                        signals.append({"severity": sev, "kind": "param_surface",
                                        "host": host,
                                        "detail": label + " -> " + p})
                        score += 8 if sev == "high" else 3
                        break

        if port and port not in (80, 443):
            score += 6
            reasons.append("non-standard port " + str(port))
        if cdn:
            score -= 8
            reasons.append("CDN fronting " + str(cdn))

        # A host with hundreds of sensitive endpoints would otherwise score in
        # the hundreds and drown the ranking; the cap keeps the column readable
        # while "reasons" still carries every contributing signal.
        score = min(score, 99)
        if score >= 45:
            priority = "high"
        elif score >= 18:
            priority = "medium"
        elif score >= 1:
            priority = "low"
        else:
            priority = "info"

        hosts.append({
            "host": host, "status": status, "title": title[:120], "tech": tech[:12],
            "ip": ip, "port": port, "ip_kind": ip_kind, "cdn": cdn,
            "webserver": (attrs.get("webserver") or "")[:40],
            "url": attrs.get("url") or "",
            "sources": _uniq(sources)[:8],
            "provenance": provenance[:8], "discovered_by": upstreams[:8],
            "confidence": round(conf, 2),
            "passivity": passivity, "internal": bool(internal),
            "parent": a.get("parent") or "",
            "endpoints": len(eps), "params": params[:12], "sensitive": sensitive[:6],
            "score": score, "priority": priority, "reasons": _uniq(reasons)[:6],
            "first_seen": a.get("first_seen") or "",
            "last_seen": a.get("last_seen") or "",
        })

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    hosts.sort(key=lambda h: (0 if h["internal"] else 1, order[h["priority"]],
                              -h["score"], h["host"]))

    # -- endpoints worth a human look (deduped by host + path + params)
    ep_records, seen_ep = [], set()
    for e in ep_scoped:
        host = e["asset"]
        path = e.get("path") or "/"
        params = _as_list(e.get("params"))
        status = _as_int(e.get("status"))
        why = []
        for rx, label, sev in SENSITIVE_PATHS:
            if rx.search(path):
                why.append(label)
                break
        for p in params:
            for rx, label, sev in PARAM_RULES:
                if rx.match(p):
                    why.append(label.split("（")[0])
                    break
        if not why and not params:
            continue
        key = (host, path, ",".join(params))
        if key in seen_ep:
            continue
        seen_ep.add(key)
        ep_records.append({
            "host": host, "method": e.get("method") or "GET", "path": path[:160],
            "params": params[:10], "status": status,
            "title": (e.get("title") or "")[:80], "source": e.get("source") or "",
            "provenance": _tool_label(e.get("source") or ""),
            "why": _uniq(why)[:3] or ["has parameters"],
        })
    ep_records.sort(key=lambda r: (0 if r["status"] in (401, 403, 500) else 1,
                                   -len(r["params"]), r["host"], r["path"]))
    ep_total_interesting = len(ep_records)
    ep_records = ep_records[:ep_limit]

    # -- leak evidence: internal addresses and names found in pages / JS
    leak_domains = sorted({a["canonical"] for a in domains
                           if "leak-extract" in core.source_tools(a.get("sources") or "")})
    leak_ips = sorted({a["canonical"] for a in ips
                       if "leak-extract" in core.source_tools(a.get("sources") or "")})
    internal_ips = [ip for ip in ip_groups if _ip_kind(ip) == "private"]

    # -- which stages actually ran (checkpoints live in steps)
    stages = []
    try:
        for row in store.conn.execute(
                "SELECT step,status,updated_at FROM steps WHERE engagement=? ORDER BY step",
                (engagement,)):
            stages.append({"step": row["step"], "status": row["status"],
                           "updated_at": row["updated_at"]})
    except Exception:
        pass

    # -- environment / data-quality warnings (part of the result, not noise)
    warnings = []
    # A passive-only collection has no liveness/tech data at all. Reporting
    # "live: 0" without saying why would read as "nothing is up", which is a
    # different (and false) conclusion.
    ran = {s["step"] for s in stages}
    if "probe" not in ran and hosts:
        warnings.append("liveness probe (probe) was not run: " + str(len(hosts)) +
                        " domains have no status/title/fingerprint; live=0 means 'not probed', not 'all dead'.")
    # "crawl not run" must be about EVIDENCE, not the checkpoint table: a
    # standalone `crawl`/`extract` never writes `steps`, so a report built
    # after exactly that run claimed the crawler had not run at all (seen on
    # the 南开大学 run: 40k endpoints and a "crawl was not run" warning).
    crawled = any((e.get("source") or "") in ("katana", "jsleak")
                  for e in (store.get_endpoints(limit=2000) or []))
    if not crawled and "crawl" not in ran and hosts:
        warnings.append("crawl was not run: an empty endpoint table does not mean the sites have no APIs.")
    if fake_ip_count:
        warnings.append(
            "detected " + str(fake_ip_count) + " domains resolving into 198.18.0.0/15 (Clash/TUN fake-IP). "
            "liveness and shared-IP aggregation are unreliable here; vhost needs real IPs.")
    if ep_noise:
        warnings.append(str(ep_noise) + " endpoint rows are outside the target scope "
                        "(crawler overreach or cross-engagement residue); excluded from conclusions.")
    if dropped:
        warnings.append(str(dropped) + " assets are outside the target scope "
                        "(shared store or other engagements); excluded.")
    if urls:
        warnings.append(str(len(urls)) + " URL assets recorded for JS/endpoint reflow only; not visited one by one.")
    if not suffixes:
        warnings.append("no scope determined: this report covers the whole shared store and may mix in other engagements; pass --match to scope it.")
    # a display budget cut is NOT "collection complete": say it explicitly
    if len(hosts) > limit:
        warnings.append("hosts truncated to first " + str(limit) + " of " + str(len(hosts)) +
                        " (adjust with --limit); the full set is in the store (assets --kind domain).")
    if ep_total_interesting > len(ep_records):
        warnings.append("endpoints truncated to first " + str(len(ep_records)) + " of " +
                        str(ep_total_interesting) + " (adjust with --ep-limit).")

    # -- next steps: each line is a concrete command or decision
    next_steps = []
    if not suffixes:
        next_steps.append("re-run report --match <scope> so other engagements in the shared store cannot leak into this one.")
    if fake_ip_count:
        next_steps.append("disable TUN / switch to a direct egress and re-run dns and probe; or take real IPs from the mapping platforms and run vhost --ip <real-ip> --domain <scope> --wordlist vhost.")
    if not leak_ips and not internal_ips:
        next_steps.append("run extract --from-store --domain <scope> on live hosts to "
                          "pull internal IPs and endpoints from JS.")
    if ep_total_interesting:
        top_hosts = _uniq([r["host"] for r in ep_records])[:5]
        next_steps.append("review parameterised endpoints first: " + ", ".join(top_hosts) +
                          " (read-only echo-style checks only at first).")
    if any(h["status"] in (401, 403) for h in hosts):
        next_steps.append("401/403 hosts need credentials or allowlisting; queue them for manual "
                          "review instead of blind brute force.")
    if not any(h["internal"] for h in hosts):
        next_steps.append("no internal services yet: confirm a real shared "
                          "IP exists, then run vhost --ip <ip> --domain "
                          "<scope> --wordlist vhost.")
    # only SUCCEEDED checkpoints count as executed: a failed stage is not
    # "done" merely because a steps row exists. A PARTIAL stage (some sources
    # ok, some dead) is executed-but-incomplete: listing it under "not run"
    # contradicted status.coverage.done_stages and sent agents to redo work
    # that had already half-succeeded. It gets its own bucket.
    done_steps = {x["step"] for x in stages
                  if x.get("status") in ("done", "partial")}
    failed_steps = [x["step"] for x in stages if x.get("status") == "failed"]
    partial_steps = [x["step"] for x in stages if x.get("status") == "partial"]
    missing = [s for s in ("entity", "onepass", "certs", "subs", "dns", "probe", "ipagg",
                           "ports", "vhost", "crawl", "extract") if s not in done_steps]
    if missing:
        next_steps.append("stages not run: " + ", ".join(missing) + " (fill as needed; active stages need authorisation).")
    if failed_steps:
        next_steps.append("failed stages (re-running the job retries them automatically): " + ", ".join(failed_steps) + ".")
    if partial_steps:
        next_steps.append("partially succeeded (partial results kept; a re-run only retries dead sources): " +
                          ", ".join(partial_steps) + ".")
    next_steps.append("after delivery, run clean --keep <scope> so the next engagement does not inherit this one's assets.")

    # -- chart series (rendered by build_html, kept here so both outputs agree)
    status_pairs = sorted(status_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    tech_pairs = tech_counter.most_common(12)
    tool_pairs = [[_tool_label(k), v] for k, v in source_counter.most_common(12)]
    source_pairs = source_counter.most_common(10)
    port_pairs = [[str(k), v] for k, v in port_counter.most_common(8)]
    conf_pairs = _buckets(confidence_values, [0.4, 0.7, 0.9, 4.0],
                          ["<0.40", "0.40-0.70", "0.70-0.90", ">=0.90"])
    ip_pairs = sorted(((ip, len(v)) for ip, v in ip_groups.items()),
                      key=lambda kv: (-kv[1], kv[0]))[:10]

    counts = {
        "domains_in_scope": len(domains),
        "domains_dropped": dropped,
        "live": sum(1 for h in hosts if h["status"] is not None),
        "interesting": sum(1 for h in hosts if h["priority"] in ("high", "medium")),
        "internal_services": sum(1 for h in hosts if h["internal"]),
        "ips_in_scope": len(ips),
        "real_ips": len(ip_groups),
        "fake_ips": fake_ip_count,
        "urls": len(urls),
        "endpoints_in_scope": len(ep_scoped),
        "endpoints_interesting": ep_total_interesting,
        "endpoints_noise": ep_noise,
        "endpoints_unattributed": ep_unattributed,
        "leak_domains": len(leak_domains),
        "leak_ips": len(leak_ips),
        "stages_failed": len(failed_steps),
    }

    return {
        "schema": SCHEMA,
        "generated_at": core.now(),
        "scope": {"match": suffixes, "auto": scope_auto, "target": target_label,
                  "engagement": engagement},
        "counts": counts,
        "assets_total": all_counts,
        "environment": {"platform": core.PLATFORM, "warnings": warnings},
        "hosts": hosts[:limit],
        # html/md render the whole list; json keeps the capped view so an
        # agent can always read the digest in one go
        "hosts_all": hosts,
        "hosts_total": len(hosts),
        "internal_services": [h for h in hosts if h["internal"]][:limit],
        "endpoints": ep_records,
        "signals": signals[:200],
        "leaks": {"domains": leak_domains[:200], "ips": leak_ips[:200],
                  "private_ips": internal_ips[:50]},
        "ip_groups": [{"ip": ip, "hosts": sorted(hs)[:20], "hosts_count": len(hs)}
                      for ip, hs in sorted(ip_groups.items(),
                                           key=lambda kv: (-len(kv[1]), kv[0]))[:30]],
        "provenance": {
            "sources": dict(source_counter.most_common(20)),
            "passivity": dict(passivity_counter),
            "confidence": dict(conf_pairs),
        },
        "stages": stages,
        "next_steps": next_steps,
        "charts": {"status": status_pairs, "tech": tech_pairs, "sources": source_pairs,
                   "tools": tool_pairs,
                   "ports": port_pairs, "confidence": conf_pairs, "ip_share": ip_pairs},
        "truncated": {"hosts": len(hosts) > limit,
                      "endpoints": ep_total_interesting > len(ep_records)},
    }


# ---------------------------------------------------------------- markdown
def _md_escape(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def _md_cell(value, dash="-"):
    text = _md_escape(value)
    return text if text else dash


def build_md(data) -> str:
    c = data["counts"]
    scope = data["scope"]
    out = []
    scope_txt = ", ".join(scope["match"]) if scope["match"] else "(未限定：整库)"
    auto = "（自动取自最近一次 run.target）" if scope["auto"] else ""
    out.append("# 资产测绘报告 · " + scope_txt)
    out.append("")
    out.append("- 生成时间：" + data["generated_at"])
    out.append("- 目标范围：" + scope_txt + auto)
    out.append("- 引擎/平台：" + str(data["environment"].get("platform") or ""))
    out.append("- schema：`" + data["schema"] + "`（同目录 report.json 为机器可读版）")
    out.append("")

    out.append("## 1. 总览")
    out.append("")
    out.append("| 指标 | 数值 | 说明 |")
    out.append("| --- | --- | --- |")
    out.append("| 范围内域名 | " + str(c["domains_in_scope"]) + " | 已按目标域过滤 |")
    out.append("| 存活主机 | " + str(c["live"]) + " | 有 HTTP 状态码 |")
    out.append("| 高/中优先 | " + str(c["interesting"]) + " | 综合评分结果，见第 3 节 |")
    out.append("| 内部服务 | " + str(c["internal_services"]) + " | Host 头碰撞命中 |")
    out.append("| 端点（范围内） | " + str(c["endpoints_in_scope"]) + " | 待复核 "
               + str(c["endpoints_interesting"]) + " 条 |")
    out.append("| 泄露情报 | " + str(c["leak_domains"]) + " 域名 / " + str(c["leak_ips"])
               + " IP | 来自页面与 JS |")
    out.append("| 已隔离噪声 | 资产 " + str(c["domains_dropped"]) + " / 端点 "
               + str(c["endpoints_noise"]) + " | 不属于本项目，未计入 |")
    out.append("")

    warnings = data["environment"].get("warnings") or []
    if warnings:
        out.append("## 2. 范围与环境告警")
        out.append("")
        for w in warnings:
            out.append("- " + w)
        out.append("")

    hosts = data.get("hosts_all") or data["hosts"]
    out.append("## 3. 高价值主机（前 " + str(min(len(hosts), 40)) + " / 共 "
               + str(data["hosts_total"]) + "）")
    out.append("")
    if hosts:
        out.append("| 优先 | 主机 | 状态 | 标题 | 指纹 | 来源 | 评分 | 依据 |")
        out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for h in hosts[:40]:
            out.append("| " + " | ".join([
                h["priority"],
                "`" + h["host"] + "`",
                str(h["status"]) if h["status"] is not None else "-",
                _md_cell(h["title"])[:48],
                _md_cell(", ".join(h["tech"][:4])),
                ", ".join(h["provenance"][:4]) or "-",
                str(h["score"]),
                _md_cell("；".join(h["reasons"][:3]))[:110],
            ]) + " |")
    else:
        out.append("_无范围内主机。_")
    out.append("")

    internal = data["internal_services"]
    if internal:
        out.append("## 4. 内部服务（Host 头碰撞）")
        out.append("")
        out.append("| 主机 | IP | 状态 | 标题 | 来源 |")
        out.append("| --- | --- | --- | --- | --- |")
        for h in internal:
            out.append("| " + " | ".join([
                "`" + h["host"] + "`", _md_cell(h["ip"]),
                str(h["status"]) if h["status"] is not None else "-",
                _md_cell(h["title"])[:40], _md_cell(", ".join(h["sources"][:3])),
            ]) + " |")
        out.append("")
    else:
        # Keep the numbering complete and say WHY it is empty. Silently
        # skipping the section made the report jump 3 -> 5, so a reader could
        # not tell "no internal services found" from "this stage never ran".
        out.append("## 4. 内部服务（Host 头碰撞）")
        out.append("")
        ran = {s.get("step") for s in (data.get("stages") or []) if isinstance(s, dict)}
        if "vhost" in ran:
            out.append("_范围内未发现内部服务。_")
        else:
            out.append("_未执行 vhost（Host 头碰撞）阶段：内部服务为空不代表没有内部系统。_")
        out.append("")

    eps = data["endpoints"]
    out.append("## 5. 待复核端点（" + str(len(eps)) + " / 共 "
               + str(c["endpoints_interesting"]) + "）")
    out.append("")
    if eps:
        out.append("| 主机 | 方法 | 路径 | 参数 | 状态 | 关注点 |")
        out.append("| --- | --- | --- | --- | --- | --- |")
        for e in eps[:40]:
            out.append("| " + " | ".join([
                "`" + e["host"] + "`", e["method"],
                "`" + _md_escape(e["path"])[:80] + "`",
                _md_cell(", ".join(e["params"][:5])),
                str(e["status"]) if e["status"] is not None else "-",
                _md_cell("；".join(e["why"])),
            ]) + " |")
    else:
        out.append("_无带参数或敏感路径端点。_")
    out.append("")

    leaks = data["leaks"]
    out.append("## 6. 泄露情报")
    out.append("")
    if leaks["domains"] or leaks["ips"] or leaks["private_ips"]:
        if leaks["domains"]:
            out.append("- 泄露域名（" + str(len(leaks["domains"])) + "）："
                       + ", ".join(leaks["domains"][:40]))
        if leaks["ips"]:
            out.append("- 泄露公网 IP（" + str(len(leaks["ips"])) + "）："
                       + ", ".join(leaks["ips"][:40]))
        if leaks["private_ips"]:
            out.append("- 内网 IP（" + str(len(leaks["private_ips"])) + "）："
                       + ", ".join(leaks["private_ips"][:40]))
        out.append("")
    else:
        out.append("_未发现泄露域名/IP"
                   + ("" if "extract" in {x.get("step") for x in (
                       data.get("stages") or []) if isinstance(x, dict)}
                      else "；且未执行 extract（内容/JS 提取）阶段")
                   + "。_")
        out.append("")

    prov = data["provenance"]
    out.append("## 7. 来源与可信度")
    out.append("")
    if prov.get("sources"):
        out.append("| 工具 | 覆盖资产数 |")
        out.append("| --- | --- |")
        for k, v in data["charts"].get("tools") or []:
            out.append("| " + str(k) + " | " + str(v) + " |")
        out.append("")
        if prov.get("passivity"):
            out.append("- 被动/主动：" + ", ".join(
                str(k) + "=" + str(v) for k, v in prov["passivity"].items()))
        if prov.get("confidence"):
            out.append("- 置信度分布：" + ", ".join(
                str(k) + "=" + str(v) for k, v in prov["confidence"].items()))
        out.append("")
    else:
        out.append("_资产来源信息为空（资产库中没有范围内记录）。_")
        out.append("")

    out.append("---")
    out.append("")
    out.append("同目录 report.html 为可视化看板，可直接转发/打印。"
               "report.json 为可选的机器可读版（--with-json，" + str(data["schema"]) + "）。")
    return "\n".join(out)


# ---------------------------------------------------------------- html helpers
_CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel2:#1d2029;--line:#2a2f3a;--fg:#e6e9ef;
--dim:#9aa3b2;--hi:#ff5c5c;--md:#ffb454;--lo:#5bc0eb;--ok:#3ddc97;--accent:#7c9cff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.6 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
header{padding:28px 32px 18px;border-bottom:1px solid var(--line);
background:linear-gradient(180deg,#191d26,#0f1115)}
h1{margin:0 0 6px;font-size:22px;letter-spacing:.3px}
.meta{color:var(--dim);font-size:12.5px}
.meta b{color:var(--fg);font-weight:600}
main{padding:24px 32px 60px;max-width:1280px;margin:0 auto}
section{margin:0 0 30px}
h2{font-size:15px;margin:0 0 12px;color:var(--accent);letter-spacing:.4px}
h2 span{color:var(--dim);font-weight:400;font-size:12.5px;margin-left:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:26px;font-weight:700;line-height:1.1}
.card .k{color:var(--dim);font-size:12px;margin-top:4px}
.card.hi .n{color:var(--hi)} .card.md .n{color:var(--md)}
.card.ok .n{color:var(--ok)} .card.lo .n{color:var(--lo)}
.banner{background:#2a1d1d;border:1px solid #5a2b2b;border-left:3px solid var(--hi);
border-radius:8px;padding:12px 16px;margin:0 0 10px;font-size:13px}
.banner.info{background:#1a2230;border-color:#2c3d55;border-left-color:var(--lo)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.panel h3{margin:0 0 10px;font-size:13px;color:var(--dim);font-weight:600}
.bars{margin:0}
.bar{display:grid;grid-template-columns:112px 1fr 40px;gap:8px;align-items:center;
margin:5px 0;font-size:12.5px}
.bar .lab{color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .track{background:#12151b;border-radius:4px;height:14px;overflow:hidden}
.bar .fill{height:100%;border-radius:4px;background:linear-gradient(90deg,#3d5afe,#7c9cff)}
.bar .val{text-align:right;color:var(--fg);font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:var(--dim);font-weight:600;padding:7px 10px;
border-bottom:1px solid var(--line);white-space:nowrap;background:var(--panel2)}
td{padding:7px 10px;border-bottom:1px solid #21242d;vertical-align:top}
tr:hover td{background:#1a1e26}
.host{font-family:ui-monospace,Consolas,monospace;color:#cfe0ff;word-break:break-all}
.mono{font-family:ui-monospace,Consolas,monospace;color:#a8b6cc;word-break:break-all}
.tag{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;
border:1px solid var(--line);color:var(--dim);margin:1px 3px 1px 0;white-space:nowrap}
.tag.src{color:#9ad0ff;border-color:#2a4763;background:#132030}
.tag.tch{color:#c8b6ff;border-color:#3b3355;background:#1c1830}
.pri{display:inline-block;min-width:52px;text-align:center;padding:1px 8px;border-radius:5px;
font-size:11px;font-weight:700}
.pri.high{background:#3a1414;color:#ff8080;border:1px solid #6b2020}
.pri.medium{background:#3a2a10;color:#ffc46b;border:1px solid #6b4a1a}
.pri.low{background:#12283a;color:#7fd4ff;border:1px solid #1f4a68}
.pri.info{background:#1c1f27;color:#8d97a8;border:1px solid #2a2f3a}
.st{font-variant-numeric:tabular-nums;font-weight:600}
.st.s2{color:var(--ok)} .st.s3{color:var(--md)} .st.s4{color:#ff8a8a} .st.s5{color:#ff6b6b}
ol.steps{margin:0;padding-left:20px;color:#cdd6e4}
ol.steps li{margin:5px 0}
footer{border-top:1px solid var(--line);margin-top:30px;padding-top:14px;
color:var(--dim);font-size:12px}
.empty{color:var(--dim);font-style:italic;padding:10px 0}
@media print{body{background:#fff;color:#111}header,main{background:#fff}
.panel,.card{background:#fff;border-color:#ddd}.bars .fill{background:#4a63d8}
th{background:#f2f4f8;color:#555}td{border-color:#e5e5e5}.tag{color:#555;border-color:#ddd}
.host{color:#123}.mono{color:#333}h2{color:#2b3fa0}}
/* --- collapsible sections + table controls --- */
.sec-head{display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none;
margin:0 0 12px;padding:0}
.sec-head h2{margin:0}
.sec-head .chev{color:var(--dim);font-size:11px;transition:transform .15s;display:inline-block}
.sec-head.collapsed .chev{transform:rotate(-90deg)}
.sec-head:hover h2{filter:brightness(1.15)}
.sec-body{overflow:hidden}
.sec-body.hidden{display:none}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px;
padding:10px 12px;background:var(--panel2);border:1px solid var(--line);
border-radius:8px;font-size:12.5px}
.toolbar input[type=search],.toolbar select{background:#12151b;border:1px solid var(--line);
color:var(--fg);border-radius:6px;padding:4px 8px;font-size:12.5px;font-family:inherit}
.toolbar input[type=search]{min-width:200px}
.toolbar .cnt{color:var(--dim);margin-left:auto;font-variant-numeric:tabular-nums}
.toolbar .cnt b{color:var(--fg)}
.toolbar button{background:#1d2534;border:1px solid var(--line);color:#b9c6da;
border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer;font-family:inherit}
.toolbar button:hover{background:#25303f;color:#fff}
.pager{display:flex;gap:6px;align-items:center;justify-content:center;margin:12px 0 0;
font-size:12.5px;color:var(--dim)}
.pager button{min-width:30px}
.pager button:disabled{opacity:.35;cursor:default}
.pager .info{margin:0 10px;font-variant-numeric:tabular-nums}
h2 .badge{display:inline-block;margin-left:8px;padding:1px 8px;border-radius:20px;
font-size:11px;background:#1d2534;border:1px solid var(--line);color:#9fb0c8;
font-weight:400;vertical-align:middle}
tr.dup td{opacity:.62}
tr.dup:hover td{opacity:1}
.dupmark{display:inline-block;font-size:10.5px;color:#8d97a8;border:1px dashed #3a4150;
border-radius:4px;padding:0 5px;margin-left:6px}
@media print{.toolbar,.pager{display:none}.sec-body.hidden{display:block}}"""



_JS = """
(function(){
  // ---- collapsible sections -------------------------------------------------
  document.querySelectorAll(".sec-head").forEach(function(h){
    h.addEventListener("click", function(){
      var body = document.getElementById(h.dataset.target);
      if(!body) return;
      var hidden = body.classList.toggle("hidden");
      h.classList.toggle("collapsed", hidden);
    });
  });

  // ---- table controls: search / status / source / dup-collapse / paging ----
  function uniq(arr){var s={},o=[];arr.forEach(function(v){if(v&&!s[v]){s[v]=1;o.push(v);}});return o.sort();}

  document.querySelectorAll(".toolbar").forEach(function(tb){
    var uid = tb.dataset.for;
    var body = document.getElementById(uid);
    if(!body) return;
    var table = body.querySelector("table");
    var tbody = table && table.querySelector("tbody");
    if(!tbody) return;
    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
    var pager = document.querySelector('.pager[data-for="' + uid + '"]');
    var per = pager ? parseInt(pager.dataset.per, 10) : 50;
    var page = 1;
    var hideDup = false;

    // populate status + source dropdowns from the rows themselves
    var statusSel = tb.querySelector('[data-role="status"]');
    var srcSel = tb.querySelector('[data-role="source"]');
    if(statusSel){
      uniq(rows.map(function(r){return r.dataset.status;})).forEach(function(v){
        var o=document.createElement("option"); o.value=v; o.textContent=v; statusSel.appendChild(o);
      });
    }
    if(srcSel){
      var srcs=[];
      rows.forEach(function(r){(r.dataset.src||"").split("|").forEach(function(s){if(s)srcs.push(s);});});
      uniq(srcs).forEach(function(v){
        var o=document.createElement("option"); o.value=v; o.textContent=v; srcSel.appendChild(o);
      });
    }

    function match(r){
      var q = (tb.querySelector('[data-role="q"]')||{}).value || "";
      q = q.trim().toLowerCase();
      if(q && (r.textContent||"").toLowerCase().indexOf(q) === -1) return false;
      if(statusSel && statusSel.value && r.dataset.status !== statusSel.value) return false;
      if(srcSel && srcSel.value && (r.dataset.src||"").split("|").indexOf(srcSel.value) === -1) return false;
      if(hideDup && r.dataset.dup === "1") return false;
      return true;
    }

    function render(){
      var hits = rows.filter(match);
      var pages = Math.max(1, Math.ceil(hits.length / per));
      if(page > pages) page = pages;
      var start = (page - 1) * per, end = start + per;
      rows.forEach(function(r){ r.style.display = "none"; });
      hits.slice(start, end).forEach(function(r){ r.style.display = ""; });
      var shown = tb.querySelector('[data-role="shown"]');
      if(shown) shown.textContent = hits.length;
      if(pager){
        var cur = pager.querySelector('[data-role="cur"]');
        if(cur) cur.textContent = page;
        var pagesEl = pager.querySelector(".info b:last-of-type");
        pager.querySelectorAll("button").forEach(function(b){ b.disabled = false; });
        if(page <= 1){
          pager.querySelector('[data-role="first"]').disabled = true;
          pager.querySelector('[data-role="prev"]').disabled = true;
        }
        if(page >= pages){
          pager.querySelector('[data-role="next"]').disabled = true;
          pager.querySelector('[data-role="last"]').disabled = true;
        }
        var info = pager.querySelector(".info");
        if(info) info.innerHTML = 'page <b>' + page + '</b> / ' + pages;
      }
    }

    tb.addEventListener("input", function(e){
      if(e.target.dataset.role === "q"){ page = 1; render(); }
    });
    tb.addEventListener("change", function(e){
      if(e.target.dataset.role === "status" || e.target.dataset.role === "source"){ page = 1; render(); }
    });
    tb.addEventListener("click", function(e){
      var role = e.target.dataset.role;
      if(role === "reset"){
        tb.querySelectorAll("input,select").forEach(function(el){ el.value = ""; });
        hideDup = false; page = 1; render();
      } else if(role === "duptoggle"){
        hideDup = !hideDup;
        e.target.textContent = hideDup ? "显示重复标题" : "折叠重复标题";
        page = 1; render();
      }
    });
    if(pager){
      pager.addEventListener("click", function(e){
        var role = e.target.dataset.role;
        var pages = Math.max(1, Math.ceil(rows.filter(match).length / per));
        if(role === "first") page = 1;
        else if(role === "prev") page = Math.max(1, page - 1);
        else if(role === "next") page = Math.min(pages, page + 1);
        else if(role === "last") page = pages;
        else return;
        render();
      });
    }
    render();
  });
})();
"""


def _esc(value, limit=None):
    text = _html.escape(str(value if value is not None else ""), quote=True)
    if limit and len(text) > limit:
        text = text[:limit] + "..."
    return text


def _status_class(status):
    if status is None:
        return ""
    if 200 <= status < 300:
        return "s2"
    if 300 <= status < 400:
        return "s3"
    if 400 <= status < 500:
        return "s4"
    return "s5"


def _bars(pairs, limit=12):
    """Horizontal bar chart; pairs is [(label, value)]."""
    pairs = [(str(k), int(v)) for k, v in list(pairs)[:limit]]
    if not pairs:
        return '<div class="empty">no data</div>'
    top = max(v for _, v in pairs) or 1
    rows = []
    for label, value in pairs:
        pct = max(2, int(round(value * 100.0 / top)))
        rows.append(
            '<div class="bar"><div class="lab" title="' + _esc(label) + '">' + _esc(label, 24)
            + '</div><div class="track"><div class="fill" style="width:' + str(pct)
            + '%"></div></div><div class="val">' + str(value) + "</div></div>")
    return '<div class="bars">' + "".join(rows) + "</div>"


def _kpi(value, label, kind=""):
    return ('<div class="card ' + kind + '"><div class="n">' + _esc(value)
            + '</div><div class="k">' + _esc(label) + "</div></div>")


def _host_rows(hosts):
    """Render every host row; filtering/paging happens client-side.

    Each <tr> carries data-pri / data-status / data-src / data-dup so the
    toolbar can filter without re-querying, and duplicate titles stay
    collapsible instead of being silently truncated to 60 rows.
    """
    if not hosts:
        return '<tr><td colspan="8" class="empty">no in-scope hosts</td></tr>'
    rows = []
    seen_titles = {}
    for h in hosts:
        tags = "".join('<span class="tag tch">' + _esc(t, 24) + "</span>"
                       for t in h["tech"][:6])
        srcs = "".join('<span class="tag src">' + _esc(s, 28) + "</span>"
                       for s in h["provenance"][:5])
        if h["internal"]:
            srcs = ('<span class="tag src" style="color:#ff9d9d;border-color:#6b2020">'
                    "internal services</span>" + srcs)
        reasons = "；".join(_esc(r, 70) for r in h["reasons"][:3])
        # duplicate titles: first occurrence is the canonical row, later ones
        # are marked so the UI can collapse them behind a toggle
        title = (h["title"] or "").strip()
        dup = False
        dup_note = ""
        if title:
            if title in seen_titles:
                dup = True
                seen_titles[title] += 1
                dup_note = '<span class="dupmark">dup ×' + str(seen_titles[title]) + "</span>"
            else:
                seen_titles[title] = 1
        status_txt = h["status"] if h["status"] is not None else "-"
        src_attr = "|".join(h["provenance"]) if h["provenance"] else ""
        rows.append(
            '<tr data-pri="' + _esc(h["priority"]) + '"'
            + ' data-status="' + _esc(status_txt) + '"'
            + ' data-src="' + _esc(src_attr) + '"'
            + ' data-title="' + _esc(title) + '"'
            + (' data-dup="1"' if dup else "")
            + (' class="dup"' if dup else "") + ">"
            + "<td><span class=\"pri " + h["priority"] + '">' + _esc(h["priority"])
            + "</span></td>"
            + '<td><span class="host">' + _esc(h["host"]) + "</span>"
            + ('<br><span class="meta">' + _esc(h["ip"]) + "</span>" if h["ip"] else "")
            + '</td><td><span class="st ' + _status_class(h["status"]) + '">'
            + _esc(status_txt) + "</span></td>"
            + "<td>" + _esc(title, 60) + dup_note + "</td>"
            + "<td>" + (tags or '<span class="meta">-</span>') + "</td>"
            + "<td>" + (srcs or '<span class="meta">-</span>') + "</td>"
            + '<td><span class="st">' + str(h["score"]) + "</span></td>"
            + '<td class="meta">' + (reasons or "-") + "</td></tr>")
    return "".join(rows)


def _endpoint_rows(eps):
    """Render every endpoint row; filtering/paging happens client-side."""
    if not eps:
        return '<tr><td colspan="6" class="empty">no parameterised or sensitive endpoints</td></tr>'
    rows = []
    for e in eps:
        status_txt = e["status"] if e["status"] is not None else "-"
        rows.append(
            '<tr data-host="' + _esc(e["host"]) + '"'
            + ' data-method="' + _esc(e["method"]) + '"'
            + ' data-status="' + _esc(status_txt) + '"'
            + ' data-src="' + _esc(e["provenance"]) + '"'
            + ">"
            + '<td><span class="host">' + _esc(e["host"]) + "</span></td>"
            + "<td>" + _esc(e["method"]) + "</td>"
            + '<td class="mono">' + _esc(e["path"], 90) + "</td>"
            + '<td class="mono">' + _esc(", ".join(e["params"][:5]), 60) + "</td>"
            + '<td><span class="st ' + _status_class(e["status"]) + '">'
            + _esc(status_txt) + "</span></td>"
            + '<td><span class="tag src">' + _esc(e["provenance"])
            + "</span> " + _esc("；".join(e["why"]), 60) + "</td></tr>")
    return "".join(rows)




def _section(title, subtitle="", collapsed=False, body_id=""):
    """Open a collapsible section. Pair with _section_end().

    A collapsed section keeps the report short: the caller still emits the
    full table, it is just display:none until the header is clicked.
    """
    cls = "sec-head collapsed" if collapsed else "sec-head"
    sub = ("<span>" + _esc(subtitle) + "</span>") if subtitle else ""
    return ('<section><div class="' + cls + '" data-target="' + body_id + '">'
            + '<span class="chev"></span><h2>' + _esc(title) + sub + "</h2></div>"
            + '<div class="sec-body' + (" hidden" if collapsed else "")
            + '" id="' + body_id + '">')


def _section_end():
    return "</div></section>"


def _toolbar(uid, status=True, source=True, dup=False, total=0):
    """Filter/search toolbar bound to the table that follows it."""
    parts = ['<div class="toolbar" data-for="' + uid + '">']
    parts.append('<input type="search" data-role="q" placeholder="search hosts / paths / titles...">')
    if status:
        parts.append('<select data-role="status"><option value="">all statuses</option></select>')
    if source:
        parts.append('<select data-role="source"><option value="">all sources</option></select>')
    if dup:
        parts.append('<button type="button" data-role="duptoggle">collapse duplicate titles</button>')
    parts.append('<button type="button" data-role="reset">reset</button>')
    parts.append('<span class="cnt">showing <b data-role="shown">0</b> / ' + str(total) + "</span>")
    parts.append("</div>")
    return "".join(parts)


def _pager(uid, total, per_page=50):
    pages = max(1, (total + per_page - 1) // per_page)
    return ('<div class="pager" data-for="' + uid + '" data-per="' + str(per_page)
            + '" data-pages="' + str(pages) + '">'
            + '<button type="button" data-role="first">&laquo;</button>'
            + '<button type="button" data-role="prev">&lsaquo;</button>'
            + '<span class="info">page <b data-role="cur">1</b> / ' + str(pages) + "</span>"
            + '<button type="button" data-role="next">&rsaquo;</button>'
            + '<button type="button" data-role="last">&raquo;</button>'
            + "</div>")


def build_html(data) -> str:
    c = data["counts"]
    scope = data["scope"]
    scope_txt = ", ".join(scope["match"]) if scope["match"] else "未限定（整库）"
    if scope["auto"]:
        scope_txt += "（自动取自最近 run）"
    parts = []
    parts.append('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append("<title>资产测绘报告 · " + _esc(scope_txt) + "</title>")
    parts.append("<style>" + _CSS + "</style></head><body>")

    parts.append("<header><h1>资产测绘报告</h1>")
    parts.append('<div class="meta">目标范围 <b>' + _esc(scope_txt) + "</b>"
                 + " · 生成时间 <b>" + _esc(data["generated_at"]) + "</b>"
                 + " · 平台 <b>" + _esc(data["environment"].get("platform") or "-")
                 + "</b> · schema <b>" + _esc(data["schema"]) + "</b></div></header>")

    parts.append("<main>")
    parts.append('<section><div class="cards">'
                 + _kpi(c["domains_in_scope"], "范围内域名")
                 + _kpi(c["live"], "存活主机", "ok")
                 + _kpi(c["interesting"], "高/中优先", "md")
                 + _kpi(c["internal_services"], "内部服务", "hi")
                 + _kpi(c["endpoints_interesting"], "待复核端点", "lo")
                 + _kpi(c["leak_domains"] + c["leak_ips"], "泄露情报")
                 + "</div></section>")

    warnings = data["environment"].get("warnings") or []
    if warnings:
        parts.append("<section><h2>范围与环境告警<span>这些会直接影响结论可信度</span></h2>")
        for w in warnings:
            parts.append('<div class="banner info">' + _esc(w) + "</div>")
        parts.append("</section>")

    charts = data["charts"]
    parts.append("<section><h2>分布概览<span>状态 / 指纹 / 工具来源 / 置信度 / IP 共享</span></h2>")
    parts.append('<div class="grid2">')
    parts.append('<div class="panel"><h3>HTTP 状态分布</h3>' + _bars(charts.get("status") or []) + "</div>")
    parts.append('<div class="panel"><h3>工具来源（每资产计一次）</h3>' + _bars(charts.get("tools") or []) + "</div>")
    parts.append('<div class="panel"><h3>指纹/技术栈 Top</h3>' + _bars(charts.get("tech") or []) + "</div>")
    parts.append('<div class="panel"><h3>置信度分桶</h3>' + _bars(charts.get("confidence") or []) + "</div>")
    parts.append('<div class="panel"><h3>共享 IP Top（同 IP 主机数）</h3>' + _bars(charts.get("ip_share") or []) + "</div>")
    parts.append('<div class="panel"><h3>端口分布</h3>' + _bars(charts.get("ports") or []) + "</div>")
    parts.append("</div></section>")

    hosts = data.get("hosts_all") or data["hosts"]
    parts.append(_section(
        "高价值主机",
        "共 " + str(data["hosts_total"]) + " 条，内部服务优先（可搜索 / 筛选 / 翻页）",
        body_id="sec-hosts"))
    parts.append(_toolbar("sec-hosts", status=True, source=True, dup=True,
                          total=len(hosts)))
    parts.append('<div class="panel"><table><thead><tr><th>优先</th><th>主机</th>'
                 "<th>状态</th><th>标题</th><th>指纹</th><th>来源</th><th>评分</th>"
                 '<th>判定依据</th></tr></thead><tbody>' + _host_rows(hosts)
                 + "</tbody></table></div>")
    parts.append(_pager("sec-hosts", len(hosts)))
    parts.append(_section_end())

    internal = data["internal_services"]
    if internal:
        parts.append("<section><h2>内部服务（Host 头碰撞）<span>未出现在公开 DNS 中</span></h2>")
        parts.append('<div class="panel"><table><thead><tr><th>主机</th><th>IP</th><th>状态</th>'
                     "<th>标题</th><th>来源</th></tr></thead><tbody>")
        for h in internal[:40]:
            parts.append('<tr><td><span class="host">' + _esc(h["host"]) + "</span></td>"
                         + '<td class="mono">' + _esc(h["ip"]) + "</td>"
                         + '<td><span class="st ' + _status_class(h["status"]) + '">'
                         + _esc(h["status"] if h["status"] is not None else "-") + "</span></td>"
                         + "<td>" + _esc(h["title"], 50) + "</td>"
                         + "<td>" + "".join('<span class="tag src">' + _esc(s, 26) + "</span>"
                                            for s in h["provenance"][:4]) + "</td></tr>")
        parts.append("</tbody></table></div></section>")

    eps = data["endpoints"]
    parts.append(_section(
        "待复核端点",
        str(len(eps)) + " 条，按关注度排序（默认折叠，点击标题展开）",
        collapsed=True,
        body_id="sec-eps"))
    parts.append(_toolbar("sec-eps", status=True, source=True, total=len(eps)))
    parts.append('<div class="panel"><table><thead><tr><th>主机</th><th>方法</th><th>路径</th>'
                 '<th>参数</th><th>状态</th><th>来源 / 关注点</th></tr></thead><tbody>'
                 + _endpoint_rows(eps) + "</tbody></table></div>")
    parts.append(_pager("sec-eps", len(eps)))
    parts.append(_section_end())

    leaks = data["leaks"]
    if leaks["domains"] or leaks["ips"] or leaks["private_ips"]:
        parts.append("<section><h2>泄露情报<span>来自页面与 JS 抽取</span></h2>")
        parts.append('<div class="grid2">')
        parts.append('<div class="panel"><h3>泄露域名（' + str(len(leaks["domains"]))
                     + "）</h3><div>" + "".join('<span class="tag">' + _esc(d) + "</span>"
                                                for d in leaks["domains"][:60]) + "</div></div>")
        parts.append('<div class="panel"><h3>内网 IP（' + str(len(leaks["private_ips"]))
                     + "）</h3><div>" + "".join('<span class="tag">' + _esc(ip) + "</span>"
                                                for ip in leaks["private_ips"][:60]) + "</div></div>")
        parts.append("</div></section>")

    ip_groups = data["ip_groups"]
    if ip_groups:
        parts.append("<section><h2>共享 IP 聚类<span>同 IP 多主机通常指向同一个后端集群</span></h2>")
        parts.append('<div class="panel"><table><thead><tr><th>IP</th><th>主机数</th>'
                     "<th>主机</th></tr></thead><tbody>")
        for g in ip_groups[:20]:
            parts.append('<tr><td class="mono">' + _esc(g["ip"]) + "</td><td>" + str(g["hosts_count"])
                         + '</td><td class="mono">' + _esc(", ".join(g["hosts"][:8]), 120)
                         + "</td></tr>")
        parts.append("</tbody></table></div></section>")

    parts.append('<footer>本页由 findinfo report 生成，单文件自包含（无外部 JS/CSS/字体），'
                 "可直接归档、打印或转发。资产采用共享库 + 范围过滤：本次已隔离 "
                 + str(c["domains_dropped"]) + " 条资产、"
                 + str(c["endpoints_noise"]) + " 条端点。</footer>")
    parts.append("</main>")
    parts.append("<script>" + _JS + "</script>")
    parts.append("</body></html>")
    return "".join(parts)


# ---------------------------------------------------------------- write
def write_bundle(data, out_dir=None, slug=None, json_limit=None,
                 with_json=False, with_brief=False, brief_top=None,
                 brief_max_bytes=None, coverage=None, with_md=False) -> dict:
    """Write the HTML report; Markdown and machine files are opt-in.

    Default output is what people open: report.html. The agent
    read path is the `brief` command (library query -> stdout, no file), so
    report.brief.json and report.json are only written when a script asks
    for them (--with-brief / --with-json). with_md adds report.md;
    json_limit caps digest arrays.
    """
    c = data["counts"]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if not slug:
        match = data["scope"].get("match") or []
        slug = match[0].replace(".", "-") if match else "all"
    base = Path(out_dir) if out_dir else (Path(core.DATA) / "reports" / (stamp + "-" + slug))
    base.mkdir(parents=True, exist_ok=True)

    digest = data
    if json_limit and (len(data["hosts"]) > json_limit or len(data["endpoints"]) > json_limit):
        digest = dict(data)
        digest["hosts"] = data["hosts"][:json_limit]
        digest["endpoints"] = data["endpoints"][:json_limit]
        digest["internal_services"] = data["internal_services"][:json_limit]
        digest["signals"] = data["signals"][:json_limit]
        digest["truncated"] = dict(data.get("truncated") or {})
        digest["truncated"]["by_json_limit"] = json_limit

    paths = {}
    if with_brief:
        paths["brief"] = write_brief(data, base, top=brief_top,
                                     max_bytes=brief_max_bytes,
                                     coverage=coverage)["path"]
    if with_json:
        p = base / "report.json"
        # Compact, not indented: this file is read by a script, and the
        # pretty form roughly doubles the bytes for no readability gain
        # at 100 KB.
        p.write_text(json.dumps(digest, ensure_ascii=False, separators=(",", ":")),
                     encoding="utf-8")
        paths["json"] = str(p)
    if with_md:
        p = base / "report.md"
        p.write_text(build_md(data), encoding="utf-8")
        paths["md"] = str(p)
    p = base / "report.html"
    p.write_text(build_html(data), encoding="utf-8")
    paths["html"] = str(p)
    paths["dir"] = str(base)

    # A "latest" pointer is what both audiences actually open. A symlink needs
    # developer mode / admin on Windows, so fall back to a plain text pointer
    # instead of silently leaving nothing behind.
    reports = Path(core.DATA) / "reports"
    latest = reports / "latest"
    try:
        if latest.is_symlink():
            latest.unlink()
        if latest.exists():
            raise OSError("latest is a real directory, not a pointer")
        latest.symlink_to(base, target_is_directory=True)
        paths["latest"] = str(latest)
    except (OSError, NotImplementedError):
        try:
            ptr = reports / "latest.txt"
            ptr.write_text(str(base), encoding="utf-8")
            paths["latest"] = str(ptr)
        except OSError:
            pass
    return paths


# ------------------------------------------------------------ agent brief
# An agent should never open report.json: the digest is sized for scripts and
# downstream tools, and at 1000+ domains it runs to several hundred KB. The
# brief is the file an agent reads: same facts, hard byte ceiling, and every
# cut is stated in "truncated" so a short brief can never be mistaken for a
# complete one.
BRIEF_SCHEMA = "findinfo.brief/1"
BRIEF_TOP = 20              # default number of high-priority hosts
BRIEF_LEAKS = 20            # default number of leak examples
BRIEF_MAX_BYTES = 32 * 1024
BRIEF_MAX_COVERAGE = 40
# A brief smaller than this cannot carry its own envelope (schema, counts,
# coverage summary, truncation flags). Refusing is honest; emitting a
# half-document that quietly exceeds the ceiling is not (F14).
BRIEF_MIN_BYTES = 512


def _brief_arrays(value, path=()):
    """Walk retained arrays; omitted parent rows need only their parent cut."""
    if isinstance(value, list):
        yield path, value
        for index, item in enumerate(value):
            yield from _brief_arrays(item, path + (str(index),))
    elif isinstance(value, dict):
        for key, item in value.items():
            if not path and key == "truncated":
                continue
            yield from _brief_arrays(item, path + (str(key),))


def fit_brief(brief: dict, max_bytes, ascii_safe=None, *,
              trailing_newline=True) -> dict:
    """Final fit+measure of a COMPLETE brief, using the stdout encoder.

    Call this after every section (coverage, metered, note) has been merged:
    it shrinks in the documented order, then writes brief_bytes equal to the
    real stdout byte count under the same ASCII/UTF-8 policy emit() uses. After
    this call nothing may append to the object -- the number would be a lie.
    """
    if max_bytes is None:
        max_bytes = BRIEF_MAX_BYTES
    max_bytes = int(max_bytes)
    if max_bytes < BRIEF_MIN_BYTES:
        raise core.FindInfoError(
            "max_bytes is too small for a brief envelope (minimum "
            + str(BRIEF_MIN_BYTES) + "): " + str(max_bytes))
    if ascii_safe is None:
        ascii_safe = core.emit_ascii_default()
    brief.setdefault("truncated", {})
    brief["brief_max_bytes"] = max_bytes
    # Save totals BEFORE any fit pass mutates arrays. Earlier explicit caps
    # and earlier fit_brief calls may already have recorded a larger total.
    totals = {path: len(array) for path, array in _brief_arrays(brief)}
    for path, total in (
            (("top_hosts",), brief.get("top_hosts_total")),
            (("internal_services",), brief.get("internal_services_total")),
            (("leaks", "domains"), brief.get("leaks", {}).get("domains_total")),
            (("leaks", "ips"), brief.get("leaks", {}).get("ips_total")),
            (("coverage", "unavailable"),
             brief.get("coverage", {}).get("unavailable_total"))):
        if isinstance(total, int):
            totals[path] = max(totals.get(path, 0), total)
    for path in totals:
        previous = brief["truncated"].get(".".join(path))
        if isinstance(previous, dict) and isinstance(previous.get("total"), int):
            totals[path] = max(totals[path], previous["total"])

    def record_array_cuts():
        # Every successful payload describes its FINAL arrays, even if a
        # later shrink pass emptied a list that an earlier pass kept at one.
        retained = dict(_brief_arrays(brief))
        for path in totals:
            if path not in retained:
                # The parent array's cut accounts for the whole omitted row.
                brief["truncated"].pop(".".join(path), None)
        for path, array in retained.items():
            total = totals.get(path, len(array))
            if len(array) < total:
                key = ".".join(path)
                previous = brief["truncated"].get(key)
                cut = dict(previous) if isinstance(previous, dict) else {}
                cut.update(kept=len(array), total=total)
                brief["truncated"][key] = cut

    brief["truncated"].update(_shrink_brief(
        brief, max_bytes, ascii_safe, trailing_newline))

    def measure():
        # The size number is part of the document. Settle its digit count
        # before testing the ceiling, including the truncation metadata.
        for _ in range(8):
            size = _brief_size(brief, ascii_safe, trailing_newline)
            if brief.get("brief_bytes") == size:
                return size
            brief["brief_bytes"] = size
        raise core.FindInfoError("could not measure brief_bytes consistently")

    # Truncation metadata consumes bytes too. Reconcile it before measuring
    # and repeat the tail fit if those truthful counters cross the ceiling.
    for _ in range(8):
        record_array_cuts()
        size = measure()
        if size <= max_bytes:
            return brief
        _shrink_brief_overflow(brief, max_bytes, ascii_safe, trailing_newline)
    record_array_cuts()
    size = measure()
    if size > max_bytes:
        # Identity, exact counts and the remaining stage verdict must not be
        # silently corrupted to manufacture a successful bounded response.
        raise core.FindInfoError(
            "max_bytes cannot hold the required brief identity, counts and "
            "coverage (required " + str(size) + ", max_bytes " + str(max_bytes)
            + "); raise --max-bytes or narrow --match; use status --run <run_id> "
            "for stage details")
    return brief


_BRIEF_HOST_FIELDS = ("host", "score", "priority", "reasons", "provenance")


def _brief_host(h):
    """Only the fields an agent branches on; cosmetic detail stays in report.json."""
    out = {}
    for k in _BRIEF_HOST_FIELDS:
        out[k] = h.get(k)
    # without these three a finding cannot be acted on without a second lookup
    for k in ("status", "ip", "internal"):
        if h.get(k) not in (None, "", False):
            out[k] = h[k]
    return out


def _is_gap_value(value) -> bool:
    """True for a value that actually describes a gap.

    coverage.unavailable carries two flags next to the real lists -- blocking
    (a bool) and note (often empty). Expanding every key into a row produced
    junk like {"kind": "blocking", "reason": "False"}, which makes a reader
    distrust the whole block. A bool says nothing on its own and an empty
    string says less; the caller handles both explicitly instead.
    """
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, dict, set)):
        return bool(value)
    return True


_GAP_FLAG_KEYS = ("blocking", "blocking_tools", "note")


def _brief_coverage(data=None, coverage=None):
    """Failed / not-run / unavailable stages, each with a human-readable why.

    This is the part agents get wrong most often: a run with three unavailable
    sources is not the same as a run with nothing found, and a brief that only
    lists findings cannot tell the two apart.

    known is part of the answer: when no run could be read there are no gaps
    to report, which is NOT the same as "there were no gaps", and the brief
    has to say so rather than show an empty list that reads like a clean bill.
    """
    # Callers pass either a whole digest (data) or a ready coverage block; both
    # have to end up in the same shape, or a caller-supplied block silently
    # keeps its raw dict-of-lists form and the agent gets inconsistent output.
    if coverage is None:
        coverage = (data or {}).get("coverage")
    cov = coverage or {}
    unavail = cov.get("unavailable") or {}
    unavailable = []
    blocking = cov.get("blocking") is True
    note = str(cov.get("note") or "").strip()
    for key, entries in unavail.items():
        if key in _GAP_FLAG_KEYS:
            continue
        if isinstance(entries, dict):
            entries = list(entries.items())
        if not isinstance(entries, (list, tuple)):
            if _is_gap_value(entries):
                unavailable.append({"kind": key, "reason": str(entries)})
            continue
        for item in entries:
            if isinstance(item, dict):
                row = dict(item)
                row.setdefault("kind", key)
                unavailable.append(row)
            elif _is_gap_value(item):
                unavailable.append({"kind": key, "reason": str(item)})
    out = {
        "source": str(cov.get("source") or "none"),
        "known": bool(cov.get("known")),
        "failed_stages": [dict(x) for x in (cov.get("failed_stages") or [])
                          if isinstance(x, dict)],
        "not_run_stages": list(cov.get("not_run_stages") or []),
        "skipped_stages": list(cov.get("skipped_stages") or []),
        "unavailable": unavailable[:BRIEF_MAX_COVERAGE],
        "unavailable_total": len(unavailable),
    }
    # A brief that lists findings but omits the run's own verdict reads as a
    # clean result. These fields are what tell an agent "partial, because
    # these stages under-collected" -- the most action-relevant fact after
    # the counts. Carried verbatim when the run's coverage block has them.
    for key in ("complete", "requested_complete", "stop_reason", "reason",
                "partial_stages", "stage_states", "work_queue", "js_queue",
                # What the paid mapping spent and what this TASK already owns:
                # a run whose engines were all skipped or refused looks exactly
                # like a target with no assets unless these travel with it.
                "metered", "mapping"):
        if key in cov and cov.get(key) is not None:
            out[key] = cov[key]
    res = (data or {}).get("result") if isinstance(data, dict) else None
    if isinstance(res, dict) and res.get("status"):
        out["result_status"] = res.get("status")
        if res.get("reason"):
            out["result_reason"] = res.get("reason")
    # _run_coverage attaches the run's verdict to the coverage block it read
    # (the digest has no result of its own -- it describes the library, not a
    # run). Promote those, then never leak the private carriers.
    if out.get("result_status") is None and cov.get("_result_status"):
        out["result_status"] = cov.get("_result_status")
        if cov.get("_result_reason"):
            out["result_reason"] = cov.get("_result_reason")
    for _priv in ("_result_status", "_result_reason", "_result_attempt"):
        out.pop(_priv, None)
    if blocking:
        # A blocking gap is what explains a partial run, so it gets its own
        # top-level entry instead of hiding in unavailable as reason=True.
        out["blocking"] = True
        if note:
            out["blocking_reason"] = note
    elif note:
        out["note"] = note
    if not out["known"]:
        out["hint"] = ("no run matched, so this does not mean there were no "
                       "gaps; pass --run <run_id> (see: runs) to read real "
                       "coverage")
    return out


def build_brief(data, top=None, leak_limit=None, max_bytes=None,
                coverage=None, ascii_safe=None) -> dict:
    """Shape one collection pass into a brief small enough to read whole.

    Only what an agent needs to decide the next action: how much was found,
    what the collection could not do, the highest-priority hosts, every
    internal service, leak counts, and the suggested next steps. The big
    arrays (all hosts, endpoints, signals, charts) stay in report.json.
    """
    top = BRIEF_TOP if top is None else max(int(top), 0)
    leak_limit = BRIEF_LEAKS if leak_limit is None else max(int(leak_limit), 0)
    max_bytes = BRIEF_MAX_BYTES if max_bytes is None else int(max_bytes)

    counts = dict(data.get("counts") or {})
    hosts_all = data.get("hosts_all") or data.get("hosts") or []
    ranked = [h for h in hosts_all if h.get("priority") in ("high", "medium")]
    if not ranked:
        ranked = hosts_all
    leaks = data.get("leaks") or {}
    internal = data.get("internal_services") or []

    brief = {
        "schema": BRIEF_SCHEMA,
        "generated_at": data.get("generated_at") or core.now(),
        "note": ("Agents read this. report.json is the full digest for scripts and "
                 "downstream tools; do not load it whole into context."),
        "scope": dict(data.get("scope") or {}),
        "counts": counts,
        "environment": {
            "warnings": list((data.get("environment") or {}).get("warnings") or [])},
        "coverage": _brief_coverage(data, coverage),
        "top_hosts": [_brief_host(h) for h in ranked[:top]],
        "top_hosts_total": len(ranked),
        "internal_services": [_brief_host(h) for h in internal],
        "internal_services_total": len(internal),
        "leaks": {
            "domains_total": counts.get("leak_domains", len(leaks.get("domains") or [])),
            "ips_total": counts.get("leak_ips", len(leaks.get("ips") or [])),
            "domains": list(leaks.get("domains") or [])[:leak_limit],
            "ips": list(leaks.get("ips") or [])[:leak_limit],
            "private_ips": list(leaks.get("private_ips") or [])[:leak_limit],
        },
        "next_steps": list(data.get("next_steps") or []),
        "truncated": {},
    }

    # -- first the explicit caps the caller asked for -----------------------
    if len(ranked) > len(brief["top_hosts"]):
        brief["truncated"]["top_hosts"] = {
            "kept": len(brief["top_hosts"]), "total": len(ranked),
            "hint": "adjust --brief-top; the full list is in report --with-json, or assets --export"}
    if len(internal) > len(brief["internal_services"]):
        brief["truncated"]["internal_services"] = {
            "kept": len(brief["internal_services"]), "total": len(internal),
            "hint": "the full list is in report --with-json, or assets --export"}
    for key in ("domains", "ips", "private_ips"):
        total = (len(leaks.get(key) or []) if key == "private_ips"
                 else brief["leaks"][key + "_total"])
        kept = len(brief["leaks"][key])
        if total > kept:
            brief["truncated"]["leaks." + key] = {"kept": kept, "total": total}

    # -- then the hard byte ceiling ----------------------------------------
    # brief_bytes/brief_max_bytes are part of the file, so the ceiling has to
    # be measured under a payload that already carries them; otherwise the
    # final write is a few bytes larger than what was measured and the
    # promise "never exceeds max_bytes" is off by a rounding error.
    if ascii_safe is None:
        ascii_safe = core.emit_ascii_default()
    # The caller may still merge metered/note and call fit_brief() again; this
    # pass makes build_brief() usable on its own (report --with-brief).
    brief["brief_bytes"] = 0
    return fit_brief(brief, max_bytes, ascii_safe)


def _encode_brief(brief, ascii_safe=None, trailing_newline=True) -> str:
    blob = core.encode_json_line(brief, ascii_safe)
    return blob if trailing_newline else blob[:-1]


def _brief_size(brief, ascii_safe=None, trailing_newline=True) -> int:
    """Real stdout bytes of this brief (the SAME encoder emit() uses).

    Includes the separators and the trailing newline, and honours the
    ASCII/UTF-8 emission mode: brief_bytes is the true byte count an agent
    reads on stdout, not a differently-encoded approximation (F14).
    """
    return len(_encode_brief(brief, ascii_safe, trailing_newline).encode("utf-8"))


def _shrink_brief(brief, max_bytes, ascii_safe=None,
                  trailing_newline=True) -> dict:
    """Cut the cheapest things first until the brief fits, recording each cut.

    Order matters: prose goes before findings, findings go before counts, and
    the coverage gaps shrink last because a brief without them reads as a
    complete result.
    """
    cuts = {}

    def fits():
        return _brief_size(brief, ascii_safe, trailing_newline) <= max_bytes

    if fits():
        return cuts

    # 1. prose first
    if "note" in brief:
        brief.pop("note")
        cuts["note"] = "prose omitted to fit the byte ceiling"
    if fits():
        return cuts

    # 2. leak examples -- cut by count first, the counts are never lost
    for key, total_key in (("domains", "domains_total"), ("ips", "ips_total"),
                           ("private_ips", None)):
        arr = list(brief["leaks"].get(key) or [])
        brief["leaks"][key] = arr
        while arr and not fits():
            arr.pop()
        if total_key:
            # only a real drop counts: a total shared with another array
            # would otherwise mark an array that lost nothing
            kept = len(arr)
            if kept < brief["leaks"].get(total_key, 0):
                cuts["leaks." + key] = {"kept": kept,
                                        "total": brief["leaks"][total_key]}
    if fits():
        return cuts

    # 3. per-host detail before per-host count: a rank with one host and
    # every reason is more useful than twenty hosts with none. The field
    # is where the bytes actually are (a reason is a full sentence).
    for h in brief["top_hosts"]:
        h["reasons"] = (h.get("reasons") or [])[:2]
        h["provenance"] = (h.get("provenance") or [])[:3]
    cuts["detail"] = "reasons cut to 2, provenance cut to 3"
    if fits():
        return cuts

    # 4. internal services: they are findings, so only trim the tail
    while len(brief["internal_services"]) > 1 and not fits():
        brief["internal_services"].pop()
    if len(brief["internal_services"]) < brief["internal_services_total"]:
        cuts["internal_services"] = {
            "kept": len(brief["internal_services"]),
            "total": brief["internal_services_total"]}
    if fits():
        return cuts

    # 5. only now start dropping high-priority hosts, worst rank first
    while len(brief["top_hosts"]) > 1 and not fits():
        brief["top_hosts"].pop()
    cuts["top_hosts"] = {"kept": len(brief["top_hosts"]),
                         "total": brief["top_hosts_total"]}
    if fits():
        return cuts

    # 6. metered detail: the SPEND COUNTS stay, per-engine rows shrink first
    metered = brief.get("metered") or {}
    if isinstance(metered, dict) and metered.get("by_engine"):
        while metered["by_engine"] and not fits():
            metered["by_engine"].popitem()
        if not metered["by_engine"]:
            metered.pop("by_engine", None)
        cuts["metered.by_engine"] = ("per-engine rows dropped; totals kept")
    if fits():
        return cuts

    # 7. long free text (warnings / stage errors): keep the family, cut the
    # prose. A truncated gap still names WHAT failed.
    for key in ("warnings",):
        arr = list(brief.get("environment", {}).get(key) or [])
        if arr:
            brief["environment"][key] = [
                (str(w)[:160] + ("..." if len(str(w)) > 160 else ""))
                for w in arr[:5]]
            cuts["environment." + key] = ("warnings shortened to 5 x 160 chars")
    gaps = brief.get("coverage", {}).get("gaps") or []
    if gaps:
        for g in gaps:
            if isinstance(g, dict) and isinstance(g.get("reason"), str):
                g["reason"] = g["reason"][:160]
        cuts["coverage.reasons"] = "gap reasons shortened to 160 chars"
    if fits():
        return cuts

    # 8. last resort: shrink the gap list and next steps, and SAY so loudly.
    # The COUNT is preserved in coverage so "how much is missing" survives.
    while brief["coverage"].get("unavailable") and not fits():
        brief["coverage"]["unavailable"].pop()
    while len(brief.get("next_steps") or []) > 2 and not fits():
        brief["next_steps"].pop()
    while len(brief.get("top_hosts") or []) > 0 and not fits():
        brief["top_hosts"].pop()
    cuts["coverage"] = {
        "kept": len(brief["coverage"].get("unavailable") or []),
        "total": brief["coverage"].get("unavailable_total", 0)}
    return cuts


def _shrink_brief_overflow(brief, max_bytes, ascii_safe, trailing_newline):
    """Bound variable prose/arrays left after the normal finding-first fit.

    Stage names, run/source identity and exact counts survive. A long or
    unexpected required field can still make the envelope impossible; the
    final encoder check in fit_brief then refuses instead of emitting it.
    Rebuild nested values so fitting does not shorten the persisted coverage
    snapshot or the caller's report data through shared references.
    """
    cuts = brief["truncated"]
    marker = cuts.setdefault("byte_budget", {
        "hint": "stage details: status --run <run_id>; full data: report --with-json or assets --export"})
    shortened = 0
    identity = {"schema", "generated_at", "source", "run_id", "stage", "host",
                "ip", "domain", "engagement", "match", "domains", "ips",
                "private_ips", "not_run_stages", "skipped_stages"}

    def shorten(value, key=""):
        nonlocal shortened
        if isinstance(value, str):
            if key not in identity and len(value) > 160:
                shortened += 1
                return value[:157] + "..."
            return value
        if isinstance(value, dict):
            return {k: shorten(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [shorten(v, key) for v in value]
        return value

    for key in ("scope", "environment", "coverage", "top_hosts",
                "internal_services", "leaks", "next_steps", "metered"):
        if key in brief:
            brief[key] = shorten(brief[key])
    if shortened:
        marker["shortened_strings"] = marker.get("shortened_strings", 0) + shortened

    def fits():
        return _brief_size(brief, ascii_safe, trailing_newline) <= max_bytes

    # Keep at least one scope/stage identity. Every shortened array records
    # the original total, including when fit_brief is called a second time.
    for section, key, minimum in (
            ("scope", "match", 1),
            ("coverage", "failed_stages", 1),
            ("coverage", "partial_stages", 1),
            ("coverage", "not_run_stages", 1),
            ("coverage", "skipped_stages", 1),
            ("coverage", "unavailable", 0),
            ("environment", "warnings", 0),
            (None, "top_hosts", 1),
            (None, "internal_services", 0),
            (None, "next_steps", 1)):
        container = brief.get(section, {}) if section else brief
        arr = container.get(key)
        if not isinstance(arr, list):
            continue
        path = (section + "." if section else "") + key
        previous = cuts.get(path)
        total = max(len(arr), previous.get("total", 0)
                    if isinstance(previous, dict) else 0)
        while len(arr) > minimum and not fits():
            del arr[max(minimum, len(arr) // 2):]
            cuts[path] = {"kept": len(arr), "total": total}
        if fits():
            return

    # Optional detailed maps can grow independently of their row counts.
    # Their omission is a display cut, never a change to the run verdict.
    for container, key, path in (
            (brief.get("metered", {}), "by_engine", "metered.by_engine"),
            (brief.get("metered", {}), "blocked_engines", "metered.blocked_engines"),
            (brief.get("coverage", {}), "mapping", "coverage.mapping"),
            (brief.get("coverage", {}).get("metered", {}), "by_engine",
             "coverage.metered.by_engine")):
        if fits():
            return
        if isinstance(container, dict) and key in container:
            container.pop(key)
            cuts[path] = "detail omitted; see status --run <run_id>"


def write_brief(data, base, top=None, leak_limit=None, max_bytes=None,
                coverage=None) -> dict:
    """Write report.brief.json next to report.json; returns path + stats.

    The file is measured with the SAME content it writes (no compact-vs-file
    mix-up): brief_bytes describes the bytes on disk, and the ceiling applies
    to that document too.
    """
    brief = build_brief(data, top=top, leak_limit=leak_limit,
                        max_bytes=max_bytes, coverage=coverage, ascii_safe=False)
    p = Path(base) / "report.brief.json"
    # The file shares the stdout encoder, but has no trailing newline.
    fit_brief(brief, max_bytes, ascii_safe=False, trailing_newline=False)
    blob = _encode_brief(brief, ascii_safe=False, trailing_newline=False)
    p.write_text(blob, encoding="utf-8")
    return {"path": str(p), "bytes": len(blob.encode("utf-8")),
            "truncated": brief["truncated"]}
