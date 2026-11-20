"""DNS fidelity: fake-IP filtering, DoH fallback and certificate names.

Three problems this module owns:

1. 198.18.0.0/15 is the benchmarking range Clash/TUN hands out as "fake IP".
   A resolver that answers a non-existent name with 198.18.x.x (or 198.19.x.x
   -- the old `startswith("198.18.")` check missed the whole upper half of the
   /15) is synthesising addresses, and every hostname mapped to one is a
   phantom. `is_fake_ip` is the single predicate every resolution path must
   apply before an address is stored.
2. Once fake IPs are filtered there is nothing left to resolve, so the dns and
   probe stages have to reach a resolver that is not the poisoned local one.
   `detect_fake_ip` proves the condition, `ResolutionPlan` decides which
   resolver to use, and `DohClient` performs the query over HTTPS (one JSON
   API endpoint, configurable, bounded concurrency).
3. A certificate names hosts. httpx `-tls-grab` reports them under `tls`
   (`subject_an` / `subject_cn` / `issuer_dn`); `parse_cert_names` turns one
   row into `{"san": [...], "cn": ..., "issuer": ...}` without shelling out to
   anything, and `cert_queue_entries` splits the names a certificate claims
   into "in scope, ask dns next round" versus "related asset" -- the case where
   one certificate is served by many unrelated names.

Everything here is standard library only and performs no network I/O unless a
caller passes an explicit `fetcher` / uses `DohClient` deliberately.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

# Clash / mihomo TUN mode answers every A query with an address from a
# benchmark block. It covers 198.18.0.0/15 -- BOTH 198.18.x.x and 198.19.x.x.
# Matching on "198.18." accepted the second half as a real asset and, worse,
# let a wildcard-probe answer from 198.19.x.x slip through the wildcard filter.
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")


def is_fake_ip(value: str) -> bool:
    """True when `value` is an address from the fake-IP benchmark range.

    Anything unparsable is NOT a fake IP: the caller decides separately whether
    an address it cannot parse is usable at all.
    """
    try:
        return ipaddress.ip_address(str(value).strip()) in FAKE_IP_NET
    except Exception:
        return False


def filter_fake_ips(values) -> tuple[list[str], list[str]]:
    """Split addresses into (kept, dropped_fake_ips), preserving order."""
    kept, dropped = [], []
    for v in values or []:
        s = str(v).strip()
        if not s:
            continue
        if is_fake_ip(s):
            dropped.append(s)
        else:
            kept.append(s)
    return kept, dropped


def fake_ip_in(answers) -> str:
    """First fake address found in `answers`, or "" when none.

    The inverse of is_fake_ip, kept apart so a caller that only needs "did any
    answer look synthetic" does not have to re-implement the predicate.
    """
    for a in answers or []:
        if is_fake_ip(a):
            return str(a).strip()
    return ""


# ---------------------------------------------------------------- detection
# A random label under .invalid (RFC 2606: guaranteed never to exist) is the
# cheapest honest probe: a correct resolver answers NXDOMAIN, a fake-IP DNS
# answers an address in the benchmark range.
_PROBE_LABEL = "findinfo-fakeip-probe-8c41d7.invalid"

# When the system resolver itself is fake, asking it to resolve a domain name
# returns 198.18.x.x. These literals are resolved by the OS from a hosts file
# or not at all, so they say nothing about the DNS path and are never probed:
# the check is about *name resolution*, and asking one of these would report
# "no fake IP" inside a tunnel that fakes everything else.
_NON_DNS_LITERALS = frozenset(("localhost", "localhost.localdomain", "ip6-localhost"))


def _default_getaddrinfo():
    import socket
    return lambda host: [i[4][0] for i in socket.getaddrinfo(host, None)]


def detect_fake_ip(resolve=None) -> dict:
    """Resolve a name that cannot exist and report whether the answer is fake.

    `resolve` maps host -> list of addresses (default: the OS resolver). The
    result is the `environment.fake_ip_dns` block doctor publishes:
    `{"fake_ip_dns": bool, "probe": <name>, "answers": [...], "reason": str}`.
    A resolver that raises (no network at all) is NOT fake-IP evidence, so the
    reason says so instead of claiming a clean environment.
    """
    resolve = resolve or _default_getaddrinfo()
    try:
        answers = [str(a) for a in (resolve(_PROBE_LABEL) or [])]
    except Exception as exc:
        return {"fake_ip_dns": False, "probe": _PROBE_LABEL, "answers": [],
                "reason": "resolver error (" + type(exc).__name__ +
                          "): no evidence either way"}
    fake = fake_ip_in(answers)
    if fake:
        return {"fake_ip_dns": True, "probe": _PROBE_LABEL, "answers": answers,
                "fake_ip": fake,
                "reason": "a non-existent name answered " + fake +
                          " (198.18.0.0/15): the local resolver synthesises "
                          "addresses (Clash/TUN fake-IP)"}
    if answers:
        return {"fake_ip_dns": False, "probe": _PROBE_LABEL, "answers": answers,
                "reason": "a non-existent name answered " + ", ".join(answers[:3]) +
                          " (not in 198.18.0.0/15): suspicious but not fake-IP"}
    return {"fake_ip_dns": False, "probe": _PROBE_LABEL, "answers": [],
            "reason": "non-existent name correctly answered NXDOMAIN/empty"}


# ---------------------------------------------------------------- resolver plan
# Default DoH endpoint: Cloudflare's JSON API. Configurable because a CN host
# that cannot reach Cloudflare needs Alibaba/DNSPod instead -- the endpoint is
# data, not a constant of the program.
DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"

RESOLVER_DNSX = "dnsx"
RESOLVER_SYSTEM = "system-dns"
RESOLVER_DOH = "doh"
RESOLVER_PYTHON = "python-doh"     # this module performing the whole query


def doh_config() -> dict:
    """The `dns` section of config.json merged over the built-in defaults."""
    from . import core
    raw = (core.CFG.get("dns") or {}) if isinstance(core.CFG, dict) else {}
    limits = core.CFG.get("limits") or {}
    if not isinstance(raw, dict):
        raw = {}
    return {"doh_url": (raw.get("doh_url") or DEFAULT_DOH_URL),
            "doh_concurrency": int(raw.get("doh_concurrency") or
                                   limits.get("doh_concurrency") or 20),
            "doh_timeout": float(raw.get("doh_timeout") or 8.0),
            "doh_retry": int(raw.get("doh_retry") if raw.get("doh_retry") is not None
                             else 1),
            # "auto" = detect at runtime through the environment self-check
            "fake_ip": str(raw.get("fake_ip") or "auto").lower()}


def detect_environment(fake_ip_dns: bool | None = None) -> dict:
    """The `environment.fake_ip_dns` block for this process.

    Cached process-wide: the answer cannot change mid-run and doctor plus
    every stage must agree on it (a stage that decides differently from
    status would print two contradictory resolvers for one run).
    `fake_ip_dns` forces the value (tests, explicit config).
    """
    if fake_ip_dns is not None:
        return {"fake_ip_dns": bool(fake_ip_dns), "probe": "", "answers": [],
                "reason": "forced by caller"}
    with _ENV_LOCK:
        if _ENV_CACHE.get("value") is not None:
            return dict(_ENV_CACHE["value"])
        block = detect_fake_ip()
        _ENV_CACHE["value"] = block
        return dict(block)


_ENV_LOCK = threading.Lock()
_ENV_CACHE: dict = {"value": None}


def reset_environment_cache() -> None:
    """Forget the cached detection (tests, and a resumed worker after a
    network change)."""
    with _ENV_LOCK:
        _ENV_CACHE["value"] = None


class ResolutionPlan:
    """Which resolver a run should use, and why.

    `resolution_mode()` is the single decision point; the stage code and the
    status payload both read it so "which resolver ran" is never re-derived.
    """

    def __init__(self, fake_ip: bool, doh_url: str = DEFAULT_DOH_URL,
                 mode: str = "auto"):
        self.fake_ip = bool(fake_ip)
        self.doh_url = doh_url or DEFAULT_DOH_URL
        self.mode = (mode or "auto").lower()

    @classmethod
    def for_run(cls, config: dict | None = None) -> "ResolutionPlan":
        cfg = config if config is not None else doh_config()
        mode = cfg.get("fake_ip") or "auto"
        if mode in ("on", "true", "always", "yes"):
            return cls(True, cfg.get("doh_url") or DEFAULT_DOH_URL, mode)
        if mode in ("off", "false", "never", "no"):
            return cls(False, cfg.get("doh_url") or DEFAULT_DOH_URL, mode)
        block = detect_environment()
        return cls(bool(block.get("fake_ip_dns")), cfg.get("doh_url") or DEFAULT_DOH_URL,
                   mode)

    def resolution_mode(self) -> str:
        """`doh` when fake-IP was detected, `local` otherwise."""
        return RESOLVER_DOH if self.fake_ip else "local"

    def payload(self) -> dict:
        """The `resolution` block published by dns/probe stages and status."""
        return {"mode": self.resolution_mode(), "fake_ip_dns": self.fake_ip,
                "doh_url": self.doh_url if self.fake_ip else "",
                "detection": "auto" if self.mode == "auto" else "config:" + self.mode}

    def resolver(self) -> str:
        """Which resolver this plan will USE, before any query runs."""
        return RESOLVER_DOH if self.fake_ip else RESOLVER_DNSX


def resolution_payload(plan: ResolutionPlan, resolver: str) -> dict:
    """The `resolution` block, stamped with the resolver that ACTUALLY ran.

    `plan.payload()` describes the plan; this describes the run. The two differ
    whenever the plan says "local" and dnsx failed so the system resolver
    answered, or when dnsx was not installed at all -- and an agent reading
    status needs the measured fact, not the intention.
    """
    out = plan.payload()
    out["resolver"] = resolver or plan.resolver()
    out["planned_resolver"] = plan.resolver()
    return out


def explain_resolution(block: dict) -> str:
    """One line for status/brief: which resolver ran and why."""
    block = block or {}
    res = block.get("resolver") or block.get("planned_resolver") or "unknown"
    if res in (RESOLVER_DOH, RESOLVER_PYTHON):
        return ("resolved through DoH (" + str(block.get("doh_url") or DEFAULT_DOH_URL) +
                ") because the local resolver returns fake IPs")
    if res == RESOLVER_SYSTEM:
        return ("resolved through the system resolver (dnsx unavailable or it "
                "returned nothing for those names)")
    if res == RESOLVER_DNSX:
        return "resolved through dnsx"
    return "resolver not recorded"
    def explain(self) -> str:
        """One sentence a human (or an agent) can quote in a report."""
        if self.fake_ip:
            return ("fake-IP local resolver (198.18.0.0/15): resolving through DoH at "
                    + self.doh_url)
        return "local resolver (no fake-IP detected)"


# ---------------------------------------------------------------- DoH client
def build_doh_url(url: str, name: str, rtype: str = "A") -> str:
    """GET URL for one JSON-API query."""
    base = url or DEFAULT_DOH_URL
    sep = "&" if "?" in base else "?"
    return base + sep + urlencode({"name": name, "type": rtype})


def _default_http_get(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(
        url, method="GET",
        headers={"Accept": "application/dns-json",
                 "User-Agent": "findinfo-doh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(getattr(resp, "status", 200)), resp.read().decode("utf-8", "replace")


# DNS RCODEs -> our per-name state vocabulary.
_DOH_RCODE_NXDOMAIN = 3


def parse_doh_answer(payload) -> dict:
    """Reduce a JSON-API answer to {"a": [...], "cname": [...], "rcode": int}.

    Accepts the wire shape {"Status": 0, "Answer": [{"name","type","data"}]}.
    Type 1 = A, type 5 = CNAME. CNAME chains are followed by the API itself
    only one hop at a time, so every CNAME in the answer is collected.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            return {"a": [], "cname": [], "rcode": None, "error": "bad json"}
    if not isinstance(payload, dict):
        return {"a": [], "cname": [], "rcode": None, "error": "not an object"}
    rcode = payload.get("Status")
    a, cname = [], []
    for ans in payload.get("Answer") or []:
        if not isinstance(ans, dict):
            continue
        data = str(ans.get("data") or "").strip().rstrip(".")
        try:
            rtype = int(ans.get("type"))
        except Exception:
            rtype = 0
        if rtype == 1 and data:
            a.append(data)
        elif rtype == 5 and data:
            cname.append(data)
    return {"a": a, "cname": cname, "rcode": rcode if isinstance(rcode, int) else None}


class DohClient:
    """Query one JSON DoH endpoint for many names with bounded concurrency.

    The fetcher is injectable (`get(url, timeout) -> (status, body)`) so the
    whole dns stage can be exercised with no network at all.
    """

    def __init__(self, url: str = DEFAULT_DOH_URL, concurrency: int = 20,
                 timeout: float = 8.0, get=None, retry: int = 1):
        self.url = url or DEFAULT_DOH_URL
        self.concurrency = max(1, int(concurrency or 1))
        self.timeout = float(timeout or 8.0)
        self.retry = max(0, int(retry or 0))
        self._get = get or _default_http_get

    def _query_once(self, name: str) -> dict:
        url = build_doh_url(self.url, name)
        try:
            status, body = self._get(url, self.timeout)
        except Exception as exc:
            return {"state": "transient_fail", "a": [], "cname": [], "rcode": None,
                    "error": type(exc).__name__ + ": " + str(exc)[:120]}
        if status and int(status) >= 500:
            return {"state": "transient_fail", "a": [], "cname": [], "rcode": None,
                    "error": "http " + str(status)}
        parsed = parse_doh_answer(body)
        if parsed.get("error"):
            return {"state": "transient_fail", "a": [], "cname": [], "rcode": None,
                    "error": str(parsed["error"])}
        ips, _fake = filter_fake_ips(parsed["a"])
        rcode = parsed.get("rcode")
        if ips:
            return {"state": "resolved", "a": ips, "cname": parsed["cname"],
                    "rcode": rcode, "fake_answers": len(parsed["a"]) - len(ips)}
        if rcode is not None and rcode != 0:
            # SERVFAIL/REFUSED are about the server, NXDOMAIN is about the name.
            if rcode == _DOH_RCODE_NXDOMAIN:
                return {"state": "nxdomain", "a": [], "cname": [], "rcode": rcode}
            return {"state": "transient_fail", "a": [], "cname": [], "rcode": rcode,
                    "error": "rcode " + str(rcode)}
        return {"state": "nxdomain", "a": [], "cname": parsed["cname"], "rcode": rcode}

    def query(self, name: str) -> dict:
        """One name, with a single retry on a transient failure."""
        first = self._query_once(name)
        if first["state"] != "transient_fail" or self.retry <= 0:
            return first
        second = self._query_once(name)
        if second["state"] != "transient_fail":
            second["retried"] = True
            return second
        return {"state": "transient_fail", "a": [], "cname": [], "rcode": None,
                "error": (second.get("error") or first.get("error") or "failed twice"),
                "attempts": 2}

    def resolve_many(self, names: list[str]) -> dict[str, dict]:
        """Resolve every name; returns {name: result}. Order is not preserved
        (the caller owns ordering). Concurrency is bounded so a 5000-name list
        does not open 5000 sockets."""
        names = [n for n in names if n]
        if not names:
            return {}
        if self.concurrency <= 1 or len(names) == 1:
            return {n: self.query(n) for n in names}
        out: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for name, res in zip(names, pool.map(self.query, names)):
                out[name] = res
        return out


# ---------------------------------------------------------------- TLS names
# httpx -tls-grab puts the standard TLS fields under "tls". Field names taken
# from the bundled binary's JSON: subject_cn / subject_an / issuer_cn /
# issuer_dn, plus "dns_names" on builds that emit the raw certificate names.
_TLS_KEYS = ("tls", "tls_grab", "tlsgrab")


def _tls_block(row) -> dict:
    if not isinstance(row, dict):
        return {}
    for k in _TLS_KEYS:
        v = row.get(k)
        if isinstance(v, dict):
            return v
    return {}


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [x for x in re.split(r"[,\s]+", v) if x]
    if isinstance(v, (list, tuple, set)):
        out = []
        for x in v:
            if isinstance(x, str):
                out.extend([y for y in re.split(r"[,\s]+", x) if y])
        return out
    return []


def _as_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v if x)
    return str(v).strip()


def parse_cert_names(httpx_json_row) -> dict:
    """Certificate identities from one httpx row.

    Returns {"san": [...], "cn": str, "issuer": str}. `san` merges every name
    the certificate claims (subject_an / dns_names) plus the CN, deduplicated
    in first-seen order; `cn` is the first subject CN. An empty result means
    "no certificate observed", which is a different fact from "a certificate
    with no names" -- the caller must not store a row for it.
    """
    tls = _tls_block(httpx_json_row)
    if not tls:
        return {"san": [], "cn": "", "issuer": ""}
    names: list[str] = []
    for key in ("subject_an", "dns_names", "san"):
        for n in _as_list(tls.get(key)):
            low = n.strip().lower()
            if low and low not in names and not low.startswith("*."):
                names.append(low)
            elif low.startswith("*.") and low not in names:
                # a wildcard is a real SAN; keep it verbatim (it is evidence
                # of the parent zone, callers decide whether it is a host)
                names.append(low)
    cn = _as_text(tls.get("subject_cn") or tls.get("subject_cn_name")
                  or tls.get("cn"))
    if not cn:
        cn_list = _as_list(tls.get("subject_cn"))
        cn = cn_list[0] if cn_list else ""
    if cn and cn.lower() not in names:
        names.insert(0, cn.lower())
    issuer = _as_text(tls.get("issuer_cn") or tls.get("issuer_dn")
                      or tls.get("issuer"))
    return {"san": names, "cn": cn, "issuer": issuer}


def cert_host_names(parsed: dict) -> list[str]:
    """Hostnames a parsed certificate can be used as, wildcards dropped.

    A wildcard SAN (*.example.com) is evidence about the zone, not a host: it
    would never resolve and would pollute the dns queue.
    """
    out = []
    for n in (parsed or {}).get("san") or []:
        n = (n or "").strip().lower().rstrip(".")
        if not n or n.startswith("*") or " " in n:
            continue
        if n not in out:
            out.append(n)
    return out


# ---------------------------------------------------------------- certs -> dns
# A certificate is evidence about NAMES, and one certificate routinely answers
# for a pile of unrelated hosts (a shared CDN edge, a multi-tenant SaaS
# front-end). Splitting the names a certificate claims into "in scope" and
# "related" is the whole point: the in-scope ones go back to the dns queue for
# the next round, the rest are stored as related assets and never probed.
CERT_IN_SCOPE = "in_scope"
CERT_RELATED = "related"


def _norm_cert_name(name: str) -> str:
    return (name or "").strip().lower().rstrip(".")


def cert_queue_entries(parsed: dict, sources, scope, ip: str = "",
                       seen: set | None = None) -> dict:
    """Route the host names of one certificate.

    `sources` is the host (or hosts) whose HTTP response carried the
    certificate, `scope` the engagement scope (`core.canon_scope` shape:
    host prefixes; a name is in scope when it equals an entry or ends with
    ".<entry>"). Returns

        {"in_scope": [{"host", "cert_ip", "source", "sans"}],
         "related": [{"host", "cert_ip", "source"}],
         "skipped": [{"name", "reason"}]}

    `related` is the storage contract owned by part p4-ip-cert: a host the
    certificate names but the engagement did not ask for. `skipped` keeps the
    names we deliberately did not forward (wildcards, garbage) so the gap is
    visible instead of silently dropped. `seen` is an optional set of names
    already forwarded, used to de-duplicate across many rows in one round.
    """
    parsed = parsed or {}
    scope = [s for s in (scope or []) if s]
    if isinstance(sources, str):
        sources = [sources]
    sources = [s for s in (sources or []) if s]
    in_scope: list[dict] = []
    related: list[dict] = []
    skipped: list[dict] = []
    seen = seen if isinstance(seen, set) else set()
    names = cert_host_names(parsed)
    for raw in (parsed.get("san") or []):
        n = _norm_cert_name(raw)
        if n.startswith("*"):
            skipped.append({"name": n, "reason": "wildcard"})
        elif n and n not in names:
            skipped.append({"name": n, "reason": "not_a_hostname"})
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        source = _source_for(name, sources)
        if is_in_scope(name, scope):
            in_scope.append({"host": name, "cert_ip": ip or "",
                             "source": source, "sans": names})
        else:
            related.append({"host": name, "cert_ip": ip or "",
                            "source": source})
    return {"in_scope": in_scope, "related": related, "skipped": skipped}


def _source_for(name: str, sources: list) -> str:
    """The host whose certificate most likely carried `name`.

    Prefer the closest name in the same registrable family (the vhost that owns
    the SAN), else the first source. Only a hint for provenance: storage keys
    on `name`, not on the referrer.
    """
    for s in sources:
        if s == name:
            return s
    fam = _family(name)
    for s in sources:
        if fam and _family(s) == fam:
            return s
    return sources[0] if sources else ""


def _family(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def is_in_scope(name: str, scope) -> bool:
    """Host-prefix scope test (identical to `core.in_scope` semantics).

    Duplicated here on purpose: the dns module must be usable (and testable)
    without importing the whole core module, and an empty scope means "no
    scope given", never "everything matches".
    """
    name = _norm_cert_name(name)
    if not name:
        return False
    for s in scope or []:
        s = _norm_cert_name(s)
        if not s:
            continue
        if name == s or name.endswith("." + s):
            return True
    return False


# ---------------------------------------------------------------- name states
# Per-name resolution state. NXDOMAIN is final (the name does not exist; asking
# again costs a query and returns the same answer), a transient failure is
# retried once by the resolver and then left open for a later round.
NAME_RESOLVED = "resolved"
NAME_NXDOMAIN = "nxdomain"
NAME_TRANSIENT = "transient_fail"


def ensure_name_states(states):
    """The per-name resolution record, created when the caller has none.

    One shape for the whole program: `{name: {"state": ..., "a": [...],
    "cname": [...], ...}}`. Returning the same object (not a copy) is the
    point -- the dns stage updates it in place so a later round can skip the
    work instead of re-querying a NXDOMAIN.
    """
    return states if isinstance(states, dict) else {}


def merge_name_states(into: dict, extra: dict) -> dict:
    """Merge `extra` into `into` and return `into`.

    A resolved record replaces a NXDOMAIN one (the name exists after all), but
    a NXDOMAIN never overwrites a resolved record: the second answer came from a
    different resolver and losing a real address would hide an asset.
    """
    into = into if isinstance(into, dict) else {}
    for name, rec in (extra or {}).items():
        if not name or not isinstance(rec, dict):
            continue
        cur = into.get(name)
        if cur and cur.get("state") == NAME_RESOLVED \
                and rec.get("state") == NAME_NXDOMAIN:
            continue
        into[name] = rec
    return into


# Ports that speak TLS by convention. 443/8443 are the obvious ones; the rest
# are what naabu finds on real appliances (device panels, admin APIs).
TLS_PORTS = frozenset((443, 8443, 9443, 10443, 9083, 9028, 6443, 4443))


def is_tls_port(port) -> bool:
    """True when a port is conventionally TLS, so a handshake is worth trying."""
    try:
        return int(port) in TLS_PORTS
    except (TypeError, ValueError):
        return False


def name_state(result: dict) -> str:
    """Classify one resolver result into the per-name state vocabulary."""
    if not isinstance(result, dict):
        return NAME_TRANSIENT
    if result.get("state"):
        return str(result["state"])
    if result.get("a") or result.get("cname"):
        return NAME_RESOLVED
    return NAME_NXDOMAIN


def should_query(name: str, states: dict) -> bool:
    """True unless the name is already known to be NXDOMAIN.

    Resolved names are re-checked (an address can change between rounds; it is
    cheap and keeps the graph fresh); only a NXDOMAIN is final.
    """
    rec = (states or {}).get(name)
    state = rec.get("state") if isinstance(rec, dict) else rec
    return state != NAME_NXDOMAIN
