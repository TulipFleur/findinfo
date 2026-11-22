"""findinfo tools: thin, typed wrappers around bundled binaries + APIs.

Every function:
  - takes explicit inputs
  - returns structured dicts (never raw HTML)
  - writes normalized records into the store
"""
from __future__ import annotations

import atexit
import json
import ipaddress
import os
import urllib.error
import urllib.request
import uuid
import re
import socket
import threading
import time
import concurrent.futures as futures
from pathlib import Path
from typing import Any

from . import core
from . import doh

# ---------------------------------------------------------------- helpers
BASE_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.I)
# Real records read 湘ICP备05009865号-1 (no letter between the province and ICP); old
# formats allow one letter, so it is optional rather than required. Requiring
# it made every real ICP number invisible to the harvester.
ICP_RE = re.compile(r"[\u4eac\u6d25\u6caa\u6e1d\u5180\u8c6b\u4e91\u8fbd\u9ed1\u6e58\u7696\u9c81\u65b0\u82cf\u6d59\u8d63\u9102\u6842\u7518\u664b\u8499\u9655\u5409\u95fd\u8d35\u7ca4\u9752\u85cf\u5ddd\u5b81\u743c][A-Za-z]?ICP[\u5907\u8bc1]\d+\u53f7(?:-\d+)?")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


# Tool input lists live in DATA/_tmp. Each call REUSES one slot per suffix
# instead of minting a new mkstemp name: a long background run calls this on
# every stage of every round, and with atexit-only cleanup the directory grew
# without bound until the process exited (a 20-minute run left dozens of
# multi-megabyte dnsx/httpx inputs behind). One file per stage is overwritten
# in place, so the on-disk footprint stays at (#suffixes) files.
_TMP_FILES: dict[str, str] = {}


def _cleanup_tmp() -> None:
    for path in list(_TMP_FILES.values()):
        try:
            os.remove(path)
        except Exception:
            pass
    _TMP_FILES.clear()


atexit.register(_cleanup_tmp)


def _tmp_lines(rows: list[str], suffix: str = ".txt") -> str:
    """Write a tool input list into a per-suffix slot, overwriting it.

    The file is truncated in place, so nothing accumulates while a long run
    is in flight. It is still removed at process exit.
    """
    tmpdir = core.DATA / "_tmp"
    tmpdir.mkdir(parents=True, exist_ok=True)
    path = _TMP_FILES.get(suffix)
    if not path:
        path = str(tmpdir / ("stdin" + suffix))
        _TMP_FILES[suffix] = path
    body = chr(10).join([r for r in rows if r]) + chr(10)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(body)
    return path


def _uniq(seq) -> list:
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _looks_public(domain: str) -> bool:
    """True when the value is a host a recon run could plausibly see.

    This is not a shape check: core.canon_domain already enforces the shape
    and rejects JS property chains (`e.style.top`), file names (`x.js`) and
    anything without a real public suffix. Testing the shape again with a
    looser regex let every one of those back in -- a live run stored 145
    bogus "domains" (`b.filter.id`, `math.pi`, `arg.lengths`) out of 181,
    so 80% of the domain list was JavaScript noise.
    """
    return bool(core.canon_domain(domain or ""))


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
# Per-entity harvest. The old `harvest_entity` flattened every company, ICP
# number and domain into three global lists and then attached ALL domains to
# the FIRST kept company: once two entities were in the answer, entity B's
# assets became entity A's, which could widen the active scope to a company
# the run was never authorised for (F06). The functions below keep every asset
# with the subject that actually filed it.

_SUBJECT_NAME_KEYS = ("company", "name", "enterprise", "legal_name",
                      "company_name", "entname")
_SUBJECT_ID_KEYS = ("id", "eid", "entity_id", "pid", "subject_id", "entid")


def _entity_subject(node: dict) -> dict:
    """Best-effort subject identity of one ENScan entity object."""
    subject_id = ""
    for k, v in node.items():
        if str(k).lower() in _SUBJECT_ID_KEYS and isinstance(v, (str, int)):
            if str(v).strip():
                subject_id = str(v).strip()
                break
    name = ""
    for k, v in node.items():
        if str(k).lower() in _SUBJECT_NAME_KEYS and isinstance(v, str):
            if v.strip():
                name = v.strip()
                break
    return {"subject_id": subject_id, "legal_name": name}


def _own_assets(node: dict, depth: int = 0) -> dict:
    """Domains/ICP/apps that belong to THIS entity object (not to children).

    Nested objects that carry their own subject identity are other companies
    (investment/branch lists); their assets stay with them.
    """
    out = {"domains": [], "icp": [], "apps": []}
    if depth > 6 or not isinstance(node, dict):
        return out
    for key, val in node.items():
        k = str(key).lower()
        if isinstance(val, str):
            if "domain" in k:
                d = core.canon_domain(val)
                if d and _looks_public(d):
                    out["domains"].append(d)
            if "icp" in k:
                out["icp"].extend(ICP_RE.findall(val))
            if "app" in k and len(val) < 200:
                out["apps"].append(val.strip())
            for m in DOMAIN_RE.findall(val):
                d = core.canon_domain(m)
                if d and _looks_public(d):
                    out["domains"].append(d)
        elif isinstance(val, dict):
            if _entity_subject(val)["legal_name"]:
                continue        # a nested subject: its own assets, not ours
            sub = _own_assets(val, depth + 1)
            for kk in out:
                out[kk].extend(sub[kk])
        elif isinstance(val, list):
            for it in val:
                if isinstance(it, dict):
                    if _entity_subject(it)["legal_name"]:
                        continue
                    sub = _own_assets(it, depth + 1)
                    for kk in out:
                        out[kk].extend(sub[kk])
    for kk in out:
        out[kk] = _uniq([x for x in out[kk] if x])
    return out


def harvest_entities(obj: Any, depth: int = 0) -> list:
    """Every entity object that has a subject identity, with its own assets.

    Each entry: {subject_ref, subject_id, legal_name, aliases, domains, icp,
    apps, evidence_ref}. `subject_ref` prefers the source's own stable ID and
    falls back to a marked name reference, so a display-name change cannot
    orphan the assets (T07).

    ENScan documents put the company records and the asset tables SIDE BY SIDE
    (e.g. {"enterprise_info":[{name}], "icp":[{domain, icp}]}), so a document
    with exactly ONE subject identity is attributed that document's assets.
    With several subjects the assets stay with the container and are NOT
    assigned to any of them -- guessing which company filed an unattached
    domain is exactly the F06 failure.
    """
    found: list = []
    if depth > 14:
        return found
    if isinstance(obj, dict):
        subject = _entity_subject(obj)
        if subject["legal_name"] or subject["subject_id"]:
            own = _own_assets(obj)
            aliases = []
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in ("alias", "aliases", "short_name", "brand") \
                        and isinstance(v, str) and v.strip():
                    aliases.append(v.strip())
            ref = (("id:" + subject["subject_id"])
                   if subject["subject_id"] else
                   ("name:" + subject["legal_name"]))
            found.append({
                "subject_ref": ref,
                "subject_id": subject["subject_id"],
                "legal_name": subject["legal_name"],
                "aliases": _uniq(aliases),
                "domains": own["domains"],
                "icp": own["icp"],
                "apps": own["apps"],
                "evidence_ref": ("enscan:" + ref),
            })
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    if isinstance(v, dict) and _entity_subject(v)["legal_name"]:
                        continue
                    found.extend(harvest_entities(v, depth + 1))
            return _merge_by_ref(found)
        # no subject at this level: collect child entities AND, when the
        # document names exactly one subject anywhere, attribute this level's
        # own asset tables to it
        child_entities: list = []
        for v in obj.values():
            if isinstance(v, (dict, list)):
                child_entities.extend(harvest_entities(v, depth + 1))
        child_entities = _merge_by_ref(child_entities)
        if len(child_entities) == 1:
            own = _own_assets(obj)
            ent = child_entities[0]
            if own["domains"] or own["icp"] or own["apps"]:
                ent = dict(ent)
                ent["domains"] = _uniq(ent["domains"] + own["domains"])
                ent["icp"] = _uniq(ent["icp"] + own["icp"])
                ent["apps"] = _uniq(ent["apps"] + own["apps"])
                child_entities = [ent]
        return child_entities
    if isinstance(obj, list):
        out: list = []
        for it in obj:
            out.extend(harvest_entities(it, depth + 1))
        return _merge_by_ref(out)
    return found


def _merge_by_ref(entities: list) -> list:
    """Collapse entities that are the SAME subject, unioning their assets.

    The same company can appear twice in one document: once as
    {id, name} and once as {name} alone (a child table repeats the name
    without the id). Merging by subject_ref alone kept them apart. A stable
    SOURCE ID wins: every name-ref of that legal name is folded into the
    id-ref, so one subject has exactly one identity (T07).
    """
    # first pass: which legal names have a stable id?
    id_for_name: dict = {}
    for ent in entities:
        if ent.get("subject_id") and ent.get("legal_name"):
            id_for_name.setdefault(ent["legal_name"], ent["subject_ref"])
    by_ref: dict = {}
    order: list = []
    for ent in entities:
        key = ent["subject_ref"]
        if not ent.get("subject_id") and ent.get("legal_name") in id_for_name:
            key = id_for_name[ent["legal_name"]]
        if key not in by_ref:
            merged = dict(ent)
            merged["subject_ref"] = key
            by_ref[key] = merged
            order.append(key)
            continue
        cur = by_ref[key]
        for kk in ("domains", "icp", "apps", "aliases"):
            cur[kk] = _uniq(cur[kk] + ent[kk])
        if not cur.get("subject_id") and ent.get("subject_id"):
            cur["subject_id"] = ent["subject_id"]
    return [by_ref[k] for k in order]


def harvest_entity(obj: Any, depth: int = 0) -> dict:
    """Format-tolerant harvest: pull companies / ICP / domains out of any ENScan JSON.

    Legacy flat view kept for counters and old callers. Asset decisions use
    harvest_entities(), which keeps each asset with its subject.
    """
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



# ------------------------------------------------------- subject and scope
def resolve_entity_identity(raw: str, candidates: list,
                            explicit_domains: list) -> dict:
    """Decide whether a brand resolves to ONE subject before any traffic.

    A short brand match can produce CANDIDATE subjects, not automatic
    ownership (docs/RELIABILITY-PLAN.md par.8). When more than one plausible
    subject exists and no explicit seed disambiguates, the caller must stop
    with identity_ambiguous + input-required next steps: launching discovery
    on a guessed target would probe the wrong company. An explicit seed
    (user-typed domain) anchors the run without the brand at all.
    """
    seed = [d for d in (explicit_domains or []) if d]
    if seed:
        return {"status": "ok", "subject_id": None, "basis": "explicit seed",
                "retryable": False, "next_steps": []}
    names = [c.get("name") or "" for c in (candidates or [])]
    exact = [c for c in (candidates or []) if c.get("name") == raw]
    if len(exact) == 1:
        return {"status": "ok", "subject_id": exact[0].get("id"),
                "basis": "unique exact match", "retryable": False,
                "next_steps": []}
    if len(set(names)) > 1 or len(exact) > 1:
        return {"status": "identity_ambiguous", "subject_id": None,
                "basis": "%d plausible subject(s)" % len(set(names)),
                "retryable": False,
                "next_steps": ["input required: provide an explicit "
                               "--domain or the exact registered company "
                               "name, then start a new run"]}
    if not candidates:
        return {"status": "no_match", "subject_id": None,
                "basis": "no subject answered for the brand",
                "retryable": False,
                "next_steps": ["check the brand name, or seed with --domain"]}
    return {"status": "ok", "subject_id": candidates[0].get("id"),
            "basis": "single candidate", "retryable": False,
            "next_steps": []}


def seeds_for_subject(store, subject_id: str) -> list:
    """Domain seeds anchored to one subject, by reference not by alias.

    The store keys ENScan rows by parent=<subject id>; a later display-name
    change (or the brand never matching the legal name, T07) must not
    orphan the seeds, so the lookup goes through the subject reference.
    """
    return [a["canonical"] for a in store.get_assets(kind="domain")
            if (a.get("parent") or "") == subject_id]


def evidence_grants_scope(store, canonical: str, scope: list) -> bool:
    """Whether an asset may ENTER the active stages for this scope.

    Only explicit user scope does (T12): suffix membership. Evidence links
    (a related SAN, a same-IP neighbour, a co-issued certificate) are kept
    as evidence rows -- they never widen the active scope on their own.
    """
    return core.in_scope(canonical, scope)


def endpoint_of(value: str):
    """(ip, port|None) of a bare IP or ip:port target (T13).

    The port is preserved exactly: 203.0.113.10:8443 is an endpoint target,
    and normalising it to a hostname would drop the only property the user
    actually gave.
    """
    text = str(value or "").strip().strip("[]")
    if ":" in text:
        host, _, port = text.rpartition(":")
        host = host.strip("[]")
        if host and port.isdigit() and 0 < int(port) < 65536:
            ip = core.canon_ip(host)
            if ip:
                return ip, int(port)
        return None, None
    ip = core.canon_ip(text)
    return (ip, None) if ip else (None, None)


def classify_negative(answer: dict) -> str:
    """Distinguish every non-answer from an authoritative NXDOMAIN (T15).

    fake_ip      -- a synthetic resolver address (198.18.0.0/15): proof of
                    a lying resolver, never a verdict about the name;
    transient    -- no answer at all (timeout/NODATA with nothing else): an
                    open question a later round may answer;
    cname_only   -- a CNAME chain that must be resolved further, not judged;
    resolved     -- an ordinary address exists.
    Only an explicit NXDOMAIN rcode settles a name as absent (see
    classify_nxdomain); none of these states may.
    """
    ans = answer or {}
    ips = [x for x in (ans.get("a") or []) if x]
    if any(doh.is_fake_ip(x) for x in ips):
        return "fake_ip"
    if ips:
        return "resolved"
    if ans.get("cname"):
        return "cname_only"
    return "transient"


def classify_nxdomain(answer: dict) -> bool:
    """True only for an authoritative NXDOMAIN rcode (T15)."""
    return bool((answer or {}).get("rcode") == 3)

def store_approved_entities(store, companies, approved) -> dict:
    """Write the company / domain / ICP / APP rows for the APPROVED subjects.

    Split out of t_enscan so the storage contract can be tested without
    starting the ENScan binary (it holds a cross-process lock and resumes a job
    cache). `approved` is the per-subject list harvest_entities() produced;
    anything not approved by the anchor gate is never stored (F06).

    Apps were the gap: the payload carried them, the store did not, so the
    brief / report / xlsx all reported zero mini-programs for a company whose
    ENScan answer listed a dozen.
    """
    for c in companies or []:
        store.upsert_asset("company", c, source="enscan",
                           confidence=0.9, passivity="passive")
    domains: list = []
    icp: list = []
    apps: list = []
    for ent in approved or []:
        ref = ent["subject_ref"]
        store.upsert_asset("company", ent["legal_name"] or ref,
                           source="enscan:" + ref, confidence=0.9,
                           passivity="passive", parent=ref)
        for d in ent["domains"]:
            store.upsert_asset("domain", d, source="enscan",
                               confidence=0.9, passivity="passive", parent=ref)
            domains.append(d)
        for code in ent["icp"]:
            store.upsert_asset("icp", code, source="enscan", confidence=0.9,
                               passivity="passive", parent=ref)
            icp.append(code)
        for app in ent.get("apps") or []:
            store.upsert_asset("app", app, source="enscan", confidence=0.85,
                               passivity="passive", parent=ref)
            apps.append(app)
    return {"domains": _uniq(domains), "icp": _uniq(icp), "apps": _uniq(apps)}


def t_enscan(store, name: str, invest: int = 51, deep: int = 1,
             outdir: Path | None = None, timeout: int = 0,
             field: str = "icp,app,wx_app,wechat,copyright,invest,enterprise_info",
             delay: int = 2, supplier: bool = False,
             branch: bool = False) -> dict:
    exe = core.tool("enscan")
    outdir = outdir or (core.RUNS_DIR / "enscan")
    outdir.mkdir(parents=True, exist_ok=True)
    # Snapshot existing outputs so a re-run cannot harvest stale JSON from a
    # previous target/time (that silently merged another company's domains in).
    before = {p.resolve() for p in outdir.rglob("*.json")}
    cmd = [exe, "-n", name, "-invest", str(invest), "-deep", str(deep),
           "-json", "-out-dir", str(outdir), "-type", "aqc",
           "-delay", str(delay), "-is-fast"]
    # Supplier/branch expansion walks OTHER companies (a supplier network
    # depth-first for pages on end) and returns almost no asset rows for the
    # target, so both are opt-in: coverage first, quota and time after.
    if branch:
        cmd += ["-branch"]
    if supplier:
        cmd += ["-supplier"]
    if field:
        cmd += ["-field", field]
    core.log("enscan: " + " ".join(cmd[1:]))
    # ENScan is the slowest stage in practice: a deep query with every field can
    # run for tens of minutes against aiqicha. Say so up front and keep a beat,
    # so a waiting agent can tell "working" from "stuck".
    core.log("enscan: deep=" + str(deep) + " fields=" +
             str(len(field.split(",")) if field else 0) + " - this can take 10+ min")
    # ENScan persists its unfinished JOB queue in bin/enscan.gob and RESUMES it
    # on the next start -- even when the new command asks for a different query.
    # One interrupted deep query (a 79-page branch walk killed at the 20 min
    # cap) then poisons every later run: each invocation reloads that queue and
    # times out without exporting anything. Observed live: 350 s timeouts with
    # 'remaining batch tasks=1' until the file was deleted, then 12 s and a
    # normal export. Stale state is never worth resuming across runs here, so
    # drop it before launching; the file is a cache, not a data source.
    _enscan_cache = Path(exe).parent / "enscan.gob"
    try:
        _enscan_cache.unlink()
        core.log("enscan: dropped stale job cache " + str(_enscan_cache))
    except FileNotFoundError:
        pass
    except OSError as exc:
        core.log("enscan: could not drop job cache: " + str(exc))
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
    entities: list = []
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
        # per-entity view: each asset stays with the subject that filed it
        for ent in harvest_entities(data):
            ent = dict(ent)
            ent["evidence_ref"] = "enscan:" + p.name + ":" + ent["subject_ref"]
            entities.append(ent)
    for k in merged:
        merged[k] = _uniq(merged[k])
    # merge the per-entity view across files by subject reference
    by_ref: dict = {}
    for ent in entities:
        key = ent["subject_ref"]
        if key not in by_ref:
            by_ref[key] = dict(ent)
        else:
            cur = by_ref[key]
            for kk in ("domains", "icp", "apps", "aliases"):
                cur[kk] = _uniq(cur[kk] + ent[kk])
    entities = list(by_ref.values())
    # ANCHORING GATE. Only entities that really are the requested one may
    # contribute assets. aiqicha answers a MISS with a popular lookalike, so
    # trusting the response wrote another company 42 domains and 27 ICP
    # numbers into the store under the user name at confidence 0.9 -- the
    # worst failure mode, because the report then looks authoritative.
    company_names = [e["legal_name"] for e in entities if e["legal_name"]] \
        or merged["companies"]
    kept, rejected = filter_entities(company_names, name)
    if not kept:
        core.log("enscan: no entity matched " + str(name) +
                 "; discarding " + str(len(rejected)) + " unrelated result(s)" +
                 ((": " + ", ".join(rejected[:3])) if rejected else "") +
                 " -- unanchored (coverage gap), not this entity")
        return {"rc": rc, "json_files": files, "stderr": err[-800:],
                "table_only": files == 0 and table,
                "anchor_failed": True, "rejected": rejected[:20],
                "companies": [], "icp": [], "domains": [], "apps": [],
                "subjects": [], "candidates": [
                    {"name": e["legal_name"], "ref": e["subject_ref"],
                     "domains": len(e["domains"])} for e in entities]}
    # Approved subjects are the ONLY ones whose assets are granted. Every
    # other returned entity is preserved as candidate evidence (subject list,
    # asset counts) and never enters the seed/scope set (F06).
    #
    # Approval is decided per ENTITY: its legal name must be one filter_entities
    # kept as THE requested name. A short brand like "fixture-subject" shares a
    # prefix with both A and B -- name_matches alone would approve both, so the
    # approved set is intersected with the exact kept names.
    kept_set = set(kept)
    approved = [e for e in entities if e["legal_name"] in kept_set]
    if not approved and entities:
        # no entity carried a kept legal name: treat the single-entity case
        # conservatively -- the anchor gate above already proved the name
        # matches, and with ONE subject there is nothing to confuse it with.
        if len(entities) == 1:
            approved = entities
    candidates = [e for e in entities if e not in approved]
    merged["companies"] = kept
    _stored = store_approved_entities(store, kept, approved)
    approved_domains = _stored["domains"]
    approved_icp = _stored["icp"]
    approved_apps = _stored["apps"]
    if files == 0 and table:
        core.log("enscan: printed a report table but wrote no JSON to " +
                 str(outdir) + " — entity data could not be parsed; treat as a "
                 "coverage gap, not as 'this company has no assets'")
    if kept and not approved_domains:
        core.log("enscan: anchored " + kept[0] +
                 " but this source filed no domain -- the company is real, its "
                 "domain set is simply empty here")
    return {"rc": rc, "json_files": files, "stderr": err[-800:],
            "table_only": files == 0 and table,
            "companies": merged["companies"][:200],
            "icp": approved_icp, "domains": approved_domains,
            "apps": approved_apps[:100],
            "subjects": [{"ref": e["subject_ref"],
                          "legal_name": e["legal_name"],
                          "approved": True,
                          "domains": len(e["domains"])} for e in approved],
            "candidates": [{"ref": e["subject_ref"],
                            "legal_name": e["legal_name"],
                            "approved": False,
                            "domains": len(e["domains"])} for e in candidates]}


# Entity-name anchoring: what makes an ENScan hit THIS target and not
# another company. aiqicha answers a query that misses with a popular
# lookalike (a search for a college name came back with 13 meituan-group
# companies), and accepting those wrote another company's 42 domains into
# the store under the user's name at confidence 0.9.
_NAME_STRIP = " ()\uff08\uff09\u00b7.,\uff0c\u3001-\u2014_\u3000\u2308\u2309\u300c\u300d\u3010\u3011\u3008\u3009\u300a\u300b"
_NAME_SUFFIX = (
    "\u6709\u9650\u8d23\u4efb\u516c\u53f8", "\u80a1\u4efd\u6709\u9650\u516c\u53f8",
    "\u6709\u9650\u516c\u53f8", "\u80a1\u4efd\u516c\u53f8", "\u5206\u516c\u53f8",
    "\u96c6\u56e2", "\u516c\u53f8", "\u4f01\u4e1a", "\u5382", "\u5e97",
)


def norm_entity_name(name: str) -> str:
    """Comparable form of a company/school name (no legal form, no spaces).

    The legal suffix is dropped because the same entity is written both ways
    ("X Tech Co Ltd" in the registry, "X Tech" in a report), and a suffix
    mismatch must not read as "a different company".
    """
    s = str(name or "").strip()
    for ch in _NAME_STRIP:
        s = s.replace(ch, "")
    s = s.lower()
    for suf in _NAME_SUFFIX:
        if s.endswith(suf) and len(s) > len(suf) + 1:
            s = s[: -len(suf)]
            break
    return s


def name_matches(wanted: str, got: str) -> bool:
    """Whether entity ``got`` is plausibly the entity the user asked for.

    Deliberately strict: a substring hit on one shared word is how a college
    query got answered with a delivery company. Two rules pass: one name
    contains the other after normalisation (a parent company vs its branch),
    or the two differ only by a tiny suffix/typo (a shared brand plus one
    trailing word is NOT enough).

    The prefix rule used to accept anything sharing 6+ leading characters, so
    "fixture-subject-A" and "fixture-subject-B" -- two DIFFERENT subjects
    under one brand -- both anchored, and one company's assets could be
    granted to the other (F06). The prefix now has to cover essentially the
    whole shorter name (differing by at most one character), which keeps
    typo/parent-company tolerance and rejects sibling brand members.
    """
    a, b = norm_entity_name(wanted), norm_entity_name(got)
    if not a or not b:
        return False
    if a == b:
        return True
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    if len(short) >= 4 and short in long_:
        return True
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    if n < 6:
        return False
    if n >= min(len(a), len(b)) - 1:
        # A long shared prefix is identity only when the names then end, or
        # the remaining tail is a BOUNDARY suffix ("公司长沙分公司"), not a
        # different token ("-A" vs "-B"). Two sibling brand members share a
        # prefix and differ in one character exactly like a typo does, so the
        # tie-break is the shape of the tail.
        ta, tb = a[n:], b[n:]
        if not ta or not tb:
            return True
        sep = "-_.  "
        if (ta.startswith(tuple(sep)) or tb.startswith(tuple(sep))):
            return True
        # a single differing alphanumeric tail on BOTH sides is a sibling
        # marker (A/B, 1/2), not a shared identity
        if len(ta) <= 2 and len(tb) <= 2 and ta[-1:].isalnum() and tb[-1:].isalnum():
            return False
        return True
    return False


def filter_entities(companies: list, wanted: str) -> tuple:
    """Split harvested company names into (kept, rejected).

    ``kept`` is empty when NOTHING matched: the caller then reports an
    unanchored entity instead of harvesting a stranger's assets.
    """
    kept, rejected = [], []
    for c in companies or []:
        (kept if name_matches(wanted, c) else rejected).append(c)
    return _uniq(kept), _uniq(rejected)


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
# Each engine is asked in its own query language (core.uncover_query); an
# empty answer cannot be told apart from an upstream error, so it is marked.
UNCONFIRMED_NOTE = ("uncover answers an upstream error the same way (rc=0, "
                    "no rows): this empty is unconfirmed")


def t_icp(store, codes: list[str], engines: str = "fofa,quake,hunter",
          timeout: int = 0, ledger=None) -> dict:
    """ICP reverse lookup; `ledger` records one row per billed request."""
    from . import metered as _metered

    def _billed(engine: str, input_hash: str = "", **kw) -> None:
        if ledger is None:
            return
        try:
            ledger.record(engine=engine, input_hash=input_hash or
                          _metered.hash_input({"engine": engine}), **kw)
        except Exception:
            pass

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
    unconfirmed: list[str] = []
    unsupported: list[str] = []
    for code in codes:
        code = code.strip()
        if not code:
            continue
        store.upsert_asset("icp", code, source="icp-seed", confidence=0.9,
                           passivity="passive")
        # A self-hosted FOFA relay covers ICP reverse lookup without uncover.
        if core.api_base("fofa"):
            _t0 = time.time()
            res = fofa_gateway_query('icp="' + code + '"', size=10000, timeout=timeout)
            _billed("fofa-gateway",
                    input_hash=_metered.hash_input({"icp": code}),
                    status=_metered.ST_QUOTA if (res and res.get("quota_exhausted"))
                    else (_metered.ST_FAILED if res is None else
                          (_metered.ST_EMPTY if not (res or {}).get("count")
                           else _metered.ST_OK)),
                    requested=1, returned=int((res or {}).get("count") or 0),
                    elapsed_sec=time.time() - _t0,
                    quota={"remaining": (res or {}).get("remaining"),
                           "maxQueries": (res or {}).get("maxQueries")})
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
        for eng in usable:
            q = core.uncover_query("icp", eng, code)
            if not q:
                # Shodan/Censys have no ICP field: asking them anyway only
                # ever produced a silent zero. Not asked, reported as a gap.
                if eng not in unsupported:
                    unsupported.append(eng)
                continue
            core.throttle(eng)
            core.mapping_wait()
            _t1 = time.time()
            rc, out, err = core.run([exe, "-q", q, "-e", eng, "-json",
                                     "-silent"], timeout=timeout)
            _n = sum(1 for _ in core.parse_jsonl(out))
            _billed("uncover:" + eng, input_hash=_metered.hash_input(
                        {"icp": code, "engine": eng}),
                    unit=_metered.UNIT_NATIVE_DISPATCH,
                    rc=rc, requested=1, returned=_n,
                    elapsed_sec=time.time() - _t1,
                    error=(err or "")[-200:] if rc not in (0, None) else "",
                    status=("failed" if rc == 124 else
                            "empty" if _n == 0 and rc in (0, None) else
                            "ok" if rc in (0, None) else "failed"))
            _low = (err or "").lower()
            # "requires keys but no keys were found" / "no api key" is a
            # CAPABILITY gap (docs: a missing optional credential is not a
            # stage failure), not a tool fault.
            _missing_key = any(k in _low for k in
                               ("requires keys", "no keys", "no api key",
                                "unauthorized", "401", "403"))
            if rc != 0 or (_missing_key and not (out or "").strip()):
                core.log("icp " + code + " via " + eng + ": uncover rc=" + str(rc)
                         + ("; " + err.strip()[:200] if err.strip() else ""))
                _entry = {"code": code, "engine": eng, "rc": rc,
                          "stderr": err.strip()[:300]}
                if _missing_key:
                    _entry["unavailable"] = True
                errors.append(_entry)
            elif not (out or "").strip():
                # uncover swallows upstream API errors (bad key -> empty stdout
                # with rc=0), so this zero is indistinguishable from "no
                # results": a visible gap, not a clean empty and not a failure.
                core.log("icp " + code + " via " + eng + ": no rows (" +
                         UNCONFIRMED_NOTE + ")")
                if "uncover:" + eng not in unconfirmed:
                    unconfirmed.append("uncover:" + eng)
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
            "errors": errors, "unconfirmed_empty": sorted(unconfirmed),
            "unsupported_engines": unsupported}


# ---------------------------------------------------------------- 4. passive subdomains
# onepass sources that need NO credential (rust/onepass/src/sources.rs:
# every entry with Auth::None). Passive collection uses exactly this
# set, so the stage can never spend mapping quota.
KEYLESS_ONEPASS_SOURCES = ("crtsh", "certspotter", "hackertarget",
                            "rapiddns", "anubis", "alienvault",
                            "threatminer", "subdomain_center")


def _empty_provider_config() -> str:
    """Path to an empty subfinder provider-config, created once.

    subfinder reads the operator's global provider config unless -pc
    overrides it; an empty file is how this stage stays keyless
    (no fofa/quake/hunter key reaches it, and no second paid query).
    """
    path = core.DATA / "_empty_subfinder_provider.yaml"
    try:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# intentionally empty: findinfo queries "
                            "engines itself" + chr(10), encoding="utf-8")
    except OSError:
        pass
    return str(path)


def t_subs(store, domain: str, engines: str = "fofa,quake,hunter,shodan,censys",
           timeout: int = 0, ledger=None) -> dict:
    """Passive subdomain enumeration across the mapping engines.

    `ledger` is the run's MeteredLedger: every BILLed provider request
    (fofa-gateway call, uncover dispatch) appends exactly one row -- one row
    per REQUEST, never per result row (docs/RELIABILITY-PLAN.md par.10). None
    of the free sources (subfinder, chaos, onepass CT) is recorded.
    """
    from . import metered as _metered
    raw = domain
    domain = core.canon_domain(domain)
    if not domain:
        raise core.FindInfoError("invalid domain: " + str(raw))
    found: dict[str, set] = {}

    def _billed(engine: str, input_hash: str = "", **kw) -> None:
        """One ledger row per billed provider REQUEST (ledger is optional)."""
        if ledger is None:
            return
        try:
            ledger.record(engine=engine,
                          input_hash=input_hash or _metered.hash_input(
                              {"domain": domain, "engine": engine}), **kw)
        except Exception:
            pass

    def add(d: str, src: str) -> None:
        cd = core.canon_domain(d)
        if not cd:
            return
        if not (cd == domain or cd.endswith("." + domain)):
            return
        found.setdefault(cd, set()).add(src)

    # The FOFA relay is a PAID mapping backend: it is dispatched by the
    # single `mapping` stage (through the ledger), never from this passive
    # stage. Called here it paid for the same seed a second time in one run.

    per_source: list[dict] = []

    def run_source(sid: str, cmd: list[str], *, key: str, tool: str,
                   billed: bool = False) -> None:
        core.log(tool + " " + domain)
        _t0 = time.time()
        rc, out, err = core.run(cmd, timeout=timeout)
        before = len(found)
        for r in core.parse_jsonl(out):
            add(r.get(key, "") or r.get("host", ""), sid)
        n = sum(1 for srcs in found.values() if sid in srcs)
        outcome = core.outcome_from_rc(rc, n)
        entry = {"id": sid, "outcome": outcome, "found": n, "rc": rc,
                 "error": ("timeout" if rc == 124 else
                           (err or "")[-200:].strip() if rc not in (0, None) else "")}
        if tool == "uncover" and outcome == core.OUTCOME_EMPTY:
            entry["confirmed"] = False
            entry["note"] = UNCONFIRMED_NOTE
        per_source.append(entry)
        if outcome in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT):
            core.log(sid + ": " + outcome + " rc=" + str(rc))
        if billed:
            # uncover is the billed dispatcher (its engines all cost quota);
            # free sources (subfinder, chaos) never reach the ledger. One row
            # per engine dispatch, so a quota/auth verdict names its engine.
            _billed(sid, rc=rc, requested=1, returned=n,
                    unit=_metered.UNIT_NATIVE_DISPATCH,
                    elapsed_sec=time.time() - _t0,
                    error=(err or "")[-200:] if rc not in (0, None) else "",
                    status=("failed" if rc == 124 else
                            "empty" if n == 0 and rc in (0, None) else
                            "ok" if rc in (0, None) else "failed"))

    if core.has_tool("subfinder"):
        # subfinder reads a provider config when it can: with a global
        # ~/.config/subfinder/provider-config.yaml it silently re-queries
        # the same paid engines mapping already asked (and bills again).
        # -pc points it at an EMPTY file we own, so this stage stays
        # keyless whatever the operator has configured globally.
        run_source("subfinder",
                   [core.tool("subfinder"), "-d", domain, "-all",
                    "-recursive", "-silent", "-json",
                    "-pc", _empty_provider_config()],
                   key="host", tool="subfinder")
    else:
        per_source.append({"id": "subfinder", "outcome": core.OUTCOME_UNAVAILABLE,
                           "found": 0, "rc": None, "error": "binary not found"})

    # Paid mapping (uncover + the FOFA gateway + Chaos's keyed sources) is
    # NOT done here: it belongs to the single `mapping` stage, which consults
    # the task ledger so each question is paid for once. This stage is
    # passive and keyless by construction.
    unsupported: list[str] = []
    _ = engines  # accepted for interface compatibility; no dispatch here

    rows = []
    for d, srcs in found.items():
        conf = 0.5 if len(srcs) == 1 else (0.75 if len(srcs) == 2 else 0.95)
        store.upsert_asset("domain", d, source=",".join(sorted(srcs)),
                           confidence=conf, passivity="passive", parent=domain)
        rows.append({"domain": d, "sources": sorted(srcs), "confidence": conf})
    rows.sort(key=lambda x: x["domain"])

    outcomes = [p["outcome"] for p in per_source]
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
           "hint": core.outcome_hint(outcome),
           # gaps the outcome alone cannot show: an engine that answered
           # nothing (indistinguishable from an upstream error) and an engine
           # that was never asked because its syntax is unknown
           "unconfirmed_empty": sorted(p["id"] for p in per_source
                                       if p.get("confirmed") is False),
           "unsupported_engines": unsupported}
    return out


def _wildcard_report(evidence: dict) -> list:
    """Display rows for a wildcard evidence table (parent, address, probes)."""
    return [{"parent": k, "ip": v.get("ip") or v.get("fake") or "",
             "cname": v.get("cname") or "", "probes": int(v.get("probes") or 0),
             "signature": bool(doh.wildcard_signature_complete(evidence, k))}
            for k, v in sorted(evidence.items())]


def _accept_dns(store, domain: str, ips: list[str], cnames: list[str],
                source: str, wildcard: dict, rows: list) -> bool:
    """Store a resolved name unless the answer is ONLY a wildcard artefact.

    Shared by the dnsx path, the system-resolver fallback and the DoH path so
    all three apply identical rules (docs par.9):

    * the evidence table is keyed by the REGISTRABLE parent -- one key for
      every resolver path, never the probe name or a "wild." label;
    * only a COMPLETE signature (>=2 ordinary probe answers) filters, and
      only when the candidate's addresses are ALL the wildcard's own answer:
      a name carrying an additional independent A/AAAA/CNAME is mixed
      evidence and is kept, not erased;
    * a fake IP was already removed before this is called.

    Returns True when the name was stored. `rows` is the display list only;
    every row is stored regardless of the display cap.
    """
    parent = core.registrable_domain(domain) or ""
    if (parent and doh.wildcard_signature_complete(wildcard, parent)
            and doh.wildcard_answer_matches(wildcard, parent, ips)):
        return False              # wildcard echo: random names resolve here too
    for ip in ips:
        store.upsert_asset("ip", ip, source=source, confidence=0.6,
                           passivity="passive", parent=domain)
    store.upsert_asset("domain", domain, source=source, confidence=0.8,
                       passivity="passive")
    if len(rows) < core.ROW_LIMIT:      # display cap only; store gets all
        rows.append({"domain": domain, "a": ips, "cname": cnames})
    return True


def t_dns(store, domains: list[str], timeout: int = 0,
           states: dict | None = None, doh_client=None,
           plan: "doh.ResolutionPlan | None" = None,
           check_again: bool = False) -> dict:
    """Resolve domains with wildcard filtering.

    The wildcard filter is keyed on the REGISTRABLE parent (public-suffix
    aware), not "last two labels" -- customer.co.uk must not collapse to
    co.uk. Both resolvers (dnsx + system fallback) apply the SAME filter: the
    fallback used to accept every name a wildcard zone answered, which turned
    random subdomains into "trusted assets".
    `ok=False` means dnsx itself failed (rc!=0); partial results may still be
    present and the caller must not checkpoint the stage as done.

    Every path also drops fake-IP answers (198.18.0.0/15, see lib.doh): a
    Clash/TUN resolver answers EVERY name with 198.18.x.x, and the old
    "198.18." prefix test let 198.19.x.x through. When such a resolver is
    detected the whole resolution moves to DoH (`plan`), because the local
    one cannot be trusted at all.

    `states` is the per-name resolution record ({name: {state, a, cname}}).
    It is read (a NXDOMAIN name is never queried again) and updated in place,
    so a later round does not redo work. `doh_client` injects a resolver for
    tests.
    """
    domains = _uniq([core.canon_domain(d) for d in domains if core.canon_domain(d)])
    plan = plan or doh.ResolutionPlan.for_run()
    if not domains:
        return {"count": 0, "domains": [], "wildcard": [], "ok": True, "rc": 0,
                "states": states if states is not None else {},
                "resolution": doh.resolution_payload(plan, plan.resolution_mode())}
    # states is the round-to-round record: a NXDOMAIN answer is final (asking
    # again costs a query and returns the same thing), a transient failure is
    # left open so a later round retries it. check_again forces the re-query
    # (--force-stage / a resolver change), which is how a name that was
    # NXDOMAIN while the network was down gets a second chance.
    states = doh.ensure_name_states(states)
    skipped_nx = [] if check_again else [d for d in domains
                                         if not doh.should_query(d, states)]
    todo = [d for d in domains if check_again or doh.should_query(d, states)]
    # One wildcard evidence table for EVERY resolver path (docs par.9): key is
    # the registrable parent, value counts ordinary A/CNAME probe answers.
    # The old code kept two shapes (dnsx keyed by registrable parent, DoH
    # keyed by the probe name minus its first label -- i.e. "wild.example.com"
    # WITH the wild. label) so the same zone was two unrelated entries and a
    # name seen by one path was never filtered by the other's evidence.
    wildcard_ev: dict = doh.new_wildcard_evidence()
    fake_resolver = False
    parents = sorted({core.registrable_domain(d) for d in domains
                      if core.registrable_domain(d)})
    use_doh = plan.fake_ip
    if use_doh:
        # dnsx has no DoH flag (checked against `dnsx -h`: resolvers are plain
        # UDP/TCP endpoints), so the DoH path resolves and wildcard-detects in
        # Python instead of shelling out.
        client = doh_client or doh.DohClient(
            url=plan.doh_url,
            concurrency=doh.doh_config()["doh_concurrency"],
            timeout=doh.doh_config()["doh_timeout"])
        rows: list[dict] = []
        resolved = 0
        transient: list[str] = []
        nxnames: list[str] = []
        fake_dropped = 0
        # Multiple unpredictable probes, no "wild." label: one lucky hit is
        # not a signature (par.9), and fake/timeout answers prove nothing --
        # record_wildcard_probe keeps the fake address as evidence but never
        # counts it toward the signature.
        probers = doh.wildcard_probe_names(parents[:20])
        probes = client.resolve_many(probers)
        for name, res in probes.items():
            parent = doh.wildcard_parent(name)
            if parent:
                doh.record_wildcard_probe(wildcard_ev, parent, res)
        answers = client.resolve_many(todo)
        for d in todo:
            got = answers.get(d) or {"state": doh.NAME_TRANSIENT, "a": [], "cname": []}
            st = doh.name_state(got)
            ips, fake = doh.filter_fake_ips(got.get("a") or [])
            fake_dropped += len(fake)
            states[d] = {"state": st if ips or st != doh.NAME_RESOLVED else doh.NAME_NXDOMAIN,
                         "a": ips, "cname": got.get("cname") or [],
                         "retried": bool(got.get("retried"))}
            if ips:
                accepted = _accept_dns(store, d, ips, got.get("cname") or [], "doh",
                                       wildcard_ev, rows)
                if accepted:
                    resolved += 1
                else:
                    states[d]["state"] = "wildcard"
            elif st == doh.NAME_TRANSIENT:
                transient.append(d)
            else:
                nxnames.append(d)
        for d in skipped_nx:
            rec = states.get(d) or {}
            if rec.get("a"):
                accepted = _accept_dns(store, d, rec["a"], rec.get("cname") or [],
                                       "doh", wildcard_ev, rows)
                if accepted:
                    resolved += 1
        total = resolved
        return {"count": total, "domains": rows, "truncated": total > len(rows),
                "wildcard": _wildcard_report(wildcard_ev),
                "system_fallback": 0, "resolved": resolved,
                "transient": len(transient), "nxdomain": len(nxnames),
                "skipped_nxdomain": len(skipped_nx), "fake_ip_dropped": fake_dropped,
                "states": states, "lines": 0, "rc": 0, "ok": True,
                "resolution": doh.resolution_payload(plan, doh.RESOLVER_DOH)}
    if core.has_tool("dnsx"):
        for p in parents[:20]:
            # The name goes in on STDIN. `-d` is dnsx's WORDLIST driver and
            # fails with "missing wordlist(w) flag required with domain(d)
            # input", so the old call returned rc=1 with an empty body: the
            # wildcard table stayed empty and every name in a wildcard zone
            # (hniu.com answers ANY label) was stored as a real asset.
            # Multiple probes share the SAME evidence table as the DoH path,
            # and a fake-IP answer stands the filter down rather than
            # marking every parent a wildcard.
            for probe in doh.wildcard_probe_names([p]):
                rc, out, err = core.run([core.tool("dnsx"), "-a", "-resp",
                                         "-silent", "-json"],
                                        input_text=probe, timeout=timeout)
                for r in core.parse_jsonl(out):
                    ans = {"a": [x for x in r.get("a", []) or []],
                           "cname": [x for x in r.get("cname", []) or []]}
                    if any(doh.is_fake_ip(x) for x in ans["a"]):
                        # A fake-IP resolver (Clash/TUN, 198.18.0.0/15) answers
                        # EVERY name, existing or not, so "this parent has a
                        # wildcard" would be true for every parent and the
                        # filter would drop the entire target. Detect the
                        # resolver lying and stand the filter down instead of
                        # trusting it.
                        fake_resolver = True
                        continue
                    doh.record_wildcard_probe(wildcard_ev, p, ans)
    exe = core.tool("dnsx")
    path = _tmp_lines(todo)
    if fake_resolver:
        wildcard_ev.clear()
        core.log("wildcard filtering disabled: the resolver answers "
                 "every name with a fake-IP address (198.18.0.0/15), so a "
                 "wildcard probe proves nothing; liveness/cert evidence "
                 "decides which names are real")
    core.log("dnsx resolving " + str(len(todo)) +
             " (wildcard parents: " + str(len(wildcard_ev)) + ")" +
             (" [fake-IP resolver detected: querying " + plan.doh_url + "]" if use_doh else ""))
    rows: list[dict] = []
    seen_dns: set[str] = set()
    pending: list[tuple[str, list, list]] = []   # parsed off-thread, stored here
    total = 0
    fake_dropped = 0

    def accept(d: str, ips: list[str], cnames: list[str], source: str) -> None:
        """Store + count a resolved domain, unless it is a wildcard answer.

        Shared by dnsx output and the system-resolver fallback so both paths
        apply identical filtering rules.

        Fake-IP answers (Clash/TUN 198.18.0.0/15) are dropped HERE, not in one
        branch: dnsx runs through the same tunnel as the system resolver, so a
        filter applied only to the fallback let a live run store 35 IP assets
        that were all 198.18.210.x -- every port scan and vhost test then
        aimed at the proxy, not the target.
        """
        nonlocal total
        if _accept_dns(store, d, ips, cnames, source, wildcard_ev, rows):
            total += 1

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
        # fake-IP answers are never addresses: drop them before anything else
        # so neither the store nor the wildcard signal sees one.
        raw_ips = [x for x in (core.canon_ip(x) for x in (r.get("a") or [])) if x]
        ips, fake = doh.filter_fake_ips(raw_ips)
        if fake:
            pending_fake_drops.append(len(fake))
        cnames = [x for x in (core.canon_domain(x) for x in (r.get("cname") or [])) if x]
        pending.append((d, ips, cnames, bool(fake)))

    pending_fake_drops: list[int] = []
    rc, lines, err = core.run_stream(
        [exe, "-l", path, "-a", "-cname", "-resp", "-silent", "-json",
         "-t", str(core.CFG["limits"]["dns_concurrency"])],
        handle, timeout=timeout)
    for d, ips, cnames, had_fake in pending:
        states[d] = {"state": doh.NAME_RESOLVED if ips or cnames or had_fake
                     else doh.NAME_NXDOMAIN, "a": ips, "cname": cnames}
        if not ips and not had_fake:
            continue
        # A name whose every address was a fake IP still EXISTS: the resolver
        # answered it. Dropping the address is right; dropping the name threw
        # away the only real evidence in the answer.
        accept(d, ips, cnames, "dnsx")
    fake_dropped += sum(pending_fake_drops)
    # ---- system resolver fallback -------------------------------------
    # dnsx uses public resolvers (8.8.8.8 etc). In CN networks those are often
    # blocked or poisoned; fall back to the OS resolver for anything unresolved.
    missing = [d for d in todo if d not in seen_dns]
    sys_rows: list[dict] = []
    transient: list[str] = []
    if missing:
        core.log("system-dns fallback for " + str(len(missing)) + " domains")

        def resolve_one(d: str):
            try:
                infos = socket.getaddrinfo(d, None)
                return d, sorted({core.canon_ip(i[4][0]) for i in infos} -
                                 {None})
            except Exception:
                return d, None

        with futures.ThreadPoolExecutor(max_workers=50) as pool:
            for d, ips in pool.map(resolve_one, missing):
                if ips is None:
                    # a resolver error is NOT "this name does not exist": it is
                    # an open question that a later round may answer
                    states[d] = {"state": doh.NAME_TRANSIENT, "a": [], "cname": []}
                    transient.append(d)
                    continue
                # 198.18.0.0/15 = Clash/TUN fake-IP benchmark range: the whole
                # /15, not just the 198.18.x half
                ips, fake = doh.filter_fake_ips(ips)
                if fake:
                    fake_dropped += len(fake)
                if not ips:
                    if d in states and states[d].get("state") == doh.NAME_RESOLVED:
                        continue
                    states.setdefault(d, {"state": doh.NAME_NXDOMAIN,
                                          "a": [], "cname": []})
                    if not states[d].get("a"):
                        states[d]["state"] = doh.NAME_NXDOMAIN
                    continue
                states[d] = {"state": doh.NAME_RESOLVED, "a": ips, "cname": []}
                sys_rows.append((d, ips))
        for d, ips in sys_rows:
            accept(d, ips, [], "system-dns")
    ok = rc == 0
    return {"count": total, "domains": rows, "truncated": total > len(rows),
            "wildcard": _wildcard_report(wildcard_ev),
            "system_fallback": len(sys_rows), "resolved": total,
            "transient": len(transient), "nxdomain": len([d for d in todo
                                                          if states.get(d, {}).get("state")
                                                          == doh.NAME_NXDOMAIN]),
            "skipped_nxdomain": len(skipped_nx), "fake_ip_dropped": fake_dropped,
            "states": states, "lines": lines, "rc": rc, "ok": ok,
            "resolution": doh.resolution_payload(
                plan, doh.RESOLVER_SYSTEM if sys_rows else doh.RESOLVER_DNSX)}


# ---------------------------------------------------------------- 6. httpx probe
_CHARSET_RE = re.compile(rb"""charset\s*=\s*["']?\s*([\w.:-]+)""", re.I)
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def decode_page_text(raw: bytes) -> str:
    """Decode response bytes using the page's OWN charset, then sensible fallbacks.

    httpx decodes bodies as UTF-8 unless the response declares something else,
    so a Chinese site with a GBK page and NO charset meta came back with U+FFFD
    in `title` ('������Ϣְҵ����ѧԺ' instead of 湖南信息职业技术学院 -- observed
    on mail.mail.hniu.cn / xs.hniu.cn / mail.xs.hniu.cn). Replacement
    characters are lossy: the original bytes are gone, so the repair has to
    happen where the bytes still exist -- the raw body.
    """
    if not raw:
        return ""
    order: list = []
    m = _CHARSET_RE.search(raw[:4096])
    if m:
        try:
            order.append(m.group(1).decode("ascii").strip().lower())
        except Exception:
            pass
    order += ["utf-8", "gb18030", "cp936", "big5"]
    seen = set()
    for enc in order:
        key = enc.replace("-", "").replace("_", "")
        if not key or key in seen:
            continue
        seen.add(key)
        if key in ("gb2312", "gbk"):
            enc = "gb18030"          # superset; GBK bytes decode identically
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def title_from_body(b64_body: str | None) -> str:
    """The page's <title>, decoded with the page's own charset ("" if absent)."""
    if not b64_body:
        return ""
    try:
        import base64
        raw = base64.b64decode(b64_body)
    except Exception:
        return ""
    m = _TITLE_RE.search(raw or b"")
    if not m:
        return ""
    return re.sub(r"\s+", " ", decode_page_text(m.group(1)).strip())[:200]


def _usable_title(title: str) -> bool:
    """A title httpx produced is usable only when it carries no U+FFFD."""
    t = (title or "").strip()
    return bool(t) and "\ufffd" not in t


def repair_broken_titles(store, hosts=None, scope=None, timeout: int = 0,
                         limit: int = 200) -> dict:
    """Re-fetch titles that an earlier decode destroyed (U+FFFD in the store).

    A U+FFFD title cannot be repaired from the store -- the original bytes are
    gone. The only honest fix is another fetch, decoded with the page's own
    charset, so this is a CLI-reachable maintenance entry
    (`probe --repair-titles`) rather than something an operator must do by
    hand with the raw binary.

    Hosts left unreachable are REPORTED, not silently dropped: their titles
    stay broken and the caller has to know why.
    """
    scope_list = core.canon_scope(scope or [])
    candidates: list = []
    for a in store.get_assets(kind="domain", match=scope_list or None):
        attrs = a.get("attrs") or {}
        title = attrs.get("title") or ""
        if "\ufffd" in title:
            candidates.append(a["canonical"])
    if hosts:
        want = {h for h in hosts if h}
        candidates = [h for h in candidates if h in want]
    candidates = _uniq(candidates)[:max(1, int(limit))]
    if not candidates:
        return {"checked": 0, "repaired": 0, "unreachable": [],
                "note": "no stored title contains U+FFFD"}
    repaired: dict = {}
    unreachable: list = []
    for host in candidates:
        got = ""
        try:
            _rc, out_s, _err = core.run([
                core.tool("httpx"), "-u", host, "-silent", "-json",
                "-sc", "-title", "-irrb", "-timeout", "15"],
                timeout=(timeout or 60))
        except Exception:
            out_s = ""
        for ln in (out_s or "").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except Exception:
                continue
            t = title_from_body(r.get("body"))
            if _usable_title(t):
                got = t
                break
        if not got:
            unreachable.append(host)
            continue
        repaired[host] = got
        try:
            store.upsert_asset("domain", host, source="httpx-title-repair",
                               confidence=0.8, passivity="active",
                               attrs={"title": got})
        except Exception:
            unreachable.append(host)
            repaired.pop(host, None)
    core.log("title repair: " + str(len(repaired)) + " fixed, " +
             str(len(unreachable)) + " unreachable")
    return {"checked": len(candidates), "repaired": len(repaired),
            "repaired_hosts": repaired, "unreachable": unreachable,
            "note": ("unreachable hosts keep their broken title: the page "
                     "could not be re-read, so nothing was invented")}

def t_httpx(store, hosts: list[str], timeout: int = 0,
            scope: list[str] | None = None) -> dict:
    """Probe hosts and read the certificate each one serves.

    `-tls-grab` makes httpx report the TLS block (`subject_an`, `subject_cn`,
    `issuer_dn`) for every https responder. Those names are evidence, not
    decoration: `doh.cert_queue_entries` routes the in-scope ones to the next
    round's dns queue and the rest to related assets, so a shared certificate
    is how a new asset is discovered instead of being lost. `scope` decides
    that split; without it every certificate name is out of scope and lands in
    `related`, never in the dns queue.
    """
    hosts = _uniq([h for h in hosts if h])
    if not hosts:
        return {"count": 0, "rows": [], "cert_in_scope": [], "cert_related": []}
    path = _tmp_lines(hosts)
    lim = core.CFG["limits"]
    cmd = [core.tool("httpx"), "-l", path, "-silent", "-json",
           "-sc", "-title", "-tech-detect", "-ip", "-cname", "-cdn", "-favicon",
           "-tls-grab",
           "-threads", str(lim["http_concurrency"]),
           "-timeout", "10", "-retries", "1"]
    core.log("httpx probing " + str(len(hosts)))
    rows: list[dict] = []          # only ROW_LIMIT of them: the rest live in the store
    staged: list = []              # store writes happen on the caller's thread
    cstaged: list = []             # certificate rows, same deferral
    total = 0
    cert_rows = 0

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
        # Certificate identities travel with the row: parsed here so the
        # caller's thread only has to route and store them.
        cert = doh.parse_cert_names(r)
        if cert.get("san"):
            rec["cert"] = cert
        if len(rows) < core.ROW_LIMIT:
            rows.append(rec)
        attrs = {"status": status, "title": title, "tech": tech, "url": url,
                 "ip": ip, "port": r.get("port"), "cdn": rec["cdn"],
                 "webserver": rec["webserver"]}
        if cert.get("san"):
            attrs["cert"] = {"cn": cert.get("cn", ""),
                             "issuer": cert.get("issuer", ""),
                             "san": cert["san"]}
        # store writes are deferred to the caller's thread (SQLite is
        # thread-bound; run_stream calls this from its reader thread)
        staged.append((host, ip, url, attrs, status, title))
        if cert.get("san"):
            cstaged.append((host, ip, cert))

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
    # ---- repair undecodable titles ---------------------------------------
    # httpx decodes a body as UTF-8 unless it declares a charset, so a GBK page
    # with no meta yields U+FFFD in `title` and the real characters are lost.
    # Re-fetch ONLY the affected hosts with -irrb (raw body), decode the
    # <title> with the page's own charset, and patch both the display row and
    # the staged store write. UTF-8/ASCII pages never take this path.
    _bad = [h for (h, _ip, _u, _a, _s, t) in staged if not _usable_title(t)]
    if _bad:
        core.log("httpx: " + str(len(_bad)) +
                 " host(s) returned an undecodable title; re-reading raw body")
        fixed: dict = {}
        for _h in _bad[:200]:
            try:
                rc2, lines2, err2 = core.run([
                    core.tool("httpx"), "-u", _h, "-silent", "-json",
                    "-sc", "-title", "-irrb", "-timeout", "10"],
                    timeout=timeout or 60)
            except Exception as exc:
                core.log("httpx title repair failed for " + _h + ": " +
                         repr(exc)[:120])
                continue
            for _ln in (lines2 or "").splitlines():
                _ln = _ln.strip()
                if not _ln:
                    continue
                try:
                    _r = json.loads(_ln)
                except Exception:
                    continue
                _t = title_from_body(_r.get("body"))
                if _usable_title(_t):
                    fixed[_h] = _t
                    break
        if fixed:
            for _i, _item in enumerate(staged):
                if _item[0] in fixed:
                    _attrs = dict(_item[3])
                    _attrs["title"] = fixed[_item[0]]
                    staged[_i] = (_item[0], _item[1], _item[2], _attrs,
                                  _item[4], fixed[_item[0]])
            for _rec in rows:
                if _rec.get("host") in fixed:
                    _rec["title"] = fixed[_rec["host"]]
            core.log("httpx: repaired " + str(len(fixed)) + " title(s)")
    for item in staged:
        live(item)
    # ---- certificate names -> dns queue / related assets ------------------
    # cert_ip is the address the certificate was observed on. A fake-IP answer
    # is not an address (see lib.doh); storing one here would pin every SAN to
    # a phantom host.
    cert_in_scope: list[dict] = []
    cert_related: list[dict] = []
    cert_skipped: list[dict] = []
    seen_cert: set = set()
    for host, ip, cert in cstaged:
        cert_rows += 1
        if ip and doh.is_fake_ip(ip):
            ip = ""                # synthesised address: not an observation
        routed = doh.cert_queue_entries(cert, [host], scope, ip=ip or "",
                                        seen=seen_cert)
        cert_in_scope.extend(routed["in_scope"])
        cert_related.extend(routed["related"])
        cert_skipped.extend(routed["skipped"])
        if ip:
            store.upsert_asset("ip", ip, source="httpx-tls", confidence=0.7,
                               passivity="active", parent=host)
            store.upsert_asset("domain", host, source="httpx-tls", confidence=0.9,
                               passivity="active",
                               attrs={"cert": {"cn": cert.get("cn", ""),
                                               "issuer": cert.get("issuer", ""),
                                               "san": cert.get("san", [])}})
            for name in cert.get("san") or []:
                if name.startswith("*"):
                    continue
                store.link_asset("domain", host, "cert-name", name,
                                 source="httpx-tls")
    core.log("httpx: " + str(total) + " live hosts (" + str(lines) + " lines) rc=" + str(rc) +
             (" | certificates: " + str(cert_rows) + " rows, " + str(len(cert_in_scope)) +
              " in-scope names queued, " + str(len(cert_related)) + " related"
              if cert_rows else ""))
    return {"count": total, "rows": rows, "truncated": total > len(rows),
            "lines": lines, "rc": rc, "ok": rc == 0, "stderr": err[-400:],
            "cert_rows": cert_rows,
            "cert_in_scope": cert_in_scope, "cert_related": cert_related,
            "cert_skipped": cert_skipped}


# ---------------------------------------------------------------- 7. IP aggregate + CDN
def t_ipagg(store, ips: list[str] | None = None, timeout: int = 0,
            scope: list[str] | None = None) -> dict:
    """Group domains by shared IP, dropping CDN fronts.

    `scope` restricts every read of the shared graph: candidate IPs come only
    from domains under the scope, and shared-ip groups are built only from
    in-scope hosts. Without it a second engagement's domains would drag that
    target's IPs into ports/vhost.
    """
    requested = bool(scope)
    scope = core.canon_match(scope or [])
    if requested and not scope:
        # a scope was asked for and none of it is a usable name: an empty
        # scope, never "no scope" (every IP in the shared store)
        return {"ips": [], "candidates": [], "count_candidates": 0, "scope": []}
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
# Certificate grabbing is an active handshake per ip:port; a 1000-port scan of
# 40 IPs would open 40000 of them. The budget is a ceiling, and whatever it
# skips is reported as a coverage gap instead of vanishing.
_TLS_GRAB_MAX_PORTS = 40

def _tls_grab(ip: str, port: int, timeout: float = 8.0) -> dict:
    """Read the certificate one ip:port serves, with no external binary.

    naabu has no TLS grabbing flag (checked against `naabu -h`: JSON output
    only), and an open 8443 with no certificate behind it is a very different
    finding from an open 8443 that answers for twenty hostnames. The handshake
    is done by httpx (which has `-tls-grab`) when it is available; the stdlib
    path below is the one tests exercise and the one that works without it.

    Returns {} when nothing was negotiated (no TLS, timeout, garbage), so the
    caller never stores a half-read certificate.
    """
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return {}
    except (OSError, ssl.SSLError, ValueError):
        return {}
    return parse_cert_der(der)


def _der_tlv(buf: bytes, k: int) -> tuple[int, int, int]:
    """(tag, value_start, value_end) for the TLV at `k`.

    A malformed or truncated length collapses to an empty range at the end of
    `buf`, so a caller can never read past the certificate it was handed.
    """
    if k >= len(buf):
        return 0, len(buf), len(buf)
    tag = buf[k]
    if k + 1 >= len(buf):
        return tag, len(buf), len(buf)
    b = buf[k + 1]
    pos = k + 2
    if b < 0x80:
        ln = b
    else:
        extra = b & 0x7f
        if extra == 0 or pos + extra > len(buf):
            return tag, len(buf), len(buf)
        ln = 0
        for i in range(extra):
            ln = (ln << 8) | buf[pos + i]
        pos += extra
    return tag, pos, min(len(buf), pos + ln)


def _der_walk(buf: bytes, start: int, end: int, visit) -> None:
    """Depth-first walk of the TLVs in buf[start:end], calling `visit`.

    Hand-rolled instead of recursive so a crafted certificate with deep
    nesting cannot exhaust the interpreter stack. `visit(buf, tag, vstart,
    vend)` on every element; containers (SEQUENCE / SET / context-tagged
    wrappers such as an explicit [0]) are descended into as well, because
    the extension block is wrapped one level deeper than the attributes.
    """
    stack = [(start, end)]
    while stack:
        cur, stop = stack.pop()
        while cur < stop:
            tag, vs, ve = _der_tlv(buf, cur)
            if vs <= cur or vs > stop:
                return
            if visit(buf, tag, vs, ve) is False:
                return
            descends = (tag in (0x30, 0x31) or
                        (0x80 <= tag <= 0xbf and tag not in (0x80, 0x81, 0x82,
                                                             0x84, 0x86, 0x87)))
            if descends:
                stack.append((vs, ve))
            cur = ve


def parse_cert_der(der: bytes) -> dict:
    """Best-effort name extraction from a DER certificate, stdlib only.

    `ssl.getpeercert()` returns an empty dict for an unverified certificate
    (that is what CERT_NONE buys us), so the names have to come out of the DER
    bytes. This walks the TLVs, looks for the three OIDs a certificate uses
    for identity -- subjectAltName, commonName, organizationName -- and reads
    the values that follow them. It is deliberately conservative: a structure
    it does not recognise yields fewer names, never invented ones, and a
    certificate with no dNSName comes back with an empty `san` so the caller
    can tell "no names" from "not read".

    Returns the same shape as `doh.parse_cert_names`: {"san", "cn", "issuer"}.
    """
    out = {"san": [], "cn": "", "issuer": ""}
    if not der:
        return out
    _CN_OID = bytes.fromhex("550403")      # 2.5.4.3 commonName
    _O_OID = bytes.fromhex("55040a")       # 2.5.4.10 organizationName
    _SAN_OID = bytes.fromhex("551d11")     # 2.5.29.17 subjectAltName
    cn: list[str] = []
    org: list[str] = []
    sans: list[str] = []

    def visit(buf, tag, vs, ve) -> bool:
        # OIDs are primitive and always live in a container. The attribute
        # value follows the OID directly (SEQUENCE { OID, value }); a SAN
        # extension value is an OCTET STRING wrapping the GeneralNames
        # SEQUENCE, so the OCTET STRING is skipped first.
        if tag == 0x06:
            oid = buf[vs:ve]
            if oid == _SAN_OID:
                _read_general_names(buf, ve)
            elif oid in (_CN_OID, _O_OID):
                _read_attribute(buf, ve, cn if oid == _CN_OID else org)
        return True

    def _read_attribute(buf: bytes, k: int, into: list) -> None:
        """Read the <type> <len> <bytes> string right after a name OID."""
        if k >= len(buf):
            return
        if buf[k] not in (0x0c, 0x13, 0x16):   # utf8 / printable / ia5
            return
        _tag, vs, ve = _der_tlv(buf, k)
        txt = buf[vs:ve].decode("utf-8", "ignore").strip()
        if txt:
            into.append(txt)

    def _read_general_names(buf: bytes, k: int) -> None:
        """Collect every dNSName in the GeneralNames that follow the SAN OID."""
        # skip the OCTET STRING wrapper(s), then walk the SEQUENCE
        end = len(buf)
        while k < end:
            tag, vs, ve = _der_tlv(buf, k)
            if ve <= k:
                return
            if tag == 0x04:                     # OCTET STRING
                k = vs
                end = ve
                continue
            if tag == 0x30:                     # GeneralNames SEQUENCE
                pos = vs
                while pos < ve:
                    t2, v2, e2 = _der_tlv(buf, pos)
                    if e2 <= pos:
                        return
                    # [2] dNSName: context class, primitive, tag 2 ->
                    # 0x82. OpenSSL and most CAs emit this form rather than
                    # the [7] otherName variant, so both are accepted (0x87
                    # is what some stacks use; 0xA7 is the constructed bit).
                    if t2 in (0x82, 0x87, 0xa7):
                        txt = buf[v2:e2].decode("ascii", "ignore").strip().strip(".")
                        if txt and "." in txt and txt.lower() not in sans:
                            sans.append(txt.lower())
                    pos = e2
                return
            k = ve

    _der_walk(der, 0, len(der), visit)
    if sans:
        out["san"] = sans
    if cn:
        out["cn"] = cn[0]
        root = cn[0].lower().rstrip(".")
        # a CN without a dot is a product name ("Default"), not a hostname
        if "." in root and root not in out["san"]:
            out["san"].insert(0, root)
    if org:
        # the issuer O follows the subject O in a self-signed certificate;
        # keeping the LAST one yields the issuer when both are present
        out["issuer"] = org[-1]
    return out


def t_ports(store, ips: list[str], top_ports: int = 1000, timeout: int = 0,
            scope: list[str] | None = None,
            allow_private: bool = False) -> dict:
    """Scan the given addresses with naabu.

    A private, loopback, link-local, CGNAT, benchmark (198.18.0.0/15 -- the
    Clash/TUN fake-IP range), documentation, reserved or multicast address is
    skipped unless ``allow_private`` is set: such an address came out of a
    page, a JS bundle or an internal DNS answer, and scanning it reaches
    whatever network the operator sits in, not the target. The filter lives
    here rather than only in the CLI because the run pipeline calls this
    function too, and it used to scan whatever the store held.
    """
    targets = _uniq([core.canon_ip(i) for i in ips if core.canon_ip(i)])
    skipped_private: list[str] = []
    if not allow_private:
        keep = [ip for ip in targets if core.is_public_ip(ip)]
        skipped_private = [ip for ip in targets if not core.is_public_ip(ip)]
        if skipped_private:
            core.log("ports: skipped " + str(len(skipped_private)) +
                     " private/reserved address(es); pass them with --ip to "
                     "scan them deliberately")
        targets = keep
    if not targets:
        if skipped_private:
            return {"ok": True, "count": 0, "rows": [],
                    "skipped_private": skipped_private, "error": "", "rc": 0}
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
    # ---- certificate grabbing on TLS ports -------------------------------
    # A TLS port that answers for names is how an IP is tied back to the
    # domains it serves: the certificate is the only artefact that states it.
    cert_ports: list[dict] = []
    cert_in_scope: list[dict] = []
    cert_related: list[dict] = []
    tls_failed: list[dict] = []
    seen_cert: set = set()
    tls_ports = [p for p in _uniq([str(p) for _i, p in staged])
                 if doh.is_tls_port(int(p))]
    core.log("naabu: " + str(len(tls_ports)) + " TLS port(s) to grab certificates on")
    for port in tls_ports[: _TLS_GRAB_MAX_PORTS]:
        for ip in targets:
            if (ip, int(port)) not in {(i, int(p)) for i, p in staged}:
                continue
            cert = _tls_grab(ip, int(port))
            if not cert.get("san"):
                tls_failed.append({"ip": ip, "port": int(port)})
                continue
            cert_ports.append({"ip": ip, "port": int(port),
                               "cn": cert.get("cn", ""),
                               "issuer": cert.get("issuer", ""),
                               "san": cert.get("san", [])})
            # map the IP back to the names it serves: cert_ip is the
            # observation, the name is the asset
            owners = [a["canonical"] for a in store.get_assets(kind="domain",
                                                               match=list(scope or []) or None)
                      if (a.get("attrs") or {}).get("ip") == ip]
            routed = doh.cert_queue_entries(cert, owners or [], scope, ip=ip,
                                            seen=seen_cert)
            cert_in_scope.extend(routed["in_scope"])
            cert_related.extend(routed["related"])
    if len(tls_ports) > _TLS_GRAB_MAX_PORTS:
        # never silently: the grabbed ports are listed, the rest is a gap
        tls_failed.append({"skipped": "budget",
                           "ports": tls_ports[_TLS_GRAB_MAX_PORTS:]})
    core.log("naabu: certificates on " + str(len(cert_ports)) + " port(s), " +
             str(len(cert_in_scope)) + " in-scope name(s), " +
             str(len(cert_related)) + " related")
    return {"targets": targets, "count": total, "rows": rows,
            "truncated": total > len(rows), "lines": lines, "rc": rc, "ok": rc == 0,
            "cert_ports": cert_ports, "cert_in_scope": cert_in_scope,
            "cert_related": cert_related, "tls_grab_failed": tls_failed,
            "skipped_private": skipped_private}


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
        # A JS-concatenation fragment is source text, not a location.
        if not core.is_junk_path(p):
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
    """Domains and IPv4 addresses mentioned in text.

    An address is canonicalised first, so a version string like
    `03.06.03.118` is dropped instead of becoming an asset. A PRIVATE or
    loopback address is kept but reported separately (`internal_ips`): an
    internal address in a JS bundle is real evidence of a leak, yet it is not
    a scan target -- putting it in `ips` made ports/probe treat it as one.
    """
    domains, ips, internal = [], [], []
    for m in DOMAIN_RE.finditer(text or ""):
        d = core.canon_domain(m.group(1))
        if d and _looks_public(d):
            domains.append(d)
    for m in IPV4_RE.finditer(text or ""):
        ip = core.canon_ip(m.group(0))
        if not ip:
            continue
        (ips if core.is_public_ip(ip) else internal).append(ip)
    return {"domains": _uniq(domains), "ips": _uniq(ips),
            "internal_ips": _uniq(internal)}



def _is_js_asset(url: str) -> bool:
    """True when a URL is a JavaScript bundle worth fetching as JS work.

    .js and .mjs are JS bundles; a source map (.map) is fetched with its
    bundle only when something references it, so it is not JS work on its own.
    JSON is NOT JS work either -- the old filter counted .json/.map as
    candidates, so API responses (and HTML pages whose path merely ended in
    .json) were queued as unprocessed JavaScript.
    """
    return bool(re.search(r"\.m?js(\?|#|$)", url or "", re.I))


def _js_work_set(urls, scope) -> list:
    """The URLs that are genuinely JS work for this run.

    HTML pages are NOT JS work: a page is evidence that may REFERENCE JS, and
    the caller's discovery step extracts the reference. Queuing every input
    URL (including the crawl seeds and HTML pages) is what left a finished run
    with phantom pending items forever.
    """
    out = []
    scope_list = [s for s in (scope or []) if s]
    for u in _uniq(urls or []):
        u = str(u or "").strip()
        if not u.startswith("http"):
            continue
        if not _is_js_asset(u):
            continue
        host = core.split_url(u)[0] or ""
        if scope_list and not core.in_scope(host, scope_list):
            continue
        out.append(u)
    return out


def _seen_endpoints(api_hits, api_paths) -> set:
    """Unique (host, template, verb) endpoint keys for the api_hosts count."""
    seen: set = set()
    for host, p, verb in api_hits or []:
        seen.add((host, core.path_template(p), verb))
    for p in api_paths or []:
        seen.add(("leak", core.path_template(p), "GET"))
    return seen


def _finish_tail(store, got, api_paths, api_hits, scope) -> tuple:
    """Post-fetch normalisation + storage shared by both backends.

    Kept as one helper so pipeline mode (lease-protected) and standalone
    mode (legacy queue) produce the same findings, scope split and endpoint
    storage -- only the SCHEDULING differs between them. Returns
    (in_scope_domains, related_domains).
    """
    got["domains"] = _uniq(d for d in got["domains"] if core.canon_domain(d))
    # An internal/loopback address is evidence of a leak, not a scan target:
    # keep it in the report, keep it OUT of the asset graph, where probe and
    # ports would treat it as something to touch.
    internal = list(got.get("internal_ips") or [])
    public: list = []
    for ip in got["ips"]:
        if core.is_public_ip(ip):
            public.append(ip)
        else:
            internal.append(ip)
    got["ips"] = _uniq(public)
    got["internal_ips"] = _uniq(internal)
    api_paths = _uniq(api_paths)[:500]
    for p in api_paths:
        if core.is_junk_path(p):
            continue
        store.upsert_endpoint("leak", "GET", core.path_template(p), [], source="jsleak")
    seen_ep: set = set()
    for host, p, verb in api_hits:
        if core.is_junk_path(p):
            continue
        tpl = core.path_template(p)
        key = (host, tpl, verb)
        if key in seen_ep:
            continue
        seen_ep.add(key)
        store.upsert_endpoint(host, verb, tpl, [], source="jsleak")
    scope_list = [s for s in (scope or []) if s]
    in_scope_domains: list = []
    related_domains: list = []
    for d in got["domains"]:
        if not scope_list or core.in_scope(d, scope_list):
            in_scope_domains.append(d)
        else:
            related_domains.append(d)
    for d in in_scope_domains:
        store.upsert_asset("domain", d, source="leak-extract", confidence=0.4,
                           passivity="passive")
    for ip in got["ips"]:
        store.upsert_asset("ip", ip, source="leak-extract", confidence=0.4,
                           passivity="passive")
    return in_scope_domains, related_domains


def t_extract(store, crawl_rows: list[dict], urls: list[str] | None = None,
              timeout: int = 0, fetch_limit: int | None = None,
              scope: list[str] | None = None,
              run_id: str | None = None) -> dict:
    """Extract leaked domains/IPs/paths/secrets from crawl output and fetched JS.

    Inputs are complete work sets, not display samples: `urls` should come
    from a scoped store query (see run's extract stage), and crawl_rows from
    the crawler's full output. fetch_limit caps how many bundles are fetched
    (a work budget, reported as such), never how many are discovered.

    `fetch_limit` defaults to `limits.js_fetch_limit` (2000): a work
    budget for how many bundles THIS call scans, never a cap on what is
    discovered or queued.

    Two scheduling backends, ONE claimable queue per invocation:

    * `run_id` given (pipeline mode): work_items/stage='extract' is the only
      source of JS scheduling and stats. Discovery inserts real JS work only;
      the fetch set is claimed through the durable queue with a lease, and
      each result commits membership + observation + ack atomically under
      that lease. A finished item stays done across rounds/restarts.
    * no run_id (standalone): the legacy Store.js_* queue, unchanged.
    """
    from . import jsleak
    from . import work as _work

    if fetch_limit is None:
        try:
            fetch_limit = int((core.CFG.get("limits") or {})
                              .get("js_fetch_limit") or 0) or 2000
        except (TypeError, ValueError):
            fetch_limit = 2000
    fetch_limit = max(0, int(fetch_limit))

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
    roots = [d for d in (scope or []) if d]
    got = extract_from_text(text, roots)
    hit = jsleak.extract(text, roots)
    got["domains"].extend(hit["domains"])
    got["ips"].extend(hit["ips"])

    js_set = _js_work_set(urls, scope)
    discovered_js = len(js_set)
    api_paths: list[str] = []
    api_hits: list[tuple[str, str, str]] = []
    secrets: dict = {}

    def scan_bundle(u: str) -> dict | None:
        # Network work happens OUTSIDE any database transaction.
        rc, body, err = core.curl([u], timeout=timeout)
        if rc != 0 or not body:
            return None
        found = jsleak.extract(body, roots)
        found["_url"] = u
        return found

    def absorb(url: str, found: dict) -> None:
        got["domains"].extend(found["domains"])
        got["ips"].extend(found["ips"])
        api_paths.extend(found["api_paths"])
        host = core.split_url(found.get("_url") or url)[0]
        if not host:
            return
        meta = found.get("path_meta") or {}
        for p in found["api_paths"]:
            verb = ((meta.get(p) or {}).get("method") or "GET").upper()
            api_hits.append((host, p, verb if verb in
                             ("GET", "POST", "PUT", "DELETE", "PATCH") else "GET"))
        for k, v in found["secrets"].items():
            secrets.setdefault(k, []).extend(v)

    if run_id:
        # ---- pipeline mode: work_items is the ONLY source of truth --------
        try:
            _work.ensure_schema(store)
        except Exception:
            pass
        queued = 0
        for u in js_set:
            try:
                if _work.enqueue(store, run_id, _work.ROUTE_JS, "url", u):
                    queued += 1
            except Exception:
                continue
        before = _work.queue_stats(store, run_id)
        claimed = _work.claim(store, run_id, _work.ROUTE_JS,
                              limit=max(0, int(fetch_limit)))
        candidates = [c["canonical"] for c in claimed]
        results: list = []
        if candidates:
            with futures.ThreadPoolExecutor(
                    max_workers=min(10, len(candidates))) as pool:
                results = list(pool.map(scan_bundle, candidates))
        for item, found in zip(claimed, results):
            members: list = []
            observations: list = []
            if found is not None:
                for d in _uniq([core.canon_domain(x) for x in
                                (found.get("domains") or []) if core.canon_domain(x)]):
                    members.append({"kind": "domain", "canonical": d})
                    observations.append({"kind": "domain", "canonical": d,
                                         "producer": "extract",
                                         "upstream": "jsleak"})
                for ip in _uniq(found.get("ips") or []):
                    members.append({"kind": "ip", "canonical": ip})
                    observations.append({"kind": "ip", "canonical": ip,
                                         "producer": "extract",
                                         "upstream": "jsleak"})
            # Result + membership + ack under ONE valid lease.
            settled = _work.commit_result(
                store, run_id, item["id"], item["lease_token"],
                members=members, observations=observations,
                ok=found is not None,
                reason="" if found is not None else "fetch failed or empty body",
                retryable=found is None)
            if not settled or found is None:
                continue
            absorb(item["canonical"], found)
        after_q = _work.queue_stats(store, run_id)
        attempted = len(candidates)
        pending = int(after_q.get("outstanding") or 0)
        budget_hit = pending > 0 or attempted >= fetch_limit
        in_scope, related = _finish_tail(store, got, api_paths, api_hits, scope)
        return {"count_domains": len(got["domains"]),
                "count_ips": len(got["ips"]),
                "internal_ips": got.get("internal_ips") or [],
                "fetched": max(0, int(after_q.get("done") or 0)
                               - int(before.get("done") or 0)),
                "attempted": attempted,
                "js_discovered": discovered_js,
                "js_succeeded": int(after_q.get("done") or 0),
                "js_failed": int(after_q.get("failed") or 0)
                             + int(after_q.get("blocked") or 0),
                "js_pending": pending,
                "js_queued": queued,
                "js_fetch_limit": fetch_limit,
                "js_budget_hit": budget_hit,
                "outcome": (core.OUTCOME_PARTIAL if budget_hit and discovered_js
                            else core.OUTCOME_OK),
                "api_paths": api_paths[:300],
                "api_hosts": len(_seen_endpoints(api_hits, api_paths)),
                "secrets": _redact_secrets(secrets),
                "in_scope_domains": in_scope[:1000],
                "related_domains": related[:1000],
                "count_related": len(related),
                "domains": got["domains"][:1000], "ips": got["ips"][:1000]}

    # ---- standalone: legacy Store.js_* queue (unchanged behaviour) --------
    candidates = list(js_set)
    store.js_enqueue(candidates)
    before = store.js_stats()
    candidates = store.js_claim(fetch_limit, allow_urls=candidates)
    if candidates:
        with futures.ThreadPoolExecutor(max_workers=min(10, len(candidates))) as pool:
            results = list(pool.map(scan_bundle, candidates))
        for u, found in zip(candidates, results):
            store.js_finish(u, ok=found is not None,
                            error="" if found is not None
                            else "fetch failed or empty body")
            if found is not None:
                absorb(u, found)
    after = store.js_stats()
    attempted = len(candidates)
    pending = after["pending"] + after["failed"]
    budget_hit = pending > 0 or attempted >= fetch_limit
    in_scope, related = _finish_tail(store, got, api_paths, api_hits, scope)
    return {"count_domains": len(got["domains"]), "count_ips": len(got["ips"]),
            "internal_ips": got.get("internal_ips") or [],
            "fetched": after["succeeded"] - before["succeeded"],
            "attempted": attempted,
            "js_discovered": after["discovered"],
            "js_succeeded": after["succeeded"],
            "js_failed": after["failed"],
            "js_pending": pending,
            "js_fetch_limit": fetch_limit,
            "js_budget_hit": budget_hit,
            "outcome": (core.OUTCOME_PARTIAL if budget_hit and after["discovered"]
                        else core.OUTCOME_OK),
            "api_paths": api_paths[:300],
            "api_hosts": len(_seen_endpoints(api_hits, api_paths)),
            "secrets": _redact_secrets(secrets),
            "in_scope_domains": in_scope[:1000],
            "related_domains": related[:1000],
            "count_related": len(related),
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
    # Follow every page a paged source will give: the CLI default is 4 and
    # the binary clamps at 20, so "collect everything" means asking for the
    # clamp. A source that still holds more is reported truncated, never
    # silently treated as complete.
    pages = 0
    try:
        pages = int((core.CFG.get("limits") or {}).get("mapping_pages") or 0)
    except (TypeError, ValueError):
        pages = 0
    if pages > 0:
        cmd += ["--max-pages", str(min(20, pages))]
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
                   "found": s.get("found"), "code": s.get("code"),
                   # paging report (onepass >= 0.2): rows the upstream holds
                   # beyond what came back -- a coverage limit, not a failure
                   **{k: s[k] for k in ("pages", "truncated", "total", "page_error")
                      if k in s}}
                  for s in data.get("sources", [])]
    truncated = sorted("onepass:" + str(s.get("id")) for s in data.get("sources", [])
                       if s.get("truncated") is True)
    if truncated:
        core.log("onepass: upstream answers capped (more rows exist than were "
                 "fetched): " + ",".join(truncated))
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
        "truncated_sources": truncated,
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


def doctor_offline() -> dict:
    """doctor without any tool execution, network probe or key validation.

    Everything a subprocess or a socket would answer is reported as
    ``not_checked`` -- never false (``false`` means "checked and failed",
    which this mode never does). The tool table lists file presence and
    metadata only; runtime health, egress, credentials and the relay stay
    unknown. Default doctor keeps its full behaviour (docs/RELIABILITY-PLAN
    par.12: offline diagnostics must be usable in an air-gapped build).
    """
    import sys as _sys
    names = ["enscan", "subfinder", "httpx", "dnsx", "naabu", "cdncheck",
             "uncover", "katana", "chaos", "ksubdomain", "onepass",
             "hostCollision"]
    report = {}
    missing = []
    for n in names:
        try:
            exe = core.tool(n)
        except core.ToolMissing:
            report[n] = {"present": False}
            missing.append(n)
            continue
        entry = {"present": True, "path": exe, "source": "bundle"}
        try:
            st = Path(exe).stat()
            entry["size"] = st.st_size
            entry["mtime"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                           time.gmtime(st.st_mtime))
        except OSError as exc:
            entry["stat_error"] = str(exc)[:120]
        entry["health"] = "not_checked"
        report[n] = entry
    env = {"python_version": ".".join(map(str, _sys.version_info[:3])),
           "python_ok": _sys.version_info >= (3, 10),
           "python_required": ">=3.10",
           # egress/fake-IP would require sockets: unknown in this mode
           "net_egress": {"probes": {}, "any_reachable": None,
                          "checked": False},
           "fake_ip_dns": {"fake_ip_dns": None, "checked": False,
                           "reason": "offline mode: resolver not probed"}}
    keys = {k: "not_checked" for k in ["fofa", "quake", "hunter", "shodan",
                                        "chaos", "securitytrails", "virustotal",
                                        "urlscan"]}
    return {"python": "ok" if env["python_ok"] else "incompatible:" + env["python_version"],
            "skill_version": core.skill_version(),
            "mode": "offline",
            "environment": env,
            "tools": report, "api_keys": keys,
            "fofa_gateway": {"base": "not_checked", "reachable": None,
                             "checked": False},
            "tools_summary": {
                "total": len(names),
                "in_bin": len(names) - len(missing),
                "outside_bin": [],
                "missing": missing,
                "suspect": "not_checked",
                "stale_binary": "not_checked",
                "not_executable": "not_checked",
                "all_in_bin": None,  # runtime health unknown
                "checked": False,
            },
            "bin_dir": str(core.BIN_PLATFORM),
            "bin_platform": core.PLATFORM,
            "db": str(core.DATA / "findinfo.db"),
            "root": str(core.ROOT), "home": str(core.HOME)}


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
    # fake-IP detection: a Clash/TUN resolver answers EVERY name with an
    # address from 198.18.0.0/15, which makes the whole resolution graph
    # untrustworthy. Publishing the verdict here means status/brief and the dns
    # stage quote one detection instead of each probing on their own.
    env["fake_ip_dns"] = doh.detect_environment()
    env["resolution"] = doh.ResolutionPlan.for_run().payload()
    if env["fake_ip_dns"].get("fake_ip_dns"):
        env["fake_ip_hint"] = ("the local resolver synthesises addresses "
                               "(198.18.0.0/15); dns and probe stages use DoH at "
                               + str(env["resolution"].get("doh_url") or ""))
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
