"""The ONE place a paid mapping query is dispatched (batch 1 of the repair).

Why this module exists
----------------------
Metered mapping used to be spread across onepass, the FOFA gateway, the subs
uncover loop and the icp uncover loop, so the same seed was sent to FOFA three
times inside one run and to Quake twice, and each standalone command paid
again. API keys were also injected into every child process, not just the one
being called.

Everything that can spend quota now goes through :func:`ask`:

* the task ledger (lib/mapping.py) decides whether a question was already
  asked; an answered question is NOT re-dispatched -- its stored results are
  merged back with their ORIGINAL observation time;
* only this module builds a child environment, and only with the variables the
  called tool reads (``core.tool_env("uncover"|"onepass")``);
* ``uncover`` is always given an explicit ``-limit``, and a full page is
  reported as a possible truncation instead of looking like a complete answer;
* a dispatch that fails is recorded (spend already happened) and never
  retried automatically -- ``remap=True`` is the caller's explicit opt-in.

No network happens here unless a caller actually dispatches; the ledger half is
pure. All exchange with the outside world goes through ``core.run``, which is
what the offline tests fake.
"""
from __future__ import annotations

from . import core
from . import mapping
from . import metered

# Engines whose query syntax this build knows, per question kind. A name
# absent from the table is NEVER dispatched: uncover hands `-q` over verbatim,
# so a guessed syntax produces a silent zero that looks like "no assets".
SUPPORTED_ENGINES = {
    "domain": tuple(core.UNCOVER_DOMAIN_QUERY),
    "icp": tuple(core.UNCOVER_ICP_QUERY),
}

# Default row ceiling per dispatch. uncover's own default is 100, which is a
# silent cap: a query that has more rows than this must SAY so.
DEFAULT_LIMIT = 1000


def mapping_limit() -> int:
    try:
        v = int((core.CFG.get("limits") or {}).get("mapping_rows") or 0)
    except (TypeError, ValueError):
        v = 0
    return v if v > 0 else DEFAULT_LIMIT


def engines_for(kind: str, requested: str | None = None) -> tuple[list, list]:
    """(usable, skipped) engines for a question kind, keys considered.

    `skipped` entries explain WHY an engine was not asked (no key, no query
    syntax); they become coverage gaps, never silent omissions.
    """
    supported = SUPPORTED_ENGINES.get(kind) or ()
    want = [e.strip().lower() for e in (requested or "").split(",") if e.strip()]
    if not want:
        want = list(supported)
    usable, skipped = [], []
    for e in want:
        if e not in supported:
            skipped.append({"engine": e,
                            "reason": "no " + kind + " query syntax for this engine"})
            continue
        if not core.engine_has_key(e):
            skipped.append({"engine": e, "reason": "no api key"})
            continue
        usable.append(e)
    return usable, skipped


def engines_for_task(store, kind: str, requested: str | None = None,
                     task: str | None = None) -> tuple[list, list]:
    """engines_for() minus engines whose key the provider already rejected.

    The operator's policy: a missing key, or a key that no longer works, is
    SKIPPED -- never an error and never an endless retry. A rejected engine
    stays in the skipped list with its reason so coverage names it.
    """
    usable, skipped = engines_for(kind, requested)
    try:
        dead = set(mapping.blocked_engines(store, task))
    except Exception:
        dead = set()
    if not dead:
        return usable, skipped
    keep = []
    for e in usable:
        if e in dead:
            skipped.append({"engine": e,
                            "reason": "credential rejected earlier in this task"})
        else:
            keep.append(e)
    return keep, skipped


def _parse_uncover_rows(out: str) -> list:
    """Host/ip rows from uncover's JSONL (fields vary per engine)."""
    rows: list = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json
            r = json.loads(line)
        except Exception:
            continue
        host = r.get("host") or r.get("domain") or ""
        d = core.canon_domain(host)
        ip = core.canon_ip(r.get("ip") or "")
        if d:
            rows.append(("domain", d))
        if ip and ip != "0.0.0.0":
            rows.append(("ip", ip))
    # stable, deduplicated
    seen = set()
    out_rows = []
    for kind, val in rows:
        if (kind, val) in seen:
            continue
        seen.add((kind, val))
        out_rows.append((kind, val))
    return out_rows


def ask(store, run_id: str, engine: str, kind: str, value: str,
        *, requested_engines: str | None = None, remap: bool = False,
        timeout: int = 0, ledger=None, limit: int | None = None) -> dict:
    """Ask ONE (engine, question) unless the task ledger already has it.

    Returns {"engine", "kind", "value", "status", "rows", "reused",
    "truncated", "results": [(kind, canonical), ...], "reason"}.
    """
    query = core.uncover_query(kind, engine, value)
    if not query:
        return {"engine": engine, "kind": kind, "value": value,
                "status": "skipped", "rows": 0, "reused": False,
                "truncated": False, "results": [],
                "reason": "no " + kind + " query syntax for this engine"}
    q = mapping.question(engine, kind, value, query)
    prior = mapping.lookup(store, q)
    if prior and not remap:
        cached = mapping.results(store, q)
        return {"engine": engine, "kind": kind, "value": q["value"],
                "status": prior["status"], "rows": int(prior["rows"] or 0),
                "reused": True, "truncated": bool(prior["truncated"]),
                "results": [(r["kind"], r["canonical"]) for r in cached],
                "reason": "already asked in this task"}

    cap = mapping_limit() if limit is None else int(limit)
    cmd = [core.tool("uncover"), "-q", query, "-e", engine,
           "-json", "-silent", "-limit", str(max(1, cap))]
    core.log("mapping: " + engine + " " + kind + " " + q["value"])
    core.throttle(engine)
    core.mapping_wait()
    # only the engine being asked gets its credential: uncover otherwise
    # runs with every configured engine key in its environment
    rc, out, err = core.run(cmd, timeout=timeout,
                            env=core.tool_env("uncover", [engine]))
    got = _parse_uncover_rows(out)
    n = len(got)
    # a page that fills the ceiling may hide more rows: say so, never guess
    truncated = n >= cap
    # classify from the wire: quota/auth hints in stderr win over "zero rows",
    # because uncover reports an upstream error as rc=0 with an empty body
    status = metered.status_of("", rc=rc, count=n, error=(err or ""))
    mapping.record(store, q, status, rows=n, truncated=truncated,
                   run_id=run_id, last_error=(err or "")[:300])
    if got:
        mapping.save_results(store, q, "domain", [v for k, v in got if k == "domain"])
        mapping.save_results(store, q, "ip", [v for k, v in got if k == "ip"])
    if ledger is not None:
        try:
            ledger.record(engine=engine, input_hash=metered.hash_input(
                {"q": query, "e": engine}),
                unit=metered.UNIT_NATIVE_DISPATCH, rc=rc, requested=1,
                returned=n, status=status,
                error=(err or "")[:200] if rc not in (0, None) else "")
        except Exception:
            pass
    return {"engine": engine, "kind": kind, "value": q["value"],
            "status": status, "rows": n, "reused": False,
            "truncated": truncated, "results": got,
            "reason": (err or "").strip()[:200]}


def ask_all(store, run_id: str, kind: str, values, *,
            engines: str | None = None, remap: bool = False,
            timeout: int = 0, ledger=None) -> dict:
    """Ask every (engine, value) for one kind; the run's mapping entry point."""
    usable, skipped = engines_for_task(store, kind, engines)
    asked, reused = [], 0
    results: list = []
    truncated: list = []
    for value in values:
        for engine in usable:
            r = ask(store, run_id, engine, kind, value,
                    remap=remap, timeout=timeout, ledger=ledger)
            if r["reused"]:
                reused += 1
            if r["status"] not in (metered.ST_OK, metered.ST_EMPTY):
                asked.append({"engine": r["engine"], "value": r["value"],
                              "status": r["status"], "reason": r["reason"]})
            if r["truncated"]:
                truncated.append("uncover:" + r["engine"])
            results.extend(r["results"])
    return {"kind": kind, "dispatched": len(usable) * len(list(values)),
            "reused": reused, "failures": asked,
            "truncated_sources": sorted(set(truncated)),
            "skipped_engines": skipped,
            "results": results}


def store_results(store, results) -> dict:
    """Write mapping rows as assets (one source token per engine answer)."""
    n = {"domain": 0, "ip": 0}
    for kind, val in results:
        try:
            if kind == "domain":
                store.upsert_asset("domain", val, source="mapping",
                                   confidence=0.75, passivity="passive")
            else:
                store.upsert_asset("ip", val, source="mapping",
                                   confidence=0.6, passivity="passive")
            n[kind] = n.get(kind, 0) + 1
        except Exception:
            continue
    return n
