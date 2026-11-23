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

import time

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

# Row ceiling per dispatch. uncover's own default is 100, which is a silent
# cap, so every dispatch passes an explicit one and a full page is reported
# `truncated`.
#
# It is NOT "the bigger the better". uncover PAGINATES, and the engine bills
# per page, so `-limit` is a spend ceiling, not a quality knob:
#
#   * quake: `sources/agent/quake/quake.go` requests a fixed Size=100 and
#     loops on a Start offset until `numberOfResults > query.Limit`. Each
#     round trip is one billed page. A measured `-limit 10000` against a
#     50-row answer cost 700 credits (7 pages); `-limit 1` cost 100 (the
#     engine's minimum page).
#   * fofa/shodan/hunter: one request, rows up to the engine's own page cap.
#
# EVERY engine pages at 100 rows per request (verified in the bundled uncover
# sources: quake Size=100, fofa Size=100, shodan page=..., hunter Size=100,
# zoomeye pagesize=100). `-limit` is therefore a PAGE BUDGET, and the only
# question is how many pages one dispatch may buy.
#
# No single number is right for every engine: fofa bills per query and its own
# single-page ceiling is 10000, while quake bills 100 credits per 100-row page
# and its whole free month is 3000. The operator's rule is "collect
# everything, ask once", so each engine gets its OWN ceiling (ENGINE_LIMITS),
# and a per-engine config always wins.
DEFAULT_LIMIT = 3000

# Rows per PAGE per engine, from the bundled uncover sources. Turns a row
# ceiling into an honest page/billing estimate.
PAGED_ENGINES = {
    "quake": 100, "fofa": 100, "shodan": 100,
    "hunter": 100, "zoomeye": 100, "censys": 100,
}

# Row ceiling of ONE upstream page, as uncover actually requests it. fofa's
# API accepts size=10000, but uncover hard-codes `Size = 100` (fofa.go:22) and
# never raises it, so a fofa dispatch also brings back 100 rows per request.
# The page count below must use what the TOOL asks for, not what the API
# would allow: 10000 rows of fofa is 100 requests, not one.
ENGINE_PAGE_MAX = {
    "quake": 100, "fofa": 100, "shodan": 100,
    "hunter": 100, "zoomeye": 100, "censys": 100,
}

# Engine-specific default row ceiling -- what "everything" costs there.
ENGINE_LIMITS = {
    # quake: 100 credits per 100-row page; the free month is 3000 credits, so
    # 3000 rows is one whole month in a single question.
    "quake": 3000,
    # fofa: uncover asks 100 rows a page and fofa bills the QUERY, so a wide
    # ceiling is one query per page either way. 1000 rows = 10 queries.
    "fofa": 1000,
    # shodan: free plans cannot search at all; paid plans bill per query.
    "shodan": 1000,
    # hunter: free accounts have no openApi; paid plans bill per page.
    "hunter": 1000,
    # no query template by default; kept for completeness.
    "zoomeye": 1000, "censys": 1000,
}


def mapping_limit(engine: str = "") -> int:
    """Rows to request for one dispatch (a spend ceiling, see DEFAULT_LIMIT).

    A per-engine override wins: `limits.mapping_rows_<engine>`. That is how a
    task says "spend more on quake" without changing every other engine.
    """
    limits = core.CFG.get("limits") or {}
    name = (engine or "").strip().lower()
    keys = []
    if name:
        keys.append("mapping_rows_" + name)
    keys.append("mapping_rows")
    for key in keys:
        try:
            v = int(limits.get(key) or 0)
        except (TypeError, ValueError):
            v = 0
        if v > 0:
            return v
    # No explicit config: the engine's own ceiling (see ENGINE_LIMITS). Every
    # engine pages at 100 rows, so this is a page budget, not a sample size.
    if name and name in ENGINE_LIMITS:
        return ENGINE_LIMITS[name]
    return DEFAULT_LIMIT


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


_ENTITLEMENT_HINTS = ("无 api 访问权限", "需升级", "membership", "无权限",
                      "requires membership", "not entitled", "insufficient",
                      "no credits")


def _entitlement_probe(engine: str, timeout: int = 20) -> tuple[str, str]:
    """Ask the provider whether this key may SEARCH at all: ("", "") or ("auth", why).

    Needed because uncover reports an upstream entitlement refusal as rc=0 with
    no rows and no message:
      * a Shodan key on the free `oss` plan answers every query with 0 rows;
      * a Hunter key on a free account answers "账号无 API 访问权限，需升级为付费账号".
    Both are indistinguishable from "this target has no assets", and recording
    them as `empty` publishes a billing limitation as a finding. Each provider
    publishes the answer without spending a search credit, so it is cheap to
    ask (one tiny request per engine, only when a zero comes back).
    """
    key = core.api_key(engine)
    if not key:
        return "", ""
    if engine == "shodan":
        rc, out, _err = core.curl(["-sS", "--max-time", str(max(5, timeout)),
                                   "https://api.shodan.io/api-info?key=" + key],
                                  timeout=timeout + 10)
        if rc != 0 or not (out or "").strip().startswith("{"):
            return "", ""
        try:
            import json as _json
            info = _json.loads(out)
        except Exception:
            return "", ""
        plan = str(info.get("plan") or "")
        if plan and plan.lower() == "oss" and not info.get("query_credits"):
            return "auth", ("shodan plan " + plan + " has no query credits: "
                            "search requires membership or higher")
        return "", ""
    if engine == "hunter":
        # One minimal page. A paid account answers code=200; a free account
        # answers code=400 with "账号无 API 访问权限". The query string is the
        # smallest one Hunter accepts.
        import urllib.parse as _up
        url = ("https://hunter.qianxin.com/openApi/search?api-key=" + key +
               "&search=" + _up.quote('domain="example.com"') +
               "&page=1&page_size=1&is_web=3")
        rc, out, _err = core.curl(["-sS", "--max-time", str(max(5, timeout)),
                                   "-A", "curl/8.4.0", url], timeout=timeout + 10)
        if rc != 0 or not (out or "").strip().startswith("{"):
            return "", ""
        try:
            import json as _json
            info = _json.loads(out)
        except Exception:
            return "", ""
        msg = str(info.get("message") or "")
        low = msg.lower()
        if any(h in low for h in _ENTITLEMENT_HINTS):
            return "auth", "hunter: " + msg[:160]
        return "", ""
    return "", ""


def key_state(store, engine: str, task: str | None = None) -> tuple[str, str]:
    """(state, reason) for one engine's credential, from this task's ledger.

    A provider that already refused the credential in this task (a deleted or
    expired key) is not worth asking again: every retry re-sends the same dead
    key. The ledger is the only place that knows, so dispatch consults it
    before spending a request.
    """
    try:
        for r in store.conn.execute(
                "SELECT status, last_error FROM mapping_ledger"
                " WHERE task=? AND engine=? AND status IN (?, ?)"
                " ORDER BY asked_at DESC LIMIT 1",
                (mapping.task_of() if task is None else task, engine,
                 metered.ST_AUTH, metered.ST_QUOTA)):
            if r["status"] == metered.ST_AUTH:
                return "auth", (r["last_error"] or "credential rejected")[:160]
            return "quota", (r["last_error"] or "quota exhausted")[:160]
    except Exception:
        pass
    return "", ""


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


def _gateway_available(engine: str) -> bool:
    """True when a relay gateway is configured for this engine.

    Only FOFA has a gateway protocol here (POST /api/v1/query + X-Ak). Its AK
    is valid ONLY at the relay, so it must never be handed to uncover: uncover
    speaks the official API and needs FOFA_EMAIL + FOFA_KEY, which a gateway
    user by definition does not have. Sending it there produced
    "agents [fofa] requires keys but no keys were found" on every dispatch.
    """
    return engine == "fofa" and bool(core.api_base("fofa"))


def _rows_from_gateway(res: dict) -> list:
    """(kind, canonical) pairs from a relay answer.

    A relay reports the registered domain in `domain` and the real hostname in
    `link`/`host`; both are worth keeping, the hostname more so.
    """
    out: list = []
    seen = set()

    def _add(kind: str, value: str) -> None:
        if kind == "domain":
            from . import core as _core
            value = _core.canon_domain(value or "")
        else:
            from . import core as _core
            value = _core.canon_ip(value or "")
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        out.append((kind, value))

    for r in (res.get("results") or []):
        if not isinstance(r, dict):
            continue
        host = r.get("host") or ""
        if not host:
            link = str(r.get("link") or "")
            if "://" in link:
                host = link.split("://", 1)[1].split("/")[0].split(":")[0]
        if host:
            _add("domain", host)
        if not host and r.get("domain"):
            _add("domain", r.get("domain"))
        if r.get("ip"):
            _add("ip", r.get("ip"))
    return out


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



def pages_spent(engine: str, rows: int, cap: int) -> int:
    """Billed round trips a dispatch of this size implies (best estimate).

    Reported so a run can be audited against the provider's own bill: "9
    credits" on the quake dashboard is 9 PAGES, i.e. 9 round trips of
    page_size rows, not 9 different questions. Before this the skill recorded
    ONE request per dispatch and the difference was invisible.

    The estimate is replaced by the MEASURED value when the provider exposes a
    balance (`engine_pages_measured`), because uncover stops on two different
    conditions (limit reached, or no more data) and only the provider knows
    which one fired.
    """
    name = (engine or "").strip().lower()
    # How many rows ONE round trip can bring back: the engine page ceiling,
    # never more than what was asked for.
    page = min(max(1, cap), ENGINE_PAGE_MAX.get(name) or max(1, cap))
    if not page:
        return 1
    # uncover checks the limit AFTER each page, so it fetches one page even for
    # a zero-row answer; beyond that it is ceil(ceiling / rows-per-page).
    return max(1, -(-max(1, cap) // page))


def engine_credit(engine: str, timeout: int = 15) -> int | None:
    """Current credit balance for an engine that publishes one, else None.

    Only quake has a documented, free endpoint for this. Used to MEASURE what
    a dispatch really cost instead of estimating it from row counts.
    """
    if (engine or "").strip().lower() != "quake":
        return None
    key = core.api_key("quake")
    if not key:
        return None
    rc, out, _err = core.curl(["-sS", "--max-time", str(max(5, timeout)),
                               "-H", "X-QuakeToken: " + key,
                               "https://quake.360.net/api/v3/user/info"],
                              timeout=timeout + 5)
    if rc != 0 or not (out or "").strip().startswith("{"):
        return None
    try:
        import json as _json
        data = (_json.loads(out) or {}).get("data") or {}
        v = data.get("credit")
        return int(v) if v is not None else None
    except Exception:
        return None


def _limits() -> dict:
    return core.CFG.get("limits") or {}


def _gateway_max_rows() -> int:
    """Largest answer the FOFA relay accepts in one question."""
    return max(1, int(_limits().get("fofa_gateway_max_rows") or 2000))


def _rate_retries() -> int:
    """Extra attempts after a rate-limit answer (0 disables the wait)."""
    v = _limits().get("mapping_rate_retries")
    return max(0, int(1 if v is None else v))


def _rate_wait_seconds() -> float:
    """How long a rate-limited engine is left alone: one per-minute window."""
    return max(1.0, float(_limits().get("mapping_rate_wait_sec") or 60))


def _rate_wait(seconds: float) -> None:
    time.sleep(seconds)


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
    state, why = key_state(store, engine)
    if state:
        # already refused in this task: asking again cannot succeed
        return {"engine": engine, "kind": kind, "value": value,
                "status": "skipped", "rows": 0, "reused": False,
                "truncated": False, "results": [],
                "reason": state + " earlier in this task: " + why}
    q = mapping.question(engine, kind, value, query)
    prior = mapping.lookup(store, q)
    # A rate-limited question was never answered: it is asked again, not
    # reused (every other recorded outcome is reused until --remap).
    if prior and not remap and prior["status"] != metered.ST_RATE:
        cached = mapping.results(store, q)
        return {"engine": engine, "kind": kind, "value": q["value"],
                "status": prior["status"], "rows": int(prior["rows"] or 0),
                "reused": True, "truncated": bool(prior["truncated"]),
                "results": [(r["kind"], r["canonical"]) for r in cached],
                "reason": "already asked in this task"}

    cap = mapping_limit(engine) if limit is None else int(limit)
    gateway = _gateway_available(engine)
    if gateway and cap > _gateway_max_rows():
        # the relay refuses an oversized answer outright ("超过最大值2000"):
        # ask its maximum and let `truncated` say there may be more
        core.log("mapping: the fofa relay answers at most " +
                 str(_gateway_max_rows()) + " rows; asking that instead of " + str(cap))
        cap = _gateway_max_rows()
    core.log("mapping: " + engine + " " + kind + " " + q["value"] +
             " (limit " + str(cap) + ")")
    # Measuring the spend means TWO extra round trips per dispatch (a balance
    # read before and after). That is cheap but not free of rate-limit budget,
    # so it is OFF unless the operator asks: `limits.measure_credits: true`.
    # The page count is still estimated from the limit and reported either way.
    measure = bool((core.CFG.get("limits") or {}).get("measure_credits"))
    credit_before = engine_credit(engine, timeout=min(15, timeout or 15)) if measure else None
    attempts = 1 + _rate_retries()
    for attempt in range(attempts):
        # the relay keeps its own pace (10/min seen live), the engines theirs
        core.throttle("fofa-gateway" if gateway else engine)
        core.mapping_wait()
        rc, err = 0, ""
        if gateway:
            # A relay AK is only valid at the relay and needs no email: uncover
            # cannot carry it, so the gateway is asked directly.
            res = core.fofa_query(query, fields="host,ip,domain,link,title",
                                  size=max(1, cap), timeout=timeout or 60)
            if not res.get("ok"):
                err = str(res.get("error") or "gateway error")
                rc = 1
                got = []
            else:
                got = _rows_from_gateway(res)
        else:
            cmd = [core.tool("uncover"), "-q", query, "-e", engine,
                   "-json", "-silent", "-limit", str(max(1, cap))]
            # only the engine being asked gets its credential: uncover otherwise
            # runs with every configured engine key in its environment
            rc, out, err = core.run(cmd, timeout=timeout,
                                    env=core.tool_env("uncover", [engine]))
            got = _parse_uncover_rows(out)
        n = len(got)
        # classify from the wire: quota/auth hints in stderr win over "zero
        # rows", because uncover reports an upstream error as rc=0, no body
        status = metered.status_of("", rc=rc, count=n, error=(err or ""))
        if status != metered.ST_RATE or attempt + 1 >= attempts:
            break
        wait = _rate_wait_seconds()
        core.log("mapping: " + engine + " is rate-limited (" + (err or "")[:80] +
                 "); waiting " + str(int(wait)) + "s, then asking again")
        _rate_wait(wait)
    # a page that fills the ceiling may hide more rows: say so, never guess
    truncated = n >= cap
    # uncover answers rc=0 with no rows for an upstream it could not query
    # ("Requires membership or higher", "no keys"), with no message at all.
    # A zero is therefore NOT proof of an empty result unless the credential is
    # entitled to search: ask the provider (cheaply, where it publishes it) and
    # record a refusal as such.
    if status == metered.ST_EMPTY:
        state, why = key_state(store, engine)
        if not state:
            state, why = _entitlement_probe(engine, timeout=timeout or 20)
        if state == "auth":
            status = metered.ST_AUTH
            err = (err or "") + (" " if err else "") + why
            core.log("mapping: " + engine + " cannot search: " + why)
    mapping.record(store, q, status, rows=n, truncated=truncated,
                   run_id=run_id, last_error=(err or "")[:300])
    if got:
        mapping.save_results(store, q, "domain", [v for k, v in got if k == "domain"])
        mapping.save_results(store, q, "ip", [v for k, v in got if k == "ip"])
    pages = pages_spent(engine, n, cap)
    credit_after = engine_credit(engine, timeout=min(15, timeout or 15)) if measure else None
    credits = None
    if credit_before is not None and credit_after is not None:
        credits = max(0, credit_before - credit_after)
        size = PAGED_ENGINES.get((engine or "").strip().lower()) or 0
        if size and credits:
            # the measured charge is the ground truth for the page count
            pages = max(1, credits // size)
        core.log("mapping: " + engine + " spent " + str(credits) +
                 " credit(s), " + str(pages) + " page(s)")
    if ledger is not None:
        try:
            ledger.record(engine=engine, input_hash=metered.hash_input(
                {"q": query, "e": engine}),
                unit=metered.UNIT_NATIVE_DISPATCH, rc=rc, requested=pages,
                returned=n, status=status,
                error=(err or "")[:200] if rc not in (0, None) else "")
        except Exception:
            pass
    return {"engine": engine, "kind": kind, "value": q["value"],
            "status": status, "rows": n, "reused": False,
            "pages": pages, "credits": credits, "limit": cap,
            "truncated": truncated, "results": got,
            "reason": (err or "").strip()[:200]}


def resolve_by_name(store, run_id: str, name: str, *,
                    engines: str | None = None, remap: bool = False,
                    timeout: int = 0,
                    ledger=None, kind: str = "domain") -> dict:
    """Find a company's MAIN DOMAIN by asking the engines for its NAME.

    Used when ENScan cannot anchor a target at all (no such keyword, or only
    lookalikes came back): the operator's rule is that the company name is
    still a usable search value, so the engines are asked `icp="<name>"` and
    `domain="<name>"` and whatever domains come back seed the run.

    A name is NOT a domain, so it deliberately bypasses canon_user_domain
    (which would drop every Chinese corporate name). Safety comes from
    core.uncover_query, which strips quotes and backslashes so the value stays
    inside its quoted term.

    Returns {"domains": [...], "answered": n_engines_with_an_answer,
    "attempted": n, "skipped_engines": [...], "results": [(kind, value)]}.
    """
    label = str(name or "").strip()
    out = {"domains": [], "answered": 0, "attempted": 0,
           "skipped_engines": [], "results": [], "name": label}
    if not label:
        return out
    usable, skipped = engines_for_task(store, kind, engines)
    out["skipped_engines"] = list(skipped)
    domains: list = []
    results: list = []
    for engine in usable:
        out["attempted"] += 1
        r = ask(store, run_id, engine, kind, label, remap=remap, timeout=timeout,
                ledger=ledger)
        if r.get("status") in (metered.ST_OK, metered.ST_EMPTY,
                               metered.ST_TRUNCATED):
            out["answered"] += 1
        for k, v in (r.get("results") or []):
            results.append((k, v))
            if k == "domain" and v not in domains:
                domains.append(v)
        # an engine that refused the credential stays in the ledger's blocked
        # list, so the rest of the run will not touch it again
        if r.get("status") == metered.ST_AUTH:
            out["skipped_engines"].append(
                {"engine": engine, "reason": "credential rejected: " +
                 str(r.get("reason") or "")[:120]})
    out["domains"] = domains
    out["results"] = results
    return out


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
            # Each row remembers the question that produced it: a domain
            # returned by an ICP reverse lookup belongs to that filing
            # number, and dropping the link made the report unable to say
            # which filing a host came from.
            _ctx = {"engine": r["engine"], "kind": kind,
                    "asked": r["value"]}
            results.extend(tuple(x) + (_ctx,) for x in r["results"])
    return {"kind": kind, "dispatched": len(usable) * len(list(values)),
            "reused": reused, "failures": asked,
            "truncated_sources": sorted(set(truncated)),
            "skipped_engines": skipped,
            "results": results}


def store_results(store, results) -> dict:
    """Write mapping rows as assets, keeping the question that produced them.

    Each row is (kind, value[, context]). The context names the engine and the
    value that was asked; for an ICP reverse lookup that value IS the filing
    number, so the returned domain is stored with `parent=<filing>` and the
    report can say which filing a host belongs to. Without it the link was
    lost: every mapped domain looked like a direct answer about the seed.
    """
    n = {"domain": 0, "ip": 0}
    for row in results:
        if len(row) >= 3:
            kind, val, ctx = row[0], row[1], row[2] or {}
        else:
            kind, val, ctx = row[0], row[1], {}
        asked_kind = str(ctx.get("kind") or "")
        asked = str(ctx.get("asked") or "")
        # A domain/IP answered by an ICP question belongs to that filing.
        parent = asked if asked_kind == "icp" and asked else None
        tag = "mapping:" + ("icp" if asked_kind == "icp" else "domain")
        try:
            if kind == "domain":
                store.upsert_asset("domain", val, source=tag,
                                   confidence=0.75, passivity="passive",
                                   parent=parent)
            else:
                store.upsert_asset("ip", val, source=tag,
                                   confidence=0.6, passivity="passive",
                                   parent=parent)
            n[kind] = n.get(kind, 0) + 1
        except Exception:
            continue
    return n


def check_engines(domain: str, engines: str | None = None,
                  timeout: int = 30) -> dict:
    """One minimal query per engine, to verify key AND syntax acceptance.

    Runs ONLY when an operator explicitly asks (the CLI requires
    --yes-spend-quota): each call can consume a paid unit. It answers, per
    engine: was the key accepted (rc/stderr), was the syntax accepted, how many
    rows came back, and whether the page was capped. Nothing is cached in the
    task ledger -- this is a self-check, not task mapping.
    """
    usable, skipped = engines_for("domain", engines)
    out = {"domain": domain, "checked": [], "skipped": skipped}
    for engine in usable:
        query = core.uncover_query("domain", engine, domain)
        if not query:
            out["skipped"].append({"engine": engine,
                                   "reason": "no domain query syntax"})
            continue
        core.throttle(engine)
        core.mapping_wait()
        if _gateway_available(engine):
            res = core.fofa_query(query, fields="host,ip,domain,link",
                                  size=1, timeout=timeout or 30)
            rc = 0 if res.get("ok") else 1
            err = "" if res.get("ok") else str(res.get("error") or "")
            rows = _rows_from_gateway(res) if res.get("ok") else []
        else:
            cmd = [core.tool("uncover"), "-q", query, "-e", engine,
                   "-json", "-silent", "-limit", "1"]
            rc, body, err = core.run(cmd, timeout=timeout,
                                     env=core.tool_env("uncover", [engine]))
            rows = _parse_uncover_rows(body)
        low = (err or "").lower()
        out["checked"].append({
            "engine": engine, "query": query, "rc": rc,
            "rows": len(rows),
            "key_accepted": not any(k in low for k in
                                    ("401", "403", "unauthor", "invalid key",
                                     "api key", "requires keys")),
            "syntax_accepted": not any(k in low for k in
                                       ("syntax", "parse", "invalid query",
                                        "unexpected token")),
            "error": (err or "").strip()[:200],
        })
    return out
