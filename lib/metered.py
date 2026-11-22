"""Per-request metered ledger for billed provider queries.

Why this module exists
----------------------
Mapping engines (fofa/quake/hunter/shodan/censys and any relay) are the only
stages that spend money. The baseline had no unified record of a billed
request, so an agent could not answer "what would the next round cost?" nor
prove that a quota ceiling was the real stop reason (docs/RELIABILITY-PLAN
par.7).

Design
------
One ledger per run (a JSONL file in the run dir, plus buffered rows), one
append per REQUEST, not per result row:

* record -- append one billed request: engine, run id, input hash,
  status (ST_*), requested/returned counts, elapsed, and the provider
  own quota fields when it answers them (remaining/max). Failures are
  recorded too -- a request that died is cost incurred with no data.
* status_of -- map a call outcome onto the typed ST_* vocabulary; the
  caller verdict never re-interprets strings.
* totals/by_engine -- deterministic summaries from the ledger.
* quota_remaining -- best known ceiling from the freshest provider
  answer; None means "unknown", never "infinite".
* replay guard: identical (run_id, engine, input_hash) re-records only
  when the status changed (a retry is new spend, a duplicate is not).

Nothing here talks to a provider; the caller hands in what it observed.
The fofa-gateway remaining/maxQueries map onto quota fields unchanged.
"""
from __future__ import annotations

import hashlib
import json
import time

# Typed statuses: one vocabulary shared by callers and reports.
ST_OK = "ok"                       # answered, rows returned
ST_EMPTY = "empty"                 # answered, zero rows (a valid answer)
ST_TRUNCATED = "truncated"         # answered but cut by the provider
ST_QUOTA = "quota"                 # ceiling reached (quota exhausted)
ST_AUTH = "auth"                   # credential rejected -- never retry blind
ST_FAILED = "failed"               # transport/tool failure, retry may help
ST_UNCERTAIN = "uncertain"         # dispatch happened, outcome/billing unknown

_ALL = (ST_OK, ST_EMPTY, ST_TRUNCATED, ST_QUOTA, ST_AUTH, ST_FAILED,
        ST_UNCERTAIN)

# Count units. A provider HTTP request we make ourselves and one native-tool
# process invocation are DIFFERENT observable facts; neither is a price.
UNIT_PROVIDER_HTTP = "provider_http"     # the request count IS observable
UNIT_NATIVE_DISPATCH = "native_dispatch"  # one process run; internal fan-out unknown
_UNITS = (UNIT_PROVIDER_HTTP, UNIT_NATIVE_DISPATCH)


def status_of(outcome: str, rc=None, count: int | None = None,
              error: str = "") -> str:
    """Typed status from a raw collector outcome (never re-guessed later)."""
    oc = (outcome or "").strip().lower()
    err = (error or "").lower()
    if oc in _ALL:
        return oc
    if "quota" in err or "exceed" in err or "limit" in err:
        return ST_QUOTA
    # A credential the provider refuses is a SKIP, not a failure: retrying it
    # cannot help and (on a paid plan) only burns time. Providers word this
    # several ways -- uncover says "requires keys but no keys were found" for a
    # missing variable, a relay says "key does not exist or has been deleted",
    # an HTTP API answers 401/403. All of them mean the same thing here.
    # "Requires membership or higher" is the same class: the credential is
    # recognised, the ACCOUNT is not entitled to search. Retrying cannot fix
    # it and recording it as `empty` would publish a paid-plan limitation as
    # "this target has no assets" -- exactly the confusion this project bans.
    if rc == 401 or rc == 403 or any(k in err for k in (
            "unauthor", "api key", "requires keys", "no keys were found",
            "invalid key", "key not found", "forbidden", "unauthorized",
            "membership", "requires membership", "not entitled", "no credits",
            "no query credits", "insufficient credits",
            "密钥", "未授权", "无权", "权限")):
        return ST_AUTH
    if rc == 124 or "timeout" in err or "timed out" in err:
        return ST_FAILED
    # A non-zero exit is a FAILURE even with zero rows: checking "count == 0"
    # first recorded a crashed dispatch as a valid empty answer, which the
    # ledger then reused forever (the query would never be retried).
    if rc not in (None, 0):
        return ST_FAILED
    if count == 0:
        return ST_EMPTY
    return ST_OK


class MeteredLedger:
    """Append-only billed-request ledger for one engagement."""

    def __init__(self, path=None, buffer: list | None = None,
                 run_id: str = ""):
        self.path = path
        self.buffer = buffer if buffer is not None else []
        # The run every record() call stamps by default; collectors receive
        # the ledger and do not need to know the run's public id.
        self.run_id = run_id or ""
        self._seen: dict = {}

    # ---------------------------------------------------------------- record
    def record(self, run_id: str = "", engine: str = "", input_hash: str = "",
               *, status: str = ST_OK, requested: int = 0,
               returned: int = 0, elapsed_sec: float = 0.0,
               rc=None, error: str = "", quota: dict | None = None,
               unit: str = UNIT_PROVIDER_HTTP, dispatch_id: str = "",
               replay: bool = False, settled: bool = True) -> bool:
        """Append one billed dispatch -- one row per REAL dispatch.

        Two things are deliberately distinct (F08):

        * a real second dispatch of the same query is TWO rows. The old
          `_seen` guard collapsed "same input_hash + same status" into one,
          which made a genuinely repeated paid query invisible. Deduplication
          now happens ONLY when the caller marks the call as `replay=True`
          (the same log event written twice);
        * `unit` states WHAT was counted: `provider_http` (a provider HTTP
          request we perform ourselves) or `native_dispatch` (one process
          invocation of a native tool whose internal per-provider calls we
          cannot see). A native dispatch is NOT one HTTP request and not a
          price -- callers and reports must not read it as either.

        `settled=False` records a dispatch whose outcome is unknown right now
        (a crash/deadline that may already have been billed); recovery keeps
        it unsettled rather than inventing a charge or a free call.
        """
        st = status_of(status, rc=rc, count=returned, error=error)
        if not settled:
            st = ST_UNCERTAIN
        run_id = run_id or getattr(self, "run_id", "") or ""
        engine = engine or "unknown"
        if unit not in _UNITS:
            unit = UNIT_PROVIDER_HTTP
        key = (run_id, engine, input_hash or "", unit)
        if replay and input_hash and self._seen.get(key) == st:
            return False
        if input_hash:
            self._seen[key] = st
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "run_id": run_id, "engine": engine,
               "unit": unit,
               "dispatch_id": dispatch_id or (
                   "%s:%s:%s" % (engine, (input_hash or "nohash")[:12],
                                 len(self.buffer) + 1)),
               "input_hash": input_hash or "",
               "status": st, "requested": int(requested or 0),
               "returned": int(returned or 0),
               "settled": bool(settled),
               "elapsed_sec": round(float(elapsed_sec or 0.0), 3)}
        if rc is not None:
            row["rc"] = rc
        if error:
            row["error"] = str(error)[:200]
        if quota:
            row["quota"] = _norm_quota(quota)
        self.buffer.append(row)
        if self.path is not None:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + chr(10))
        return True

    # ---------------------------------------------------------------- reads
    def rows(self, run_id: str | None = None,
             engine: str | None = None) -> list[dict]:
        out = []
        for r in self.buffer:
            if run_id and r.get("run_id") != run_id:
                continue
            if engine and r.get("engine") != engine:
                continue
            out.append(r)
        return out

    def totals(self, run_id: str | None = None) -> dict:
        """Spend summary: per-status dispatch counts, returned rows, by unit.

        `requests` counts DISPATCHES, not a bill: a native dispatch fans out
        to provider calls we cannot see. `by_unit` keeps the two observable
        units apart, and `unsettled` counts dispatches whose outcome is still
        unknown (never folded into "free").
        """
        per_status: dict = {s: 0 for s in _ALL}
        by_unit: dict = {u: 0 for u in _UNITS}
        requests = returned = unsettled = 0
        for r in self.rows(run_id):
            per_status[r["status"]] = per_status.get(r["status"], 0) + 1
            unit = r.get("unit") or UNIT_PROVIDER_HTTP
            by_unit[unit] = by_unit.get(unit, 0) + 1
            if r.get("settled") is False or r.get("status") == ST_UNCERTAIN:
                unsettled += 1
            requests += 1
            returned += int(r.get("returned") or 0)
        return {"requests": requests, "dispatch_units": by_unit,
                "unsettled": unsettled,
                "returned_rows": returned, "by_status": per_status,
                "note": ("dispatch counts, not a price: provider_http is an "
                         "HTTP request we make; native_dispatch is one native "
                         "process whose internal fan-out is not observable")}

    def by_engine(self, run_id: str | None = None) -> dict:
        out: dict = {}
        for r in self.rows(run_id):
            e = out.setdefault(r["engine"], {"requests": 0,
                                             "returned_rows": 0,
                                             "statuses": {}})
            e["requests"] += 1
            e["returned_rows"] += int(r.get("returned") or 0)
            e["statuses"][r["status"]] = e["statuses"].get(r["status"], 0) + 1
        return out

    def quota_remaining(self, engine: str) -> "int | None":
        """Best-known ceiling from the freshest provider answer.

        None means unknown (the provider never answered a quota field) --
        never treated as infinite spend headroom.
        """
        best = None
        for r in self.buffer:
            if r.get("engine") != engine:
                continue
            q = r.get("quota") or {}
            if q.get("remaining") is not None:
                best = int(q["remaining"])
        return best

    def blocked_engines(self, run_id: str | None = None) -> list:
        """Engines whose last request proved no further spend is useful:
        quota exhausted or credentials rejected (never ST_FAILED -- a
        transport failure may succeed on retry)."""
        last: dict = {}
        for r in self.rows(run_id):
            last[r["engine"]] = r["status"]
        return sorted(e for e, s in last.items() if s in (ST_QUOTA, ST_AUTH))


def _norm_quota(quota: dict) -> dict:
    """Map provider quota shapes (fofa gateway maxQueries/remaining...) to
    {remaining: int|None, max: int|None, source: str}."""
    out = {"remaining": None, "max": None, "source": "provider"}
    for k, v in (quota or {}).items():
        lk = str(k).lower()
        try:
            if "remaining" in lk and v is not None:
                out["remaining"] = int(v)
            elif lk in ("max", "maxqueries", "max_queries") and v is not None:
                out["max"] = int(v)
        except (TypeError, ValueError):
            continue
    if quota and quota.get("source"):
        out["source"] = str(quota["source"])
    return out


def load_ledger(path, run_id: str = "") -> "MeteredLedger":
    """Read a run's persisted metered.jsonl back into a ledger (brief/report).

    The file is the durable spend record: a later session summarises the
    engagement without the process that incurred it. A missing file is an
    empty ledger, not an error.
    """
    led = MeteredLedger(run_id=run_id)
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                led.buffer.append(row)
                if row.get("input_hash"):
                    led._seen[(row.get("run_id") or "", row.get("engine") or "",
                               row["input_hash"])] = row.get("status")
    except OSError:
        pass
    return led


def hash_input(value) -> str:
    """Stable short hash of a billed request input (replay guard key)."""
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]