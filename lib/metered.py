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

_ALL = (ST_OK, ST_EMPTY, ST_TRUNCATED, ST_QUOTA, ST_AUTH, ST_FAILED)


def status_of(outcome: str, rc=None, count: int | None = None,
              error: str = "") -> str:
    """Typed status from a raw collector outcome (never re-guessed later)."""
    oc = (outcome or "").strip().lower()
    err = (error or "").lower()
    if oc in _ALL:
        return oc
    if "quota" in err or "exceed" in err or "limit" in err:
        return ST_QUOTA
    if rc == 401 or rc == 403 or "unauthor" in err or "api key" in err:
        return ST_AUTH
    if rc == 124 or "timeout" in err or "timed out" in err:
        return ST_FAILED
    if count == 0:
        return ST_EMPTY
    if rc not in (None, 0):
        return ST_FAILED
    return ST_OK


class MeteredLedger:
    """Append-only billed-request ledger for one engagement."""

    def __init__(self, path=None, buffer: list | None = None):
        self.path = path
        self.buffer = buffer if buffer is not None else []
        self._seen: dict = {}

    # ---------------------------------------------------------------- record
    def record(self, run_id: str, engine: str, input_hash: str = "",
               *, status: str = ST_OK, requested: int = 0,
               returned: int = 0, elapsed_sec: float = 0.0,
               rc=None, error: str = "", quota: dict | None = None) -> bool:
        """Append one billed request. False only for a duplicate no-change
        replay of (run_id, engine, input_hash) with the same status."""
        st = status_of(status, rc=rc, count=returned, error=error)
        key = (run_id, engine, input_hash or "")
        if input_hash and self._seen.get(key) == st:
            return False
        if input_hash:
            self._seen[key] = st
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "run_id": run_id, "engine": engine,
               "input_hash": input_hash or "",
               "status": st, "requested": int(requested or 0),
               "returned": int(returned or 0),
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
        """Spend summary: per-status request counts and returned rows."""
        per_status: dict = {s: 0 for s in _ALL}
        requests = returned = 0
        for r in self.rows(run_id):
            per_status[r["status"]] = per_status.get(r["status"], 0) + 1
            requests += 1
            returned += int(r.get("returned") or 0)
        return {"requests": requests, "returned_rows": returned,
                "by_status": per_status}

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


def hash_input(value) -> str:
    """Stable short hash of a billed request input (replay guard key)."""
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]