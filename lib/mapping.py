"""Task-level ledger for metered mapping queries: ask each question once.

Why this module exists
----------------------
The same engine was asked the same question several times inside one task:

* one seed domain was sent to FOFA three times in a single run (onepass's
  fofa source, subs' gateway, subs' ``uncover -e fofa``) and to Quake twice;
* the standalone ``passive`` / ``subs`` / ``icp`` commands had no checkpoint
  at all, so every invocation paid again;
* the stage checkpoint hashes the WHOLE seed list, so adding one seed
  re-queried all of them.

Paid mapping is also the only kind of request this skill makes that can cost
quota, so "asked once" has to be a persistent fact, not a per-process cache.

Design
------
One row per (task, engine, kind, normalised value), stored in the task's own
SQLite database, so it survives restarts and is isolated per ``--task``:

    mapping_ledger(engine, kind, value, query, query_hash, status, rows,
                   total, run_id, asked_at, attempts, last_error)

* ``status`` reuses the ``ST_*`` vocabulary from lib/metered.py -- one
  vocabulary for "what happened on the wire", shared with the billed ledger.
* ``query_hash`` is ``metered.hash_input`` of the exact query text, so a
  changed template is a NEW question rather than a silent cache hit.
* A row is written for EVERY outcome (ok, empty, quota, auth, failed,
  uncertain): a failure is spend that already happened and must not be
  retried automatically. Only an explicit ``--remap`` asks again.
* Results are stored separately (``mapping_results``) so a later run can
  attach the already-paid evidence to its own membership instead of
  re-querying -- with the ORIGINAL observation time, never a new one.

Nothing here performs I/O; the caller dispatches and reports back.
"""
from __future__ import annotations

from . import core
from . import metered

SCHEMA = """
CREATE TABLE IF NOT EXISTS mapping_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT NOT NULL DEFAULT '',
  engine TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  query TEXT NOT NULL DEFAULT '',
  query_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT '',
  rows INTEGER NOT NULL DEFAULT 0,
  total INTEGER,
  truncated INTEGER NOT NULL DEFAULT 0,
  run_id TEXT NOT NULL DEFAULT '',
  asked_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 1,
  last_error TEXT NOT NULL DEFAULT '',
  UNIQUE (task, engine, kind, value, query_hash)
);
CREATE INDEX IF NOT EXISTS idx_mapping_lookup
  ON mapping_ledger(task, engine, kind, value);
CREATE TABLE IF NOT EXISTS mapping_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT NOT NULL DEFAULT '',
  query_hash TEXT NOT NULL,
  kind TEXT NOT NULL,
  canonical TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  UNIQUE (task, query_hash, kind, canonical)
);
CREATE INDEX IF NOT EXISTS idx_mapping_results_hash
  ON mapping_results(task, query_hash);
"""


def ensure_schema(store) -> None:
    with store._write():
        store.conn.executescript(SCHEMA)


def task_of() -> str:
    """The task this process is operating on ('' == the shared default store)."""
    import os
    return os.environ.get("FINDINFO_TASK", "") or ""


def normalise_icp(value: str) -> str:
    """The filing MAIN number: '京ICP备00000001号-1' and '-2' are one question.

    The suffix identifies an individual site under one filing; asking the
    engine once per site multiplied the paid queries for no new evidence
    (the engine returns the same filing's domain set either way).
    """
    v = str(value or "").strip()
    if not v:
        return ""
    head, sep, tail = v.rpartition("-")
    if sep and tail.isdigit() and head:
        return head
    return v


def question(engine: str, kind: str, value: str, query: str,
             task: str | None = None) -> dict:
    """The identity of one question (what makes a cache hit a real hit)."""
    t = task_of() if task is None else task
    val = normalise_icp(value) if kind == "icp" else str(value or "").strip()
    return {"task": t, "engine": engine or "", "kind": kind or "",
            "value": val, "query": query or "",
            "query_hash": metered.hash_input({"e": engine, "k": kind,
                                              "v": val, "q": query or ""})}


def lookup(store, q: dict) -> dict | None:
    """The existing row for this question, or None."""
    row = store.conn.execute(
        "SELECT * FROM mapping_ledger WHERE task=? AND engine=? AND kind=?"
        " AND value=? AND query_hash=?",
        (q["task"], q["engine"], q["kind"], q["value"],
         q["query_hash"])).fetchone()
    return dict(row) if row else None


def record(store, q: dict, status: str, *, rows: int = 0,
           total: int | None = None, truncated: bool = False,
           run_id: str = "", last_error: str = "") -> None:
    """Upsert one question's outcome (every outcome counts as spend)."""
    ts = core.now()
    with store._write():
        store.conn.execute(
            "INSERT INTO mapping_ledger(task, engine, kind, value, query,"
            " query_hash, status, rows, total, truncated, run_id, asked_at,"
            " attempts, last_error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?)"
            " ON CONFLICT(task, engine, kind, value, query_hash) DO UPDATE SET"
            " status=excluded.status, rows=excluded.rows, total=excluded.total,"
            " truncated=excluded.truncated, run_id=excluded.run_id,"
            " asked_at=excluded.asked_at, attempts=attempts+1,"
            " last_error=excluded.last_error",
            (q["task"], q["engine"], q["kind"], q["value"], q["query"],
             q["query_hash"], metered.status_of(status, count=rows),
             int(rows or 0), total,
             1 if truncated else 0, run_id, ts, (last_error or "")[:300]))


def save_results(store, q: dict, kind: str, canonicals, observed_at=None) -> int:
    """Remember the rows a question returned, so a reuse can attach them."""
    ts = observed_at or core.now()
    n = 0
    with store._write():
        for c in canonicals or []:
            if not c:
                continue
            cur = store.conn.execute(
                "INSERT OR IGNORE INTO mapping_results(task, query_hash, kind,"
                " canonical, observed_at) VALUES(?,?,?,?,?)",
                (q["task"], q["query_hash"], kind, c, ts))
            n += cur.rowcount or 0
    return n


def blocked_engines(store, task: str | None = None) -> list:
    """Engines whose credential was REJECTED by the provider in this task.

    A key that the provider refuses (401/403) is dead: asking again with the
    same key only burns time and, on metered providers, quota. The operator's
    policy is "no key, or a key that no longer works -> skip", so a rejected
    engine is dropped from dispatch for the rest of the task and reported as a
    capability gap instead of an error.
    """
    t = task_of() if task is None else task
    out: list = []
    for r in store.conn.execute(
            "SELECT engine FROM mapping_ledger WHERE task=? AND status=?"
            " ORDER BY engine", (t, metered.ST_AUTH)):
        e = r["engine"]
        if e not in out:
            out.append(e)
    return out


def results(store, q: dict, kind: str | None = None) -> list:
    """Rows this question returned (original observation time preserved)."""
    sql = ("SELECT kind, canonical, observed_at FROM mapping_results"
           " WHERE task=? AND query_hash=?")
    args: list = [q["task"], q["query_hash"]]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    return [dict(r) for r in store.conn.execute(sql + " ORDER BY id", args)]


def coverage(store, task: str | None = None) -> dict:
    """Per-engine question counts, for coverage/brief (no network)."""
    t = task_of() if task is None else task
    per: dict = {}
    for r in store.conn.execute(
            "SELECT engine, status, COUNT(*) c FROM mapping_ledger"
            " WHERE task=? GROUP BY engine, status", (t,)):
        e = per.setdefault(r["engine"], {})
        e[r["status"]] = r["c"]
    out = {}
    for engine, by in per.items():
        asked = sum(by.values())
        out[engine] = {
            "asked": asked,
            "reused": by.get(metered.ST_OK, 0) + by.get(metered.ST_EMPTY, 0),
            "failed": by.get(metered.ST_FAILED, 0),
            "quota": by.get(metered.ST_QUOTA, 0),
            "auth": by.get(metered.ST_AUTH, 0),
            "unconfirmed": by.get(metered.ST_UNCERTAIN, 0),
            "total": asked,
        }
    return {"task": t, "by_engine": out,
            "questions": sum(v["total"] for v in out.values())}
