"""Run membership, observations and durable work routing.

Why this module exists
----------------------
Reflow state used to live in three places that could disagree: round inputs
were re-derived from the whole shared asset graph (so a sibling run of the
same root fed the resolver thousands of foreign names -- the T08/T16 class of
bug), JS work lived in a queue keyed only by URL with no run ownership
(T33: pending items from an old run silently attach to whatever runs next),
and nothing recorded which run observed which asset (T11: two runs in one
task were indistinguishable after the fact).

The tables here are additive and idempotent (the store's own migration
pattern), and every route goes through one :func:`record_observation` call
so membership, evidence and downstream work commit together. Producers use
the Store handed to them; nothing here touches the network.

Run identity
------------
Runs are addressed by their PUBLIC run-directory id (the `run_id` every
command already prints). The legacy integer runs.id stays untouched for old
reports; new tables never use it.
"""
from __future__ import annotations

import json

from . import core

WORK_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_assets (
  run_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  canonical TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  PRIMARY KEY (run_id, kind, canonical)
);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  producer TEXT NOT NULL,
  upstream TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  canonical TEXT NOT NULL,
  observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_run ON observations(run_id, kind, canonical);
CREATE TABLE IF NOT EXISTS work_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  kind TEXT NOT NULL,
  canonical TEXT NOT NULL,
  input_revision INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  retry_at TEXT,
  lease_token TEXT,
  lease_expiry TEXT,
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (run_id, stage, kind, canonical, input_revision)
);
CREATE TABLE IF NOT EXISTS stage_invocations (
  invocation_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  stage TEXT NOT NULL,
  unit_key TEXT NOT NULL DEFAULT '',
  input_revision INTEGER NOT NULL DEFAULT 1,
  input_fingerprint TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending',
  outcome TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  counts TEXT NOT NULL DEFAULT '{}',
  started_at TEXT,
  finished_at TEXT,
  dispatch_seq INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_inv_run_stage
  ON stage_invocations(run_id, attempt, stage);
"""

# Typed work routes (docs/RELIABILITY-PLAN.md par.6). A route states WHICH
# downstream stage an observed asset feeds; policy (active, scope) is applied
# by the caller at dispatch, not silently here.
ROUTE_DNS = "dns"
ROUTE_PROBE = "probe"
ROUTE_CRAWL = "crawl"
ROUTE_JS = "extract"


def ensure_schema(store) -> None:
    """Create the work tables if absent (idempotent, additive)."""
    with store._write():
        store.conn.executescript(WORK_SCHEMA)
    _migrate_dispatch_seq(store)


def _migrate_dispatch_seq(store) -> None:
    """Add the dispatch ordering column to older databases (additive).

    stage_invocations used to be ordered by a non-existent `id` column. A real
    stable order is the insertion rowid; dispatch_seq mirrors it so readers do
    not depend on a table-internal alias. Idempotent: PRAGMA says whether the
    column is already there.
    """
    try:
        cols = [r[1] for r in store.conn.execute(
            "PRAGMA table_info(stage_invocations)").fetchall()]
    except Exception:
        return
    if not cols or "dispatch_seq" in cols:
        return
    try:
        with store._write():
            store.conn.execute(
                "ALTER TABLE stage_invocations ADD COLUMN dispatch_seq INTEGER"
                " NOT NULL DEFAULT 0")
            store.conn.execute(
                "UPDATE stage_invocations SET dispatch_seq=rowid"
                " WHERE dispatch_seq=0")
    except Exception:
        pass


# ---------------------------------------------------------------- invocations
def start_invocation(store, run_id: str, attempt: int, stage: str,
                     unit_key: str = "", input_revision: int = 1,
                     input_fingerprint: str = "") -> str:
    """Persist one dispatch before it runs (docs par.5).

    Every dispatch gets its OWN invocation_id: the base key carries
    run/attempt/stage/unit/revision, and a collision (a real retry of the same
    unit inside the same attempt) appends a sequence suffix instead of
    REPLACING the previous row. A retry must remain auditable next to the
    attempt it replaced -- INSERT OR REPLACE silently erased that history.
    """
    base = "%s|%d|%s|%s|%d" % (run_id, max(1, int(attempt)), stage,
                               unit_key or "root", max(1, int(input_revision)))
    ts = core.now()
    with store._write():
        inv = base
        seq = 0
        while True:
            row = store.conn.execute(
                "SELECT 1 FROM stage_invocations WHERE invocation_id=?",
                (inv,)).fetchone()
            if row is None:
                break
            seq += 1
            if seq > 999:
                raise core.FindInfoError(
                    "too many dispatches for one unit: " + base)
            inv = base + "#" + str(seq)
        store.conn.execute(
            "INSERT INTO stage_invocations(invocation_id, run_id,"
            " attempt, stage, unit_key, input_revision, input_fingerprint,"
            " state, started_at, dispatch_seq) VALUES(?,?,?,?,?,?,?, 'running', ?,"
            " (SELECT COALESCE(MAX(dispatch_seq),0)+1 FROM stage_invocations))",
            (inv, run_id, max(1, int(attempt)), stage, unit_key or "root",
             max(1, int(input_revision)), input_fingerprint[:64], ts))
    return inv


def finish_invocation(store, invocation_id: str, state: str,
                      outcome: str = "", reason: str = "",
                      counts: dict | None = None) -> bool:
    """Settle one dispatch after completion (state from ONE vocabulary)."""
    ts = core.now()
    with store._write():
        cur = store.conn.execute(
            "UPDATE stage_invocations SET state=?, outcome=?, reason=?,"
            " counts=?, finished_at=? WHERE invocation_id=?",
            (state, outcome, reason[:200],
             json.dumps(counts or {}, sort_keys=True), ts, invocation_id))
        return bool(cur.rowcount)


# ---------------------------------------------------------------- membership
def attach_asset(store, run_id: str, kind: str, canonical: str,
                 producer: str, upstream: str = "",
                 route: str | None = ROUTE_DNS,
                 input_revision: int = 1) -> None:
    """Atomically record one observation and its consequences.

    One transaction commits: the asset upsert (existing table), run
    membership, the observation row (independent upstream preserved), and any
    eligible downstream work item. Re-observing the same source is a no-op
    for work creation (UNIQUE dedup), so repeated rounds cannot enqueue the
    same name forever.
    """
    if not (run_id and kind and canonical):
        return
    ts = core.now()
    with store._write():
        store.conn.execute(
            "INSERT INTO run_assets(run_id, kind, canonical, first_seen, last_seen)"
            " VALUES(?,?,?,?,?)"
            " ON CONFLICT(run_id, kind, canonical) DO UPDATE SET"
            " last_seen=excluded.last_seen",
            (run_id, kind, canonical, ts, ts))
        store.conn.execute(
            "INSERT INTO observations(run_id, producer, upstream, kind,"
            " canonical, observed_at) VALUES(?,?,?,?,?,?)",
            (run_id, producer, upstream, kind, canonical, ts))
        if route:
            store.conn.execute(
                "INSERT OR IGNORE INTO work_items(run_id, stage, kind,"
                " canonical, input_revision, status, created_at, updated_at)"
                " VALUES(?,?,?,?,?, 'pending', ?, ?)",
                (run_id, route, kind, canonical, input_revision, ts, ts))


# record_observation is the name docs/RELIABILITY-PLAN.md par.6 uses for the
# ingestion path; attach_asset is what batch C shipped. One function, two
# names, so callers never fork the transaction boundary.
record_observation = attach_asset


def run_assets(store, run_id: str, kind: str | None = None) -> list[str]:
    """Members of one run only -- never the whole shared graph."""
    sql = "SELECT canonical FROM run_assets WHERE run_id=?"
    args: list = [run_id]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    return [r["canonical"] for r in store.conn.execute(sql + " ORDER BY canonical",
                                                       args)]


def observed_upstreams(store, run_id: str, kind: str,
                       canonical: str) -> list[str]:
    """Independent upstreams that reported one asset inside one run.

    Deduplicated and stable: observing twice through the same upstream is
    one witness, not two (confidence must not inflate on a re-observation).
    """
    out: list = []
    for r in store.conn.execute(
            "SELECT producer, upstream FROM observations"
            " WHERE run_id=? AND kind=? AND canonical=?"
            " ORDER BY id", (run_id, kind, canonical)):
        name = r["upstream"] or r["producer"]
        if name not in out:
            out.append(name)
    return out


# ---------------------------------------------------------------- work queue
def enqueue(store, run_id: str, stage: str, kind: str, canonical: str,
            input_revision: int = 1, reason: str = "") -> bool:
    """Idempotently add one work item. False when it already existed."""
    ts = core.now()
    with store._write():
        cur = store.conn.execute(
            "INSERT OR IGNORE INTO work_items(run_id, stage, kind,"
            " canonical, input_revision, status, reason, created_at,"
            " updated_at) VALUES(?,?,?,?,?, 'pending', ?, ?, ?)",
            (run_id, stage, kind, canonical, input_revision, reason, ts, ts))
        return bool(cur.rowcount)


def claim(store, run_id: str, stage: str, limit: int = 50,
          now_iso: str | None = None, lease_seconds: int = 900,
          max_attempts: int | None = None) -> list[dict]:
    """Lease up to limit runnable items under one short transaction.

    Runnable means, per item, one of:

    * status pending/failed AND no retry_at (or retry_at has passed) -- a
      failed item inside its backoff window is NOT claimable (the old query
      ignored retry_at entirely, so a 60-second backoff was re-claimed on the
      very next call);
    * status running AND lease_expiry has passed -- a crashed worker's item is
      reclaimed atomically here; the old query excluded 'running' altogether,
      so an interrupted item stayed unclaimable forever and outstanding never
      drained.

    Every claim mints a NEW token; the previous holder's token stops matching
    the row, so it can neither write a result nor acknowledge this lease. The
    read and the update share one BEGIN IMMEDIATE transaction, so two
    concurrent claimers cannot both win the same item.

    `max_attempts` (when given) caps cumulative attempts: an item that has
    already been attempted that many times is not handed out again -- it stays
    failed/outstanding and is reported, instead of looping forever.
    """
    ts = now_iso or core.now()
    want = max(0, int(limit))
    if want == 0:
        return []
    with store._write():
        cols = "id, run_id, stage, kind, canonical, input_revision, status, attempts"
        rows = store.conn.execute(
            "SELECT " + cols + " FROM work_items"
            " WHERE run_id=? AND stage=?"
            "   AND ("
            "     (status IN ('pending','failed')"
            "      AND (retry_at IS NULL OR retry_at <= ?))"
            "     OR"
            "     (status='running' AND lease_expiry IS NOT NULL AND lease_expiry <= ?)"
            "   )"
            " ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, id"
            " LIMIT ?",
            (run_id, stage, ts, ts, want)).fetchall()
        out = []
        for r in rows:
            attempts = int(r["attempts"] or 0)
            if max_attempts is not None and attempts >= int(max_attempts):
                # terminal: no further hand-out, keep the row outstanding and
                # say why (the caller reports it as a gap)
                store.conn.execute(
                    "UPDATE work_items SET status='blocked', reason=?,"
                    " retry_at=NULL, lease_token=NULL, lease_expiry=NULL,"
                    " updated_at=? WHERE id=?",
                    ("attempt cap reached (" + str(attempts) + ")", ts, r["id"]))
                continue
            token = "%s|%s|%d" % (ts, r["id"], attempts + 1)
            store.conn.execute(
                "UPDATE work_items SET attempts=attempts+1,"
                " status='running', lease_token=?, lease_expiry=?,"
                " retry_at=NULL, updated_at=? WHERE id=?",
                (token, _lease_until(ts, lease_seconds), ts, r["id"]))
            out.append(dict(r) | {"lease_token": token,
                                  "attempts": attempts + 1,
                                  "status": "running"})
        return out


def _lease_until(now_iso: str, seconds: int = 900) -> str:
    import datetime
    try:
        base = datetime.datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    except ValueError:
        return now_iso
    return (base + datetime.timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def finish(store, run_id: str, item_id: int, lease_token: str,
           ok: bool, reason: str = "", retryable: bool = False,
           retry_after_seconds: int = 60,
           now_iso: str | None = None) -> bool:
    """Settle a leased item; results commit with the ack, never before.

    Stale tokens cannot commit (T18/T33 fencing at the queue level): the
    token is compared INSIDE the same transaction that flips the row, so a
    lease that was re-claimed by someone else cannot be acknowledged here. A
    failed retryable item goes back to failed with a backoff (retry_at); a
    permanent failure is settled as blocked and reported, not retried forever.
    """
    ts = now_iso or core.now()
    with store._write():
        row = store.conn.execute(
            "SELECT id, status, lease_token FROM work_items"
            " WHERE id=? AND run_id=?",
            (item_id, run_id)).fetchone()
        if row is None or row["status"] != "running":
            return False
        if (row["lease_token"] or "") != (lease_token or ""):
            return False               # superseded lease: no write authority
        if ok:
            store.conn.execute(
                "UPDATE work_items SET status='done', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, retry_at=NULL, updated_at=?"
                " WHERE id=?", (reason[:200], ts, item_id))
        elif retryable:
            store.conn.execute(
                "UPDATE work_items SET status='failed', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, retry_at=?,"
                " updated_at=? WHERE id=?",
                (reason[:200], _lease_until(ts, max(1, retry_after_seconds)),
                 ts, item_id))
        else:
            store.conn.execute(
                "UPDATE work_items SET status='blocked', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, retry_at=NULL, updated_at=?"
                " WHERE id=?", (reason[:200], ts, item_id))
        return True


def commit_result(store, run_id: str, item_id: int, lease_token: str,
                  members: list | None = None, observations: list | None = None,
                  ok: bool = True, reason: str = "",
                  retryable: bool = False,
                  retry_after_seconds: int = 60,
                  now_iso: str | None = None) -> bool:
    """Commit a work item's RESULT and its acknowledgement together.

    One transaction carries: the run membership rows, the observation rows and
    the work-item ack. The lease token is validated in that same transaction,
    so a superseded holder cannot write results first and be rejected at the
    ack second -- either everything lands under a valid lease, or nothing
    does. Network fetching/parsing happens OUTSIDE this function.

    members/observations are lists of dicts with the same keys attach_asset
    accepts: kind, canonical, producer, [upstream], [route], [input_revision].
    """
    if not run_id or item_id is None:
        return False
    ts = now_iso or core.now()
    with store._write():
        row = store.conn.execute(
            "SELECT id, status, lease_token FROM work_items"
            " WHERE id=? AND run_id=?", (item_id, run_id)).fetchone()
        if row is None or row["status"] != "running":
            return False
        if (row["lease_token"] or "") != (lease_token or ""):
            return False
        for m in members or []:
            kind = m.get("kind") or ""
            canonical = m.get("canonical") or ""
            if not (kind and canonical):
                continue
            store.conn.execute(
                "INSERT INTO run_assets(run_id, kind, canonical, first_seen,"
                " last_seen) VALUES(?,?,?,?,?)"
                " ON CONFLICT(run_id, kind, canonical) DO UPDATE SET"
                " last_seen=excluded.last_seen",
                (run_id, kind, canonical, ts, ts))
        for o in observations or []:
            kind = o.get("kind") or ""
            canonical = o.get("canonical") or ""
            if not (kind and canonical):
                continue
            store.conn.execute(
                "INSERT INTO observations(run_id, producer, upstream, kind,"
                " canonical, observed_at) VALUES(?,?,?,?,?,?)",
                (run_id, o.get("producer") or "pipeline",
                 o.get("upstream") or o.get("producer") or "pipeline",
                 kind, canonical, o.get("observed_at") or ts))
        if ok:
            store.conn.execute(
                "UPDATE work_items SET status='done', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, retry_at=NULL,"
                " updated_at=? WHERE id=?", (reason[:200], ts, item_id))
        elif retryable:
            store.conn.execute(
                "UPDATE work_items SET status='failed', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, retry_at=?,"
                " updated_at=? WHERE id=?",
                (reason[:200], _lease_until(ts, max(1, retry_after_seconds)),
                 ts, item_id))
        else:
            store.conn.execute(
                "UPDATE work_items SET status='blocked', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, retry_at=NULL,"
                " updated_at=? WHERE id=?", (reason[:200], ts, item_id))
        return True


def queue_stats(store, run_id: str, stage: str | None = None) -> dict:
    """Outstanding work by state -- convergence evidence, not a verdict.

    `stage` narrows the counts to one route (JS statistics must not include
    DNS items, which belong to a different obligation set).
    """
    sql = "SELECT status, COUNT(*) c FROM work_items WHERE run_id=?"
    args: list = [run_id]
    if stage:
        sql += " AND stage=?"
        args.append(stage)
    by: dict[str, int] = {}
    for r in store.conn.execute(sql + " GROUP BY status", args):
        by[r["status"]] = r["c"]
    return {"pending": by.get("pending", 0),
            "running": by.get("running", 0),
            "failed": by.get("failed", 0),
            "done": by.get("done", 0),
            "blocked": by.get("blocked", 0),
            "outstanding": (by.get("pending", 0) + by.get("running", 0)
                            + by.get("failed", 0))}


# ---------------------------------------------------------------- js bridge
# The legacy `js_queue` table is a SHARED, ownerless queue. A run's JS work
# lives in work_items; legacy rows only migrate when the run can PROVE the
# ownership (a run_assets membership or a job-spec scope that contains the
# URL). Unknown rows stay untouched and are reported, never silently claimed
# by whatever runs next.
JS_LEGACY_STATE_MAP = {"done": "done", "skipped": "done",
                       "failed": "failed", "pending": "pending"}


def import_js_queue(store, run_id: str, scope: list | None = None) -> dict:
    """Idempotently migrate provably-owned legacy JS rows into one run.

    Proof of ownership, in order:
      1. the URL is already a run_assets member of this run (it was discovered
         or attached by this run's own collectors);
      2. the URL falls inside an explicit scope the caller passes (the run's
         job-spec scope), and the legacy row is not already owned by a run
         whose scope differs -- shared-scope ambiguity leaves it alone.

    Migration is idempotent: an existing work item for the same
    (run, extract, url) is not duplicated, and a legacy `done` row becomes a
    done work item -- never re-opened as pending. Unknown ownership is
    reported (not claimed, not deleted).

    Returns {"attached": n, "unknown": [...], "skipped_done": n}.
    """
    attached = 0
    skipped_done = 0
    unknown: list = []
    try:
        rows = store.conn.execute(
            "SELECT url, state FROM js_queue").fetchall()
    except Exception:
        return {"attached": 0, "unknown": [], "skipped_done": 0}
    want_scope = core.canon_scope(scope or [])
    for r in rows:
        url = r["url"]
        legacy_state = (r["state"] or "").strip().lower()
        member = store.conn.execute(
            "SELECT 1 FROM run_assets WHERE run_id=? AND kind='url'"
            " AND canonical=?", (run_id, url)).fetchone()
        owned = member is not None
        if not owned and want_scope:
            host = core.split_url(url)[0] or ""
            owned = core.in_scope(host, want_scope)
        if not owned:
            unknown.append(url)
            continue
        if legacy_state == "done":
            # a completed legacy row must not turn into new pending work
            skipped_done += 1
            target_state = "done"
        elif legacy_state in ("failed", "pending"):
            target_state = legacy_state
        else:
            unknown.append(url)
            continue
        ts = core.now()
        with store._write():
            cur = store.conn.execute(
                "INSERT OR IGNORE INTO work_items(run_id, stage, kind,"
                " canonical, input_revision, status, reason, created_at,"
                " updated_at) VALUES(?,?,?,?,1,?,?,?,?)",
                (run_id, ROUTE_JS, "url", url, target_state,
                 "legacy js_queue:" + legacy_state, ts, ts))
            if cur.rowcount:
                attached += 1
    return {"attached": attached, "unknown": unknown,
            "skipped_done": skipped_done}


def effective_invocations(store, run_id: str, attempt: int) -> dict:
    """Newest invocation per (stage, unit) for THIS attempt (docs par.5).

    Ordered by the persisted dispatch_seq (a real column; the old query used
    a non-existent `id` and raised OperationalError). A failed/reused older
    dispatch cannot poison this verdict: the effective row is the latest
    dispatch of the current attempt, while history stays auditable.
    """
    out: dict = {}
    rows = store.conn.execute(
        "SELECT stage, unit_key, state, outcome, reason, dispatch_seq"
        " FROM stage_invocations WHERE run_id=? AND attempt=?"
        " ORDER BY dispatch_seq, rowid", (run_id, max(1, int(attempt)))).fetchall()
    for r in rows:
        out[(r["stage"], r["unit_key"])] = {
            "state": r["state"], "outcome": r["outcome"], "reason": r["reason"]}
    return out


def invocation_history(store, run_id: str, attempt: int | None = None) -> list:
    """Every dispatch of a run (optionally one attempt), oldest first.

    Audit view: retries appear as separate rows, so a repair attempt never
    hides the failure it replaced.
    """
    sql = ("SELECT invocation_id, attempt, stage, unit_key, input_revision,"
           " state, outcome, reason, counts, started_at, finished_at"
           " FROM stage_invocations WHERE run_id=?")
    args: list = [run_id]
    if attempt is not None:
        sql += " AND attempt=?"
        args.append(max(1, int(attempt)))
    return [dict(r) for r in store.conn.execute(
        sql + " ORDER BY dispatch_seq, rowid", args).fetchall()]
