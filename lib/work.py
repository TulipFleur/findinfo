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
  finished_at TEXT
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
          now_iso: str | None = None) -> list[dict]:
    """Lease up to limit runnable items under one short transaction.

    A leased item carries a token; only the token holder may finish it, and
    an expired lease makes the item claimable again (crashed worker). No
    network happens under the lock -- claiming only flips rows.
    """
    ts = now_iso or core.now()
    with store._write():
        rows = store.conn.execute(
            "SELECT * FROM work_items"
            " WHERE run_id=? AND stage=? AND status IN ('pending','failed')"
            "   AND (lease_expiry IS NULL OR lease_expiry <= ?)"
            " ORDER BY id LIMIT ?",
            (run_id, stage, ts, max(0, limit))).fetchall()
        out = []
        for r in rows:
            token = core.now() + "|" + str(r["id"]) + "|" + str(
                (r["attempts"] or 0) + 1)
            store.conn.execute(
                "UPDATE work_items SET attempts=attempts+1,"
                " status='running', lease_token=?, lease_expiry=?,"
                " updated_at=? WHERE id=?",
                (token, _lease_until(ts), ts, r["id"]))
            out.append(dict(r) | {"lease_token": token})
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
           ok: bool, reason: str = "", retryable: bool = False) -> bool:
    """Settle a leased item; results commit with the ack, never before.

    Stale tokens cannot commit (T18/T33 fencing at the queue level). A
    failed retryable item goes back to pending with a backoff; a permanent
    failure is settled and reported, not retried forever.
    """
    ts = core.now()
    with store._write():
        row = store.conn.execute(
            "SELECT id, status FROM work_items WHERE id=? AND run_id=?"
            " AND lease_token=?",
            (item_id, run_id, lease_token)).fetchone()
        if row is None or row["status"] != "running":
            return False
        if ok:
            store.conn.execute(
                "UPDATE work_items SET status='done', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, updated_at=?"
                " WHERE id=?", (reason[:200], ts, item_id))
        elif retryable:
            store.conn.execute(
                "UPDATE work_items SET status='failed', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, retry_at=?,"
                " updated_at=? WHERE id=?",
                (reason[:200], _lease_until(ts, 60), ts, item_id))
        else:
            store.conn.execute(
                "UPDATE work_items SET status='blocked', reason=?,"
                " lease_token=NULL, lease_expiry=NULL, updated_at=?"
                " WHERE id=?", (reason[:200], ts, item_id))
        return True


def queue_stats(store, run_id: str) -> dict:
    """Outstanding work by state -- convergence evidence, not a verdict."""
    by: dict[str, int] = {}
    for r in store.conn.execute(
            "SELECT status, COUNT(*) c FROM work_items WHERE run_id=?"
            " GROUP BY status", (run_id,)):
        by[r["status"]] = r["c"]
    return {"pending": by.get("pending", 0),
            "running": by.get("running", 0),
            "failed": by.get("failed", 0),
            "done": by.get("done", 0),
            "blocked": by.get("blocked", 0),
            "outstanding": (by.get("pending", 0) + by.get("running", 0)
                            + by.get("failed", 0))}


# ---------------------------------------------------------------- js bridge
def import_js_queue(store, run_id: str) -> int:
    """One-time import of legacy JS rows into the run queue (T33).

    Only rows whose run membership can be PROVED attach silently; the legacy
    table has no owner, so rows attach only when the run's own summary
    already references them. Unknown ownership is left untouched -- never
    silently attached to a different run (docs par.6).
    """
    rows = store.conn.execute("SELECT url FROM js_queue").fetchall()
    attached = 0
    for r in rows:
        url = r["url"]
        # Proof of ownership: the run's own URL assets include this url and
        # the run's run_assets has that asset as a member.
        hit = store.conn.execute(
            "SELECT 1 FROM run_assets ra JOIN assets a"
            "  ON a.kind='url' AND a.canonical=ra.canonical"
            " WHERE ra.run_id=? AND ra.kind='url' AND a.canonical=?",
            (run_id, url)).fetchone()
        if hit and enqueue(store, run_id, ROUTE_JS, "url", url):
            attached += 1
    return attached
