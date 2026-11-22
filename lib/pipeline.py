"""The `run` pipeline: stage order, checkpoints, rounds and the final verdict.

Moved out of findinfo.py, which keeps the CLI (argument parsing, the other
subcommands, background launch and resume) and re-exports these names so
`findinfo.X` keeps working for callers and tests.

Module rule: no import-time state derived from HOME or the task. lib.core
resolves those when it is imported and the tests reload it in place, so this
module reaches core/tools/work/... through the module object at call time.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from . import core, jobs, tools, work
from . import mapdispatch
from . import mapping as mapping_mod
from . import metered as metered_mod


def out(obj) -> None:
    """One JSON line on stdout (same contract as findinfo.out)."""
    core.emit(obj)


def _active_enabled(args) -> bool:
    """--ports/--vhost/--crawl/--brute imply --active, as --help documents."""
    return bool(args.active or args.ports or args.vhost or args.crawl or args.brute)


# ---------------------------------------------------------------- long tasks
ENGAGEMENT = "default"


# status.json is written from two threads (pipeline + heartbeat) and, for a
# background job, by exactly one worker process. lib.jobs owns the file format,
# the cross-process lock and the monotonic seq counter, so both paths (foreground
# and worker) produce the same observable state.
def _input_hash(obj) -> str:
    return hashlib.sha1(json.dumps(obj, sort_keys=True, ensure_ascii=False)
                        .encode("utf-8", "replace")).hexdigest()[:16]


def _write_status(run_dir: Path, **kw) -> None:
    """Publish progress for whoever polls this run (status / wait).

    Inside a background worker every status write is FENCED: the launch token
    is read once from the spec (worker_main publishes it to the environment
    before the pipeline starts), and stage progress, heartbeats and the final
    verdict all pass through the same check. A superseded attempt can no
    longer overwrite the newer attempt's state (F05) -- the old path called
    update_state() directly, so the pipeline bypassed the fence entirely.
    Foreground runs have no token and keep the plain write.
    """
    fields = {k: v for k, v in kw.items() if k != "run_id"}
    token = os.environ.get("FINDINFO_LAUNCH_TOKEN") or ""
    try:
        if token:
            ok = jobs.fenced_write(run_dir, token, **fields)
            if not ok:
                core.log("status write refused: this attempt's launch token "
                         "is no longer current")
            return
        jobs.update_state(run_dir, **fields)
    except Exception as exc:            # a status write must never kill a stage
        core.log("status write failed: " + repr(exc)[:200])


class _Heartbeat:
    """Touch status.json every 30s for as long as a stage runs.

    Without it a stage that legitimately takes >5 minutes (big dns/naabu
    runs) stops updating status.json and `findinfo.py status` misjudges the
    process as dead. The thread is a daemon and stops on stage end, so a
    process that crashes leaves the timestamp stale -- exactly the signal
    `alive` needs.
    """

    def __init__(self, run_dir: Path, name: str):
        self._run_dir = run_dir
        self._name = name
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        n = 0
        while not self._stop.wait(30):
            n += 1
            _write_status(self._run_dir, stage=self._name, beat=n)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def _stage(store, run_dir, summary, name, inputs, args, fn, entry_fn, resume=None):
    """Run one pipeline stage with heartbeat + checkpoint.

    Returns (ok_executed, result):
      (True,  fn())     stage executed successfully (checkpoint "done")
      (False, partial)  stage failed at the tool level AFTER producing partial
                        output (checkpoint "failed"; a re-run retries it)
      (True,  resume()) checkpoint hit for identical inputs: skipped, and the
                        downstream input is rebuilt from the scoped store

    `inputs` must contain every parameter that changes the result (seeds,
    engine lists, budgets): changed inputs change the hash and re-run the
    stage. A failed stage never writes "done", so re-runs retry it.

    Every dispatch also lands in work.stage_invocations (before and after
    execution, docs par.5): one row per (run, attempt, stage, unit) so a
    retry or a later round can never overwrite the previous dispatch's
    state. Work-context failures fall back to the old behaviour (the stage
    itself is still executed and checkpointed) -- an ingestion bookkeeping
    error must never stop collection.
    """
    ih = _input_hash(inputs)
    rid = summary.get("_run_public_id") or ""
    attempt = int(summary.get("attempt") or 1)
    inv = None
    if rid:
        try:
            inv = work.start_invocation(store, rid, attempt, name,
                                        unit_key=str(inputs.get("round") or
                                                      summary.get("_stage_unit") or "root"),
                                        input_revision=summary.get("_input_revision") or 1,
                                        input_fingerprint=ih)
        except Exception as exc:
            core.log("invocation start failed for " + name + ": " + repr(exc)[:160])
    if not getattr(args, "force_stage", False) and store.step_done(ENGAGEMENT, name, ih):
        res = resume() if resume else None
        core.log("stage " + name + " skipped (done for these inputs; --force-stage to redo)")
        summary["stages"].append({"stage": name, "skipped": True,
                                  "resumed": res is not None})
        if inv:
            try:
                work.finish_invocation(store, inv, "succeeded", "reused",
                                        "checkpoint_hit")
            except Exception:
                pass
        _write_status(run_dir, stage=name, stage_state="skipped",
                      stage_index=len(summary["stages"]),
                      stage_total=max(int(summary.get("_stage_total") or 0),
                                      len(summary["stages"])))
        return True, res
    t0 = time.time()
    core.log("stage " + name + " start")
    _write_status(run_dir, stage=name, stage_state="running", stage_started=core.now())
    beat = _Heartbeat(run_dir, name)
    try:
        res = fn()
    except core.StageError as exc:
        beat.stop()
        store.set_step(ENGAGEMENT, name, ih, "failed")
        # Keep the failure class in the same vocabulary as success paths so
        # coverage can be derived (a timeout is not the same as a hard failure).
        _err = str(exc)
        _is_timeout = ("timeout" in _err.lower()) or ("rc=124" in _err)
        _oc = core.OUTCOME_TIMEOUT if _is_timeout else core.OUTCOME_FAILED
        entry = {"stage": name, "failed": True, "error": _err[:300],
                 "elapsed": round(time.time() - t0, 1),
                 "outcome": _oc, "status": "failed (timeout)" if _oc == core.OUTCOME_TIMEOUT
                 else "failed"}
        if isinstance(exc.result, dict):
            entry.update({k: v for k, v in exc.result.items()
                          if isinstance(v, (int, float, str, bool))})
        summary["stages"].append(entry)
        if inv:
            try:
                work.finish_invocation(store, inv, "failed", _oc, _err[:200])
            except Exception:
                pass
        _write_status(run_dir, stage=name, stage_state="failed", error=str(exc)[:500])
        core.log("stage " + name + " FAILED (recorded; re-run will retry): " + str(exc)[:200])
        _write_status(run_dir, stage_index=len(summary["stages"]),
                      stage_total=max(int(summary.get("_stage_total") or 0),
                                      len(summary["stages"])))
        return False, exc.result
    except Exception:
        beat.stop()
        _write_status(run_dir, stage=name, stage_state="failed",
                      error="unexpected failure")
        raise
    beat.stop()
    entry = {"stage": name, "elapsed": round(time.time() - t0, 1)}
    entry.update(entry_fn(res) or {})
    # Stage status comes from ONE vocabulary (see core.OUTCOME_*), so result,
    # coverage and next_steps can be derived instead of re-interpreted.
    entry.setdefault("outcome", core.OUTCOME_OK)
    _oc = entry.get("outcome")
    entry["status"] = ("succeeded" if _oc in (core.OUTCOME_OK, core.OUTCOME_EMPTY,
                                             core.OUTCOME_UNAVAILABLE)
                       else ("budget" if _oc == core.OUTCOME_BUDGET else "partial"))
    # The checkpoint decides whether a re-run may SKIP this stage. Writing
    # "done" for a partial stage meant a later run skipped it forever, so the
    # half-collected part could never be completed -- the agent saw a green
    # checkpoint on work that explicitly reported itself as incomplete.
    # Partial/budget runs therefore checkpoint as "partial": still usable
    # (downstream stages read the store, not the checkpoint), but re-runnable.
    _cp = ("done" if entry["status"] == "succeeded"
           else "partial" if entry["status"] in ("partial", "budget")
           else "failed")
    store.set_step(ENGAGEMENT, name, ih, _cp)
    summary["stages"].append(entry)
    if inv:
        try:
            _inv_state = ("succeeded" if entry["status"] == "succeeded"
                          else "partial")
            work.finish_invocation(store, inv, _inv_state, _oc or "",
                                   counts={k: entry.get(k) for k in
                                           ("found", "resolved", "live", "urls")
                                           if isinstance(entry.get(k), (int, float))})
        except Exception:
            pass
    _write_status(run_dir, stage=name, stage_state="done", elapsed=entry["elapsed"],
                  stage_index=len(summary["stages"]),
                  stage_total=max(int(summary.get("_stage_total") or 0),
                                  len(summary["stages"])),
                  counts=summary.get("counts") or None)
    return True, res


# ---------------------------------------------------------------- full pipeline
# Domains proven "resolved" by these collectors -- the dns stage's output is
# rebuilt from the store with this set when a checkpoint skip resumes the run.
_DNS_SOURCES = frozenset(("dnsx", "system-dns", "ksubdomain", "httpx"))


def _attach(store, summary, kind, canonical, producer, upstream="", route=None):
    """Record one observation into the run's own membership tables.

    Failure here never stops a stage: the collector already stored the asset;
    the membership/observation rows are bookkeeping the run's reflow and
    reports read. A broken bookkeeping write must not throw away the data.
    """
    rid = summary.get("_run_public_id") or ""
    if not rid:
        return
    try:
        work.attach_asset(store, rid, kind, canonical,
                          producer=producer or "pipeline",
                          upstream=upstream or producer or "pipeline",
                          route=route)
    except Exception as exc:
        core.log("attach failed for " + str(canonical) + ": " + repr(exc)[:160])


def _adopt_membership(store, summary, scope, min_conf: float = 0.0) -> int:
    """Reconcile membership with what THIS run's collectors actually stored.

    Round inputs come from run_assets, but the collectors upsert into the
    shared asset graph through Store.upsert_asset, which predates the work
    tables. This helper closes that gap WITHOUT inventing evidence (F07):

    * a domain whose `sources` column names a producer THIS run ran (dnsx,
      httpx, subfinder, katana, onepass, ...) joins the membership -- the run
      really did observe it;
    * membership only: NO new observation row and NO refreshed timestamp are
      written here, so a historical asset is never presented as a fresh
      observation;
    * an asset that exists only because of an EARLIER run (its sources name
      none of this run's producers) is attached as an explicitly-marked
      reuse: attached_at now, original observed_at preserved, and the reason
      recorded -- never as a current pipeline observation.
    """
    rid = summary.get("_run_public_id") or ""
    if not rid or not scope:
        return 0
    producers = set(summary.get("_run_producers") or ())
    adopted = 0
    try:
        rows = store.get_assets(kind="domain", min_conf=min_conf, match=scope)
    except Exception:
        return 0
    ts = core.now()
    for a in rows:
        canonical = a.get("canonical") or ""
        if not canonical:
            continue
        sources = core.source_tools(a.get("sources") or "")
        by_this_run = bool(sources & producers) if producers else False
        try:
            with store._write():
                cur = store.conn.execute(
                    "INSERT OR IGNORE INTO run_assets(run_id, kind, canonical,"
                    " first_seen, last_seen) VALUES(?,?,?,?,?)",
                    (rid, "domain", canonical, ts, ts))
                if not cur.rowcount:
                    continue
                adopted += 1
                if by_this_run:
                    # this run's own collector already wrote the observation;
                    # membership is enough, no synthetic evidence needed
                    pass
                else:
                    store.conn.execute(
                        "INSERT INTO observations(run_id, producer, upstream,"
                        " kind, canonical, observed_at) VALUES(?,?,?,?,?,?)",
                        (rid, "reuse", "reuse:run_membership", "domain",
                         canonical, ts))
        except Exception:
            continue
    return adopted


# ---------------------------------------------------------------- run: helpers
def _worker_run_dir():
    """Run dir handed down by lib.jobs.worker_main (background worker only).

    Without this the worker would create a second, unrelated run dir and the
    parent's state file would never see the stages finish.
    """
    raw = os.environ.get("FINDINFO_RUN_DIR") or ""
    if raw:
        p = Path(raw)
        if p.is_dir():
            return p
    return None


def _round_plan(args, active) -> list:
    plan = ["dns"]
    if active:
        plan.append("probe")
        plan.append("ipagg")
        if args.ports:
            plan.append("ports")
        if args.vhost:
            plan.append("vhost")
        if args.crawl:
            plan += ["crawl", "extract"]
    return plan


def _plan_stages(args, active) -> list:
    """The stages this run intends to execute.

    A stage the caller explicitly disabled is NOT planned -- putting it here and
    then reporting it as "not run" would tell the agent to fill a gap it was
    told to leave alone (e.g. --no-icp producing "resume with icp").
    """
    plan = []
    if args.name:
        plan.append("entity")
    if not getattr(args, "no_onepass", False):
        plan.append("onepass")
    plan += ["certs", "subs"]
    if active and getattr(args, "brute", False):
        plan.append("brute")
    # The mapping stage owns EVERY paid question: one per seed domain and one
    # per filing number. A run always has at least one seed (a domain is
    # required), so the stage is always planned unless explicitly disabled --
    # `--no-mapping` is the opt-out, not "no brand given".
    if not getattr(args, "no_mapping", False):
        plan.append("mapping")
    return plan + _round_plan(args, active)


def _engine_key(engine: str) -> bool:
    """Whether the mapping engine has a usable credential.

    Delegates to core.engine_has_key so the coverage report and the uncover
    gating in lib/tools.py can never disagree about which engines are usable.
    """
    return core.engine_has_key(engine)


def _coverage_unavailable(args, active) -> dict:
    """Which capabilities were missing, and whether that blocks the plan.

    Missing optional sources (an engine without a key) are a coverage gap, not
    a failure: the run continues on whatever is available. Missing a tool the
    planned stages need IS blocking, and is reported as such instead of being
    disguised as "found nothing".
    """
    need = ["dnsx", "subfinder"]
    if not getattr(args, "no_onepass", False):
        need.append("onepass")
    if active:
        need.append("httpx")
    if active and getattr(args, "ports", False):
        need.append("naabu")
    if active and getattr(args, "vhost", False):
        need.append("hostCollision")
    if active and getattr(args, "crawl", False):
        need.append("katana")
    if getattr(args, "brute", False):
        need.append("ksubdomain")
    missing = [t for t in need if not core.has_tool(t)]
    # only a TOOL the planned stages needed can block them; a missing optional
    # collector downgrades coverage instead (a source that is down while the
    # pipeline still produced results is a gap, not a blocked run)
    blocking = [t for t in missing if t in _BLOCKING_TOOLS]
    engines = [e.strip() for e in (args.engines or "").split(",") if e.strip()]
    no_key = [e for e in engines if not _engine_key(e)]
    return {
        "missing_tools": missing,
        "blocking_tools": blocking,
        "engines_without_key": no_key,
        "blocking": bool(blocking),
        "note": ("required tools missing: " + ",".join(blocking)) if blocking else
                (("optional tools missing: " + ",".join(missing)) if missing else ""),
    }


def _subs_stage_inputs(seeds: list, engines: str) -> dict:
    """Checkpoint identity of the subs stage.

    The usable-engine set is part of it on purpose: adding a mapping key must
    re-run this stage instead of hitting a checkpoint written when the engine
    had no key (which recorded "unavailable"). The question each usable engine
    is asked is part of it too, so a corrected query re-runs a stage that asked
    the old one. It is added only when an engine will be asked, so a keyless
    checkpoint keeps its old identity and nothing re-runs for nothing.
    """
    usable, _ = core.split_engines(engines)
    inputs = {"seeds": seeds, "engines": engines, "usable_engines": usable}
    queries = core.uncover_query_identity("domain", usable)
    if queries:
        inputs["queries"] = queries
    return inputs


def _subs_stage_entry(r: dict) -> dict:
    """The summary entry of a finished subs stage.

    Project the OUTCOME, not just the count: _subs merged the per-source
    outcomes through core.combine_outcome, and the stage entry defaulted it to
    OUTCOME_OK. A partial run (one engine timed out, the rest answered) was
    then written as "succeeded" and checkpointed "done", so a later run skipped
    the stage forever while half the sources never answered. The engine gaps
    travel along for _fold_runtime_unavailable.
    """
    entry = {"found": r["found"],
             "outcome": r.get("outcome") or core.OUTCOME_OK,
             "sources": len(r.get("per_source") or [])}
    if r.get("quota_exhausted"):
        entry["quota_exhausted"] = True
    for key in ("unconfirmed_empty", "unsupported_engines"):
        if r.get(key):
            entry[key] = list(r[key])
    return entry


def _fold_runtime_unavailable(unavailable: dict, stages: list,
                               blocked_engines: list | None = None) -> dict:
    """Add gaps that only become known while the run is executing.

    A source whose quota runs out mid-engagement must show up as a coverage
    gap. Left in the stage payload nobody reads it, and the source then looks
    like it simply "found nothing" -- the exact confusion this project forbids.

    The typed engine verdict comes from the metered ledger (blocked_engines:
    quota/auth on the LAST request, docs par.10) -- not from a stage payload
    flag alone: a partial stage entry can drop it, and the ledger is the
    per-request record the stage answer cannot contradict.
    """
    hits = [st.get("stage") or "subs" for st in stages
            if isinstance(st, dict) and st.get("quota_exhausted")]
    blocked = sorted(set(blocked_engines or []))

    def _listed(key: str) -> list:
        return sorted({str(x) for st in stages if isinstance(st, dict)
                       for x in (st.get(key) or [])})

    # An engine that answered nothing through uncover cannot be told apart
    # from one whose upstream errored (uncover reports both as rc=0, no rows),
    # and an engine with no known query was never asked at all. Both are
    # gaps the stage outcome alone hides.
    unconfirmed = _listed("unconfirmed_empty")
    unsupported = _listed("unsupported_engines")
    # An upstream that holds more rows than one page budget returned
    # (onepass reports it per source): the rest exists, it was not fetched.
    capped = _listed("truncated_sources")
    if not hits and not blocked and not unconfirmed and not unsupported and not capped:
        return unavailable
    out = dict(unavailable)
    if hits:
        names = sorted(set(hits))
        out["quota_exhausted"] = names
    if blocked:
        out["blocked_engines"] = blocked
    if unconfirmed:
        out["unconfirmed_empty"] = unconfirmed
    if unsupported:
        out["unsupported_engines"] = unsupported
    if capped:
        out["truncated_sources"] = capped
    parts: list = []
    if hits:
        parts.append("quota exhausted during run: " + ",".join(sorted(set(hits))))
    if blocked:
        parts.append("engines blocked (quota/auth): " + ",".join(blocked))
    if unconfirmed:
        parts.append("no rows from " + ",".join(unconfirmed) + " (unconfirmed: "
                     "uncover reports an upstream error the same way)")
    if unsupported:
        parts.append("engines not asked, no known query: " + ",".join(unsupported))
    if capped:
        parts.append("upstream answers capped, more rows exist than were fetched: "
                     + ",".join(capped))
    note = out.get("note") or ""
    out["note"] = (note + "; " if note else "") + "; ".join(parts)
    return out


# Stages that publish a summary line but collect nothing on their own: they are
# never a coverage gap, so they must not appear in "not_run_stages".
_INFORMATIONAL_STAGES = frozenset(("ipagg",))


# Tools whose absence genuinely blocks a planned stage. Everything else the run
# can live without (it only lowers coverage), so it must not turn a run that
# produced results into "failed/blocked".
_BLOCKING_TOOLS = frozenset(("dnsx",))


def _not_run_stages(planned: list, stages: list) -> list:
    """Planned stages with no effective execution -- the real gaps.

    Rules (each one is a bug that used to make an agent loop forever):

    * Checkpoint hit  -> covered, regardless of whether the stage supplied a
      resume() callback. Before this, entity/onepass/certs/subs/brute/icp/
      ports/vhost/crawl/extract were reported as "not run" on every second run
      because they only set skipped=True. A completed stage is not a gap.
    * skipped + reason == "no_input" -> not a gap either: the stage had nothing
      to chew on (probe with zero resolved hosts). Its reason is surfaced
      separately as no_input, not as "you must re-run this".
    * skipped + a real failure reason (no_hosts is not a failure; anything
      prefixed "failed"/"error") -> a gap.
    * A stage absent from the run entirely -> a gap.
    """
    def _state(name: str) -> str:
        rows = [s for s in stages if s.get("stage") == name]
        if not rows:
            return "absent"
        # A failed stage also carries elapsed -- check failure FIRST, or a
        # crashed stage would be counted as succeeded and vanish from coverage.
        if any(r.get("failed") for r in rows):
            return "failed"
        if any("elapsed" in r for r in rows):
            return "succeeded"
        if any(r.get("skipped") for r in rows):
            why = str(([r for r in rows if r.get("skipped")][0].get("reason") or "")).lower()
            if "no_input" in why or "no_hosts" in why:
                return "no_input"
            if why.startswith("failed") or why.startswith("error"):
                return "failed"
            return "checkpoint_hit"
        return "absent"

    gaps = []
    for name in planned:
        if name in _INFORMATIONAL_STAGES:
            continue
        # A stage that RAN and failed is reported through failed_stages. Listing
        # it here as well made an agent see the same stage twice under two
        # different headings and "not_run" stopped meaning "never attempted".
        if _state(name) == "absent":
            gaps.append(name)
    return sorted(set(gaps))


def _current_attempt() -> int:
    """Which attempt this process is executing.

    The worker knows its attempt (it was written into job.json by _start_background
    / _resume_run). A foreground run has no job spec, so it is attempt 1. The
    number is stamped into summary.jsonl so a later reader can tell "this
    result belongs to attempt N" from "this is a leftover from attempt N-1".
    """
    raw = os.environ.get("FINDINFO_ATTEMPT") or ""
    if raw.isdigit():
        return int(raw)
    return 1


@dataclasses.dataclass
class RunContext:
    """What one run's stages share: they used to be _run_pipeline's locals.

    The pipeline-only private keys of `summary` (_ledger, the approved subject
    references/names, the identity verdict) live here now. `summary` keeps
    `_run_public_id`, `_run_producers` and `_stage_total`: _stage, _attach and
    _adopt_membership read them from the summary they are handed.
    """
    args: Any
    store: Any
    run_id: Any
    run_dir: Path
    summary: dict
    active: bool
    attempt: int
    target_label: str
    planned: list
    ledger: Any
    rounds: int
    time_budget: float
    tool_timeout: int
    max_seed: int
    t_start: float
    # seed phase
    domains: list = dataclasses.field(default_factory=list)
    icp_codes: list = dataclasses.field(default_factory=list)
    named: list = dataclasses.field(default_factory=list)
    seeds: list = dataclasses.field(default_factory=list)
    scope: list = dataclasses.field(default_factory=list)
    approved_refs: list = dataclasses.field(default_factory=list)
    approved_names: list = dataclasses.field(default_factory=list)
    identity_ambiguous: dict | None = None
    # rounds
    round_no: int = 0
    # Per-name resolution record, kept for the whole run so round N+1 does
    # not re-query what round N already answered. NXDOMAIN is final; a
    # transient failure stays open and is retried (once per round).
    dns_states: dict = dataclasses.field(default_factory=dict)
    # Names a certificate named this round; merged into the next round's
    # dns input so a SAN is verified instead of merely recorded.
    cert_queue: set = dataclasses.field(default_factory=set)
    dns_hosts: list = dataclasses.field(default_factory=list)
    ipagg: dict = dataclasses.field(default_factory=dict)
    rounds_log: list = dataclasses.field(default_factory=list)
    stop_reason: str = ""


def _scoped_rows(ctx: RunContext, min_conf: float):
    return ctx.store.get_assets(kind="domain", min_conf=min_conf, match=ctx.scope)


def _scoped_domains(ctx: RunContext, min_conf: float) -> list:
    return [a["canonical"] for a in _scoped_rows(ctx, min_conf)]


def _dns_resumed(ctx: RunContext) -> dict:
    hosts = [a["canonical"] for a in _scoped_rows(ctx, 0.4)
             if core.source_tools(a.get("sources") or "") & _DNS_SOURCES]
    return {"resolved": len(hosts), "hosts": hosts, "resumed": True}


def _prepare_run(args, store, max_seed: int) -> RunContext:
    """Open the run: ids, run dir, ledger, budgets and the first status frame."""
    active = _active_enabled(args)
    attempt = _current_attempt()
    summary: dict = {"engagement": ENGAGEMENT, "active": active, "stages": [],
                     "attempt": attempt}
    target_label = args.name or (",".join(args.domain) if args.domain else "?")
    run_id = store.start_run(ENGAGEMENT, target_label)
    run_dir = _worker_run_dir() or core.new_run_dir(target_label)
    # Work tables key on the PUBLIC run-directory id (the one every command
    # prints), never the legacy integer runs.id.
    summary["_run_public_id"] = run_dir.name
    summary["run_dir"] = str(run_dir)
    # Which collectors THIS run actually ran. Membership reconciliation uses
    # this to tell "this run observed it" from "an earlier run left it in the
    # shared graph"; the latter is only ever a marked reuse (F07).
    summary["_run_producers"] = ["seed:user", "dnsx", "system-dns", "doh",
                                 "ksubdomain", "httpx", "katana",
                                 "onepass", "enscan", "fofa-gateway",
                                 "subfinder", "chaos", "uncover", "naabu",
                                 "hostCollision", "tls-grab"]
    # Per-request ledger for every billed provider call (batch F): the file
    # lives in the run dir, so a later session reads the spend without the
    # process that incurred it. Collectors receive it as `ledger=` and record
    # one row per REQUEST (never per result row).
    ledger = metered_mod.MeteredLedger(path=run_dir / "metered.jsonl",
                                       run_id=run_dir.name)
    rounds = max(1, int(getattr(args, "rounds", 1) or 1))
    time_budget = float(getattr(args, "time_budget", 0) or 0)
    tool_timeout = int(getattr(args, "tool_timeout", 0) or 0)
    planned = _plan_stages(args, active)
    summary["planned_stages"] = planned
    summary["_stage_total"] = len(planned)
    summary["rounds_requested"] = rounds
    t_start = time.monotonic()
    _write_status(run_dir, stage="prepare", state="running", stage_state="running",
                  target=target_label, run_id=run_id, active=active,
                  # scope is a recovery field: a new session must be able to
                  # answer "what was actually collected" from status alone, so
                  # the foreground path publishes it exactly like the
                  # background path does (it used to stay null here).
                  scope=core.canon_scope(args.domain or []),
                  planned_stages=planned, stage_index=0, stage_total=len(planned),
                  started_ts=jobs.now_ts(), rounds=rounds,
                  budget={"rounds": rounds, "time_budget_sec": time_budget})
    return RunContext(args=args, store=store, run_id=run_id, run_dir=run_dir,
                      summary=summary, active=active, attempt=attempt,
                      target_label=target_label, planned=planned, ledger=ledger,
                      rounds=rounds, time_budget=time_budget,
                      tool_timeout=tool_timeout, max_seed=max_seed,
                      t_start=t_start)


def _stage_entity(ctx: RunContext) -> None:
    """1. entity: ENScan anchoring (or the engines asked by NAME), then the
    approved subject references every later seed step reads."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    tool_timeout = ctx.tool_timeout
    def _entity():
        # ENScan pages through aiqicha with a per-request delay; with a
        # deep query it can wait indefinitely. Bound it (default 20 min,
        # --entity-timeout) so the run cannot hang forever: on timeout
        # the partial result is kept and the stage is retried later.
        entity_timeout = int(getattr(args, "entity_timeout", 1200) or 0)
        r = tools.t_enscan(store, args.name, invest=args.invest, deep=args.deep,
                           outdir=run_dir / "enscan", timeout=entity_timeout,
                           supplier=getattr(args, "supplier", False),
                           branch=getattr(args, "branch", False))
        if r.get("rc") == 124:
            raise core.StageError(
                "enscan timed out after " + str(entity_timeout) + "s",
                result={"companies": len(r.get("companies", [])),
                        "icp": len(r.get("icp", [])),
                        "domains": len(r.get("domains", []))})
        if r.get("anchor_failed") and not getattr(args, "no_mapping", False):
            # ENScan could NOT anchor the target (aiqicha has no such
            # keyword, or answered with lookalikes only). The operator's
            # rule: do not stop here -- the NAME is still the best
            # search value we have, so ask the internet engines for the
            # company's main domain and let the normal seed path take
            # over from whatever comes back.
            #
            # This is deliberately NOT a StageError: failing the stage
            # left the agent with "enscan did not match" and nothing to
            # run, which is exactly the dead end the rule removes. The
            # engine answer is recorded as the stage result, with the
            # probe's own status so a total failure is still visible.
            _probe = mapdispatch.resolve_by_name(
                store, summary.get("_run_public_id") or "",
                args.name, engines=getattr(args, "engines", None),
                remap=bool(getattr(args, "remap", False)),
                timeout=tool_timeout or 0,
                ledger=ctx.ledger)
            r = dict(r)
            r["name_probe"] = _probe
            r["domains"] = list(_probe.get("domains") or [])
            r["companies"] = []
            # The seed step reads domains from the STORE by subject
            # reference, so the engine answer must land there -- with a
            # name-derived reference, since ENScan supplied none.
            if r["domains"]:
                _ref = "name:" + str(args.name).strip()
                for _d in r["domains"]:
                    try:
                        # 0.9: the seed step reads approved
                        # subjects' domains at that floor, and this
                        # IS an engine-confirmed answer for the
                        # anchored name (not a scraped guess).
                        store.upsert_asset(
                            "domain", _d, source="mapping:name",
                            confidence=0.9, passivity="passive",
                            parent=_ref)
                    except Exception:
                        continue
                r["subjects"] = [{"ref": _ref,
                                  "legal_name": str(args.name).strip(),
                                  "approved": True,
                                  "domains": len(r["domains"])}]
            _dbg = ("enscan could not anchor '" + str(args.name) +
                    "'; asked the mapping engines by NAME instead -> " +
                    str(len(r["domains"])) + " domain(s) from " +
                    str(_probe.get("answered") or 0) + " engine(s)")
            core.log(_dbg)
            if not r["domains"] and not _probe.get("answered"):
                # No engine could even be asked: that IS a gap, and the
                # agent must see why (no key / refused credential).
                r["outcome"] = core.OUTCOME_UNAVAILABLE
                r["unavailable_sources"] = list(
                    (_probe.get("skipped_engines") or [])[:5])
            # fall through: the normal seed step below uses r["domains"]
        if r.get("rc") not in (0, None) and not r.get("json_files"):
            # rc != 0 with no JSON used to fail the stage outright. But
            # ENScan can print a complete report table and still not
            # write the JSON (observed on a deep test-company query: 35 KB of
            # tables, zero files), and it can also die while wrapping up.
            # Neither is "the entity was not found": report the real
            # shape -- table seen, JSON missing -- and let the stage
            # record a coverage gap instead of a red failure.
            msg = ("enscan rc=" + str(r.get("rc")) + " no output files" +
                   (" (report table printed, JSON missing)" if r.get("table_only") else ""))
            raise core.StageError(
                msg,
                result={"companies": 0, "icp": 0, "domains": 0,
                        "table_only": bool(r.get("table_only"))})
        # Subject gate (docs par.8, T06): a brand that matches MORE
        # than one plausible legal subject is ambiguous. Without an
        # explicit --domain seed the run must stop and ask, never
        # guess a company and probe the wrong target. With a seed the
        # brand is context only and the gate passes.
        verdict = tools.resolve_entity_identity(
            raw=args.name,
            candidates=[{"name": c, "id": c} for c in
                        (r.get("companies") or [])],
            explicit_domains=list(args.domain or []))
        if verdict.get("status") == "identity_ambiguous":
            ctx.identity_ambiguous = {
                "brand": args.name,
                "candidates": (r.get("companies") or [])[:10],
                "next_steps": verdict.get("next_steps") or []}
            raise core.StageError(
                "identity_ambiguous: brand '" + str(args.name) +
                "' matches " + str(len(r.get("companies") or [])) +
                " plausible subjects (" +
                ", ".join((r.get("companies") or [])[:3]) +
                "); " + "; ".join(verdict.get("next_steps") or []),
                result={"companies": len(r.get("companies") or []),
                        "icp": 0, "domains": 0,
                        "identity_ambiguous": True,
                        "subject_candidates": (r.get("companies") or [])[:10]})
        return r
    _entity_inputs = {"name": args.name, "invest": args.invest,
                      "deep": args.deep}
    for _flag in ("no_mapping", "remap"):
        if getattr(args, _flag, False):
            _entity_inputs[_flag] = True
    _ok_entity, _entity_res = _stage(
        store, run_dir, summary, "entity",
        _entity_inputs,
        args, _entity,
        lambda r: {"companies": len(r.get("companies", [])),
                   "icp": len(r.get("icp", [])),
                   "domains": len(r.get("domains", []))},
        resume=lambda: {"companies": [], "icp": [], "domains": []})
    # Persist the APPROVED subject references for this run: the seed
    # step below, a resumed attempt and the durable anchor all read
    # them, so an alias/legal-name mismatch can never drop the seeds
    # (F10) and unapproved entities are never swept in (F06).
    if isinstance(_entity_res, dict) and _entity_res.get("subjects"):
        approved_refs = [s.get("ref") for s in
                         (_entity_res.get("subjects") or [])
                         if s.get("ref")]
    else:
        # checkpoint hit (or a resumed attempt): the entity stage did
        # not run, so read the anchors THIS run already published
        approved_refs = list(
            (jobs.read_state(run_dir) or {}).get(
                "approved_subject_refs") or [])
    ctx.approved_refs = approved_refs
    approved_names = []
    if isinstance(_entity_res, dict):
        _raw_names = _entity_res.get("companies")
        if isinstance(_raw_names, (list, tuple)):
            approved_names = [str(x) for x in _raw_names if x]
        elif isinstance(_raw_names, str) and _raw_names:
            approved_names = [_raw_names]
    if not approved_names:
        # checkpoint hit: reuse the anchors this run published earlier
        approved_names = list((jobs.read_state(run_dir) or {}).get(
            "approved_company_names") or [])
    if not approved_refs and not approved_names and args.name:
        # LEGACY COMPATIBILITY. An existing task's entity checkpoint
        # predates subject references, so neither the run state nor the
        # stage result names an approved subject -- yet the store's
        # company rows (and their domain parents) are the anchor the
        # earlier run approved with this exact name. Recover ONLY the
        # companies the anchor gate itself would keep for this name; a
        # company that does not match is not silently adopted.
        try:
            _stored = [a["canonical"] for a in
                       store.get_assets(kind="company")]
        except Exception:
            _stored = []
        # Prefer an EXACT normalised match (the real anchor); only if
        # there is none fall back to the tolerant name matcher, and
        # only when it yields exactly one candidate.
        _norm = {tools.norm_entity_name(args.name)}
        _exact = [c for c in _stored
                  if tools.norm_entity_name(c) in _norm]
        _pick = _exact
        if not _pick:
            _pick, _ = tools.filter_entities(_stored, args.name)
        if len(_pick) == 1:
            approved_names = [str(x) for x in _pick[:1]]
            core.log("entity checkpoint predates subject refs; "
                     "recovered the approved company anchor: " +
                     approved_names[0])
    ctx.approved_names = approved_names
    if approved_refs or approved_names:
        _write_status(run_dir, approved_subject_refs=approved_refs,
                      approved_company_names=approved_names)


def _collect_seed_domains(ctx: RunContext) -> None:
    """Seeds from the caller's --domain values, then from the approved subjects."""
    args, store, summary = ctx.args, ctx.store, ctx.summary
    domains, icp_codes = ctx.domains, ctx.icp_codes
    if args.domain:
        # User-typed input: canon_user_domain validates INTENT (private
        # TLDs like .local, bare IPs, IDN -> punycode are all legitimate
        # targets). The strict canon_domain de-noiser used to sit here and
        # silently threw 127.0.0.1:18765 / *.test / dev.corp.local away.
        for d in args.domain:
            # An IP:port / endpoint target is NOT silently reduced to its
            # host: the current pipeline cannot carry an explicit port
            # through to a collection stage, and dropping the port then
            # reporting "no seeds" hides what the caller actually asked
            # for (F12). Report the limit and stop.
            _endpoint_of = getattr(tools, "endpoint_of", None)
            if _endpoint_of is not None:
                _ip, _port = _endpoint_of(d)
            else:
                _ip, _port = None, None
            if _ip and _port:
                raise core.FindInfoError(
                    "unsupported_target_kind: '" + str(d) + "' is an "
                    "IP:port endpoint target; this build's run path has no "
                    "endpoint collection stage (the port would be dropped "
                    "silently). Pass the bare IP '" + str(_ip) + "' or a "
                    "domain instead, and probe the port with the disabled "
                    "active stages once supported.")
            cd = core.canon_user_domain(d)
            if not cd:
                raise core.FindInfoError(
                    "invalid domain: " + str(d) +
                    " (user input is never dropped silently; fix the value "
                    "or drop the flag explicitly)")
            domains.append(cd)
    if args.name:
        # Seeds come from the APPROVED SUBJECT's assets, looked up through
        # the subject reference -- never by parent == the search string.
        # An alias or legal name that differs from the query is therefore
        # not lost (F10), and an unapproved entity's assets are not swept in
        # because their parent happens to be the brand text (F06).
        subject_refs = ctx.approved_refs or []
        ref_set = set(subject_refs)
        for a in store.get_assets(kind="domain", min_conf=0.9):
            parent = a.get("parent") or ""
            if parent in ref_set:
                domains.append(a["canonical"])
                _attach(store, summary, "domain", a["canonical"],
                        producer="entity", upstream="enscan",
                        route=work.ROUTE_DNS)
        for a in store.get_assets(kind="icp"):
            parent = a.get("parent") or ""
            if parent in ref_set:
                icp_codes.append(a["canonical"])
                _attach(store, summary, "icp", a["canonical"],
                        producer="entity", upstream="enscan", route=None)
        if not subject_refs:
            # Compatibility: a collector that predates subject references
            # (an injected adapter, an older ENScan build) only returns
            # `companies` and stores domains with parent=<name>. Accept
            # that ONLY when exactly one company was approved -- with two
            # or more candidates the assets cannot be attributed and the
            # run must not guess (F06).
            approved_names = ctx.approved_names or []
            if len(approved_names) == 1:
                _only = approved_names[0]
                for a in store.get_assets(kind="domain", min_conf=0.9):
                    if (a.get("parent") or "") == _only and \
                            a["canonical"] not in domains:
                        domains.append(a["canonical"])
                        _attach(store, summary, "domain", a["canonical"],
                                producer="entity", upstream="enscan",
                                route=work.ROUTE_DNS)
                for a in store.get_assets(kind="icp"):
                    if (a.get("parent") or "") == _only and \
                            a["canonical"] not in icp_codes:
                        icp_codes.append(a["canonical"])
                        _attach(store, summary, "icp", a["canonical"],
                                producer="entity", upstream="enscan",
                                route=None)


def _finish_identity_ambiguous(ctx: RunContext) -> int:
    """docs par.8: a brand that matched several subjects launches no traffic."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    active, attempt, target_label = ctx.active, ctx.attempt, ctx.target_label
    run_id, t_start = ctx.run_id, ctx.t_start
    # docs par.8: launch NO downstream traffic on a guessed subject.
    # The gap is already recorded on the failed entity stage; skipping
    # straight to the verdict keeps every downstream stage out of
    # not_run (the run was never supposed to run them) while the
    # result carries the input-required next steps.
    summary["identity_ambiguous"] = ctx.identity_ambiguous
    summary["planned_stages"] = ["entity"]
    summary["_stage_total"] = 1
    coverage = {
        "planned_stages": ["entity"],
        "done_stages": [],
        "skipped_stages": [],
        "failed_stages": [
            {"stage": s["stage"], "error": s.get("error"),
             "elapsed": s.get("elapsed")}
            for s in summary["stages"] if s.get("failed")],
        "partial_stages": [],
        "not_run_stages": [],
        "unavailable": _coverage_unavailable(args, active),
        "identity_ambiguous": True,
        "subject_candidates": summary["identity_ambiguous"]["candidates"],
        "next_steps": summary["identity_ambiguous"]["next_steps"],
        "stage_states": {"entity": "failed"},
        "disabled_stages": [x for x in ("entity", "onepass", "icp", "brute")
                            if x != "entity"],
        "js_queue": {}, "work_queue": {}, "complete": False,
    }
    summary["counts"] = store.count_assets()
    summary["coverage"] = coverage
    summary["result"] = {
        "status": "partial", "reason": "identity_ambiguous",
        "run_id": run_dir.name, "attempt": attempt,
        "target": target_label, "scope": [], "active": False,
        "counts": summary["counts"], "endpoints": 0,
        "elapsed_sec": round(time.monotonic() - t_start, 1),
        "next_steps": summary["identity_ambiguous"]["next_steps"],
        "artifacts": {"summary": str(run_dir / "summary.jsonl"),
                      "state": str(run_dir / "status.json"),
                      "stdout_log": str(run_dir / "stdout.log"),
                      "stderr_log": str(run_dir / "stderr.log"),
                      "spec": str(run_dir / "job.json")},
    }
    for _private in ("_run_producers", "_run_public_id"):
        summary.pop(_private, None)
    core.write_jsonl(run_dir / "summary.jsonl", [summary])
    store.finish_run(run_id, summary)
    # Same rule as the normal tail: the worker owns a background
    # job's terminal state; a foreground run publishes its own.
    _terminal = {}
    if _worker_run_dir() is None:
        _terminal = {"state": "completed", "exit_code": 5}
    _write_status(run_dir, stage="done",
                  stage_state="done", counts=summary["counts"],
                  result=summary["result"], coverage=coverage,
                  stage_index=1, stage_total=1, **_terminal)
    out(summary)
    return 5


def _fix_seed_scope(ctx: RunContext) -> None:
    """Order the seeds, store them as user input, and fix the active scope."""
    args, store, summary = ctx.args, ctx.store, ctx.summary
    domains, max_seed = ctx.domains, ctx.max_seed
    # Explicit seeds come first, followed by the approved entity anchors.
    # By default every seed is expanded; an explicit positive --max-seed
    # opts into a breadth budget while preserving this priority order.
    named = [core.canon_domain(d) for d in (args.domain or [])]
    named = [d for d in named if d]
    discovered = [d for d in domains if d not in named]
    domains = core.canon_scope(named + discovered)
    summary["seed_domains"] = domains
    if not domains:
        # The operator's rule: when ENScan anchors a real company but this
        # source filed NO domain, the run must not just die -- it must tell
        # the agent WHAT to search the internet engines for. A bare
        # "no seed domain" left the agent with nothing to act on, and the
        # anchored company (the one asset we DID establish) was thrown away.
        _anchor_names = list(ctx.approved_names or [])
        if _anchor_names:
            _cands = [n for n in _anchor_names if n][:5]
            _queries = ['icp="' + n + '"' for n in _cands] +                            ['domain="' + n + '"' for n in _cands]
            raise core.SeedDomainRequired(
                "enscan anchored " + str(len(_cands)) + " subject(s) " +
                ", ".join(_cands) + " but no source filed a domain for " +
                "them; the company is real, its domain set is empty here",
                candidates=_cands, queries=_queries,
                hint=("search the company name on the mapping engines "
                      "before seeding: python findinfo.py map --<kind> "
                      "<value> (icp / domain), then re-run with "
                      "--domain <what comes back>"))
        raise core.SeedDomainRequired(
            "no seed domain and no anchored subject; give --domain or "
            "check ENScan output",
            hint="give --domain <domain> (repeatable) to seed the run")
    # Explicit seeds are USER INPUT, not evidence. They must reach the DNS
    # stage even when every passive source returns nothing -- otherwise
    # "this domain has no subdomains" silently skips the target the user
    # actually asked about. Stored with a seed-only source id so it is
    # visibly unverified until dns/probe produce real evidence.
    for d in domains:
        store.upsert_asset("domain", d, source="seed:user", confidence=0.5,
                           passivity="passive", parent=d)
        _attach(store, summary, "domain", d, producer="seed:user",
                upstream="seed:user", route=work.ROUTE_DNS)
    seeds = domains[:max_seed] if max_seed else list(domains)
    if max_seed and len(named) > max_seed:
        core.log("notice: " + str(len(named)) + " named domains but --max-seed " +
                 str(args.max_seed) + "; only the first " + str(args.max_seed) +
                 " get onepass/certs/subs/brute (use --max-seed 0 for all)")

    # ACTIVE SCOPE MODEL: only what the caller asked for (--domain args plus
    # the company anchor's ENScan domains) is actively probed. Assets merely
    # DISCOVERED on the way are stored and reported, never auto-probed.
    scope = domains
    summary["scope"] = scope

    if len(seeds) < len(domains):
        summary["coverage_limits"] = {
            "seeds_total": len(domains), "seeds_scanned": len(seeds),
            "reason": "--max-seed budget (passive collection breadth); "
                      "DNS/probe still cover every seed"}
    ctx.named, ctx.domains, ctx.seeds, ctx.scope = named, domains, seeds, scope


def _stage_onepass(ctx: RunContext) -> None:
    """1.5 onepass (15-source passive aggregation, Rust binary)."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    seeds = ctx.seeds
    def _onepass():
        total = 0
        src_errors = 0
        outcomes = []
        capped: set = set()
        for d in seeds:
            r = tools.t_onepass(store, d)
            total += r["count"]
            src_errors += r.get("sources_error") or 0
            outcomes.append(r.get("outcome") or core.OUTCOME_OK)
            capped.update(r.get("truncated_sources") or [])
        oc = core.combine_outcome(*outcomes)
        res = {"found": total, "sources_error": src_errors, "outcome": oc}
        if capped:
            # surfaced through coverage.unavailable: an upstream that
            # holds more rows than came back is not "all there is"
            res["truncated_sources"] = sorted(capped)
        # A run where every upstream failed must not be checkpointed as
        # "done": the same inputs would then be skipped forever and the
        # agent would keep seeing an empty asset graph with no reason.
        if oc in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT):
            raise core.StageError("onepass: " + oc + " (" +
                                  str(src_errors) + " source errors)", result=res)
        return res
    _stage(store, run_dir, summary, "onepass", {"seeds": seeds}, args, _onepass,
           lambda r: {"found": r["found"], "sources_error": r["sources_error"],
                      "outcome": r.get("outcome")} |
           ({"truncated_sources": r["truncated_sources"]}
            if r.get("truncated_sources") else {}))


def _stage_certs(ctx: RunContext) -> None:
    """2. certificate transparency."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    seeds, tool_timeout = ctx.seeds, ctx.tool_timeout
    def _certs():
        total = 0
        failed: list = []
        for d in seeds:
            r = tools.t_certs(store, d, timeout=tool_timeout)
            total += r["count"]
            if not r.get("ok", True):
                failed.append(d)
        res = {"found": total, "failed_seeds": failed}
        if failed:
            raise core.StageError(
                "certs unreachable for " + ",".join(failed), result=res)
        return res
    _stage(store, run_dir, summary, "certs", {"seeds": seeds}, args, _certs,
           lambda r: {"found": r["found"], "failed_seeds": r.get("failed_seeds", [])})


def _stage_subs(ctx: RunContext) -> None:
    """3. passive subdomains."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    seeds, tool_timeout = ctx.seeds, ctx.tool_timeout
    def _subs():
        total = 0
        quota = False
        outcomes = []
        per_source: list = []
        unconfirmed: set = set()
        unsupported: set = set()
        for d in seeds:
            r = tools.t_subs(store, d, engines=args.engines,
                             timeout=tool_timeout, ledger=ctx.ledger)
            total += r["count"]
            quota = quota or bool(r.get("quota_exhausted"))
            outcomes.append(r.get("outcome") or core.OUTCOME_OK)
            per_source.extend(r.get("per_source") or [])
            unconfirmed.update(r.get("unconfirmed_empty") or [])
            unsupported.update(r.get("unsupported_engines") or [])
        oc = core.combine_outcome(*outcomes)
        res = {"found": total, "outcome": oc, "per_source": per_source}
        if quota:
            # surfaced through coverage.unavailable, never as "no assets"
            res["quota_exhausted"] = True
        if unconfirmed:
            res["unconfirmed_empty"] = sorted(unconfirmed)
        if unsupported:
            res["unsupported_engines"] = sorted(unsupported)
        # subfinder + uncover both dead used to return a clean count=0 and
        # checkpoint "done". That is the difference between "this domain has
        # no subdomains" and "we never actually asked".
        # failed and timeout share this branch: neither may be
        # checkpointed as done, or a stage that only ran out of time would
        # be skipped forever and the stage would look empty, not slow.
        if oc in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT):
            raise core.StageError(
                "subs: " + oc + " (" +
                ",".join(sorted({p.get("id", "?") for p in per_source
                                 if p.get("outcome") in (core.OUTCOME_FAILED,
                                                         core.OUTCOME_TIMEOUT)})) + ")",
                result=res)
        return res
    # usable engines and the query each is asked are both part of the
    # checkpoint identity (see _subs_stage_inputs)
    _stage(store, run_dir, summary, "subs",
           _subs_stage_inputs(seeds, args.engines),
           args, _subs, _subs_stage_entry)


def _stage_brute(ctx: RunContext) -> None:
    """3.5 brute force (active, raw socket)."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    seeds, tool_timeout = ctx.seeds, ctx.tool_timeout
    def _brute():
        total = 0
        failed: list = []
        for d in seeds:
            r = tools.t_brute(store, d, wordlist=args.brute_wordlist,
                              bandwidth=args.brute_bandwidth, timeout=tool_timeout)
            total += r["count"]
            if not r.get("ok", True):
                failed.append(d)
        res = {"found": total, "failed_seeds": failed}
        if failed and not total:
            raise core.StageError("ksubdomain rc!=0 for " + ",".join(failed),
                                  result=res)
        return res
    _stage(store, run_dir, summary, "brute",
           {"seeds": seeds, "wordlist": args.brute_wordlist,
            "bandwidth": args.brute_bandwidth}, args, _brute,
           lambda r: {"found": r["found"], "failed_seeds": r.get("failed_seeds", [])})


def _stage_mapping(ctx: RunContext) -> None:
    """4. mapping: the only stage that spends mapping quota."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    named, scope, icp_codes = ctx.named, ctx.scope, ctx.icp_codes
    tool_timeout = ctx.tool_timeout
    # One question per (engine, domain seed) and per (engine, filing main
    # number); the task ledger decides whether it was already paid for, so
    # a second run, a later seed or a standalone `map` never asks twice.
    # Every other stage (certs/subs/dns/probe/...) is keyless: their
    # children get no credential at all (core.run strips them).
    _map_engines = args.engines
    _remap = bool(getattr(args, "remap", False))

    def _mapping():
        _seed_values = list(dict.fromkeys(list(named) + list(scope)))
        dom = mapdispatch.ask_all(
            store, summary["_run_public_id"], "domain", _seed_values,
            engines=_map_engines, remap=_remap, timeout=tool_timeout,
            ledger=ctx.ledger)
        icp = {"dispatched": 0, "reused": 0, "failures": [],
               "truncated_sources": [], "skipped_engines": [],
               "results": []}
        if icp_codes and not getattr(args, "no_icp", False):
            icp = mapdispatch.ask_all(
                store, summary["_run_public_id"], "icp", icp_codes,
                engines=_map_engines, remap=_remap, timeout=tool_timeout,
                ledger=ctx.ledger)
        all_results = list(dom.get("results") or []) + \
            list(icp.get("results") or [])
        stored = mapdispatch.store_results(store, all_results)
        # Attach what the mapping learned to THIS run's membership --
        # including rows that were REUSED from an earlier run (original
        # observation time preserved by the ledger).
        for kind, val in all_results:
            _attach(store, summary, kind, val, producer="mapping",
                    upstream="mapping", route=None)
        failures = list(dom.get("failures") or []) + \
            list(icp.get("failures") or [])
        truncated = sorted(set(list(dom.get("truncated_sources") or []) +
                               list(icp.get("truncated_sources") or [])))
        skipped = list(dom.get("skipped_engines") or []) + \
            list(icp.get("skipped_engines") or [])
        res = {
            "domains": stored.get("domain", 0),
            "ips": stored.get("ip", 0),
            "dispatched": int(dom.get("dispatched") or 0) +
                          int(icp.get("dispatched") or 0),
            "reused": int(dom.get("reused") or 0) +
                      int(icp.get("reused") or 0),
            "failures": len(failures),
            "truncated_sources": truncated,
            "unsupported_engines": sorted({s["engine"] for s in skipped
                                           if "syntax" in
                                           str(s.get("reason") or "")}),
        }
        # An engine that answered nothing cannot be told apart from one
        # whose upstream errored (uncover reports both as rc=0 + no
        # rows). Surface it as a coverage gap, exactly as the engine
        # tables intend -- silence here would read as "no assets".
        _unconfirmed = sorted({
            "uncover:" + str(f.get("engine"))
            for f in failures
            if str(f.get("status") or "") in (metered_mod.ST_EMPTY,
                                             metered_mod.ST_OK)})
        if _unconfirmed:
            res["unconfirmed_empty"] = _unconfirmed
        # A missing key / unknown syntax is a CAPABILITY GAP (docs: an
        # absent optional credential must not become exit 5).
        _usable_engines, _ = mapdispatch.engines_for("domain",
                                                   _map_engines)
        if not _usable_engines:
            res["outcome"] = core.OUTCOME_UNAVAILABLE
            res["unavailable_sources"] = sorted(
                {str(x.get("reason") or "")[:60] for x in skipped})[:5]
            return res
        # An EMPTY answer is a VALID answer ("this engine knows
        # nothing about the seed"), not a failure: only a transport or
        # auth fault on every available engine fails the stage.
        _hard = [f for f in failures
                 if str(f.get("status") or "") not in
                 (metered_mod.ST_EMPTY, metered_mod.ST_OK,
                  metered_mod.ST_TRUNCATED)]
        if _hard and not all_results and len(_hard) >= len(_usable_engines or []):
            raise core.StageError(
                "mapping failed on every available engine",
                result=res)
        return res

    _stage(store, run_dir, summary, "mapping",
           {"seeds": list(named) + list(scope),
            "codes": ([] if getattr(args, "no_icp", False)
                      else list(icp_codes)),
            "engines": args.engines, "remap": _remap},
           args, _mapping,
           lambda r: {k: r[k] for k in
                      ("domains", "ips", "dispatched", "reused",
                       "failures", "truncated_sources",
                       "unsupported_engines",
                       "unconfirmed_empty") if k in r} |
           ({"unavailable_sources": r["unavailable_sources"]}
            if r.get("unavailable_sources") else {}))


def _stage_dns(ctx: RunContext) -> None:
    """Resolve the round's names: membership, scope, named seeds, cert SANs."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    scope, named, round_no = ctx.scope, ctx.named, ctx.round_no
    tool_timeout, dns_states, cert_queue = ctx.tool_timeout, ctx.dns_states, ctx.cert_queue
    # Round input = the run's OWN membership (run_assets), not the
    # shared graph re-scoped on the fly (T08/T11): a sibling run of
    # the same root used to feed the resolver thousands of foreign
    # names. Members come from what this run observed/adopted; the
    # union with scope/named keeps explicit seeds resolvable even
    # when no source answered yet (they were attached at seed time).
    member_domains = set(work.run_assets(store, summary["_run_public_id"],
                                         "domain"))
    # EVERY member at any confidence, plus the user-named seeds. DNS
    # costs no quota, and the 0.4 floor that gates the active stages
    # (probe/crawl) used to gate this one too: a name a passive source
    # mentioned once at 0.1 was never resolved, so a real asset stayed
    # invisible for the sake of a threshold that protects nothing
    # here. The confidence floor stays where it belongs -- on the
    # stages that send traffic to the target.
    all_domains = sorted(member_domains | set(scope) | set(named) |
                         set(cert_queue))

    def _dns():
        r = tools.t_dns(store, all_domains, timeout=tool_timeout,
                        states=dns_states)
        res = {"resolved": r["count"], "wildcard": len(r.get("wildcard", [])),
               "truncated": r.get("truncated", False),
               "queried": r.get("queried", 0),
               "nxdomain": r.get("nxdomain", 0),
               "transient": r.get("transient", 0),
               "skipped_nxdomain": r.get("skipped_nxdomain", 0),
               "fake_ip_dropped": r.get("fake_ip_dropped", 0),
               "resolution": r.get("resolution") or {}}
        if not r.get("ok", True):
            raise core.StageError("dnsx rc=" + str(r.get("rc")), result=res)
        return res
    # Lease and settle the run's own dns work items around the stage
    # call (durable queue, T08/T10): the claim/finish pair wraps BOTH
    # the executed and the checkpoint-skip path, so an item enqueued
    # by seed attachment cannot stay pending merely because the stage
    # was skipped for identical inputs.
    _dns_claimed = []
    try:
        _dns_claimed = work.claim(store, summary["_run_public_id"],
                                  work.ROUTE_DNS, limit=100000)
    except Exception as exc:
        core.log("dns work claim failed: " + repr(exc)[:160])
    _stage(store, run_dir, summary, "dns",
           {"domains": all_domains, "round": round_no}, args, _dns,
           lambda r: {"resolved": r["resolved"], "wildcard": r["wildcard"],
                      "nxdomain": r.get("nxdomain", 0),
                      "transient": r.get("transient", 0),
                      "skipped_nxdomain": r.get("skipped_nxdomain", 0)},
           resume=lambda: _dns_resumed(ctx))
    for _item in _dns_claimed:
        try:
            work.finish(store, summary["_run_public_id"],
                        _item["id"], _item["lease_token"],
                        ok=True, reason="round settled")
        except Exception:
            pass
    # Whatever dnsx/the system resolver just accepted becomes this
    # run's membership (compatibility seam: collectors write to the
    # shared graph; membership records whose reflow reads it).
    for host in _dns_resumed(ctx)["hosts"]:
        _attach(store, summary, "domain", host, producer="dns",
                upstream="dns", route=None)
    _adopt_membership(store, summary, scope)
    # probe input is ALWAYS the full scoped store set (every resolved
    # row), never the ROW_LIMIT-truncated display list a tool returned
    dns_hosts = _dns_resumed(ctx)["hosts"]
    summary["dns_hosts"] = len(dns_hosts)
    ctx.dns_hosts = dns_hosts


def _stage_probe(ctx: RunContext) -> None:
    """Liveness and fingerprint of the resolved hosts; certificate names reflow."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    scope, round_no, tool_timeout = ctx.scope, ctx.round_no, ctx.tool_timeout
    cert_queue, dns_hosts = ctx.cert_queue, ctx.dns_hosts
    if dns_hosts:
        def _probe():
            p = tools.t_httpx(store, dns_hosts, timeout=tool_timeout,
                              scope=scope)
            # Certificate names are how a host reveals the rest of its
            # family: in-scope names join next round's dns queue,
            # out-of-scope ones are kept as related assets (part
            # p4-ip-cert owns that storage).
            for ent in p.get("cert_in_scope") or []:
                cert_queue.add(ent["host"])
                store.upsert_asset("domain", ent["host"],
                                   source="cert-san", confidence=0.45,
                                   passivity="passive", parent=ent["host"])
                _attach(store, summary, "domain", ent["host"],
                        producer="cert-san", upstream="cert-san",
                        route=work.ROUTE_DNS)
            for ent in p.get("cert_related") or []:
                store.upsert_asset("domain", ent["host"],
                                   source="cert-related", confidence=0.3,
                                   passivity="passive", parent=ent["host"])
                _attach(store, summary, "domain", ent["host"],
                        producer="cert-related", upstream="cert-related",
                        route=None)
                if ent.get("source"):
                    store.link_asset("domain", ent["source"], "cert-related",
                                     ent["host"], source="cert-san")
            summary.setdefault("cert_names", {"in_scope": 0, "related": 0})
            summary["cert_names"]["in_scope"] += len(p.get("cert_in_scope") or [])
            summary["cert_names"]["related"] += len(p.get("cert_related") or [])
            res = {"live": p["count"], "truncated": p.get("truncated", False),
                   "cert_in_scope": len(p.get("cert_in_scope") or []),
                   "cert_related": len(p.get("cert_related") or [])}
            if not p.get("ok", True):
                raise core.StageError("httpx rc=" + str(p.get("rc")), result=res)
            return res
        _stage(store, run_dir, summary, "probe",
               {"hosts": dns_hosts, "round": round_no}, args, _probe,
               lambda r: {"live": r["live"],
                          "cert_in_scope": r.get("cert_in_scope", 0),
                          "cert_related": r.get("cert_related", 0)},
               resume=lambda: {"live": len(dns_hosts)})
    else:
        summary["stages"].append({"stage": "probe", "skipped": True,
                                  "reason": "no_hosts"})
        _write_status(run_dir, stage="probe", stage_state="skipped")


def _stage_ipagg(ctx: RunContext) -> None:
    """Group the scope's IPs; the candidates feed ports and vhost."""
    store, run_dir, summary, scope = ctx.store, ctx.run_dir, ctx.summary, ctx.scope
    ipa = tools.t_ipagg(store, scope=scope)
    summary["stages"].append({"stage": "ipagg",
                              "candidates": ipa["count_candidates"]})
    _write_status(run_dir, stage="ipagg", stage_state="done",
                  stage_index=len(summary["stages"]),
                  stage_total=summary["_stage_total"])
    ctx.ipagg = ipa


def _stage_ports(ctx: RunContext) -> None:
    """naabu over the shared-IP candidates (or the scope's IPs)."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    scope, round_no, tool_timeout, ipa = ctx.scope, ctx.round_no, ctx.tool_timeout, ctx.ipagg
    cand_ips = [c["ip"] for c in ipa["candidates"]] or \
        [a["canonical"] for a in store.get_assets(kind="ip", match=scope)]
    _write_status(run_dir, stage="ports", stage_state="running")

    def _ports():
        pr = tools.t_ports(store, cand_ips, top_ports=args.top_ports,
                           timeout=tool_timeout)
        res = {"open": pr["count"]}
        if not pr.get("ok", True):
            raise core.StageError("naabu rc=" + str(pr.get("rc")), result=res)
        return res
    _stage(store, run_dir, summary, "ports",
           {"ips": cand_ips, "top_ports": args.top_ports, "round": round_no},
           args, _ports, lambda r: {"open": r["open"]})


def _stage_vhost(ctx: RunContext) -> None:
    """Host-header collision on the candidate IPs."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    round_no, tool_timeout, ipa = ctx.round_no, ctx.tool_timeout, ctx.ipagg
    _write_status(run_dir, stage="vhost", stage_state="running")
    vhost_ips = [c["ip"] for c in ipa["candidates"][: args.max_vhost_ips]]
    vhost_hosts = sorted({d for c in ipa["candidates"] for d in c["domains"]}
                         | set(_scoped_domains(ctx, 0.4)))

    def _vhost():
        hits = 0
        failed = 0
        for cand_ip in vhost_ips:
            vr = tools.t_vhost(store, cand_ip, vhost_hosts,
                               ports=[80, 443, 8080, 8443], timeout=tool_timeout)
            hits += vr["hits"]
            if not vr.get("ok", True):
                failed += 1
        res = {"hits": hits, "ips_failed": failed}
        if failed == len(vhost_ips) and vhost_ips:
            raise core.StageError("hostCollision failed on every candidate ip",
                                  result=res)
        return res
    _stage(store, run_dir, summary, "vhost",
           {"ips": vhost_ips, "hosts": vhost_hosts,
            "budget": args.max_vhost_ips, "round": round_no}, args, _vhost,
           lambda r: {"hits": r["hits"], "ips_failed": r.get("ips_failed", 0)})


def _stage_crawl(ctx: RunContext) -> None:
    """katana over the live URLs, bounded by the crawl ceiling."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    scope, round_no, tool_timeout = ctx.scope, ctx.round_no, ctx.tool_timeout
    _write_status(run_dir, stage="crawl", stage_state="running")
    crawl_urls = []
    for a in _scoped_rows(ctx, 0.7):
        attrs = a.get("attrs") or {}
        if attrs.get("url"):
            crawl_urls.append(attrs["url"])
    crawl_scope = sorted(set(scope) | set(_scoped_domains(ctx, 0.7)))

    def _crawl():
        if not crawl_urls:
            return {"urls": 0, "dropped_out_of_scope": 0}
        # Crawl needs its own ceiling: with -d 3 over thousands of
        # live hosts, katana can stream URLs for well over an hour
        # (observed: 57+ min and still going). A bounded run keeps
        # the job from hanging forever; whatever it collected stays
        # checkpointed and the gap is reported, not silently lost.
        crawl_timeout = tool_timeout or int(
            (core.CFG.get("limits") or {}).get("crawl_timeout") or 2700)
        cr = tools.t_crawl(store, crawl_urls, depth=args.depth,
                           scope_domains=crawl_scope, timeout=crawl_timeout)
        if cr.get("rc") == 124:
            core.log("crawl: hit the " + str(crawl_timeout) +
                     "s ceiling; keeping " + str(cr.get("count", 0)) +
                     " collected URLs and reporting the gap")
        res = {"urls": cr["count"],
               "dropped_out_of_scope": cr.get("dropped_out_of_scope", 0)}
        if not cr.get("ok", True):
            raise core.StageError("katana rc=" + str(cr.get("rc")), result=res)
        return res
    _stage(store, run_dir, summary, "crawl",
           {"urls": crawl_urls, "depth": args.depth, "scope": crawl_scope,
            "round": round_no}, args, _crawl,
           lambda r: {"urls": r["urls"],
                      "dropped_out_of_scope": r.get("dropped_out_of_scope", 0)})


def _stage_extract(ctx: RunContext) -> None:
    """JS/page leak extraction through this run's durable work queue."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    scope, round_no, tool_timeout = ctx.scope, ctx.round_no, ctx.tool_timeout
    _write_status(run_dir, stage="extract", stage_state="running")

    def _extract():
        urls = [a["canonical"] for a in
                store.get_assets(kind="url", min_conf=0.4, match=scope)
                if a["canonical"].startswith("http")]
        # run mode: t_extract schedules and settles JS through THIS
        # run's work_items (the only claimable queue), committing
        # each result's membership + ack under its lease. The old
        # blind adopt of EVERY input URL is gone: HTML pages cannot
        # become pending JS, and a bundle that already succeeded is
        # never re-opened.
        ex = tools.t_extract(store, [], urls=urls, timeout=tool_timeout,
                             scope=scope,
                             run_id=summary["_run_public_id"])
        # Keep the deliverable findings in the summary too: the run
        # result is what an agent reads (and what lands in
        # summary.jsonl), and dropping them here meant the redacted
        # secrets / api paths existed only in a transient stdout
        # line nobody could ever see afterwards.
        summary.setdefault("extract_findings", {})
        summary["extract_findings"].update({
            "api_paths": ex.get("api_paths", [])[:200],
            "api_hosts": ex.get("api_hosts", 0),
            "secrets": ex.get("secrets") or {},
            "domains": ex.get("in_scope_domains", ex.get("domains", []))[:200],
            "related_domains": ex.get("related_domains", [])[:100],
            "ips": ex.get("ips", [])[:200],
        })
        return {"new_domains": ex["count_domains"],
                "new_ips": ex["count_ips"],
                "fetched": ex["fetched"],
                "related_domains": ex.get("count_related", 0),
                "js_pending": ex.get("js_pending", 0),
                "js_discovered": ex.get("js_discovered", 0),
                "api_hosts": ex.get("api_hosts", 0),
                "secrets_found": sum(len(v) for v in (ex.get("secrets") or {}).values()),
                "outcome": ex.get("outcome") or core.OUTCOME_OK}
    _stage(store, run_dir, summary, "extract", {"scope": scope, "round": round_no},
           args, _extract,
           lambda r: {"new_domains": r["new_domains"], "new_ips": r["new_ips"],
                      "fetched": r["fetched"],
                      "js_pending": r.get("js_pending", 0),
                      "outcome": r.get("outcome")})


def _run_round(ctx: RunContext, round_no: int) -> None:
    """One discovery -> verify round: dns, then the active stages."""
    ctx.round_no = round_no
    _stage_dns(ctx)
    if not ctx.active:
        return
    _stage_probe(ctx)
    _stage_ipagg(ctx)
    if ctx.args.ports:
        _stage_ports(ctx)
    if ctx.args.vhost:
        _stage_vhost(ctx)
    if ctx.args.crawl:
        _stage_crawl(ctx)
        _stage_extract(ctx)


def _migrate_legacy_js(ctx: RunContext) -> None:
    """Adopt the earlier attempt's membership; migrate provable legacy JS rows."""
    store, summary, scope, planned = ctx.store, ctx.summary, ctx.scope, ctx.planned
    # A resumed run adopts what its earlier attempt discovered before the
    # first round: membership is the round input now, so skipping this
    # would make every checkpoint hit look like "no work".
    _adopt_membership(store, summary, scope)
    # Legacy JS rows with PROVABLE ownership (this run's membership or the
    # run's own scope) migrate idempotently into the durable queue; a
    # done row stays done, unknown ownership is reported and left in place.
    #
    # Only migrate WORK this run can actually drain: without the crawl/
    # extract stages nothing would ever claim an extract item, and a
    # migrated pending row would keep the run permanently partial with a
    # gap no retry can close. Completed legacy rows still migrate (they
    # carry history/statistics and are never re-opened).
    try:
        _can_drain_js = "extract" in planned
        _mig = work.import_js_queue(store, summary["_run_public_id"], scope,
                                    include_open=_can_drain_js)
        summary["js_migration"] = {"attached": _mig.get("attached", 0),
                                   "skipped_done": _mig.get("skipped_done", 0),
                                   "deferred_open": _mig.get("deferred_open", 0),
                                   "unknown": len(_mig.get("unknown") or [])}
        if _mig.get("unknown"):
            core.log("legacy js_queue: " + str(len(_mig["unknown"])) +
                     " row(s) have no provable owner; left untouched")
        if _mig.get("deferred_open"):
            core.log("legacy js_queue: " + str(_mig["deferred_open"]) +
                     " open row(s) belong to this run but it plans no "
                     "crawl/extract stage; left in the legacy queue")
    except Exception as exc:
        core.log("legacy js_queue migration failed: " + repr(exc)[:160])


def _run_rounds(ctx: RunContext) -> None:
    """discovery -> verify / reflow rounds until no new in-scope asset appears."""
    store, run_dir, summary, scope = ctx.store, ctx.run_dir, ctx.summary, ctx.scope
    rounds, time_budget, t_start = ctx.rounds, ctx.time_budget, ctx.t_start
    rounds_log, stop_reason = ctx.rounds_log, ctx.stop_reason
    for round_no in range(1, rounds + 1):
        if time_budget and (time.monotonic() - t_start) > time_budget:
            stop_reason = "time_budget"
            rounds_log.append({"round": round_no - 1, "new_domains": None,
                               "stop": stop_reason,
                               "elapsed_sec": round(time.monotonic() - t_start, 1)})
            break
        before = len(_scoped_domains(ctx, 0.4))
        _write_status(run_dir, stage="round-" + str(round_no), stage_state="running",
                      round=round_no, rounds=rounds,
                      stage_index=len([s for s in summary["stages"]
                                       if s.get("stage") != "ipagg"
                                       and "elapsed" in s or s.get("skipped")]),
                      stage_total=summary["_stage_total"])
        _run_round(ctx, round_no)
        _adopt_membership(store, summary, scope)
        after = len(_scoped_domains(ctx, 0.4))
        new_domains = max(0, after - before)
        # "No new domains" is NOT convergence while JS work is queued: the
        # bundles whose extraction would surface new domains have simply
        # not been fetched yet. Observed live: 41 candidates, budget 40,
        # one pending -- and the run still declared itself complete.
        #
        # run mode reads ONLY this run's durable queue: the shared legacy
        # js_queue belongs to standalone use and would let another
        # target's leftovers keep this run alive (or hide its own work).
        try:
            _wq = work.queue_stats(store, summary["_run_public_id"])
        except Exception:
            _wq = {}
        js_pending = int(_wq.get("outstanding") or 0)
        if new_domains == 0 and js_pending == 0:
            stop_reason = "no_new_assets"
        elif new_domains == 0 and js_pending > 0:
            # The queue has work left: keep going while rounds/budget allow.
            stop_reason = "" if round_no < rounds else "js_pending"
        elif round_no >= rounds:
            stop_reason = "max_rounds"
        elif time_budget and (time.monotonic() - t_start) > time_budget:
            stop_reason = "time_budget"
        rounds_log.append({"round": round_no, "new_domains": new_domains,
                           "stop": stop_reason or "continue",
                           "elapsed_sec": round(time.monotonic() - t_start, 1)})
        summary["rounds"] = rounds_log
        _write_status(run_dir, rounds=rounds_log, round=round_no,
                      counts=store.count_assets(),
                      endpoints=len(store.get_endpoints()))
        if stop_reason:
            break
    summary["rounds"] = rounds_log
    ctx.stop_reason = stop_reason


def _finish_run(ctx: RunContext) -> int:
    """Coverage, verdict, summary.jsonl and the terminal status frame."""
    args, store, run_dir, summary = ctx.args, ctx.store, ctx.run_dir, ctx.summary
    active, attempt, target_label = ctx.active, ctx.attempt, ctx.target_label
    run_id, planned, scope = ctx.run_id, ctx.planned, ctx.scope
    rounds, time_budget, t_start = ctx.rounds, ctx.time_budget, ctx.t_start
    rounds_log, stop_reason = ctx.rounds_log, ctx.stop_reason
    # ---- result + coverage -------------------------------------------
    counts = store.count_assets()
    endpoints = len(store.get_endpoints())
    done_stages = [s["stage"] for s in summary["stages"]
                   if "elapsed" in s and not s.get("failed")]
    skipped_stages = [s["stage"] for s in summary["stages"] if s.get("skipped")]
    failed_stages = [{"stage": s["stage"], "error": s.get("error"),
                      "elapsed": s.get("elapsed")}
                     for s in summary["stages"] if s.get("failed")]
    unavailable = _coverage_unavailable(args, active)
    # A source can also become unusable DURING the run (the relay's quota
    # runs out mid-engagement). That is only known from the stage results
    # and the per-request ledger, so fold the runtime findings into the
    # same "unavailable" block instead of leaving them in stage payloads
    # where nobody reads them.
    ledger = ctx.ledger
    try:
        blocked_engines = ledger.blocked_engines() if ledger else []
    except Exception:
        blocked_engines = []
    unavailable = _fold_runtime_unavailable(unavailable, summary["stages"],
                                            blocked_engines)
    source_errors = sum(int(s.get("sources_error") or 0)
                        for s in summary["stages"] if isinstance(s, dict))
    # Stages that finished but explicitly reported themselves
    # incomplete (OUTCOME_PARTIAL/BUDGET). _stage checkpoints them
    # "partial" so a re-run retries them, but the final verdict used
    # to ignore the outcome entirely: done_stages counted every
    # entry with an elapsed field, so a run whose only real work
    # was half-collected still claimed "complete".
    partial_stages = [{"stage": s["stage"], "outcome": s.get("outcome")}
                      for s in summary["stages"]
                      if isinstance(s, dict) and not s.get("failed")
                      and s.get("outcome") in (core.OUTCOME_PARTIAL,
                                                core.OUTCOME_BUDGET)]
    coverage = {
        "planned_stages": planned,
        "done_stages": done_stages,
        "skipped_stages": skipped_stages,
        "failed_stages": failed_stages,
        "partial_stages": partial_stages,
        # planned stages that never produced a result, failed, or were skipped
        # for a reason (e.g. probe with no resolved host) -- the gaps a user
        # has to be told about, distinct from checkpoint skips
        "not_run_stages": _not_run_stages(planned, summary["stages"]),
        "unavailable": unavailable,
        "sources_error": source_errors,
        "rounds": rounds_log,
        "stop_reason": stop_reason or ("single_round" if rounds == 1 else "completed"),
        "budget": {"rounds": rounds, "rounds_used": len(rounds_log),
                   "time_budget_sec": time_budget,
                   "elapsed_sec": round(time.monotonic() - t_start, 1)},
        # Per-stage machine-readable states, one vocabulary shared by the
        # planner, the runner and next_steps. An agent should never have to
        # infer "did this run?" from a mix of elapsed/skipped/reason fields.
        "stage_states": {
            s_["stage"]: (
                "succeeded" if ("elapsed" in s_ and not s_.get("failed")
                                and s_.get("outcome") in (None, core.OUTCOME_OK,
                                                          core.OUTCOME_EMPTY,
                                                          core.OUTCOME_UNAVAILABLE))
                else "partial" if ("elapsed" in s_ and not s_.get("failed")
                                   and s_.get("outcome") in (core.OUTCOME_PARTIAL,
                                                             core.OUTCOME_BUDGET))
                else "failed" if s_.get("failed")
                else ("no_input" if "no_hosts" in str(s_.get("reason") or "")
                      or "no_input" in str(s_.get("reason") or "")
                      else "checkpoint_hit")
            )
            for s_ in summary["stages"] if s_.get("stage")
        },
        # Stages the caller switched off are reported, not silently absent,
        # so "not in planned_stages" is unambiguous.
        "disabled_stages": [x for x in ("entity", "onepass", "icp", "brute")
                            if x not in planned],
        # Pending JS work is unfinished collection, not convergence. An
        # agent that only looks at "new domains == 0" would stop while
        # bundles are still queued. In run mode this is THIS run's durable
        # queue (the legacy shared table would mix other targets in).
        "js_queue": {},
    }
    try:
        _jsq = work.queue_stats(store, summary["_run_public_id"])
        coverage["js_queue"] = {
            "discovered": int(_jsq.get("done") or 0)
                          + int(_jsq.get("outstanding") or 0),
            "succeeded": int(_jsq.get("done") or 0),
            "failed": int(_jsq.get("failed") or 0),
            "pending": int(_jsq.get("pending") or 0)
                       + int(_jsq.get("running") or 0),
            "skipped": int(_jsq.get("blocked") or 0),
            "source": "run_work_items",
        }
    except Exception:
        pass
    # The billed-spend summary from the per-request ledger (batch F):
    # totals, per-engine requests and the blocked list the verdict reads.
    try:
        if ledger and ledger.rows():
            coverage["metered"] = {
                "totals": ledger.totals(),
                "by_engine": ledger.by_engine(),
                "blocked_engines": blocked_engines,
                "ledger_path": str(run_dir / "metered.jsonl"),
            }
    except Exception:
        pass
    # The run's own durable queue is the same obligation set (T16): a
    # pending/failed/running work item means the collection is unfinished,
    # whatever the shared legacy queue says.
    try:
        coverage["work_queue"] = work.queue_stats(
            store, summary["_run_public_id"])
    except Exception:
        coverage["work_queue"] = {}
    # The task mapping ledger's summary: which questions were asked, which
    # were reused, which engines the provider rejected. Coverage.metered
    # counts what THIS run spent; this says what the TASK already owns.
    try:
        import lib.mapping as _mapping
        cov_map = _mapping.coverage(store)
        if cov_map.get("questions"):
            cov_map["blocked_engines"] = _mapping.blocked_engines(store)
            coverage["mapping"] = cov_map
    except Exception:
        pass
    _wq_outstanding = int((coverage.get("work_queue") or {}).get(
        "outstanding") or 0)
    if failed_stages and not done_stages:
        status, reason, rc = "failed", "all_stages_failed", 1
    elif failed_stages:
        status, reason, rc = "partial", "stage_failed", 5
    elif stop_reason == "time_budget":
        status, reason, rc = "partial", "time_budget_exhausted", 5
    elif stop_reason == "max_rounds":
        status, reason, rc = "partial", "round_budget_exhausted", 5
    elif unavailable["blocking"]:
        status, reason, rc = "partial", "required_capability_missing", 5
    elif int((coverage.get("js_queue") or {}).get("pending") or 0) > 0:
        # Unfinished queue = unfinished collection. This check lives at the
        # FINAL decision, not only at the round stop, so a run that ends on
        # max_rounds with a full queue cannot claim "complete".
        status, reason, rc = "partial", "js_queue_pending", 5
    elif int((coverage.get("js_queue") or {}).get("failed") or 0) > 0:
        status, reason, rc = "partial", "js_queue_failed", 5
    elif stop_reason == "js_pending":
        status, reason, rc = "partial", "js_pending", 5
    elif _wq_outstanding > 0:
        # The durable queue settles with its own reason: pending/failed/
        # running work items are named obligations, distinct from the legacy
        # JS queue's counters (work_pending, docs par.6/7).
        status, reason, rc = "partial", "work_pending", 5
    elif partial_stages:
        # A stage that ran but reported itself incomplete is not a
        # completed collection. Name the stage so the agent can read
        # which one to retry instead of guessing from counts.
        reason = ("partial_stages:" +
                  ",".join(sorted({p_["stage"] for p_ in partial_stages})))
        status, rc = "partial", 5
    elif coverage["not_run_stages"]:
        # A planned, required stage that never produced a result is an
        # obligation gap, not "done": the run cannot claim complete
        # coverage of the requested work. _not_run_stages already
        # excludes informational stages and justified no_input ones.
        reason = ("planned_stage_not_run:" +
                  ",".join(coverage["not_run_stages"]))
        status, rc = "partial", 5
    else:
        status, reason, rc = "complete", (stop_reason or "all_stages_done"), 0
    coverage["complete"] = status == "complete"
    summary["counts"] = counts
    summary["endpoints"] = endpoints
    summary["coverage"] = coverage
    summary["result"] = {
        "status": status, "reason": reason, "run_id": run_dir.name,
        "attempt": attempt,
        "target": target_label, "scope": scope,
        "active": active,
        "counts": counts, "endpoints": endpoints,
        "elapsed_sec": round(time.monotonic() - t_start, 1),
        "artifacts": {"summary": str(run_dir / "summary.jsonl"),
                      "state": str(run_dir / "status.json"),
                      "stdout_log": str(run_dir / "stdout.log"),
                      "stderr_log": str(run_dir / "stderr.log"),
                      "spec": str(run_dir / "job.json")},
    }
    # Private pass-through keys (the ledger object) never serialise: the
    # summary is the persisted record; the spend facts live in its
    # metered.jsonl and the coverage.metered block above. Every private
    # (underscore) field is process-only and must not reach the file.
    for _private in ("_run_producers", "_run_public_id"):
        summary.pop(_private, None)
    core.write_jsonl(run_dir / "summary.jsonl", [summary])
    store.finish_run(run_id, summary)
    # stage_total must never be smaller than what actually ran: a resumed
    # run replays stages and can legitimately report more entries than the
    # original plan, and percent > 100 reads as corruption.
    _done_count = len(done_stages) + len(skipped_stages)
    _stage_total = max(int(summary.get("_stage_total") or 0), _done_count)
    # Terminal state: WHO writes it depends on how the run was started.
    #
    # Background: the worker writes `state=completed` together with
    # `exit_code` in ONE locked write, and it is the only writer that knows
    # the process exit code. Publishing completed here created a frame
    # where `state == "completed"` had no `exit_code`; `wait` treats
    # completed as terminal, returned that frame, and consumers saw a
    # missing field that is always present in a real terminal state (a
    # reproducible 1-in-6 flake in the worker e2e test).
    #
    # Foreground: nothing downstream publishes a terminal state, so this
    # IS the terminal write -- and it states its exit code, the same
    # `rc` main() returns.
    _terminal = {}
    if _worker_run_dir() is None:
        _terminal = {"state": "completed", "exit_code": int(rc or 0)}
    _write_status(run_dir, stage="done", stage_state="done",
                  counts=counts, endpoints=endpoints,
                  result=summary["result"], coverage=coverage,
                  stage_index=_done_count,
                  stage_total=_stage_total, **_terminal)
    out(summary)
    return rc


def _run_pipeline(args) -> int:
    """The collection pipeline itself (foreground, or inside a worker)."""
    max_seed = int(getattr(args, "max_seed", 0))
    if max_seed < 0:
        raise core.FindInfoError("--max-seed must be >= 0 (0 means all seed domains)")
    store = core.Store()
    try:
        work.ensure_schema(store)
    except Exception as exc:
        core.log("work schema init failed: " + repr(exc)[:200])
    try:
        mapping_mod.ensure_schema(store)
    except Exception as exc:
        core.log("mapping schema init failed: " + repr(exc)[:200])
    ctx = _prepare_run(args, store, max_seed)
    try:
        # 1. entity
        if args.name:
            _stage_entity(ctx)
        _collect_seed_domains(ctx)
        if ctx.identity_ambiguous:
            return _finish_identity_ambiguous(ctx)
        _fix_seed_scope(ctx)
        if not getattr(args, "no_onepass", False):
            _stage_onepass(ctx)
        _stage_certs(ctx)
        _stage_subs(ctx)
        if ctx.active and args.brute:
            _stage_brute(ctx)
        # 4. mapping runs only when the PLAN contains it: a domain-only run
        # (no seed subject, no filings) has nothing to map, and planning it
        # would manufacture a phantom gap no retry could close.
        if "mapping" in ctx.planned and not getattr(args, "no_mapping", False):
            _stage_mapping(ctx)
        _migrate_legacy_js(ctx)
        _run_rounds(ctx)
        return _finish_run(ctx)
    except Exception as exc:
        _write_status(ctx.run_dir, state="failed", error=repr(exc)[:500],
                      last_error={"type": type(exc).__name__, "message": str(exc)[:300]})
        raise
    finally:
        store.close()
