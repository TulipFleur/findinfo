#!/usr/bin/env python
"""findinfo - asset reconnaissance skill CLI.

Every subcommand prints one JSON object to stdout (machine-readable for the agent)
and human-readable progress to stderr.

    python findinfo.py doctor
    python findinfo.py entity --name 示例公司
    python findinfo.py subs   --domain example.com
    python findinfo.py probe  --from-store
    python findinfo.py run    --name 示例公司 --active
"""
from __future__ import annotations

import argparse
import shlex
import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Task isolation must be decided BEFORE lib.core is imported: module-level
# path resolution (HOME/DATA/RUNS_DIR) runs at import time, so a --task given
# after import would silently point at the wrong database. (The old approach
# reloaded lib.core post-parse, which left lib.report holding a stale core.)
# The only names that may follow "findinfo.py --task"; kept next to the parser
# it mirrors, and checked by tests/test_p0_regressions.py so a new subcommand
# cannot be added without updating it.
_SUBCOMMANDS = frozenset((
    "doctor", "entity", "certs", "passive", "brute", "icp", "subs", "dns",
    "probe", "ipagg", "ports", "vhost", "crawl", "extract", "report", "clean",
    "assets", "status", "wait", "cancel", "runs", "run", "__worker",
))


def _prescan_task(argv: list[str]) -> str:
    """Find --task anywhere on the command line, before argparse exists.

    --task is accepted both as a global option (--task X run ...) and after the
    subcommand (run --task X ...). The subparser option is only registered
    later, so this scan is what makes the late form work at all -- and it has
    to run before `lib.core` is imported, because core resolves HOME/DB at
    import time.

    The value must be non-empty and must not look like another flag or a
    subcommand name: in "--task run" the "run" is the subcommand, not a task
    named "run", and swallowing it would silently point the whole run at the
    wrong database while also breaking the command. An explicit --task= wins
    over a bare "--task value" when both appear.
    """
    found = ""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--task="):
            v = a.split("=", 1)[1].strip()
            if v:
                found = v
            i += 1
            continue
        if a == "--task" and i + 1 < len(argv):
            v = argv[i + 1]
            if v and not v.startswith("-") and v not in _SUBCOMMANDS:
                found = v
                i += 2
                continue
        i += 1
    return found


def _prescan_option(argv: list[str], name: str) -> str:
    """Find a global option's value anywhere in argv, before argparse runs.

    Same reason as _prescan_task: lib.core resolves HOME/DB at import time, so
    --home has to be visible before the import, not after the parse.
    """
    for i, a in enumerate(argv):
        if a.startswith(name + "="):
            v = a.split("=", 1)[1].strip()
            if v:
                return v
        elif a == name and i + 1 < len(argv):
            v = argv[i + 1]
            if v and not v.startswith("-"):
                return v
    return ""


_TASK = _prescan_task(sys.argv)
if _TASK:
    os.environ["FINDINFO_TASK"] = _TASK

# --home pins the state root for follow-up commands copied into a new process.
# Without it a command emitted under a temporary FINDINFO_HOME (tests, CI, a
# caller that isolates per project) would silently read the user's default
# library and report "run not found".
_HOME = _prescan_option(sys.argv, "--home")
if _HOME:
    os.environ["FINDINFO_HOME"] = _HOME

from lib import core, jobs, report, tools


def out(obj) -> None:
    core.emit(obj)


# ---------------------------------------------------------------- commands
def cmd_doctor(args) -> None:
    out(tools.doctor())


def cmd_entity(args) -> None:
    store = core.Store()
    try:
        res = tools.t_enscan(store, args.name, invest=args.invest, deep=args.deep,
                            outdir=Path(args.out) if args.out else None)
        out(res)
    finally:
        store.close()


def cmd_certs(args) -> None:
    store = core.Store()
    try:
        out(tools.t_certs(store, args.domain))
    finally:
        store.close()


def cmd_passive(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store or not domains:
            domains = _domains_from_store(store, 0.7, args.scope)
        srcs = [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else None
        merged = []
        for d in domains:
            merged.append(tools.t_onepass(store, d, sources=srcs,
                                          min_confidence=args.min_conf))
        out({"domains": merged, "total": sum(m.get("count", 0) for m in merged)})
    finally:
        store.close()


def cmd_brute(args) -> None:
    store = core.Store()
    try:
        out(tools.t_brute(store, args.domain, wordlist=args.wordlist,
                          bandwidth=args.bandwidth, wildcard=args.wildcard))
    finally:
        store.close()


def cmd_icp(args) -> None:
    store = core.Store()
    try:
        codes = args.code or []
        if args.from_store:
            codes = [a["canonical"] for a in store.get_assets(kind="icp")]
        out(tools.t_icp(store, codes, engines=args.engines))
    finally:
        store.close()


def cmd_subs(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store:
            domains = _domains_from_store(store, 0.7, args.scope)
        merged = []
        for d in domains:
            r = tools.t_subs(store, d, engines=args.engines)
            merged.append(r)
        out({"domains": merged, "total": sum(m.get("count", 0) for m in merged)})
    finally:
        store.close()


def _domains_from_store(store, min_conf: float, match: list[str] | None = None) -> list[str]:
    """Domain assets from the shared graph, optionally scoped to given suffixes.

    The graph is shared across engagements on purpose (multi-agent merge), so
    every stage that reads it back must pass the current engagement's domains.
    Without `match` a second engagement inherits the first one's targets.
    """
    scope = [core.canon_domain(d) for d in (match or [])]
    scope = [d for d in scope if d]
    return [a["canonical"] for a in
            store.get_assets(kind="domain", min_conf=min_conf, match=scope or None)]


def _vhost_bases(store) -> list[str]:
    """Base domains used to qualify bare vhost wordlist labels."""
    bases: list[str] = []
    for a in store.get_assets(kind="domain", min_conf=0.4):
        parent = core.canon_domain(a.get("parent") or "")
        if parent:
            bases.append(parent)
        elif a.get("canonical"):
            bases.append(a["canonical"])
    out: list[str] = []
    for b in bases:
        cd = core.canon_domain(b)
        if cd and cd not in out:
            out.append(cd)
    return out


def _active_enabled(args) -> bool:
    """--ports/--vhost/--crawl/--brute imply --active, as --help documents."""
    return bool(args.active or args.ports or args.vhost or args.crawl or args.brute)


def cmd_dns(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store or not domains:
            domains = _domains_from_store(store, args.min_conf, args.scope)
        out(tools.t_dns(store, domains))
    finally:
        store.close()


def cmd_probe(args) -> None:
    store = core.Store()
    try:
        hosts = args.host or []
        if args.from_store or not hosts:
            hosts = _domains_from_store(store, args.min_conf, args.scope)
        out(tools.t_httpx(store, hosts))
    finally:
        store.close()


def cmd_ipagg(args) -> None:
    store = core.Store()
    try:
        out(tools.t_ipagg(store, args.ip))
    finally:
        store.close()


def cmd_ports(args) -> None:
    store = core.Store()
    try:
        ips = args.ip or [a["canonical"] for a in store.get_assets(kind="ip")]
        out(tools.t_ports(store, ips, top_ports=args.top_ports))
    finally:
        store.close()


def cmd_vhost(args) -> None:
    store = core.Store()
    try:
        hosts = args.host or []
        if args.from_store or not hosts:
            hosts = _domains_from_store(store, 0.4, args.domain)
        if args.wordlist:
            # Accept the same bare names as `brute --wordlist` ("vhost" ->
            # wordlists/vhost.txt); a plain Path() read breaks that contract.
            raw = [w.strip() for w in
                   tools.resolve_wordlist(args.wordlist).read_text(encoding="utf-8").splitlines()
                   if w.strip()]
            bases = args.domain or _vhost_bases(store)
            extra = tools.expand_host_words(raw, bases)
            core.log("vhost wordlist: " + str(len(raw)) + " words -> " +
                     str(len(extra)) + " hosts from " + str(len(bases)) + " base domain(s)")
            hosts = hosts + extra
        ports = [int(p) for p in (args.ports or "80,443").split(",") if p.strip()]
        out(tools.t_vhost(store, args.ip, hosts, ports=ports, threads=args.threads,
                          skip_live=not args.no_skip_live))
    finally:
        store.close()


def cmd_crawl(args) -> None:
    store = core.Store()
    try:
        urls = args.url or []
        scope = core.canon_scope(args.domain or [])
        scope_warning = ""
        if args.from_store or not urls:
            if not scope:
                scope_warning = ("crawl --from-store without --domain reads the shared "
                                 "graph unscoped; other engagements' URLs will be crawled")
            for a in store.get_assets(kind="domain", min_conf=0.7, match=scope or None):
                attrs = a.get("attrs") or {}
                if attrs.get("url"):
                    urls.append(attrs["url"])
        if not scope:
            # derive from the seeds themselves (registrable, public-suffix aware)
            scope = [core.registrable_domain(core.split_url(u)[0] or "") or ""
                     for u in urls]
            scope = [s for s in scope if s]
        out(tools.t_crawl(store, urls, depth=args.depth, scope_domains=scope)
            | {"scope": scope, "scope_warning": scope_warning})
    finally:
        store.close()


def cmd_extract(args) -> None:
    store = core.Store()
    try:
        rows = []
        if args.from_run:
            p = Path(args.from_run)
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            rows.append(json.loads(line))
                        except Exception:
                            pass
        urls = args.url or []
        if args.from_store and not urls:
            # 回流场景：直接拿库里的 URL 资产（crawl 阶段写进去的），
            # 不用让 agent 去猜 runs 目录里的文件路径。
            # --domain 可限定只取属于这些域的 URL：库里往往混着别的目标
            # 的历史资产，不限域会把无关站点的 JS 也抓一遍。
            only = core.canon_scope(args.domain or [])
            for a in store.get_assets(kind="url", min_conf=0.4):
                u = a["canonical"]
                if not u.startswith("http"):
                    continue
                if only:
                    h = core.canon_domain(core.split_url(u)[0] or "")
                    if not core.in_scope(h, only):
                        continue
                urls.append(u)
        out(tools.t_extract(store, rows, urls=urls))
    finally:
        store.close()


def cmd_report(args) -> None:
    """Render final deliverables: JSON digest for agents, HTML dashboard for humans.

    Scope is a suffix filter (--match) because the asset store is shared across
    engagements. Without it the report silently includes every other project's
    rows; the collector falls back to the latest run's target and says so.
    An explicit --match that canon_domain() rejects entirely is an ERROR, not a
    silent fallback to the whole library.
    """
    if args.match and not core.canon_scope(args.match):
        raise core.FindInfoError(
            "no valid domain in --match: " + ",".join(args.match) +
            " (a garbage scope must fail loudly, not degrade to a full-library report)")
    # A report must read the SAME library the run wrote to. core.Store() has
    # already resolved HOME/TASK from the environment at import time, so if the
    # caller quoted --run from another task, this process would open the wrong
    # database and cheerfully produce an empty report (rc=0). Refuse loudly and
    # say what to pass instead.
    if args.run and not os.environ.get("FINDINFO_TASK", ""):
        try:
            _spec = jobs.read_spec(args.run)
        except Exception:
            _spec = {}
        _want = str(_spec.get("task") or "")
        if _want:
            raise core.FindInfoError(
                "run " + str(args.run) + " belongs to task '" + _want +
                "'; re-run with: python findinfo.py --task " + _want +
                " report --run " + str(args.run) +
                " (without it this process reads the shared library and "
                "would report an empty scope)")
    match = list(args.match or [])
    if not match and args.run:
        # Fall back to the run's own scope: a run started with two seeds
        # (example.com + example.org) must not have half its assets reported as
        # out-of-scope noise just because the caller quoted one seed.
        spec = jobs.read_spec(args.run)
        scope = core.canon_scope(spec.get("scope") or [])
        if scope:
            match = scope
            core.log("report: scope from run " + str(args.run) + " -> " + ",".join(scope))
    store = core.Store()
    try:
        data = report.collect(store, match=match or None, min_conf=args.min_conf,
                              limit=args.limit, ep_limit=args.ep_limit,
                              engagement=args.engagement)
    finally:
        store.close()
    paths = report.write_bundle(data, out_dir=args.out, slug=args.slug,
                                json_limit=args.json_limit)
    res = {"counts": data["counts"], "scope": data["scope"],
           "paths": paths, "warnings": data["environment"]["warnings"],
           "next_steps": data["next_steps"][:3]}
    if args.print_md:
        res["md"] = report.build_md(data)
    if args.print_json:
        res["json"] = data
    out(res)


def cmd_clean(args) -> None:
    """Trim the shared asset graph: --keep X / --match X / --all.

    --all is the only mode with no scope at all: it empties the table an agent
    may not own. It therefore needs an explicit --yes and rewinds nothing, so
    a bare `clean --all` reports what it WOULD delete and exits without
    touching the store. --dry-run previews any mode the same way.
    """
    store = core.Store()
    try:
        before = store.count_assets()
        eps_before = len(store.get_endpoints())
        _dry = getattr(args, "dry_run", False)
        # --dry-run wins over the confirmation gate: a preview never deletes,
        # so demanding --yes first would just hide the preview behind an error.
        if args.all and not args.yes and not _dry:
            out({"error": "clean --all is destructive and needs --yes",
                 "hint": "re-run with: clean --all --yes (or --dry-run to preview)",
                 "would_delete": {"assets": sum(before.values()),
                                  "endpoints": eps_before,
                                  "filter": "<everything>",
                                  "before": before},
                 "assets": 0, "endpoints": 0, "deleted": False})
            return
        if _dry:
            # preview only: compute the same filter, delete nothing
            if args.all:
                res = {"assets": sum(before.values()), "endpoints": eps_before,
                       "filter": "<everything>"}
            elif args.keep:
                res = store.purge(keep=args.keep, kinds=args.kind, dry_run=True)
            elif args.match:
                res = store.purge(match=args.match, kinds=args.kind, dry_run=True)
            else:
                out({"error": "pass --keep <suffix> | --match <suffix> | --all"})
                return
            res.update({"before": before, "after": before,
                        "endpoints_before": eps_before, "endpoints_after": eps_before,
                        "dry_run": True, "deleted": False})
            out(res)
            return
        if args.all:
            res = {"assets": sum(before.values()), "endpoints": eps_before,
                   "filter": "<everything>"}
            with store._write():
                store.conn.execute("DELETE FROM endpoints")
                store.conn.execute("DELETE FROM assets")
        elif args.keep:
            res = store.purge(keep=args.keep, kinds=args.kind)
        elif args.match:
            res = store.purge(match=args.match, kinds=args.kind)
        else:
            out({"error": "pass --keep <suffix> | --match <suffix> | --all"})
            return
        if args.vacuum:
            store.vacuum()
        res["deleted"] = True
        res["before"] = before
        res["after"] = store.count_assets()
        res["endpoints_before"] = eps_before
        res["endpoints_after"] = len(store.get_endpoints())
        out(res)
    finally:
        store.close()


def cmd_assets(args) -> None:
    store = core.Store()
    try:
        if args.export:
            kind = None if args.kind == "all" else args.kind
            rows = store.get_assets(kind=kind, min_conf=args.min_conf)
            path = Path(args.export)
            n = core.write_jsonl(path, rows)
            out({"exported": n, "path": str(path),
                 "counts": store.count_assets()})
            return
        rows = store.get_assets(kind=None if args.kind == "all" else args.kind,
                                min_conf=args.min_conf, limit=args.limit)
        out({"counts": store.count_assets(), "total": len(rows),
             "endpoints": len(store.get_endpoints()), "rows": rows})
    finally:
        store.close()


def cmd_status(args) -> None:
    """Report one run: stage, progress, counts, liveness, result, coverage.

    Pass --run to address a specific run. Without it the newest run is used as a
    convenience, but anything that must resume work should keep the run id it was
    given (see the `runs` command) instead of relying on "latest".
    """
    if args.run:
        run_dir = jobs.resolve(args.run)
    else:
        recent = jobs.list_runs(limit=1)
        if not recent:
            out({"state": "no_runs",
                 "hint": "no job yet; start one with: python findinfo.py run --domain X --background",
                 "runs_dir": str(core.RUNS_DIR)})
            return
        run_dir = jobs.resolve(recent[0]["run_id"])

    st = jobs.derive(jobs.read_state(run_dir))
    spec = jobs.read_spec(run_dir)
    summary = None
    mp = run_dir / "summary.jsonl"
    if mp.exists():
        try:
            lines = [ln for ln in mp.read_text(encoding="utf-8").splitlines() if ln.strip()]
            summary = json.loads(lines[-1]) if lines else None
        except Exception:
            summary = None

    payload = {
        "run_id": st.get("run_id"), "run_dir": str(run_dir),
        "state": st.get("state"), "stage": st.get("stage"),
        "stage_state": st.get("stage_state"),
        "alive": st.get("alive"), "interrupted": st.get("interrupted"),
        "stalled": st.get("stalled"), "terminal": st.get("terminal"),
        "heartbeat_age_sec": st.get("heartbeat_age_sec"),
        "pid": st.get("pid"), "attempt": st.get("attempt"),
        "target": spec.get("target") or st.get("target"),
        "scope": spec.get("scope") or st.get("scope"),
        "params": spec.get("params"), "budget": spec.get("budget"),
        "planned_stages": st.get("planned_stages"), "seq": st.get("seq"),
        "progress": jobs.progress(st),
        "counts": st.get("counts") or {}, "endpoints": st.get("endpoints"),
        "result": st.get("result") or (summary or {}).get("result"),
        "coverage": st.get("coverage") or (summary or {}).get("coverage"),
        "last_error": st.get("last_error"),
        "next_steps": _next_steps(st),
        "paths": _run_paths(run_dir),
    }
    if st.get("hint"):
        payload["hint"] = st["hint"]
    if st.get("interrupted"):
        payload["resume"] = "python findinfo.py run --resume " + str(st.get("run_id"))
    out(payload)


def _next_steps(st: dict) -> list:
    """What to do next, derived from the stored state (not from a guess)."""
    state = st.get("state")
    rid = str(st.get("run_id"))
    ctx = " ".join(_ctx_prefix())
    if state == "completed":
        return [ctx + " report --match <scope> --run " + rid,
                "read result/coverage before describing the task as complete"]
    if state == "failed":
        return ["read coverage.failed_stages and last_error",
                ctx + " run --resume " + rid]
    if state == "cancelled":
        return ["assets collected so far are still in the store; re-run when needed"]
    if st.get("interrupted"):
        return ["worker died: " + ctx + " run --resume " + rid]
    return [ctx + " wait --run " + rid + " --timeout 30"]


def cmd_wait(args) -> None:
    """Bounded wait: returns on progress, on terminal state, or on timeout.

    A timeout is reported as timed_out=true with the current state; it never
    means the collection failed and must not trigger a restart.

    Waiting is the one command an agent calls in a loop, so by default it
    answers briefly (state/stage/counters/progress/result). Pass --full for the
    complete payload.
    """
    run_dir = jobs.resolve(args.run)
    res = jobs.wait(run_dir, timeout=args.timeout, since_seq=args.since)
    if not getattr(args, "full", False):
        # Keep the flags that carry meaning even when false (timed_out/terminal),
        # drop only the bulky echoes (coverage, run_dir, hints).
        prog = res.get("progress") or {}
        keep = ("run_id", "state", "changed", "timed_out", "terminal", "alive",
                "interrupted", "stalled", "seq", "waited_sec", "result", "note")
        res = {k: res[k] for k in keep if k in res}
        res.update({"stage": prog.get("stage"), "stage_state": prog.get("stage_state"),
                    "stage_index": prog.get("stage_index"),
                    "stage_total": prog.get("stage_total"),
                    "percent": prog.get("percent"), "counts": prog.get("counts") or {},
                    "endpoints": prog.get("endpoints")})
    out(res)


def cmd_cancel(args) -> None:
    out(jobs.cancel(args.run, reason=args.reason or "user"))


def cmd_runs(args) -> None:
    rows = jobs.list_runs(limit=args.limit, state_filter=args.state or "",
                          active_only=args.active)
    out({"runs": rows, "count": len(rows), "runs_dir": str(core.RUNS_DIR),
         "active": [r["run_id"] for r in rows if r["state"] in jobs.ACTIVE]})


def cmd_worker(args) -> int:
    """Hidden entry point of the detached worker process."""
    os.environ["FINDINFO_RUN_DIR"] = str(jobs.resolve(args.run_dir))
    return jobs.worker_main(args.run_dir)


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
    """Publish progress for whoever polls this run (status / wait)."""
    try:
        jobs.update_state(run_dir, **{k: v for k, v in kw.items() if k != "run_id"})
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
    """
    ih = _input_hash(inputs)
    if not getattr(args, "force_stage", False) and store.step_done(ENGAGEMENT, name, ih):
        res = resume() if resume else None
        core.log("stage " + name + " skipped (done for these inputs; --force-stage to redo)")
        summary["stages"].append({"stage": name, "skipped": True,
                                  "resumed": res is not None})
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
    entry["status"] = ("succeeded" if _oc in (core.OUTCOME_OK, core.OUTCOME_EMPTY)
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
    # icp needs codes harvested from --name/ENScan. With a bare --domain there
    # is nothing to reverse-look-up, so planning it guarantees a phantom gap in
    # every domain-only run ("icp未执行") that no retry can ever close.
    if not getattr(args, "no_icp", False) and getattr(args, "name", ""):
        plan.append("icp")
    return plan + _round_plan(args, active)


def _engine_key(engine: str) -> bool:
    name = (engine or "").strip().lower()
    if not name:
        return False
    if name == "fofa":
        return bool(core.api_key("fofa") or core.api_base("fofa"))
    if name == "censys":
        return bool(core.api_key("censys") or core.api_key("censys_id"))
    return bool(core.api_key(name))


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


def _fold_runtime_unavailable(unavailable: dict, stages: list) -> dict:
    """Add gaps that only become known while the run is executing.

    A source whose quota runs out mid-engagement must show up as a coverage
    gap. Left in the stage payload nobody reads it, and the source then looks
    like it simply "found nothing" -- the exact confusion this project forbids.
    """
    hits = [st.get("stage") or "subs" for st in stages
            if isinstance(st, dict) and st.get("quota_exhausted")]
    if not hits:
        return unavailable
    out = dict(unavailable)
    names = sorted(set(hits))
    out["quota_exhausted"] = names
    note = out.get("note") or ""
    out["note"] = (note + "; " if note else "") + \
        "quota exhausted during run: " + ",".join(names)
    return out


def _foreground_argv(args) -> list:
    """Rebuild the CLI argv a worker should replay (drop --background/--resume)."""
    argv = ["run"]
    if args.name:
        argv += ["--name", args.name]
    for d in (args.domain or []):
        argv += ["--domain", d]
    if _active_enabled(args):
        argv.append("--active")
    if args.ports:
        argv.append("--ports")
    if args.vhost:
        argv.append("--vhost")
    if args.crawl:
        argv.append("--crawl")
    if args.brute:
        argv += ["--brute", "--brute-wordlist", args.brute_wordlist,
                 "--brute-bandwidth", args.brute_bandwidth]
    argv += ["--depth", str(args.depth), "--invest", str(args.invest),
             "--deep", str(args.deep), "--entity-timeout", str(getattr(args, "entity_timeout", 1200)),
             "--engines", args.engines,
             "--top-ports", str(args.top_ports), "--max-seed", str(args.max_seed),
             "--max-vhost-ips", str(args.max_vhost_ips)]
    if args.no_icp:
        argv.append("--no-icp")
    if args.no_onepass:
        argv.append("--no-onepass")
    if getattr(args, "force_stage", False):
        argv.append("--force-stage")
    rounds = int(getattr(args, "rounds", 1) or 1)
    if rounds != 1:
        argv += ["--rounds", str(rounds)]
    budget = float(getattr(args, "time_budget", 0) or 0)
    if budget:
        argv += ["--time-budget", str(budget)]
    tool_timeout = int(getattr(args, "tool_timeout", 0) or 0)
    if tool_timeout:
        argv += ["--tool-timeout", str(tool_timeout)]
    task_timeout = float(getattr(args, "task_timeout", 0) or 0)
    if task_timeout:
        argv += ["--task-timeout", str(task_timeout)]
    return argv


def _dedupe_payload(args) -> dict:
    """Everything that changes what a run would collect.

    Display/budget-only switches are excluded so re-asking for the same target
    reuses the in-flight job instead of starting a second collection.
    """
    return {
        "engagement": ENGAGEMENT,
        "task": os.environ.get("FINDINFO_TASK", ""),
        "home": str(core.HOME),
        "name": args.name or "",
        "domains": sorted(core.canon_scope(args.domain or [])),
        "active": _active_enabled(args),
        "ports": bool(args.ports), "vhost": bool(args.vhost),
        "crawl": bool(args.crawl), "brute": bool(args.brute),
        "engines": args.engines,
        "max_seed": int(args.max_seed), "top_ports": int(args.top_ports),
        "depth": int(args.depth), "invest": int(args.invest), "deep": int(args.deep),
        "max_vhost_ips": int(args.max_vhost_ips),
        "no_icp": bool(args.no_icp), "no_onepass": bool(args.no_onepass),
        "brute_wordlist": args.brute_wordlist, "brute_bandwidth": args.brute_bandwidth,
    }



# ---------------------------------------------------------------- resume merge
# Budget switches a resume is allowed to override. Everything else (target,
# scope, stage selection) stays exactly as the job was started: a resume must
# never silently point the same run id at a different company.
_RESUME_OVERRIDABLE = ("--rounds", "--time-budget", "--tool-timeout",
                       "--task-timeout", "--force-stage")


def _argv_value(argv: list[str], flag: str):
    """Value of `flag` in an argv list, or None when absent."""
    for i, a in enumerate(argv):
        if a == flag and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None


def _set_argv_value(argv: list[str], flag: str, value: str) -> list[str]:
    """Replace (or append) a flag's value in argv, leaving order intact."""
    out = list(argv)
    for i, a in enumerate(out):
        if a == flag:
            if i + 1 < len(out):
                out[i + 1] = value
                return out
            out.append(value)
            return out
    out += [flag, value]
    return out



# Flags whose presence on the command line must be distinguishable from
# "argparse filled in the default". Resume merging depends on this: replaying a
# job must not overwrite the stored budget with defaults the caller never typed.
_TRACKED_FLAGS = {
    "--rounds": "rounds", "--time-budget": "time_budget",
    "--tool-timeout": "tool_timeout", "--task-timeout": "task_timeout",
    "--force-stage": "force_stage",
}


def _mark_explicit(args, argv: list[str]) -> None:
    """Record which budget flags the caller actually typed."""
    seen = set()
    for a in argv:
        for flag, attr in _TRACKED_FLAGS.items():
            if a == flag or a.startswith(flag + "="):
                seen.add(attr)
    setattr(args, "_explicit", seen)

def _remove_argv_flag(argv: list[str], flag: str) -> list[str]:
    """Remove a flag and the value that belongs to it, positionally."""
    out: list[str] = []
    skip = 0
    for i, a in enumerate(argv):
        if skip:
            skip -= 1
            continue
        if a == flag:
            if i + 1 < len(argv):
                skip = 1
            continue
        if a.startswith(flag + "="):
            continue
        out.append(a)
    return out


def _merge_resume_argv(argv: list[str], args) -> list[str]:
    """Apply the budget flags the caller explicitly typed; keep the rest.

    Without this, `run --resume <id> --rounds 5` was accepted (rc=0) and then
    ignored: the worker replayed the original argv, so the budget never changed
    and the agent believed it had widened the run. Only flags listed in
    args._explicit are applied -- a value that merely equals the default is not
    an instruction.
    """
    explicit = set(getattr(args, "_explicit", ()) or ())
    out = list(argv)
    mapping = (("rounds", "--rounds", str), ("time_budget", "--time-budget", str),
               ("tool_timeout", "--tool-timeout", str),
               ("task_timeout", "--task-timeout", str))
    for attr, flag, cast in mapping:
        if attr not in explicit:
            continue
        val = getattr(args, attr, None)
        if val in (None, "", 0, 0.0):
            # An explicit 0 means "remove this ceiling". Remove ONLY this flag
            # and its value, by position. The previous filter compared VALUES
            # against the flag's first value, so `--time-budget 0` deleted every
            # element equal to "60" -- including the unrelated
            # `--tool-timeout 60` sitting later in the same argv.
            out = _remove_argv_flag(out, flag)
            continue
        out = _set_argv_value(out, flag, cast(val))
    if "force_stage" in explicit and getattr(args, "force_stage", False):
        if "--force-stage" not in out:
            out.append("--force-stage")
    return out

def _run_paths(rd: Path) -> dict:
    return {"run_dir": str(rd),
            "state_path": str(rd / "status.json"),
            "result_path": str(rd / "summary.jsonl"),
            "log_path": str(rd / "stdout.log"),
            "error_log_path": str(rd / "stderr.log")}


def _ctx_prefix() -> list[str]:
    """Global options every follow-up command needs to address the same job.

    An agent copies the `next` command into a NEW process. Environment variables
    set by the launching command (FINDINFO_TASK / FINDINFO_HOME) are gone by
    then, so a bare `wait --run X` would resolve against the global library and
    report "run not found" -- or worse, silently address a different job.

      --task  which asset graph (per-engagement home subdirectory)
      --home  which home root   (FINDINFO_HOME: temp homes, tests, CI)

    Omitted only when empty, so the command stays readable in the common case.
    """
    parts = ["python findinfo.py"]
    task = os.environ.get("FINDINFO_TASK", "")
    if task:
        parts += ["--task", shlex.quote(task)]
    home = os.environ.get("FINDINFO_HOME", "")
    if home:
        parts += ["--home", shlex.quote(home)]
    return parts


def _followup(sub: str, rd: Path, *extra: str) -> str:
    """A complete, directly executable command for the next step of this job."""
    parts = _ctx_prefix() + [sub] + list(extra) + ["--run", rd.name]
    return " ".join(parts)


def _start_background(args) -> int:
    """Start the collection in a detached worker and return its run id at once.

    The dedupe check and the creation of a run dir must be ONE critical section.
    Two identical submissions arriving together both passed find_inflight()
    before either wrote a job.json, and both started a worker: a duplicate
    collection, double quota, two graphs. A cross-process file lock (the same
    O_CREAT|O_EXCL primitive jobs._Lock uses for status.json) closes the window.
    """
    payload = _dedupe_payload(args)
    key = jobs.dedupe_key(payload)
    lock = jobs.start_lock(key)
    with lock:
        return _start_background_locked(args, payload, key)


def _start_background_locked(args, payload, key) -> int:
    inflight = jobs.find_inflight(key)
    if inflight is not None:
        st = jobs.derive(jobs.read_state(inflight))
        out(dict({"run_id": inflight.name, "state": st.get("state"),
                  "reused": True, "started": False, "dedupe_key": key},
                 **_run_paths(inflight),
                 next=_followup("wait", inflight, "--timeout", "30")))
        return 0

    active = _active_enabled(args)
    target_label = args.name or (",".join(args.domain) if args.domain else "?")
    rd = core.new_run_dir(target_label)
    planned = _plan_stages(args, active)
    task = os.environ.get("FINDINFO_TASK", "")
    jobs.write_spec(
        rd, entry="findinfo:main", argv=_foreground_argv(args),
        target=args.name or target_label, scope=core.canon_scope(args.domain or []),
        engagement=ENGAGEMENT, task=task, home=str(core.HOME), root=str(core.ROOT),
        python=sys.executable, dedupe_key=key, attempt=1, params=payload,
        # task_timeout is a TOP-LEVEL spec field because lib/jobs.worker_main
        # reads spec["task_timeout"] to arm its hard deadline. It used to be
        # written only inside budget{}, so the timer could never start: the job
        # had no ceiling at all. Keep budget{} too -- it is what status reports.
        task_timeout=float(getattr(args, "task_timeout", 0) or 0),
        budget={"rounds": int(getattr(args, "rounds", 1) or 1),
                "time_budget_sec": float(getattr(args, "time_budget", 0) or 0),
                "task_timeout_sec": float(getattr(args, "task_timeout", 0) or 0)},
        env={"FINDINFO_HOME": str(core.HOME), "FINDINFO_TASK": task},
    )
    jobs.update_state(rd, state="queued", stage="queued", stage_state="queued",
                      target=target_label, scope=core.canon_scope(args.domain or []),
                      planned_stages=planned, stage_index=0,
                      stage_total=len(planned), active=active, attempt=1,
                      dedupe_key=key, started_ts=jobs.now_ts())
    try:
        pid = jobs.spawn(rd)
    except Exception as exc:
        # spawn() already wrote state=failed + spawn_failed; report the run id
        # so the caller can inspect the logs instead of guessing a directory.
        out(dict({"run_id": rd.name, "state": "failed", "started": False,
                  "reused": False, "dedupe_key": key, "error": str(exc)[:300],
                  "planned_stages": planned, "active": active},
                 **_run_paths(rd)))
        return 1
    jobs.update_state(rd, pid=pid)
    out(dict({"run_id": rd.name, "state": "running", "started": True, "pid": pid,
              "reused": False, "dedupe_key": key,
              "planned_stages": planned, "active": active},
             **_run_paths(rd),
             next=_followup("wait", rd, "--timeout", "30")))
    return 0


def _resume_run(args) -> int:
    rd = jobs.resolve(args.resume)
    st = jobs.derive(jobs.read_state(rd))
    if st.get("state") in jobs.ACTIVE and st.get("alive"):
        out(dict({"run_id": rd.name, "state": st.get("state"), "reused": True,
                  "resumed": False}, **_run_paths(rd),
                 hint="already running; wait on this run id instead of starting another"))
        return 0
    spec = jobs.read_spec(rd)
    if not spec.get("argv"):
        raise core.FindInfoError("not a background run (no job spec): " + rd.name)

    # -- explicit budget overrides on resume -------------------------------
    # The old behaviour replayed spec["argv"] verbatim, so `--resume <id>
    # --rounds 5` re-ran with the ORIGINAL rounds and the caller had no way to
    # widen the budget (the flag was silently ignored, rc=0). Merge only what
    # was actually typed: argparse cannot tell "not given" from "given the
    # default", so the parser records each override in args._explicit (see
    # build_parser) and everything else keeps the spec value.
    argv = _merge_resume_argv(list(spec["argv"]), args)
    spec["argv"] = argv
    # Keep the budget block consistent with the argv a worker will replay.
    budget = dict(spec.get("budget") or {})
    for flag, key, cast in (("--rounds", "rounds", int),
                            ("--time-budget", "time_budget_sec", float),
                            ("--tool-timeout", "tool_timeout_sec", int),
                            ("--task-timeout", "task_timeout_sec", float)):
        val = _argv_value(argv, flag)
        if val is not None:
            budget[key] = cast(float(val)) if key != "rounds" else cast(val)
    spec["budget"] = budget
    # task_timeout lives at the top level (that is what worker_main reads), so
    # it must be updated -- and CLEARED when the caller passed --task-timeout 0.
    # Leaving the old value behind meant "remove the ceiling" silently kept it.
    explicit = set(getattr(args, "_explicit", ()) or ())
    if "task_timeout" in explicit:
        _tt = _argv_value(argv, "--task-timeout")
        spec["task_timeout"] = float(_tt) if _tt is not None else 0.0
    spec["attempt"] = int(spec.get("attempt") or 1) + 1
    jobs.write_spec(rd, **spec)
    try:
        (rd / "cancel").unlink()
    except OSError:
        pass
    # Clear the PREVIOUS attempt's verdict before the worker starts. Without
    # this, `status` during the resume shows attempt N-1's result.status while
    # state=queued/running -- an agent reading it would report a finished run.
    jobs.update_state(rd, state="queued", stage="resume", stage_state="queued",
                      attempt=spec["attempt"], last_error=None, pid=None,
                      result={"status": "running", "reason": "resume_started",
                              "attempt": spec["attempt"],
                              "note": "attempt in progress; previous attempt's "
                                      "summary remains in summary.jsonl"},
                      coverage={"complete": False, "reason": "resume_started",
                                "attempt": spec["attempt"]})
    try:
        pid = jobs.spawn(rd)
    except Exception as exc:
        out(dict({"run_id": rd.name, "state": "failed", "resumed": False,
                  "attempt": spec.get("attempt"), "error": str(exc)[:300]},
                 **_run_paths(rd)))
        return 1
    jobs.update_state(rd, pid=pid)
    out(dict({"run_id": rd.name, "state": "running", "resumed": True,
              "attempt": spec["attempt"], "pid": pid}, **_run_paths(rd),
             next=_followup("wait", rd, "--timeout", "30")))
    return 0


# ---------------------------------------------------------------- pipeline
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


def _run_pipeline(args) -> int:
    """The collection pipeline itself (foreground, or inside a worker)."""
    store = core.Store()
    active = _active_enabled(args)
    attempt = _current_attempt()
    summary: dict = {"engagement": ENGAGEMENT, "active": active, "stages": [],
                     "attempt": attempt}
    target_label = args.name or (",".join(args.domain) if args.domain else "?")
    run_id = store.start_run(ENGAGEMENT, target_label)
    run_dir = _worker_run_dir() or core.new_run_dir(target_label)
    summary["run_dir"] = str(run_dir)
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
    rounds_log: list = []
    stop_reason = ""
    try:
        # 1. entity
        domains: list = []
        icp_codes: list = []
        if args.name:
            def _entity():
                # ENScan pages through aiqicha with a per-request delay; with a
                # deep query it can wait indefinitely. Bound it (default 20 min,
                # --entity-timeout) so the run cannot hang forever: on timeout
                # the partial result is kept and the stage is retried later.
                entity_timeout = int(getattr(args, "entity_timeout", 1200) or 0)
                r = tools.t_enscan(store, args.name, invest=args.invest, deep=args.deep,
                                   outdir=run_dir / "enscan", timeout=entity_timeout)
                if r.get("rc") == 124:
                    raise core.StageError(
                        "enscan timed out after " + str(entity_timeout) + "s",
                        result={"companies": len(r.get("companies", [])),
                                "icp": len(r.get("icp", [])),
                                "domains": len(r.get("domains", []))})
                if r.get("rc") not in (0, None) and not r.get("json_files"):
                    # rc != 0 with no JSON used to fail the stage outright. But
                    # ENScan can print a complete report table and still not
                    # write the JSON (observed on a deep 示例公司 query: 35 KB of
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
                return r
            _stage(store, run_dir, summary, "entity",
                   {"name": args.name, "invest": args.invest, "deep": args.deep},
                   args, _entity,
                   lambda r: {"companies": len(r.get("companies", [])),
                              "icp": len(r.get("icp", [])),
                              "domains": len(r.get("domains", []))},
                   resume=lambda: {"companies": [], "icp": [], "domains": []})
        if args.domain:
            for d in args.domain:
                cd = core.canon_domain(d)
                if not cd:
                    raise core.FindInfoError("invalid domain: " + str(d))
                domains.append(cd)
        if args.name:
            for a in store.get_assets(kind="domain", min_conf=0.9):
                if (a.get("parent") or "") == args.name:
                    domains.append(a["canonical"])
            for a in store.get_assets(kind="icp"):
                if (a.get("parent") or "") == args.name:
                    icp_codes.append(a["canonical"])
        # Order matters: the domains the caller named come FIRST, then the ones
        # entity anchoring discovered. certs/subs/brute only walk the first
        # --max-seed entries, and a company anchor can surface hundreds of
        # unrelated domains (ICP rows, CDN hosts) -- without this ordering a run
        # with --domain example.com would spend its cert budget on app.chaoxing.com.
        named = [core.canon_domain(d) for d in (args.domain or [])]
        named = [d for d in named if d]
        discovered = [d for d in domains if d not in named]
        domains = core.canon_scope(named + discovered)
        summary["seed_domains"] = domains
        if not domains:
            raise core.FindInfoError("no seed domain; give --domain or check ENScan output")
        # Explicit seeds are USER INPUT, not evidence. They must reach the DNS
        # stage even when every passive source returns nothing -- otherwise
        # "this domain has no subdomains" silently skips the target the user
        # actually asked about. Stored with a seed-only source id so it is
        # visibly unverified until dns/probe produce real evidence.
        for d in domains:
            store.upsert_asset("domain", d, source="seed:user", confidence=0.5,
                               passivity="passive", parent=d)
        seeds = domains[: args.max_seed]
        if len(named) > args.max_seed:
            core.log("notice: " + str(len(named)) + " named domains but --max-seed " +
                     str(args.max_seed) + "; only the first " + str(args.max_seed) +
                     " get certs/subs (raise --max-seed to widen)")

        # ACTIVE SCOPE MODEL: only what the caller asked for (--domain args plus
        # the company anchor's ENScan domains) is actively probed. Assets merely
        # DISCOVERED on the way are stored and reported, never auto-probed.
        scope = domains
        summary["scope"] = scope

        def scoped_rows(min_conf: float):
            return store.get_assets(kind="domain", min_conf=min_conf, match=scope)

        def scoped_domains(min_conf: float) -> list:
            return [a["canonical"] for a in scoped_rows(min_conf)]

        if len(seeds) < len(domains):
            summary["coverage_limits"] = {
                "seeds_total": len(domains), "seeds_scanned": len(seeds),
                "reason": "--max-seed budget (passive collection breadth); "
                          "DNS/probe still cover every seed"}

        # 1.5 onepass (15-source passive aggregation, Rust binary)
        if not getattr(args, "no_onepass", False):
            def _onepass():
                total = 0
                src_errors = 0
                outcomes = []
                for d in seeds:
                    r = tools.t_onepass(store, d)
                    total += r["count"]
                    src_errors += r.get("sources_error") or 0
                    outcomes.append(r.get("outcome") or core.OUTCOME_OK)
                oc = core.combine_outcome(*outcomes)
                res = {"found": total, "sources_error": src_errors, "outcome": oc}
                # A run where every upstream failed must not be checkpointed as
                # "done": the same inputs would then be skipped forever and the
                # agent would keep seeing an empty asset graph with no reason.
                if oc in (core.OUTCOME_FAILED, core.OUTCOME_TIMEOUT):
                    raise core.StageError("onepass: " + oc + " (" +
                                          str(src_errors) + " source errors)", result=res)
                return res
            _stage(store, run_dir, summary, "onepass", {"seeds": seeds}, args, _onepass,
                   lambda r: {"found": r["found"], "sources_error": r["sources_error"],
                              "outcome": r.get("outcome")})

        # 2. certificate transparency
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

        # 3. passive subdomains
        def _subs():
            total = 0
            quota = False
            outcomes = []
            per_source: list = []
            for d in seeds:
                r = tools.t_subs(store, d, engines=args.engines,
                                 timeout=tool_timeout)
                total += r["count"]
                quota = quota or bool(r.get("quota_exhausted"))
                outcomes.append(r.get("outcome") or core.OUTCOME_OK)
                per_source.extend(r.get("per_source") or [])
            oc = core.combine_outcome(*outcomes)
            res = {"found": total, "outcome": oc, "per_source": per_source}
            if quota:
                # surfaced through coverage.unavailable, never as "no assets"
                res["quota_exhausted"] = True
            # subfinder + uncover both dead used to return a clean count=0 and
            # checkpoint "done". That is the difference between "this domain has
            # no subdomains" and "we never actually asked".
            if oc == core.OUTCOME_FAILED:
                raise core.StageError(
                    "subs: every source failed (" +
                    ",".join(sorted({p.get("id", "?") for p in per_source
                                     if p.get("outcome") in (core.OUTCOME_FAILED,
                                                             core.OUTCOME_TIMEOUT)})) + ")",
                    result=res)
            return res
        _stage(store, run_dir, summary, "subs", {"seeds": seeds, "engines": args.engines},
               args, _subs,
               lambda r: ({"found": r["found"]} |
                          ({"quota_exhausted": True} if r.get("quota_exhausted") else {})))

        # 3.5 brute force (active, raw socket)
        if active and args.brute:
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

        # 4. icp reverse
        if icp_codes and not args.no_icp:
            def _icp():
                r = tools.t_icp(store, icp_codes, engines=args.engines, timeout=tool_timeout)
                res = {"domains": len(r.get("domains", [])),
                       "errors": len(r.get("errors", []))}
                ok = bool(r.get("domains")) or not r.get("errors")
                if not ok:
                    raise core.StageError("icp lookup failed for all codes", result=res)
                return res
            _stage(store, run_dir, summary, "icp", {"codes": icp_codes}, args, _icp,
                   lambda r: {"domains": r["domains"], "errors": r.get("errors", 0)})

        # ---- discovery -> verify / reflow rounds -------------------------
        def dns_resumed() -> dict:
            hosts = [a["canonical"] for a in scoped_rows(0.4)
                     if core.source_tools(a.get("sources") or "") & _DNS_SOURCES]
            return {"resolved": len(hosts), "hosts": hosts, "resumed": True}

        def run_round(round_no: int) -> None:
            # Union of: everything already in scope at >=0.4, plus the
            # user-named seeds. A seed stored at 0.5 qualifies, but keep the
            # explicit union so a future confidence change cannot silently drop
            # the target the caller named.
            all_domains = sorted(set(scoped_domains(0.4)) | set(named))

            def _dns():
                r = tools.t_dns(store, all_domains, timeout=tool_timeout)
                res = {"resolved": r["count"], "wildcard": len(r.get("wildcard", [])),
                       "truncated": r.get("truncated", False)}
                if not r.get("ok", True):
                    raise core.StageError("dnsx rc=" + str(r.get("rc")), result=res)
                return res
            _stage(store, run_dir, summary, "dns",
                   {"domains": all_domains, "round": round_no}, args, _dns,
                   lambda r: {"resolved": r["resolved"], "wildcard": r["wildcard"]},
                   resume=dns_resumed)
            # probe input is ALWAYS the full scoped store set (every resolved
            # row), never the ROW_LIMIT-truncated display list a tool returned
            dns_hosts = dns_resumed()["hosts"]
            summary["dns_hosts"] = len(dns_hosts)

            if not active:
                return
            if dns_hosts:
                def _probe():
                    p = tools.t_httpx(store, dns_hosts, timeout=tool_timeout)
                    res = {"live": p["count"], "truncated": p.get("truncated", False)}
                    if not p.get("ok", True):
                        raise core.StageError("httpx rc=" + str(p.get("rc")), result=res)
                    return res
                _stage(store, run_dir, summary, "probe",
                       {"hosts": dns_hosts, "round": round_no}, args, _probe,
                       lambda r: {"live": r["live"]},
                       resume=lambda: {"live": len(dns_hosts)})
            else:
                summary["stages"].append({"stage": "probe", "skipped": True,
                                          "reason": "no_hosts"})
                _write_status(run_dir, stage="probe", stage_state="skipped")

            ipa = tools.t_ipagg(store, scope=scope)
            summary["stages"].append({"stage": "ipagg",
                                      "candidates": ipa["count_candidates"]})
            _write_status(run_dir, stage="ipagg", stage_state="done",
                          stage_index=len(summary["stages"]),
                          stage_total=summary["_stage_total"])

            if args.ports:
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

            if args.vhost:
                _write_status(run_dir, stage="vhost", stage_state="running")
                vhost_ips = [c["ip"] for c in ipa["candidates"][: args.max_vhost_ips]]
                vhost_hosts = sorted({d for c in ipa["candidates"] for d in c["domains"]}
                                     | set(scoped_domains(0.4)))

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

            if args.crawl:
                _write_status(run_dir, stage="crawl", stage_state="running")
                crawl_urls = []
                for a in scoped_rows(0.7):
                    attrs = a.get("attrs") or {}
                    if attrs.get("url"):
                        crawl_urls.append(attrs["url"])
                crawl_scope = sorted(set(scope) | set(scoped_domains(0.7)))

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

                _write_status(run_dir, stage="extract", stage_state="running")

                def _extract():
                    urls = [a["canonical"] for a in
                            store.get_assets(kind="url", min_conf=0.4, match=scope)
                            if a["canonical"].startswith("http")]
                    ex = tools.t_extract(store, [], urls=urls, timeout=tool_timeout)
                    # Keep the deliverable findings in the summary too: the run
                    # result is what an agent reads (and what lands in
                    # summary.jsonl), and dropping them here meant the redacted
                    # secrets / api paths existed only in a transient stdout
                    # line nobody could see afterwards.
                    summary.setdefault("extract_findings", {})
                    summary["extract_findings"].update({
                        "api_paths": ex.get("api_paths", [])[:200],
                        "api_hosts": ex.get("api_hosts", 0),
                        "secrets": ex.get("secrets") or {},
                        "domains": ex.get("domains", [])[:200],
                        "ips": ex.get("ips", [])[:200],
                    })
                    return {"new_domains": ex["count_domains"],
                            "new_ips": ex["count_ips"],
                            "fetched": ex["fetched"],
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

        for round_no in range(1, rounds + 1):
            if time_budget and (time.monotonic() - t_start) > time_budget:
                stop_reason = "time_budget"
                rounds_log.append({"round": round_no - 1, "new_domains": None,
                                   "stop": stop_reason,
                                   "elapsed_sec": round(time.monotonic() - t_start, 1)})
                break
            before = len(scoped_domains(0.4))
            _write_status(run_dir, stage="round-" + str(round_no), stage_state="running",
                          round=round_no, rounds=rounds,
                          stage_index=len([s for s in summary["stages"]
                                           if s.get("stage") != "ipagg"
                                           and "elapsed" in s or s.get("skipped")]),
                          stage_total=summary["_stage_total"])
            run_round(round_no)
            after = len(scoped_domains(0.4))
            new_domains = max(0, after - before)
            # "No new domains" is NOT convergence while JS work is queued: the
            # bundles whose extraction would surface new domains have simply
            # not been fetched yet. Observed live: 41 candidates, budget 40,
            # one pending -- and the run still declared itself complete.
            try:
                _q = store.js_stats()
            except Exception:
                _q = {}
            js_pending = int(_q.get("pending") or 0) + int(_q.get("failed") or 0)
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
        # runs out mid-engagement). That is only known from the stage results,
        # so fold the runtime finding into the same "unavailable" block instead
        # of leaving it in the stage payload where nobody reads it.
        unavailable = _fold_runtime_unavailable(unavailable, summary["stages"])
        source_errors = sum(int(s.get("sources_error") or 0)
                            for s in summary["stages"] if isinstance(s, dict))
        coverage = {
            "planned_stages": planned,
            "done_stages": done_stages,
            "skipped_stages": skipped_stages,
            "failed_stages": failed_stages,
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
                                                              core.OUTCOME_EMPTY))
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
            # bundles are still queued.
            "js_queue": (store.js_stats() if hasattr(store, "js_stats") else {}),
        }
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
        core.write_jsonl(run_dir / "summary.jsonl", [summary])
        store.finish_run(run_id, summary)
        _write_status(run_dir, stage="done", state="completed", stage_state="done",
                      counts=counts, endpoints=endpoints,
                      result=summary["result"], coverage=coverage,
                      stage_index=len(done_stages) + len(skipped_stages),
                      stage_total=summary["_stage_total"])
        out(summary)
        return rc
    except Exception as exc:
        _write_status(run_dir, state="failed", error=repr(exc)[:500],
                      last_error={"type": type(exc).__name__, "message": str(exc)[:300]})
        raise
    finally:
        store.close()


def cmd_run(args) -> int:
    """Start or resume a collection.

    Three modes, one pipeline: foreground (default), --background (detached
    worker + run id returned immediately) and --resume <run_id> (reattach to an
    existing run, honouring its checkpoints).
    """
    if getattr(args, "resume", ""):
        return _resume_run(args)
    if getattr(args, "background", False):
        return _start_background(args)
    return _run_pipeline(args)


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="findinfo",
                                description="asset reconnaissance skill for AI agents")
    p.add_argument("--task", default="",
                   help="per-engagement state dir (~/.findinfo/tasks/<name>): "
                        "isolates the asset graph so other engagements cannot "
                        "leak into --from-store. Overrides FINDINFO_TASK.")
    p.add_argument("--home", default="",
                   help="state root (default ~/.findinfo, or $FINDINFO_HOME). "
                        "Follow-up commands echo this so a new process addresses "
                        "the same asset graph.")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="check bundled tools and api keys")
    d.set_defaults(func=cmd_doctor)

    e = sub.add_parser("entity", help="brand/company name -> subsidiaries, ICP, domains")
    e.add_argument("--name", required=True)
    e.add_argument("--invest", type=int, default=51)
    e.add_argument("--deep", type=int, default=2)
    e.add_argument("--out", default="")
    e.set_defaults(func=cmd_entity)

    c = sub.add_parser("certs", help="certificate transparency expansion")
    c.add_argument("--domain", required=True)
    c.set_defaults(func=cmd_certs)

    i = sub.add_parser("icp", help="ICP record -> domains (fofa/quake/hunter)")
    i.add_argument("--code", action="append", help="repeatable")
    i.add_argument("--from-store", action="store_true")
    i.add_argument("--engines", default="fofa,quake,hunter")
    i.set_defaults(func=cmd_icp)

    pa = sub.add_parser("passive", help="15-source passive collection via bundled Rust onepass")
    pa.add_argument("--domain", action="append")
    pa.add_argument("--from-store", action="store_true")
    pa.add_argument("--sources", default="", help="comma separated source ids (see: onepass sources)")
    pa.add_argument("--min-conf", type=float, default=0.0)
    pa.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so omit this and you inherit other engagements' targets.")
    pa.set_defaults(func=cmd_passive)

    br = sub.add_parser("brute", help="DNS brute force via ksubdomain (ACTIVE, needs Npcap)")
    br.add_argument("--domain", required=True)
    br.add_argument("--wordlist", default="wordlists/sub.txt")
    br.add_argument("--bandwidth", default="3m", help="3m/5m/10m, lower = politer")
    br.add_argument("--wildcard", default="basic", choices=["basic", "advanced", "none"])
    br.set_defaults(func=cmd_brute)

    sb = sub.add_parser("subs", help="passive subdomain enumeration")
    sb.add_argument("--domain", action="append")
    sb.add_argument("--from-store", action="store_true")
    sb.add_argument("--engines", default="fofa,quake,hunter,shodan,censys")
    sb.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so omit this and you inherit other engagements' targets.")
    sb.set_defaults(func=cmd_subs)

    dn = sub.add_parser("dns", help="resolve + wildcard filtering")
    dn.add_argument("--domain", action="append")
    dn.add_argument("--from-store", action="store_true")
    dn.add_argument("--min-conf", type=float, default=0.4)
    dn.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so omit this and you inherit other engagements' targets.")
    dn.set_defaults(func=cmd_dns)

    pr = sub.add_parser("probe", help="httpx liveness / tech / ip mapping (ACTIVE)")
    pr.add_argument("--host", action="append")
    pr.add_argument("--from-store", action="store_true")
    pr.add_argument("--min-conf", type=float, default=0.7)
    pr.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so omit this and you inherit other engagements' targets.")
    pr.set_defaults(func=cmd_probe)

    ia = sub.add_parser("ipagg", help="group domains by ip, drop CDN")
    ia.add_argument("--ip", action="append")
    ia.set_defaults(func=cmd_ipagg)

    po = sub.add_parser("ports", help="naabu port scan (ACTIVE)")
    po.add_argument("--ip", action="append")
    po.add_argument("--top-ports", type=int, default=1000)
    po.set_defaults(func=cmd_ports)

    vh = sub.add_parser("vhost", help="Host header collision -> internal services (ACTIVE)")
    vh.add_argument("--ip", required=True)
    vh.add_argument("--host", action="append")
    vh.add_argument("--from-store", action="store_true")
    vh.add_argument("--domain", action="append",
                    help="base domain for bare wordlist labels (repeatable; "
                         "defaults to parents/base domains in the store)")
    vh.add_argument("--wordlist", default="",
                    help="prefix list; bare labels are qualified with --domain")
    vh.add_argument("--ports", default="80,443")
    vh.add_argument("--threads", type=int, default=20)
    vh.add_argument("--no-skip-live", action="store_true",
                    help="collide even hosts already confirmed live (default: skip them)")
    vh.set_defaults(func=cmd_vhost)

    cr = sub.add_parser("crawl", help="katana crawl (ACTIVE)")
    cr.add_argument("--url", action="append")
    cr.add_argument("--from-store", action="store_true")
    cr.add_argument("--depth", type=int, default=3)
    cr.add_argument("--domain", action="append",
                    help="scope the crawl to these domains (repeatable); with "
                         "--from-store it also limits which URLs are picked up. "
                         "Without it the scope is derived from the seed URLs' "
                         "registrable domains.")
    cr.set_defaults(func=cmd_crawl)

    ex = sub.add_parser("extract", help="leaked domains/IPs from crawl output")
    ex.add_argument("--from-run", default="")
    ex.add_argument("--from-store", action="store_true",
                    help="use URL assets already in the store (reflow loop)")
    ex.add_argument("--domain", action="append",
                    help="restrict --from-store URLs to these domains (repeatable); "
                         "avoids re-fetching another engagement's historical assets")
    ex.add_argument("--url", action="append")
    ex.set_defaults(func=cmd_extract)

    as_ = sub.add_parser("assets", help="list / export asset graph")
    as_.add_argument("--kind", default="all",
                     choices=["all", "company", "icp", "domain", "ip", "url", "endpoint"])
    as_.add_argument("--min-conf", type=float, default=0.0)
    as_.add_argument("--limit", type=int, default=500)
    as_.add_argument("--export", default="")
    as_.set_defaults(func=cmd_assets)

    rp = sub.add_parser("report", help="final deliverables: report.json (agent) + report.html (human)")
    rp.add_argument("--match", action="append",
                    help="scope to these domain suffixes (repeatable); with --run and "
                         "no --match the run's own scope is used")
    rp.add_argument("--run", default="",
                    help="take the scope from this run id when --match is omitted")
    rp.add_argument("--min-conf", type=float, default=0.3)
    rp.add_argument("--limit", type=int, default=300, help="hosts kept in the digest")
    rp.add_argument("--ep-limit", type=int, default=400, help="endpoints kept in the digest")
    rp.add_argument("--json-limit", type=int, default=0,
                    help="cap arrays inside report.json (0 = same as the md/html view)")
    rp.add_argument("--out", default="", help="output dir (default ~/.findinfo/reports/<stamp>-<slug>)")
    rp.add_argument("--slug", default="", help="label for the default output dir")
    rp.add_argument("--engagement", default="default", help="read stage checkpoints for this run id")
    rp.add_argument("--print-md", action="store_true", help="also return the markdown text")
    rp.add_argument("--print-json", action="store_true", help="also return the full digest")
    rp.set_defaults(func=cmd_report)

    cl = sub.add_parser("clean", help="trim the shared asset graph (keep/match/all)")
    cl.add_argument("--keep", action="append",
                    help="keep only assets under these domains; delete the rest")
    cl.add_argument("--match", action="append",
                    help="delete only assets under these domains")
    cl.add_argument("--kind", action="append",
                    choices=["company", "icp", "domain", "ip", "url", "endpoint"],
                    help="limit to these asset kinds (repeatable; default all)")
    cl.add_argument("--all", action="store_true",
                    help="delete every asset and endpoint (requires --yes)")
    cl.add_argument("--yes", action="store_true",
                    help="confirm the destructive --all wipe; without it --all only reports")
    cl.add_argument("--dry-run", action="store_true",
                    help="show what would be deleted, delete nothing")
    cl.add_argument("--vacuum", action="store_true", help="reclaim disk after deleting")
    cl.set_defaults(func=cmd_clean)

    st = sub.add_parser("status", help="inspect one run (state/progress/result/coverage)")
    st.add_argument("--run", default="", help="run id (or run dir); default = newest")
    st.set_defaults(func=cmd_status)

    wt = sub.add_parser("wait", help="bounded wait for progress or completion")
    wt.add_argument("--run", required=True, help="run id from run --background")
    wt.add_argument("--timeout", type=float, default=30.0,
                    help="max seconds to block (default 30); timeout is NOT a failure")
    wt.add_argument("--since", type=int, default=None,
                    help="seq to compare against: return early when it changes")
    wt.add_argument("--full", action="store_true",
                    help="return the complete payload (including coverage/run_dir)")
    wt.set_defaults(func=cmd_wait)

    cn = sub.add_parser("cancel", help="stop a running job")
    cn.add_argument("--run", required=True)
    cn.add_argument("--reason", default="user")
    cn.set_defaults(func=cmd_cancel)

    rs = sub.add_parser("runs", help="list recent runs (state/target/run id)")
    rs.add_argument("--limit", type=int, default=20)
    rs.add_argument("--state", default="", help="filter: queued/running/completed/failed/cancelled")
    rs.add_argument("--active", action="store_true", help="only in-flight runs")
    rs.set_defaults(func=cmd_runs)

    wk = sub.add_parser("__worker", help=argparse.SUPPRESS)
    wk.add_argument("run_dir")
    wk.set_defaults(func=cmd_worker)

    rn = sub.add_parser("run", help="full pipeline: entity -> certs -> subs -> dns -> probe")
    rn.add_argument("--name", default="")
    rn.add_argument("--domain", action="append")
    rn.add_argument("--active", action="store_true", help="enable traffic-generating stages")
    rn.add_argument("--ports", action="store_true", help="naabu scan (implies --active)")
    rn.add_argument("--vhost", action="store_true", help="host collision (implies --active)")
    rn.add_argument("--crawl", action="store_true", help="katana crawl (implies --active)")
    rn.add_argument("--brute", action="store_true", help="ksubdomain DNS brute force (implies --active, needs Npcap)")
    rn.add_argument("--brute-wordlist", default="wordlists/sub.txt")
    rn.add_argument("--brute-bandwidth", default="3m")
    rn.add_argument("--depth", type=int, default=3)
    rn.add_argument("--invest", type=int, default=51)
    rn.add_argument("--deep", type=int, default=2)
    rn.add_argument("--entity-timeout", type=int, default=1200,
                    help="max seconds for the ENScan entity stage (0 = unlimited); "
                         "on timeout the stage fails and is retried later")
    rn.add_argument("--engines", default="fofa,quake,hunter,shodan,censys")
    rn.add_argument("--no-icp", action="store_true")
    rn.add_argument("--no-onepass", action="store_true", help="skip the onepass stage")
    rn.add_argument("--top-ports", type=int, default=1000)
    rn.add_argument("--max-seed", type=int, default=5)
    rn.add_argument("--max-vhost-ips", type=int, default=10)
    rn.add_argument("--force-stage", action="store_true",
                    help="ignore finished-stage checkpoints and re-run every stage")
    rn.add_argument("--background", action="store_true",
                    help="run in a detached worker and return a run id immediately")
    rn.add_argument("--resume", default="", metavar="RUN_ID",
                    help="resume an existing run (honours its checkpoints)")
    rn.add_argument("--rounds", type=int, default=1,
                    help="discovery->verify rounds; stops early when no new in-scope asset appears")
    rn.add_argument("--time-budget", type=float, default=0.0,
                    help="stop starting new rounds after this many seconds (0 = unlimited)")
    rn.add_argument("--task-timeout", type=float, default=0.0,
                    help="hard limit for the whole job in background mode (0 = none)")
    rn.add_argument("--tool-timeout", type=int, default=0,
                    help="per-tool timeout in seconds passed to each collector (0 = tool default)")
    rn.set_defaults(func=cmd_run)

    # Accept --task AFTER the subcommand too ("run --task X"), which the docs
    # have shown all along. Without this, argparse prefix-matches it onto
    # --task-timeout and fails with "invalid float value: 'X'" -- pointing the
    # caller at the wrong fix. default=SUPPRESS is essential: a real default
    # here would overwrite the global --task parsed before the subcommand.
    for _name, _sub in sub.choices.items():
        _sub.add_argument(
            "--task", default=argparse.SUPPRESS, metavar="NAME",
            help="per-engagement state dir; same as the global --task "
                 "(the late form is the one shown in the docs)")
        _sub.add_argument(
            "--home", default=argparse.SUPPRESS, metavar="DIR",
            help="state root; same as the global --home")

    return p


def main(argv: list[str]) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    if getattr(args, "task", ""):
        # keep it visible to child processes too (already set pre-import)
        os.environ["FINDINFO_TASK"] = args.task
    if getattr(args, "home", ""):
        os.environ["FINDINFO_HOME"] = args.home
    _mark_explicit(args, argv)
    try:
        rc = args.func(args)
        return int(rc or 0)
    except core.StageError as exc:
        out({"error": "stage_failed", "message": str(exc),
             "partial": exc.result or None})
        return 5
    except core.ToolMissing as exc:
        out({"error": "tool_missing", "message": str(exc)})
        return 4
    except core.FindInfoError as exc:
        out({"error": "error", "message": str(exc)})
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        out({"error": "unexpected", "message": repr(exc)})
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
