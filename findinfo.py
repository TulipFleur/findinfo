#!/usr/bin/env python
"""findinfo - asset reconnaissance skill CLI.

Every subcommand prints one JSON object to stdout (machine-readable for the agent)
and human-readable progress to stderr.

    python findinfo.py doctor
    python findinfo.py entity --name "Example Corp"
    python findinfo.py subs   --domain example.com
    python findinfo.py probe  --from-store
    python findinfo.py run    --name "Example Corp" --active
"""
from __future__ import annotations

import argparse
import shlex
import dataclasses
import json
import os
import sys
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
    "assets", "status", "wait", "cancel", "runs", "run", "map", "brief", "__worker",
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


def _offline_requested(argv: list[str]) -> tuple:
    """Detect a read-only invocation BEFORE any runtime import (F09).

    Returns ("doctor", True) for `doctor --offline`, ("run", True) for a
    `run ... --dry-run`, else (None, False). Only a cheap token scan: this runs
    before lib.core, so importing the parser (and thus the runtime) would
    defeat the purpose -- core's import resolves HOME and creates the home
    layout, which is exactly the side effect an offline mode promises not to
    have.
    """
    if not argv:
        return None, False
    sub = ""
    skip = False
    for a in argv:
        if skip:
            skip = False
            continue
        if a in ("--task", "--home"):
            skip = True            # global options take a value: skip it
            continue
        if a.startswith("--"):
            continue
        sub = a
        break
    if sub == "doctor" and _flag_present(argv, "--offline"):
        return "doctor", True
    if sub == "run" and _flag_present(argv, "--dry-run"):
        return "run", True
    return None, False


def _flag_present(argv: list[str], flag: str) -> bool:
    for a in argv:
        if a == flag or a.startswith(flag + "="):
            return True
    return False


def _run_offline(sub: str, argv: list[str]) -> int:
    """Answer an offline command with the pure modules only.

    No lib.core, no config, no credentials, no home/db creation. Everything
    that would need live facts is reported as unverified.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib import offline as offline_mod
    from lib import spec as spec_mod
    if sub == "doctor":
        _emit_offline(offline_mod.doctor_offline())
        return 0
    # run --dry-run: build the plan from RunSpec + the stage planner, without
    # importing the runtime. The planner needs only flag logic.
    args = _parse_offline_args(argv)
    rs = spec_mod.from_cli(args)
    effective = None
    if _prescan_option(argv, "--resume"):
        effective = _offline_resume_preview(argv, spec_mod)
        effective_rs = effective.pop("_effective_spec", None)
        if effective_rs is not None:
            rs = effective_rs
    active = bool(rs.active or rs.ports or rs.vhost or rs.crawl or rs.brute)
    planned = _plan_stages_pure(rs, active)
    identity_questions = []
    if rs.name and not rs.domain:
        identity_questions.append(
            "brand-only run: entity anchoring must resolve the subject before "
            "any discovery runs; ambiguous identity reports identity_ambiguous")
    if rs.name and rs.domain:
        identity_questions.append(
            "explicit domains seed the run directly; the brand is only extra "
            "context for related-asset evidence")
    payload = offline_mod.plan_preview(
        run_spec=rs, planned_stages=planned, active=active,
        disabled=[x for x in ("entity", "onepass", "icp", "brute")
                  if x not in planned],
        identity_questions=identity_questions,
        limits={"rounds": rs.rounds, "time_budget_sec": rs.time_budget,
                "task_timeout_sec": rs.task_timeout,
                "tool_timeout_sec": rs.tool_timeout,
                "engines": rs.engines, "max_seed": rs.max_seed,
                "top_ports": rs.top_ports, "max_vhost_ips": rs.max_vhost_ips,
                "depth": rs.depth},
        background=_flag_present(argv, "--background"),
        resume=_prescan_option(argv, "--resume") or None,
        effective=effective)
    _emit_offline(payload)
    return 0


def _emit_offline(obj) -> None:
    """stdout encoder for offline mode (no lib.core import)."""
    import json as _json
    ascii_safe = (os.environ.get("FINDINFO_EMIT_UTF8") or "").lower() not in (
        "1", "true", "yes")
    sys.stdout.write(_json.dumps(obj, ensure_ascii=ascii_safe,
                                 separators=(",", ":")) + chr(10))
    sys.stdout.flush()


def _parse_offline_args(argv: list[str]):
    """A tiny namespace for the offline planner: reads flags, no runtime.

    Deliberately NOT the full parser (which lives with the runtime): the
    offline path only needs the execution-affecting flags RunSpec understands.
    Unknown/absent flags take their CLI defaults, exactly like a real parse.
    """
    import argparse as _ap

    def _val(flag, default, cast=str):
        for i, a in enumerate(argv):
            if a.startswith(flag + "="):
                return cast(a.split("=", 1)[1])
            if a == flag and i + 1 < len(argv):
                return cast(argv[i + 1])
        return default

    domains = [argv[i + 1] for i, a in enumerate(argv)
               if a == "--domain" and i + 1 < len(argv)]
    domains += [a.split("=", 1)[1] for a in argv if a.startswith("--domain=")]
    return _ap.Namespace(
        name=_val("--name", ""), domain=domains, task=_TASK or "",
        active=_flag_present(argv, "--active"),
        ports=_flag_present(argv, "--ports"),
        vhost=_flag_present(argv, "--vhost"),
        crawl=_flag_present(argv, "--crawl"),
        brute=_flag_present(argv, "--brute"),
        supplier=_flag_present(argv, "--supplier"),
        branch=_flag_present(argv, "--branch"),
        brute_wordlist=_val("--brute-wordlist", "wordlists/sub.txt"),
        brute_bandwidth=_val("--brute-bandwidth", "3m"),
        depth=_val("--depth", 3, int), invest=_val("--invest", 51, int),
        deep=_val("--deep", 1, int),
        entity_timeout=_val("--entity-timeout", 1200, int),
        engines=_val("--engines", "fofa,quake,hunter,shodan,censys"),
        top_ports=_val("--top-ports", 1000, int),
        max_seed=_val("--max-seed", 0, int),
        max_vhost_ips=_val("--max-vhost-ips", 10, int),
        no_icp=_flag_present(argv, "--no-icp"),
        no_onepass=_flag_present(argv, "--no-onepass"),
        no_mapping=_flag_present(argv, "--no-mapping"),
        remap=_flag_present(argv, "--remap"),
        force_stage=_flag_present(argv, "--force-stage"),
        rounds=_val("--rounds", 1, int),
        time_budget=_val("--time-budget", 0.0, float),
        task_timeout=_val("--task-timeout", 0.0, float),
        tool_timeout=_val("--tool-timeout", 0, int),
        background=_flag_present(argv, "--background"),
        resume=_val("--resume", ""),
    )


def _plan_stages_pure(rs, active: bool) -> list:
    """The stage plan from a RunSpec, with no runtime import.

    Mirrors findinfo._plan_stages exactly; a drift between them is caught by
    the plan-consistency test (a dry run must name the stages a real run
    plans).
    """
    plan = []
    if rs.name:
        plan.append("entity")
    if not rs.no_onepass:
        plan.append("onepass")
    plan += ["certs", "subs"]
    if active and rs.brute:
        plan.append("brute")
    if not getattr(rs, "no_mapping", False):
        plan.append("mapping")
    plan.append("dns")
    if active:
        plan += ["probe", "ipagg"]
        if rs.ports:
            plan.append("ports")
        if rs.vhost:
            plan.append("vhost")
        if rs.crawl:
            plan += ["crawl", "extract"]
    return plan


def _offline_resume_preview(argv: list[str], spec_mod) -> dict:
    """Read the job spec's METADATA only (allowed: not a config read)."""
    rid = _prescan_option(argv, "--resume")
    if not rid:
        return {}
    home = os.environ.get("FINDINFO_HOME") or str(Path.home() / ".findinfo")
    task = _TASK or ""
    base = Path(home) / "tasks" / task / "runs" if task else Path(home) / "runs"
    candidate = base / rid
    if not candidate.is_dir():
        matches = sorted(base.glob(rid + "*")) if base.is_dir() else []
        candidate = matches[-1] if len(matches) == 1 else None
    if candidate is None or not (candidate / "job.json").exists():
        return {"source": "error", "error": "run not found: " + str(rid)}
    try:
        import json as _json
        spec_blob = _json.loads((candidate / "job.json").read_text(
            encoding="utf-8"))
    except Exception as exc:
        return {"source": "error", "error": str(exc)[:160]}
    out = {"source": "job.json", "run_id": spec_blob.get("run_id") or candidate.name,
           "attempt": spec_blob.get("attempt"),
           "note": "preview only: spec metadata read, no job state is changed"}
    try:
        # Reconstruct the effective identity from the stored spec (its
        # run_spec block, else a parse of the stored argv) and report the
        # target/scope/stages/limits a resume would actually run.
        rs = spec_mod.from_stored(spec_blob, _parse_offline_args)
        if rs is not None:
            rs = spec_mod.resume_from_cli(
                rs, _parse_offline_args(argv), argv=argv)
            active = bool(rs.active or rs.ports or rs.vhost or rs.crawl
                          or rs.brute)
            out.update({
                "target": rs.target_label,
                "scope": list(rs.domain),
                "planned_stages": _plan_stages_pure(rs, active),
                "limits": {"rounds": rs.rounds,
                           "time_budget_sec": rs.time_budget,
                           "task_timeout_sec": rs.task_timeout,
                           "tool_timeout_sec": rs.tool_timeout,
                           "engines": rs.engines},
                "argv": rs.to_worker_argv(),
            })
            out["_effective_spec"] = rs
    except ValueError as exc:
        out.update(source="rejected", error="resume rejected: " + str(exc))
    except Exception as exc:
        out["effective_error"] = str(exc)[:200]
    return out


_OFFLINE_SUB, _OFFLINE = _offline_requested(sys.argv[1:])
if _OFFLINE:
    sys.exit(_run_offline(_OFFLINE_SUB, sys.argv[1:]))

from lib import core, jobs, report, tools
from lib import metered as metered_mod
from lib import mapdispatch  # noqa: F401  (findinfo.mapdispatch: the tests' patch point)
from lib import spec as spec_mod

# The run pipeline lives in lib/pipeline.py. Its names stay importable from
# here: the subcommands below call them, and callers/tests address them as
# findinfo.<name>. Patch the pipeline module itself to change its behaviour.
from lib import pipeline
from lib.pipeline import (  # noqa: E402,F401  (re-exported)
    _active_enabled,
    _adopt_membership,
    _attach,
    _BLOCKING_TOOLS,
    _coverage_unavailable,
    _current_attempt,
    _DNS_SOURCES,
    _engine_key,
    _fold_runtime_unavailable,
    _Heartbeat,
    _INFORMATIONAL_STAGES,
    _input_hash,
    _not_run_stages,
    _plan_stages,
    _round_plan,
    _run_pipeline,
    _stage,
    _subs_stage_entry,
    _subs_stage_inputs,
    _worker_run_dir,
    _write_status,
    ENGAGEMENT,
)


def out(obj) -> None:
    core.emit(obj)


# ---------------------------------------------------------------- commands
def cmd_doctor(args) -> None:
    if getattr(args, "offline", False):
        out(tools.doctor_offline())
        return
    if getattr(args, "check_mapping", False):
        # Verification of engine credentials AND query syntax: one -limit 1
        # query per configured engine, reported per engine. It runs unattended
        # -- this skill is driven by an agent, and an agent cannot answer a
        # consent prompt. The cost is bounded by construction (one row per
        # engine), so the old --yes-spend-quota gate only blocked the caller
        # that was supposed to use it. The flag is still accepted (and ignored)
        # so an existing command line keeps working.
        domain = core.canon_user_domain(getattr(args, "domain", "") or "")
        if not domain:
            raise core.FindInfoError(
                "doctor --check-mapping needs --domain <your-domain>")
        import lib.mapdispatch as mapdispatch
        out({"check_mapping": mapdispatch.check_engines(
            domain, getattr(args, "engines", None),
            timeout=getattr(args, "tool_timeout", 0) or 30)})
        return
    out(tools.doctor())


def cmd_entity(args) -> None:
    store = core.Store()
    try:
        res = tools.t_enscan(store, args.name, invest=args.invest, deep=args.deep,
                             outdir=Path(args.out) if args.out else None,
                             timeout=args.tool_timeout,
                             supplier=getattr(args, "supplier", False),
                             branch=getattr(args, "branch", False))
        out(res)
    finally:
        store.close()


def cmd_certs(args) -> None:
    store = core.Store()
    try:
        out(tools.t_certs(store, args.domain, timeout=args.tool_timeout))
    finally:
        store.close()


def cmd_passive(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store or not domains:
            domains = _domains_from_store(
                store, 0.7, _store_scope(args, args.scope, "--scope", "passive",
                                        store=store))
        srcs = [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else None
        merged = []
        for d in domains:
            merged.append(tools.t_onepass(store, d, sources=srcs,
                                          min_confidence=args.min_conf,
                                          timeout=args.tool_timeout))
        out(_with_scope(args, {"domains": merged,
                              "total": sum(m.get("count", 0) for m in merged)}))
    finally:
        store.close()


def cmd_brute(args) -> None:
    store = core.Store()
    try:
        out(tools.t_brute(store, args.domain, wordlist=args.wordlist,
                          bandwidth=args.bandwidth, wildcard=args.wildcard,
                          timeout=args.tool_timeout))
    finally:
        store.close()


def cmd_icp(args) -> None:
    store = core.Store()
    try:
        codes = args.code or []
        if args.from_store:
            # The ICP table is shared across engagements, so an unscoped
            # --from-store reverse-lookups another project's filings (and
            # spends quota on them). Scope it like every other store read.
            scope = _store_scope(args, args.scope, "--scope", "icp",
                                 store=store)
            codes = [a["canonical"] for a in
                     store.get_assets(kind="icp", match=scope)]
        out(_with_scope(args, tools.t_icp(store, codes, engines=args.engines,
                                         timeout=args.tool_timeout)))
    finally:
        store.close()


def cmd_map(args) -> None:
    """The ONLY command that spends mapping quota (batch 1).

    Same ledger as the run pipeline's `mapping` stage: a question this task
    already paid for is reused, not re-asked. `--remap` is the explicit opt-in
    for asking again. Passive collection lives in `passive`/`subs`, which are
    keyless by construction.
    """
    import lib.mapdispatch as mapdispatch
    import lib.mapping as mapping_mod
    store = core.Store()
    try:
        try:
            mapping_mod.ensure_schema(store)
        except Exception as exc:
            core.log("mapping schema init failed: " + repr(exc)[:160])
        domains: list = []
        codes: list = []
        if args.domain:
            domains = [core.canon_user_domain(d) for d in args.domain]
            domains = [d for d in domains if d]
            if not domains:
                raise core.FindInfoError("invalid domain: " + ",".join(args.domain))
        if args.icp:
            codes = list(args.icp)
        # A company NAME is a legitimate search value: when ENScan anchors a
        # subject but files no domain, the engines are the only way to find
        # one. The value is asked verbatim, in the kind the caller picked.
        names = [str(n).strip() for n in (getattr(args, "name", None) or [])
                 if str(n).strip()]
        name_kind = getattr(args, "kind", "domain") or "domain"
        if names:
            if name_kind == "icp":
                codes = list(codes) + names
            else:
                # a name is not a domain: it must NOT go through
                # canon_user_domain (that would drop every Chinese name and
                # silently empty the search). The engine's quoted-term guard
                # in uncover_query is what keeps it safe.
                domains = list(domains) + names
        if args.from_store or not (domains or codes):
            scope = _store_scope(args, args.scope, "--scope", "map",
                                 store=store)
            if not domains:
                domains = [a["canonical"] for a in
                           store.get_assets(kind="domain", match=scope)]
            if not codes:
                codes = [a["canonical"] for a in
                         store.get_assets(kind="icp", match=scope)]
        # a CLI invocation owns no worker run: use a stable pseudo run id so
        # the ledger row is attributable without pretending a job exists
        run_key = "cli"
        remap = bool(getattr(args, "remap", False))
        dom = mapdispatch.ask_all(store, run_key, "domain", domains,
                                  engines=args.engines, remap=remap,
                                  timeout=args.tool_timeout)
        icp = mapdispatch.ask_all(store, run_key, "icp", codes,
                                  engines=args.engines, remap=remap,
                                  timeout=args.tool_timeout) if codes else {
            "dispatched": 0, "reused": 0, "failures": [],
            "truncated_sources": [], "skipped_engines": [], "results": []}
        stored = mapdispatch.store_results(
            store, list(dom.get("results") or []) + list(icp.get("results") or []))
        out({"stored": stored,
             "domains": {"dispatched": dom.get("dispatched", 0),
                         "reused": dom.get("reused", 0),
                         "failures": dom.get("failures", []),
                         "skipped_engines": dom.get("skipped_engines", [])},
             "icp": {"dispatched": icp.get("dispatched", 0),
                     "reused": icp.get("reused", 0),
                     "failures": icp.get("failures", []),
                     "skipped_engines": icp.get("skipped_engines", [])},
             "truncated_sources": sorted(set(
                 list(dom.get("truncated_sources") or []) +
                 list(icp.get("truncated_sources") or []))),
             "coverage": mapping_mod.coverage(store),
             "note": ("each engine+question is asked once per task; an "
                      "answered question is reused, --remap is the explicit "
                      "opt-in for asking again")})
    finally:
        store.close()


def cmd_subs(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store:
            domains = _domains_from_store(
                store, 0.7, _store_scope(args, args.scope, "--scope", "subs",
                                        store=store))
        merged = []
        for d in domains:
            r = tools.t_subs(store, d, engines=args.engines,
                             timeout=args.tool_timeout)
            merged.append(r)
        out(_with_scope(args, {"domains": merged,
                              "total": sum(m.get("count", 0) for m in merged)}))
    finally:
        store.close()


def _domains_from_store(store, min_conf: float, match: list[str] | None = None) -> list[str]:
    """Domain assets from the shared graph, optionally scoped to given suffixes.

    The graph is shared across engagements on purpose (multi-agent merge), so
    every stage that reads it back must pass the current engagement's domains.
    Without `match` a second engagement inherits the first one's targets.

    `match` entries are USER-typed (--domain/--scope), so they go through
    canon_user_domain: a dev.corp.local scope used to be silently emptied by
    the strict de-noiser and probe/crawl then reported "0 live / 0 tested"
    with ok:true -- the user's target simply vanished.
    """
    scope = [core.canon_user_domain(d) for d in (match or [])]
    scope = [d for d in scope if d]
    return [a["canonical"] for a in
            store.get_assets(kind="domain", min_conf=min_conf, match=scope or None)]


def _note_scope(args, source: str) -> None:
    """Remember how this command's store read was scoped (published in output)."""
    try:
        args._scope_source = source
    except Exception:
        pass


def _with_scope(args, payload):
    """Attach `scope_source` to a command's JSON answer.

    A caller must be able to tell an INFERRED scope from one it typed: the
    inferred one is a guess about the store's contents, and guessing wrong is
    how one target's assets end up in another target's stage.
    """
    if isinstance(payload, dict) and "scope_source" not in payload:
        src = getattr(args, "_scope_source", "")
        if src:
            return dict(payload, scope_source=src)
    return payload


def _store_scope(args, values, flag: str, command: str,
                 store=None) -> list[str] | None:
    """Scope of a single-stage command that takes its targets from the store.

    Returns the canonical scope, or None for a deliberate whole-store read.
    Otherwise raises ScopeRequired carrying the scopes the store suggests.

    Policy comes from `scope.unscoped_reads` (lib.core.scope_mode):

    ``infer``   no scope flag, but the store holds exactly ONE registrable
                domain -> use it, and say so via `scope_source:"inferred"`.
                A store mixing targets is still refused: guessing there would
                hand one weaponised asset graph to another engagement.
    ``refuse``  never infer; the strict behaviour.
    ``legacy``  no scope flag -> read everything, loudly (old scripts).

    An explicit scope always wins and is never widened; a scope that
    canonicalises to nothing is refused, never silently treated as "no scope".
    """
    if values:
        accepted, rejected = core.canon_user_scope(values)
        if not accepted:
            raise core.ScopeRequired(
                command + " " + flag + " " + ", ".join(str(v) for v in values) +
                ": no valid domain in it; refusing to widen to the whole store",
                hint="pass a domain, e.g. " + flag + " example.com",
                candidates=core.scope_candidates(store) if store is not None else [])
        if rejected:
            core.log(command + ": ignored invalid " + flag + " value(s): " +
                     ", ".join(rejected))
        _note_scope(args, "explicit")
        return accepted
    if getattr(args, "whole_store", False):
        _note_scope(args, "whole_store")
        return None
    mode = core.scope_mode()
    if mode == "legacy":
        # The old behaviour, kept for scripts written before the gate. It is
        # loud on purpose: a whole-store read is never silent.
        core.log(command + ": scope.unscoped_reads=legacy -> reading EVERY "
                 "asset in this store (other engagements included)")
        _note_scope(args, "legacy")
        return None
    if mode == "infer" and store is not None:
        guessed = core.infer_scope(store)
        if guessed:
            core.log(command + ": no " + flag + " given; inferred scope " +
                     guessed[0] + " from the store (scope.unscoped_reads=infer)")
            _note_scope(args, "inferred")
            return guessed
    raise core.ScopeRequired(
        command + " would take its targets from the whole asset store, which "
        "is shared across engagements",
        hint="pass " + flag + " <domain> (repeatable), give explicit targets, "
             "or --whole-store to read every asset in this store on purpose",
        candidates=core.scope_candidates(store) if store is not None else [])


def _host_bases(hosts: list[str]) -> list[str]:
    """Base domains for bare vhost labels, taken from the hosts being collided.

    The old fallback used the parent of EVERY domain in the shared store, so
    `vhost --wordlist` without --domain sent Host headers built on other
    engagements' domains.
    """
    out: list[str] = []
    for h in hosts:
        cd = core.canon_user_domain(h)
        base = (core.registrable_domain(cd) or cd) if cd else None
        if base and base not in out:
            out.append(base)
    return out


def cmd_dns(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store or not domains:
            domains = _domains_from_store(
                store, args.min_conf, _store_scope(args, args.scope, "--scope", "dns",
                                                  store=store))
        out(_with_scope(args, tools.t_dns(store, domains,
                                         timeout=args.tool_timeout)))
    finally:
        store.close()


def cmd_probe(args) -> None:
    store = core.Store()
    try:
        hosts = args.host or []
        if args.from_store or not hosts:
            hosts = _domains_from_store(
                store, args.min_conf, _store_scope(args, args.scope, "--scope", "probe",
                                                  store=store))
        res = tools.t_httpx(store, hosts, timeout=args.tool_timeout)
        if getattr(args, "repair_titles", False):
            # Re-read titles the OLD decode pipeline destroyed. Those rows
            # hold U+FFFD, which is lossy: the only way back is another fetch
            # of the page body, decoded with the page's own charset. Without
            # this entry an operator had to reach for the raw binary.
            res["title_repair"] = tools.repair_broken_titles(
                store, hosts if args.host else None,
                scope=args.scope, timeout=args.tool_timeout)
        out(_with_scope(args, res))
    finally:
        store.close()


def cmd_ipagg(args) -> None:
    store = core.Store()
    try:
        if args.ip:
            out(_with_scope(args, tools.t_ipagg(store, args.ip,
                                               timeout=args.tool_timeout)))
        else:
            out(_with_scope(args, tools.t_ipagg(
                store, None, timeout=args.tool_timeout,
                scope=_store_scope(args, args.scope, "--scope", "ipagg",
                                   store=store))))
    finally:
        store.close()


def cmd_ports(args) -> None:
    store = core.Store()
    try:
        if args.ip:
            # Explicit addresses are the operator's own decision. An address
            # the operator typed is used VERBATIM, private or not: the
            # private-range guard exists to stop the store from handing over
            # scraped internal addresses, not to second-guess --ip.
            res = tools.t_ports(store, args.ip, top_ports=args.top_ports,
                                timeout=args.tool_timeout, allow_private=True)
            out(_with_scope(args, res))
            return
        # From the store, only addresses OWNED by an in-scope domain (their
        # parent): an IP scraped out of a page/JS has no owner, an ICP-lookup
        # IP is owned by a filing number, and neither is a scan target.
        scope = _store_scope(args, args.scope, "--scope", "ports", store=store)
        owned = [a["canonical"] for a in store.get_assets(kind="ip", match=scope)]
        # Drop private/reserved addresses BEFORE handing the list over, so a
        # scan never even targets the operator's own network. t_ports() also
        # refuses them (the run pipeline calls it directly), which is why the
        # two skipped lists are merged instead of one of them being trusted.
        public = [ip for ip in owned if core.is_public_ip(ip)]
        dropped = [ip for ip in owned if not core.is_public_ip(ip)]
        res = tools.t_ports(store, public, top_ports=args.top_ports,
                            timeout=args.tool_timeout)
        skipped = list(dict.fromkeys(list(res.get("skipped_private") or []) + dropped))
        res["skipped_private"] = skipped
        out(_with_scope(args, res))
    finally:
        store.close()


def cmd_vhost(args) -> None:
    store = core.Store()
    try:
        hosts = args.host or []
        if args.from_store or not hosts:
            hosts = _domains_from_store(
                store, 0.4, _store_scope(args, args.domain, "--domain", "vhost",
                                         store=store))
        if args.wordlist:
            # Accept the same bare names as `brute --wordlist` ("vhost" ->
            # wordlists/vhost.txt); a plain Path() read breaks that contract.
            raw = [w.strip() for w in
                   tools.resolve_wordlist(args.wordlist).read_text(encoding="utf-8").splitlines()
                   if w.strip()]
            bases = args.domain or _host_bases(hosts)
            extra = tools.expand_host_words(raw, bases)
            core.log("vhost wordlist: " + str(len(raw)) + " words -> " +
                     str(len(extra)) + " hosts from " + str(len(bases)) + " base domain(s)")
            hosts = hosts + extra
        ports = [int(p) for p in (args.ports or "80,443").split(",") if p.strip()]
        out(_with_scope(args, tools.t_vhost(
            store, args.ip, hosts, ports=ports, threads=args.threads,
            timeout=args.tool_timeout, skip_live=not args.no_skip_live)))
    finally:
        store.close()


def cmd_crawl(args) -> None:
    store = core.Store()
    try:
        urls = args.url or []
        scope = core.canon_user_scope(args.domain or [])[0]
        if args.from_store or not urls:
            # an unscoped read used to crawl other engagements' URLs with only
            # a warning in the output; it is refused now (see _store_scope)
            read = _store_scope(args, args.domain, "--domain", "crawl",
                                store=store)
            for a in store.get_assets(kind="domain", min_conf=0.7, match=read):
                attrs = a.get("attrs") or {}
                if attrs.get("url"):
                    urls.append(attrs["url"])
        if not scope:
            # derive from the seeds themselves (registrable, public-suffix aware)
            scope = [core.registrable_domain(core.split_url(u)[0] or "") or ""
                     for u in urls]
            scope = [s for s in scope if s]
        out(_with_scope(
            args,
            tools.t_crawl(store, urls, depth=args.depth,
                          timeout=args.tool_timeout, scope_domains=scope)
            | {"scope": scope}))
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
            # Reflow: take URL assets from the store (written by the
            # crawl stage) instead of making the agent guess run-dir paths.
            # --domain scopes them to the given domains: the store usually
            # mixes other engagements' history, and without it the JS of
            # unrelated sites would be fetched too -- so it is required.
            only = _store_scope(args, args.domain, "--domain", "extract",
                                store=store)
            for a in store.get_assets(kind="url", min_conf=0.4):
                u = a["canonical"]
                if not u.startswith("http"):
                    continue
                if only:
                    h = core.canon_domain(core.split_url(u)[0] or "")
                    if not core.in_scope(h, only):
                        continue
                urls.append(u)
        scope_arg = [d for d in (core.canon_user_scope(args.domain or [])[0] or [])]
        out(_with_scope(args, tools.t_extract(
            store, rows, urls=urls, timeout=args.tool_timeout,
            fetch_limit=getattr(args, "fetch_limit", 0) or None,
            scope=scope_arg)))
    finally:
        store.close()


# Above this size a --print-json payload swamps an agent context;
# the caller still gets its data, but is told where the brief is.
PRINT_JSON_WARN_BYTES = 64 * 1024


def _run_coverage(run_id: str) -> dict:
    """The coverage block of one run, or {} when it cannot be read.

    report.collect() reads the asset graph and knows nothing about which
    stages ran; the gaps live in the run state. The brief must carry them or
    an agent reads "nothing found" as "nothing there".
    """
    if not run_id:
        return {}
    try:
        st = jobs.derive(jobs.read_state(run_id))
    except Exception:
        return {}
    cov = st.get("coverage") or (st.get("result") or {}).get("coverage") or {}
    out = dict(cov) if isinstance(cov, dict) else {}
    # The run's OWN verdict belongs with its gaps: a brief that shows the
    # findings but not "partial, because these stages under-collected" reads
    # as a clean result. Kept under distinct keys so select_coverage/report
    # keep their existing shape.
    res = st.get("result") if isinstance(st.get("result"), dict) else {}
    if res.get("status"):
        out["_result_status"] = res.get("status")
    if res.get("reason"):
        out["_result_reason"] = res.get("reason")
    if res.get("attempt"):
        out["_result_attempt"] = res.get("attempt")
    return out


def _latest_run_for_match(match: list[str], task: str) -> str:
    """Newest run in this task whose scope overlaps `match`, or "".

    Only --match is not enough to find the gaps: the asset graph is shared,
    but every run has its own coverage. Without this fallback a bare
    `brief --match example.com` reads no coverage at all and reports zero
    gaps, which reads as "nothing was missing".
    """
    want = core.canon_scope(match)
    if not want:
        return ""
    for row in jobs.list_runs(limit=200):
        rid = str(row.get("run_id") or "")
        if not rid:
            continue
        spec = jobs.read_spec(rid)
        if task and str(spec.get("task") or "") not in ("", task):
            continue
        scope = core.canon_scope(spec.get("scope") or [])
        if scope and set(scope) & set(want):
            return rid
    return ""


def _resolve_coverage(args) -> dict:
    """Where the gaps come from, in a fixed order brief and report both use.

    --run wins (the caller named a run); then an explicit --engagement that is
    not the default; then the newest run in this task matching --match. When
    nothing matches, the result says known=False instead of showing an empty
    gap list that looks like a clean report.
    """
    run_id = str(getattr(args, "run", "") or "").strip()
    engagement = str(getattr(args, "engagement", "") or "").strip()
    if run_id:
        return core.select_coverage(_run_coverage(run_id), run_id)
    if engagement and engagement != ENGAGEMENT:
        return core.select_coverage(_run_coverage(engagement), engagement)
    found = _latest_run_for_match(list(getattr(args, "match", None) or []),
                                  str(getattr(args, "task", "") or ""))
    if found:
        return core.select_coverage(_run_coverage(found), found)
    return core.empty_coverage()


def _resolve_report_scope(args) -> list:
    """Shared scope resolution for report and brief: validate --match, then
    fall back to the run's own scope. Both commands answer the same question
    ("what does the library hold for this target") so they must reject and
    resolve scopes identically -- an agent switching between them should
    never see one command accept what the other refuses."""
    if args.match and not core.canon_scope(args.match):
        raise core.FindInfoError(
            "no valid domain in --match: " + ",".join(args.match) +
            " (a garbage scope must fail loudly, not degrade to a full-library report)")
    match = list(args.match or [])
    if not match and args.run:
        # Fall back to the run's own scope: a run started with two seeds
        # (example.com + example.org) must not have half its assets reported as
        # out-of-scope noise just because the caller quoted one seed.
        spec = jobs.read_spec(args.run)
        scope = core.canon_scope(spec.get("scope") or [])
        if scope:
            match = scope
            core.log("scope from run " + str(args.run) + " -> " + ",".join(scope))
    return match


def _require_run_task(args) -> None:
    """A library read must hit the SAME library the run wrote to (see the
    long comment in cmd_report). Extracted so brief gets the same guard."""
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
                " " + str(getattr(args, "_sub", "report")) +
                " --run " + str(args.run) +
                " (without it this process reads the shared library and "
                "would report an empty scope)")


def cmd_brief(args) -> None:
    """Agent read API: query the library, print ONE brief JSON to stdout.

    This is the unified entry an agent uses instead of opening report files:
    same facts as report.brief.json (counts, coverage gaps, top hosts,
    internal services, leaks, next steps) with the same hard byte ceiling,
    but it never writes a file -- stdout is the deliverable. `report` is the
    human-facing command (md/html); scripts wanting the full digest use
    `assets --export` or `report --with-json`.
    """
    _require_run_task(args)
    match = _resolve_report_scope(args)
    store = core.Store()
    try:
        data = report.collect(store, match=match or None, min_conf=args.min_conf,
                              limit=args.limit, ep_limit=args.ep_limit,
                              engagement=args.engagement)
    finally:
        store.close()
    coverage = _resolve_coverage(args)
    # Merge EVERY section FIRST, then measure once against the real stdout
    # encoder. The old order measured a payload without metered/note and then
    # appended them, so brief_bytes described a document that was never
    # emitted (F14).
    brief = report.build_brief(data, top=args.top,
                               max_bytes=args.max_bytes,
                               coverage=coverage)
    # Billed-spend summary from the run's ledger (batch F): what was spent,
    # per engine, and which engines are blocked (quota/auth) -- an agent
    # deciding "is another round worth it" needs the quota evidence, not a
    # guess. A run with no ledger (or none reachable) simply omits the block.
    try:
        rid = str(getattr(args, "run", "") or "").strip()
        rd = jobs.resolve(rid) if rid else None
        if rd is not None and (rd / "metered.jsonl").exists():
            led = metered_mod.load_ledger(rd / "metered.jsonl", run_id=rd.name)
            if led.rows():
                brief["metered"] = {"totals": led.totals(),
                                    "by_engine": led.by_engine(),
                                    "blocked_engines": led.blocked_engines()}
    except Exception:
        pass
    brief["note"] = ("Unified agent read API: queries the store, writes no "
                     "files. report produces the human md/html only; full data "
                     "via assets --export or report --with-json.")
    brief["schema"] = brief.get("schema") or "findinfo.brief/1"
    # Re-fit + re-measure the COMPLETE object with the same encoder emit()
    # uses; nothing is appended afterwards.
    report.fit_brief(brief, args.max_bytes)
    out(brief)


def cmd_report(args) -> None:
    """Render the human deliverables: md + html for people.

    Agent reads happen through `brief` (query the library, stdout only) or
    `assets --export` (full rows for scripts). The machine files
    (report.json / report.brief.json) are opt-in via --with-json so a human
    delivery does not write files nobody opens.

    Scope is a suffix filter (--match) because the asset store is shared across
    engagements. Without it the report silently includes every other project's
    rows; the collector falls back to the latest run's target and says so.
    An explicit --match that canon_domain() rejects entirely is an ERROR, not a
    silent fallback to the whole library.
    """
    args._sub = "report"
    _require_run_task(args)
    match = _resolve_report_scope(args)
    store = core.Store()
    try:
        data = report.collect(store, match=match or None, min_conf=args.min_conf,
                              limit=args.limit, ep_limit=args.ep_limit,
                              engagement=args.engagement)
    finally:
        store.close()
    # The brief has to state what the collection could NOT do, so pull the
    # run's coverage snapshot. Same resolution order as brief (see
    # _resolve_coverage): --run, then an explicit --engagement, then the
    # newest run matching --match.
    coverage = _resolve_coverage(args)
    paths = report.write_bundle(data, out_dir=args.out, slug=args.slug,
                                json_limit=args.json_limit,
                                with_json=args.with_json,
                                with_brief=args.with_brief,
                                # getattr: a hand-built Namespace (tests, callers)
                                # should not have to know every new knob
                                brief_top=getattr(args, "brief_top", None),
                                brief_max_bytes=getattr(args, "brief_max_bytes", None),
                                coverage=coverage)
    res = {"counts": data["counts"], "scope": data["scope"],
           "paths": paths, "warnings": data["environment"]["warnings"],
           "next_steps": data["next_steps"][:3],
           "note": "agents read data via the brief command (one JSON line on stdout); machine files are only written with --with-json/--with-brief"}
    if args.print_md:
        res["md"] = report.build_md(data)
    if args.print_json:
        res["json"] = data
        # --print-json keeps its old behaviour, but a caller has to be told
        # when the payload is big enough to swamp an agent context.
        size = len(json.dumps(data, ensure_ascii=False,
                              separators=(",", ":")).encode("utf-8"))
        if size > PRINT_JSON_WARN_BYTES:
            sys.stderr.write(
                "warning: --print-json returned " + str(size // 1024) + " KB of JSON; "
                "an agent context should use the brief command instead "
                "(stdout, <= " + str(report.BRIEF_MAX_BYTES // 1024) + " KB)\n")
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
            # Assets and their stage checkpoints go together: keeping 'step done'
            # next to an empty store makes the next run skip the stage and starve
            # every downstream stage for input.
            res["steps_cleared"] = store.clear_steps()
        elif args.keep:
            res = store.purge(keep=args.keep, kinds=args.kind)
        elif args.match:
            res = store.purge(match=args.match, kinds=args.kind)
        else:
            out({"error": "pass --keep <suffix> | --match <suffix> | --all"})
            return
        if args.keep or args.match:
            # A scoped purge invalidates the stages that read those assets.
            res["steps_cleared"] = store.clear_steps(list(args.keep or args.match or []))
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


def _seen_span(rows: list[dict]) -> dict:
    """Range of first_seen/last_seen across `rows` (empty when none)."""
    firsts = [r.get("first_seen") for r in rows if r.get("first_seen")]
    lasts = [r.get("last_seen") for r in rows if r.get("last_seen")]
    return {"first_seen_min": min(firsts) if firsts else "",
            "last_seen_max": max(lasts) if lasts else ""}


def cmd_assets(args) -> None:
    store = core.Store()
    try:
        if getattr(args, "export_xlsx", ""):
            # Spreadsheet export for humans reviewing an engagement in Excel.
            # Scope comes from --match (the same suffix filter as `assets`),
            # and the notes sheet states the filter so a scoped workbook is
            # never read as "everything the library holds".
            from lib import xlsx_export
            scope = core.canon_scope(getattr(args, "match", None) or [])
            kinds = None
            if args.kind != "all":
                kinds = [args.kind]
            try:
                res = xlsx_export.write_workbook(
                    args.export_xlsx, store, scope=scope,
                    min_conf=args.min_conf, kinds=kinds,
                    notes=[("计数口径",
                            "范围过滤后仍可能是共享库的一部分；"
                            "全库计数见 assets（不带 --match）")])
            except RuntimeError as exc:
                raise core.FindInfoError(str(exc)) from None
            out(dict(res, counts=store.count_assets()))
            return
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
        # first_seen / last_seen answer "is this new since the last run?".
        # They are surfaced as timestamps untouched (UTC, trailing Z) so two
        # runs can be diffed without re-parsing anything.
        out({"counts": store.count_assets(), "total": len(rows),
             "endpoints": len(store.get_endpoints()),
             "seen": _seen_span(rows), "rows": rows})
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
        "reaped_by_host": bool(st.get("reaped_by_host")),
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
        if st.get("reaped_by_host"):
            # The host killed the detached worker before it ran any Python.
            # --resume spawns another detached worker, which dies the same
            # way: the only working modes here are foreground or a worker
            # held by a live parent process.
            return ["host reaps detached workers (empty stderr.log); do not retry --background",
                    "run the same command in the FOREGROUND with --task-timeout as a ceiling",
                    "or hold the worker under a live parent process (subprocess.Popen + wait)"]
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
        # Compact keeps every decision field; --full only ADDS the bulky
        # echoes (coverage arrays, run_dir). The old projection dropped
        # attempt/reaped_by_host/terminal/gaps, so a default wait could not
        # answer "is a worker gone and what is missing" (F13).
        prog = res.get("progress") or {}
        keep = ("run_id", "state", "attempt", "changed", "timed_out",
                "terminal", "alive", "interrupted", "stalled",
                "reaped_by_host", "retryable", "next_action",
                "gap_count", "gaps", "seq", "progress_seq", "cursor",
                "waited_sec", "result", "note", "resync_recommended")
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


def _icp_stage_inputs(codes: list, engines: str) -> dict:
    """Checkpoint identity of the icp stage (same rule as _subs_stage_inputs)."""
    usable, _ = core.split_engines(engines)
    inputs: dict = {"codes": codes}
    queries = core.uncover_query_identity("icp", usable)
    if queries:
        inputs["usable_engines"] = usable
        inputs["queries"] = queries
    return inputs


def _dedupe_payload(args) -> dict:
    """Everything that changes what a run would collect.

    Display/budget-only switches are excluded so re-asking for the same target
    reuses the in-flight job instead of starting a second collection.
    """
    payload = {
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
    # Missing flags on pre-RunSpec jobs meant False. Omit those defaults so
    # adding these fields does not invalidate an otherwise identical old key.
    for field in ("no_mapping", "remap"):
        if getattr(args, field, False):
            payload[field] = True
    return payload


# Flags whose presence on the command line must be distinguishable from
# "argparse filled in the default". Resume patching depends on this: replaying
# a job must not overwrite the stored budget with defaults the caller never
# typed (only explicitly-typed limits reach RunSpec.resume_patch).
_TRACKED_FLAGS = {
    "--rounds": "rounds", "--time-budget": "time_budget",
    "--tool-timeout": "tool_timeout", "--task-timeout": "task_timeout",
    "--force-stage": "force_stage",
}

# Identity/scope flags: explicitly typed on a --resume they are a REFUSAL
# candidate (RunSpec.resume_patch raises), never a silent repoint of the same
# run id at a different target.
_IDENTITY_FLAGS = ("--name", "--domain", "--engines", "--no-icp",
                   "--no-onepass", "--no-mapping", "--remap",
                   "--active", "--ports", "--vhost",
                   "--crawl", "--brute")


def _mark_explicit(args, argv: list[str]) -> None:
    """Record which budget flags the caller actually typed."""
    seen = set()
    for a in argv:
        for flag, attr in _TRACKED_FLAGS.items():
            if a == flag or a.startswith(flag + "="):
                seen.add(attr)
    setattr(args, "_explicit", seen)
    ident = set()
    for a in argv:
        for flag in _IDENTITY_FLAGS:
            if a == flag or a.startswith(flag + "="):
                ident.add(flag)
    setattr(args, "_explicit_identity", ident)


def _spec_from_stored(spec: dict) -> "spec_mod.RunSpec":
    """The RunSpec a stored job carries (docs par.4 legacy import).

    Preference order: the run_spec block written by RunSpec-aware launches,
    then a parse of the stored argv through the real parser (one conversion,
    never a second handwritten importer). Legacy jobs whose argv predates a
    flag keep that flag's parser default -- the same semantics the worker
    replay itself would give it.
    """
    try:
        return spec_mod.from_stored(
            spec, lambda argv: build_parser().parse_args(argv))
    except (ValueError, TypeError) as exc:
        raise core.FindInfoError(str(exc)) from None


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
        reuse = {"run_id": inflight.name, "state": st.get("state"),
                 "reused": True, "started": False, "dedupe_key": key}
        # Same collection identity, different limits: the in-flight job keeps
        # ITS limits (docs par.4) -- report the difference instead of silently
        # applying the new ones to a running job.
        try:
            stored = _spec_from_stored(jobs.read_spec(inflight))
            diff = spec_mod.from_cli(args).diff(stored)
            if diff:
                reuse["request_differences"] = diff
                reuse["note"] = ("in-flight job reused; requested limits were "
                                 "NOT applied to the running job")
        except Exception:
            pass
        out(dict(reuse, **_run_paths(inflight),
                 next=_followup("wait", inflight, "--timeout", "30")))
        return 0

    active = _active_enabled(args)
    target_label = args.name or (",".join(args.domain) if args.domain else "?")
    rd = core.new_run_dir(target_label)
    planned = _plan_stages(args, active)
    task = os.environ.get("FINDINFO_TASK", "")
    # One RunSpec owns the worker argv (the CLI, the worker replay and the
    # spec.json entry below all come from the same conversion -- a second
    # handwritten argv list is exactly the drift the plan forbids).
    rs = spec_mod.from_cli(args)
    # The FIRST launch gets an attempt and a launch token exactly like a
    # resume does. Without one the worker entered the legacy no-token branch,
    # where an empty token passed every fence (F05).
    import secrets as _secrets
    launch_token = rd.name + "|1|" + _secrets.token_hex(8)
    jobs.write_spec(
        rd, entry="findinfo:main", argv=rs.to_worker_argv(),
        target=args.name or target_label, scope=core.canon_scope(args.domain or []),
        engagement=ENGAGEMENT, task=task, home=str(core.HOME), root=str(core.ROOT),
        python=sys.executable, dedupe_key=key, attempt=1, params=payload,
        launch_token=launch_token,
        # task_timeout is a TOP-LEVEL spec field because lib/jobs.worker_main
        # reads spec["task_timeout"] to arm its hard deadline. It used to be
        # written only inside budget{}, so the timer could never start: the job
        # had no ceiling at all. Keep budget{} too -- it is what status reports.
        task_timeout=float(getattr(args, "task_timeout", 0) or 0),
        budget={"rounds": int(getattr(args, "rounds", 1) or 1),
                "time_budget_sec": float(getattr(args, "time_budget", 0) or 0),
                "task_timeout_sec": float(getattr(args, "task_timeout", 0) or 0)},
        run_spec=json.loads(rs.to_json()),
        env={"FINDINFO_HOME": str(core.HOME), "FINDINFO_TASK": task},
    )
    jobs.update_state(rd, state="queued", stage="queued", stage_state="queued",
                      target=target_label, scope=core.canon_scope(args.domain or []),
                      planned_stages=planned, stage_index=0,
                      stage_total=len(planned), active=active, attempt=1,
                      launch_token=launch_token,
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


def _resume_effective_spec(stored_spec: dict, args) -> dict:
    """The effective RunSpec a resume would run with (ONE pure function).

    This runtime wrapper and the cold `run --resume ... --dry-run` path both
    use spec.resume_from_cli, so explicit identity and limit patches have the
    same semantics (F16). Reads the stored spec dict and the parsed args,
    returns {argv, budget, task_timeout, run_spec, effective} or raises
    FindInfoError for an identity/schema violation. It does not touch state.

    Rules (docs par.4): only explicitly typed limit flags may patch the stored
    spec; an explicitly typed identity/scope/source flag that DIFFERS from the
    stored one is refused.
    """
    spec = dict(stored_spec or {})
    try:
        effective_rs = spec_mod.resume_from_cli(_spec_from_stored(spec), args)
    except ValueError as exc:
        raise core.FindInfoError("resume rejected: " + str(exc)) from None
    spec["argv"] = effective_rs.to_worker_argv()
    spec["budget"] = {"rounds": effective_rs.rounds,
                      "time_budget_sec": effective_rs.time_budget,
                      "task_timeout_sec": effective_rs.task_timeout,
                      "tool_timeout_sec": effective_rs.tool_timeout}
    spec["task_timeout"] = effective_rs.task_timeout
    if spec.get("run_spec") is not None:
        spec["run_spec"] = json.loads(effective_rs.to_json())
    spec["_effective_spec"] = effective_rs
    return spec


def _resume_run(args) -> int:
    """Resume under a per-run cross-process lock (one worker, one attempt).

    The whole decision -- reread state, check liveness, bump the attempt,
    publish the launch token, persist the queued spec, spawn, publish the
    PID -- happens while holding the lock, so two simultaneous resumes of
    the same run produce ONE new attempt and ONE worker; the loser of the
    race sees the winner's live job and reports reuse (T18).
    """
    rd = jobs.resolve(args.resume)
    with jobs.start_lock("resume:" + rd.name, timeout=60.0):
        return _resume_run_locked(args, rd)


def _resume_run_locked(args, rd) -> int:
    st = jobs.derive(jobs.read_state(rd))
    if st.get("state") in jobs.ACTIVE and st.get("alive"):
        occupied = {"state": st.get("state"), "reused": True,
                    "resumed": False}
        if st.get("pid"):
            occupied["occupied_by_pid"] = st.get("pid")
        out(dict({"run_id": rd.name}, **occupied, **_run_paths(rd),
                 hint="already running; wait on this run id instead of starting another"))
        return 0
    # An old worker may still be ALIVE while its state is not in ACTIVE (a
    # stale state file, a host-reaped pid). Taking the job over means starting
    # a second process over the same run dir: confirm the old one is gone
    # first, and if it is not, report the occupancy instead of racing it.
    old_pid = st.get("pid")
    if old_pid and jobs.pid_alive(old_pid):
        out(dict({"run_id": rd.name, "state": st.get("state"),
                  "reused": True, "resumed": False,
                  "occupied_by_pid": old_pid},
                 **_run_paths(rd),
                 hint=("the previous worker is still alive (pid "
                       + str(old_pid) + "); wait for it or cancel the run "
                       "before resuming -- a resume never starts a second "
                       "worker over a live one")))
        return 0
    spec = jobs.read_spec(rd)
    if not spec.get("argv"):
        raise core.FindInfoError("not a background run (no job spec): " + rd.name)

    # Resume patching goes through the SAME pure function the dry-run
    # preview uses, so preview and reality cannot diverge (F16).
    spec = _resume_effective_spec(spec, args)
    spec.pop("_effective_spec", None)
    spec["attempt"] = int(spec.get("attempt") or 1) + 1
    # Launch token: fencing for THIS attempt. The worker must present it to
    # publish state; a stale attempt (this resume raced with another) can
    # no longer overwrite the newer attempt's progress.
    #
    # A legacy job has no token at all. That migration happens HERE, in the
    # control entry that holds the start lock, and only after the liveness
    # check above -- the worker itself never fabricates or bypasses a token
    # (an empty token is not a licence to write; see jobs.fenced_write).
    import secrets as _secrets
    migrated_legacy = not spec.get("launch_token")
    spec["launch_token"] = rd.name + "|" + str(spec["attempt"]) + "|" + _secrets.token_hex(8)
    if migrated_legacy:
        spec["legacy_migrated_at"] = core.now()
        core.log("resume: legacy job without a launch token; identity assigned "
                 "to attempt " + str(spec["attempt"]))
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
                      launch_token=spec["launch_token"],
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
# ---------------------------------------------------------------- registry
class StageRegistry:
    """Validated stage registry: names, order, runners, dependencies.

    docs/RELIABILITY-PLAN.md par.5: one registry so the plan, the runner and
    the report can never disagree about which stages exist. Validation
    catches, at import time: an unknown stage name, a duplicate runner, a
    dependency cycle, and a stage missing a runner (T01).
    """

    def __init__(self):
        self._order: list = []
        self._runners: dict = {}
        self._needs: dict = {}

    def register(self, name: str, runner=None, needs=()):
        """Add a stage. The optional-stage convention stays: a stage the
        caller can switch off is registered with needs=() and decided by
        the planner, never silently absent from the registry."""
        if name in self._order:
            raise ValueError("duplicate stage in registry: " + name)
        self._order.append(name)
        self._runners[name] = runner
        self._needs[name] = tuple(needs)

    def validate(self):
        """Raise ValueError on any structural defect (T01)."""
        missing_runner = [n for n, r in self._runners.items() if r is None]
        if missing_runner:
            raise ValueError("stages without a runner: " + ",".join(missing_runner))
        # dependency cycle: iterative colouring
        WHITE, GREY, BLACK = 0, 1, 2
        colour = {n: WHITE for n in self._order}

        def visit(n, path):
            if colour[n] == GREY:
                raise ValueError("stage dependency cycle: " + "->".join(path + [n]))
            if colour[n] == BLACK:
                return
            colour[n] = GREY
            for d in self._needs.get(n, ()):
                if d not in colour:
                    raise ValueError("unknown dependency stage: " + d)
                visit(d, path + [n])
            colour[n] = BLACK

        for n in self._order:
            visit(n, [])
        return self

    def order(self) -> list:
        return list(self._order)

    def runner(self, name):
        return self._runners.get(name)


def _build_default_registry():
    """The pipeline stage registry: names, order and dependencies.

    The initial execution order is preserved exactly (docs par.2):
    entity? -> onepass -> certs -> subs -> brute? -> icp? ->
    [dns -> probe? -> ipagg? -> ports? -> vhost? -> crawl?/extract?].
    Optional stages are registered with their dependency so the planner
    decides from flags; each entry needs a runner to exist (T01).
    """
    reg = StageRegistry()
    reg.register("entity", runner=lambda *a, **k: None, needs=())
    reg.register("onepass", runner=lambda *a, **k: None, needs=())
    reg.register("certs", runner=lambda *a, **k: None, needs=())
    reg.register("subs", runner=lambda *a, **k: None, needs=("certs",))
    reg.register("brute", runner=lambda *a, **k: None, needs=("dns",))
    # "mapping" is the ONLY stage allowed to spend mapping quota (batch 1).
    # "icp" stays registered as a presentation alias so old plans and
    # checkpoints that name it keep resolving; dispatch happens in mapping.
    reg.register("mapping", runner=lambda *a, **k: None, needs=())
    reg.register("icp", runner=lambda *a, **k: None, needs=())
    reg.register("dns", runner=lambda *a, **k: None, needs=("certs",))
    reg.register("probe", runner=lambda *a, **k: None, needs=("dns",))
    reg.register("ipagg", runner=lambda *a, **k: None, needs=("probe",))
    reg.register("ports", runner=lambda *a, **k: None, needs=("ipagg",))
    reg.register("vhost", runner=lambda *a, **k: None, needs=("ipagg",))
    reg.register("crawl", runner=lambda *a, **k: None, needs=("probe",))
    reg.register("extract", runner=lambda *a, **k: None, needs=("crawl",))
    return reg.validate()


STAGE_REGISTRY = _build_default_registry()


def cmd_dry_run(args) -> int:
    """Compile the plan without starting anything (docs/RELIABILITY-PLAN par.12).

    Read-only in every combination: with --resume it may read the existing
    job's spec to preview the effective configuration, but no PID, attempt,
    cancellation flag or job state changes; with --background nothing is
    spawned. run_id is null (a plan has no live job identity); a spec hash is
    offered for reference. Runtime capabilities (tool presence, egress, keys)
    are reported as unverified rather than importing collectors to pretend
    they were checked.
    """
    from lib import spec as spec_mod
    rs = spec_mod.from_cli(args)
    active = _active_enabled(args)
    planned = _plan_stages(args, active)
    identity_questions = []
    if args.name and not args.domain:
        identity_questions.append(
            "brand-only run: entity anchoring must resolve the subject before "
            "any discovery runs; ambiguous identity reports identity_ambiguous")
    if args.name and args.domain:
        identity_questions.append(
            "explicit domains seed the run directly; the brand is only extra "
            "context for related-asset evidence")
    effective: dict = {}
    if getattr(args, "resume", ""):
        try:
            spec_blob = jobs.read_spec(args.resume)
            # SAME effective-spec function the real resume uses: the preview
            # shows the target, scope, stages and limits a resume would run,
            # not this command line's parser defaults (F16).
            preview = _resume_effective_spec(spec_blob, args)
            eff_rs = preview.pop("_effective_spec", None)
            if eff_rs is not None:
                rs = eff_rs
                active = bool(rs.active or rs.ports or rs.vhost or rs.crawl
                              or rs.brute)
                planned = _plan_stages(rs, active)
            effective = {"source": "job.json",
                         "run_id": spec_blob.get("run_id"),
                         "attempt": spec_blob.get("attempt"),
                         "target": rs.target_label,
                         "scope": list(rs.domain),
                         "planned_stages": planned,
                         "limits": {"rounds": rs.rounds,
                                    "time_budget_sec": rs.time_budget,
                                    "task_timeout_sec": rs.task_timeout,
                                    "tool_timeout_sec": rs.tool_timeout,
                                    "engines": rs.engines},
                         "argv": preview.get("argv"),
                         "note": "preview only: no job state is changed"}
        except core.FindInfoError as exc:
            effective = {"source": "rejected", "error": str(exc)[:300]}
        except Exception as exc:
            effective = {"source": "error", "error": str(exc)[:160]}
    out({
        "run_id": None,
        "spec_hash": rs.dedupe_identity(),
        "dry_run": True,
        "target": rs.target_label,
        "scope": list(rs.domain),
        "planned_stages": planned,
        "active": active,
        "disabled_stages": [x for x in ("entity", "onepass", "icp", "brute")
                            if x not in planned],
        "identity_questions": identity_questions,
        "limits": {"rounds": rs.rounds, "time_budget_sec": rs.time_budget,
                   "task_timeout_sec": rs.task_timeout,
                   "tool_timeout_sec": rs.tool_timeout,
                   "engines": rs.engines, "max_seed": rs.max_seed,
                   "top_ports": rs.top_ports, "max_vhost_ips": rs.max_vhost_ips,
                   "depth": rs.depth},
        "possible_requests": {"note": "network requestability is not checked "
                                       "in a dry run; counts are unknown"},
        "capabilities": {"checked": False,
                          "note": "tool presence, egress and credentials are "
                                  "not verified by a dry run"},
        "background_requested": bool(getattr(args, "background", False)),
        "resume_requested": getattr(args, "resume", "") or None,
        "effective": effective or None,
    })
    return 0


def cmd_run(args) -> int:
    """Start or resume a collection.

    Three modes, one pipeline: foreground (default), --background (detached
    worker + run id returned immediately) and --resume <run_id> (reattach to an
    existing run, honouring its checkpoints). --dry-run overlays any of them
    read-only: it compiles the plan and answers with run_id null, starting
    nothing, creating no database and touching no job state.
    """
    if getattr(args, "dry_run", False):
        return cmd_dry_run(args)
    if getattr(args, "resume", ""):
        return _resume_run(args)
    if getattr(args, "background", False):
        return _start_background(args)
    return _run_pipeline(args)


# ---------------------------------------------------------------- parser
def _add_tool_timeout(parser) -> None:
    """Give a single-stage subcommand the same --tool-timeout contract as run.

    Each stage shells out to an external binary; without this flag an agent has
    no way to bound a slow tool except by killing the whole session, which is
    exactly what the docs used to claim it could do. Default 0 means "use the
    tool's own default", matching run's semantics.
    """
    parser.add_argument(
        "--tool-timeout", type=int, default=0,
        help="per-tool timeout in seconds (0 = the tool's own default)")


def _add_whole_store(parser: argparse.ArgumentParser) -> None:
    """The explicit opt-in for a store read with no scope (see _store_scope)."""
    parser.add_argument(
        "--whole-store", action="store_true",
        help="take targets from EVERY asset in this store (all engagements in "
             "it) on purpose; without it a store read needs a scope flag")


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
    d.add_argument("--check-mapping", action="store_true",
                   help="verify each configured engine accepts our key AND our "
                        "query syntax (one -limit 1 query per engine)")
    d.add_argument("--yes-spend-quota", action="store_true",
                   help="accepted for compatibility; --check-mapping no longer "
                        "needs consent (runs unattended)")
    d.add_argument("--domain", default="",
                   help="the domain to probe in --check-mapping")
    d.add_argument("--engines", default=None,
                   help="limit --check-mapping to these engines")
    _add_tool_timeout(d)
    d.add_argument("--offline", action="store_true",
                   help="inspect python/platform/paths/file metadata only: no tool "
                        "execution, no DNS, no HTTP, no key validation; egress and "
                        "tool health report not_checked, never healthy")
    d.set_defaults(func=cmd_doctor)

    e = sub.add_parser("entity", help="brand/company name -> subsidiaries, ICP, domains")
    e.add_argument("--name", required=True)
    e.add_argument("--invest", type=int, default=51)
    e.add_argument("--deep", type=int, default=1,
                    help="ENScan recursive company expansion depth (default 1)")
    e.add_argument("--supplier", action="store_true",
                    help="also walk the supplier network (slow, other companies)")
    e.add_argument("--branch", action="store_true",
                    help="also walk branch offices (slow, few assets)")
    e.add_argument("--is-fast", action="store_true", default=True, help=argparse.SUPPRESS)
    e.add_argument("--out", default="")
    _add_tool_timeout(e)
    e.set_defaults(func=cmd_entity)

    c = sub.add_parser("certs", help="certificate transparency expansion")
    c.add_argument("--domain", required=True)
    _add_tool_timeout(c)
    c.set_defaults(func=cmd_certs)

    i = sub.add_parser("icp", help="ICP record -> domains (fofa/quake/hunter)")
    i.add_argument("--code", action="append", help="repeatable")
    i.add_argument("--from-store", action="store_true")
    i.add_argument("--engines", default="fofa,quake,hunter")
    i.add_argument("--scope", action="append",
                    help="limit --from-store to these domain suffixes (repeatable); the ICP table is shared, so --from-store requires it (or --whole-store)")
    _add_whole_store(i)
    _add_tool_timeout(i)
    i.set_defaults(func=cmd_icp)

    pa = sub.add_parser("passive", help="15-source passive collection via bundled Rust onepass")
    pa.add_argument("--domain", action="append")
    pa.add_argument("--from-store", action="store_true")
    pa.add_argument("--sources", default="", help="comma separated source ids (see: onepass sources)")
    pa.add_argument("--min-conf", type=float, default=0.0)
    pa.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so a store read requires it (or --whole-store).")
    _add_whole_store(pa)
    _add_tool_timeout(pa)
    pa.set_defaults(func=cmd_passive)

    br = sub.add_parser("brute", help="DNS brute force via ksubdomain (ACTIVE, needs Npcap)")
    br.add_argument("--domain", required=True)
    br.add_argument("--wordlist", default="wordlists/sub.txt")
    br.add_argument("--bandwidth", default="3m", help="3m/5m/10m, lower = politer")
    br.add_argument("--wildcard", default="basic", choices=["basic", "advanced", "none"])
    _add_tool_timeout(br)
    br.set_defaults(func=cmd_brute)

    mp = sub.add_parser("map", help="paid mapping (the ONLY quota-spending "
                                    "command; one question per task)")
    mp.add_argument("--domain", action="append",
                    help="seed domain to map (repeatable)")
    mp.add_argument("--icp", action="append",
                    help="filing number to reverse-look-up (repeatable)")
    mp.add_argument("--name", action="append",
                    help="company name to search by (repeatable). This is the "
                         "escape hatch when ENScan anchors a subject but files "
                         "no domain: the engines are queried with the NAME "
                         "(icp=\"<name>\", domain=\"<name>\") and whatever "
                         "comes back can seed a run")
    mp.add_argument("--from-store", action="store_true",
                    help="take targets from the store (needs --scope)")
    mp.add_argument("--scope", action="append",
                    help="limit --from-store reads to these domain suffixes")
    mp.add_argument("--engines", default="fofa,quake,hunter,shodan",
                    help="engines to ask (each must have a key)")
    mp.add_argument("--remap", action="store_true",
                    help="ask again even when this task already paid for the "
                         "question (default: reuse the recorded answer)")
    mp.add_argument("--kind", default="domain", choices=["domain", "icp"],
                    help="how to ask about --name: domain=\"...\" or "
                         "icp=\"...\" (default domain)")
    _add_tool_timeout(mp)
    mp.set_defaults(func=cmd_map)

    sb = sub.add_parser("subs", help="passive subdomain enumeration")
    sb.add_argument("--domain", action="append")
    sb.add_argument("--from-store", action="store_true")
    sb.add_argument("--engines", default="fofa,quake,hunter,shodan,censys")
    sb.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so a store read requires it (or --whole-store).")
    _add_whole_store(sb)
    _add_tool_timeout(sb)
    sb.set_defaults(func=cmd_subs)

    dn = sub.add_parser("dns", help="resolve + wildcard filtering")
    dn.add_argument("--domain", action="append")
    dn.add_argument("--from-store", action="store_true")
    dn.add_argument("--min-conf", type=float, default=0.4)
    dn.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so a store read requires it (or --whole-store).")
    _add_whole_store(dn)
    _add_tool_timeout(dn)
    dn.set_defaults(func=cmd_dns)

    pr = sub.add_parser("probe", help="httpx liveness / tech / ip mapping (ACTIVE)")
    pr.add_argument("--host", action="append")
    pr.add_argument("--from-store", action="store_true")
    pr.add_argument("--min-conf", type=float, default=0.7)
    pr.add_argument("--scope", action="append", help="scope --from-store reads to these domains (repeatable). The asset graph is shared, so a store read requires it (or --whole-store).")
    _add_whole_store(pr)
    pr.add_argument("--repair-titles", action="store_true",
                    help="also re-read stored titles that contain U+FFFD (a "
                         "page decoded with the wrong charset under an older "
                         "build) and rewrite them from the raw page bytes; "
                         "unreachable hosts are reported, never guessed")
    _add_tool_timeout(pr)
    pr.set_defaults(func=cmd_probe)

    ia = sub.add_parser("ipagg", help="group domains by ip, drop CDN")
    ia.add_argument("--ip", action="append")
    ia.add_argument("--scope", action="append",
                    help="aggregate only IPs owned by these domains (repeatable); "
                         "required without --ip (or --whole-store)")
    _add_whole_store(ia)
    _add_tool_timeout(ia)
    ia.set_defaults(func=cmd_ipagg)

    po = sub.add_parser("ports", help="naabu port scan (ACTIVE)")
    po.add_argument("--ip", action="append",
                    help="explicit targets, used as given (repeatable)")
    po.add_argument("--scope", "--domain", dest="scope", action="append",
                    help="without --ip: scan the public IPs owned by these "
                         "domains (repeatable); private/reserved ones are skipped")
    po.add_argument("--top-ports", type=int, default=1000)
    _add_whole_store(po)
    _add_tool_timeout(po)
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
    _add_whole_store(vh)
    _add_tool_timeout(vh)
    vh.set_defaults(func=cmd_vhost)

    cr = sub.add_parser("crawl", help="katana crawl (ACTIVE)")
    cr.add_argument("--url", action="append")
    cr.add_argument("--from-store", action="store_true")
    cr.add_argument("--depth", type=int, default=3)
    cr.add_argument("--domain", action="append",
                    help="scope the crawl to these domains (repeatable); with "
                         "--from-store it also limits which URLs are picked up. "
                         "Without it the scope is derived from the seed URLs' "
                         "registrable domains; a store read requires it.")
    _add_whole_store(cr)
    _add_tool_timeout(cr)
    cr.set_defaults(func=cmd_crawl)

    ex = sub.add_parser("extract", help="leaked domains/IPs from crawl output")
    ex.add_argument("--from-run", default="")
    ex.add_argument("--from-store", action="store_true",
                    help="use URL assets already in the store (reflow loop)")
    ex.add_argument("--domain", action="append",
                    help="restrict --from-store URLs to these domains (repeatable); "
                         "required with --from-store (or --whole-store), so another "
                         "engagement's historical assets are never re-fetched")
    ex.add_argument("--url", action="append")
    ex.add_argument("--fetch-limit", type=int, default=0,
                    help="how many JS bundles THIS invocation scans (default: "
                         "limits.js_fetch_limit = 2000). A work budget, not a "
                         "discovery cap: every bundle stays queued, the rest "
                         "are reported as js_pending")
    _add_whole_store(ex)
    _add_tool_timeout(ex)
    ex.set_defaults(func=cmd_extract)

    as_ = sub.add_parser("assets", help="list / export asset graph")
    as_.add_argument("--kind", default="all",
                     choices=["all", "company", "icp", "domain", "ip", "url",
                              "endpoint", "app"])
    as_.add_argument("--min-conf", type=float, default=0.0)
    as_.add_argument("--limit", type=int, default=500)
    as_.add_argument("--match", action="append",
                     help="limit to these domain suffixes (repeatable); used by "
                          "--export-xlsx so a workbook stays inside one target")
    as_.add_argument("--export", default="")
    as_.add_argument("--export-xlsx", default="", metavar="PATH",
                     help="write an .xlsx workbook (one sheet per asset kind) "
                          "instead of JSONL; combine with --match to scope it "
                          "and --kind to pick a single sheet")
    as_.set_defaults(func=cmd_assets)

    rp = sub.add_parser("report", help="human deliverables: report.md + report.html (agent reads use `brief`)")
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
    rp.add_argument("--engagement", default="default", help="coverage gaps to read: --run already picks that run, so set this only to read a different one")
    rp.add_argument("--print-md", action="store_true", help="also return the markdown text")
    rp.add_argument("--brief-top", type=int, default=20,
                    help="kept in report.brief.json when --with-brief is given "
                         "(default 20; the brief command has its own --top)")
    rp.add_argument("--brief-max-bytes", type=int, default=32768,
                    help="byte ceiling for report.brief.json; arrays shrink to fit "
                         "and every cut is recorded in its truncated field")
    rp.add_argument("--with-brief", action="store_true",
                    help="also write report.brief.json (off by default: agents use "
                         "the brief command, which prints to stdout)")
    rp.add_argument("--with-json", action="store_true",
                    help="also write report.json, the full machine digest "
                         "(off by default: scripts use assets --export)")
    rp.add_argument("--print-json", action="store_true",
                    help="also return the FULL digest on stdout -- several hundred "
                         "KB on a large target, which will flood an agent "
                         "context; use the brief command instead")
    rp.set_defaults(func=cmd_report)

    bf = sub.add_parser("brief",
                        help="agent read API: query the library, print ONE "
                             "brief JSON to stdout (no files written)")
    bf.add_argument("--match", action="append",
                    help="scope to these domain suffixes (repeatable); with --run "
                         "and no --match the run's own scope is used")
    bf.add_argument("--run", default="",
                    help="take the scope from this run id when --match is omitted")
    bf.add_argument("--min-conf", type=float, default=0.3)
    bf.add_argument("--limit", type=int, default=300, help="hosts kept in the digest")
    bf.add_argument("--ep-limit", type=int, default=400, help="endpoints kept in the digest")
    bf.add_argument("--engagement", default="default", help="coverage gaps to read: --run already picks that run, so set this only to read a different one")
    bf.add_argument("--top", type=int, default=20,
                    help="high-priority hosts kept in the brief (default 20)")
    bf.add_argument("--max-bytes", type=int, default=32768,
                    help="byte ceiling for the brief payload; arrays shrink to fit "
                         "and every cut is recorded in its truncated field")
    bf.set_defaults(func=cmd_brief)

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
    rn.add_argument("--deep", type=int, default=1,
                    help="ENScan recursive company expansion depth (default 1)")
    rn.add_argument("--supplier", action="store_true",
                    help="also walk the supplier network (slow, mostly other companies)")
    rn.add_argument("--branch", action="store_true",
                    help="also walk branch offices (slow, few assets)")
    rn.add_argument("--entity-timeout", type=int, default=1200,
                    help="max seconds for the ENScan entity stage (0 = unlimited); "
                         "on timeout the stage fails and is retried later")
    rn.add_argument("--engines", default="fofa,quake,hunter,shodan,censys")
    rn.add_argument("--no-icp", action="store_true")
    rn.add_argument("--no-mapping", action="store_true",
                    help="skip the paid mapping stage entirely (passive/keyless only)")
    rn.add_argument("--remap", action="store_true",
                    help="re-ask mapping questions this task already paid for "
                         "(default: an answered question is reused, never re-billed)")
    rn.add_argument("--no-onepass", action="store_true", help="skip the onepass stage")
    rn.add_argument("--top-ports", type=int, default=1000)
    rn.add_argument("--max-seed", type=int, default=0,
                    help="seed-domain expansion cap (0 = all, default; positive = first N)")
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
    rn.add_argument("--dry-run", action="store_true",
                    help="compile the plan without starting a job: no database, no "
                         "credentials, no process, no network")
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
        payload = {"error": getattr(exc, "code", "") or "error", "message": str(exc)}
        if getattr(exc, "hint", ""):
            payload["hint"] = exc.hint
        # A refusal names the scopes the store itself offers, so the caller does
        # not have to guess a domain and re-run. `scope_source` says whether any
        # read happened ("refused" = nothing was read or run).
        cands = getattr(exc, "candidates", None)
        if cands:
            payload["candidates"] = list(cands)
        if getattr(exc, "scope_source", ""):
            payload["scope_source"] = exc.scope_source
        # seed_domain_required carries ready-to-run engine queries: the caller
        # anchored a company but has no domain, and the next step is a mapping
        # search by name, not another guess at a seed.
        _queries = getattr(exc, "queries", None)
        if _queries:
            payload["queries"] = list(_queries)
        out(payload)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        out({"error": "unexpected", "message": repr(exc)})
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
