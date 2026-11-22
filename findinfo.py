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
    effective = None
    if rs.task and False:      # untouched: resume preview needs the job spec
        effective = None
    if _prescan_option(argv, "--resume"):
        effective = _offline_resume_preview(argv, spec_mod)
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
        max_seed=_val("--max-seed", 5, int),
        max_vhost_ips=_val("--max-vhost-ips", 10, int),
        no_icp=_flag_present(argv, "--no-icp"),
        no_onepass=_flag_present(argv, "--no-onepass"),
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
        from lib import spec as _spec
        import argparse as _ap
        rs = None
        if spec_blob.get("run_spec"):
            rs = _spec.RunSpec.from_json(_json.dumps(spec_blob["run_spec"]))
        elif spec_blob.get("argv"):
            # the offline path has no full parser; read the identity flags
            av = list(spec_blob["argv"])
            def _get(flag):
                for i, a in enumerate(av):
                    if a == flag and i + 1 < len(av):
                        return av[i + 1]
                return None
            doms = [av[i + 1] for i, a in enumerate(av)
                    if a == "--domain" and i + 1 < len(av)]
            rs = _spec.RunSpec(
                name=_get("--name") or "", domain=tuple(doms),
                active="--active" in av,
                ports="--ports" in av, vhost="--vhost" in av,
                crawl="--crawl" in av, brute="--brute" in av,
                no_icp="--no-icp" in av, no_onepass="--no-onepass" in av,
                rounds=int(_get("--rounds") or 1))
        if rs is not None:
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
            })
    except Exception as exc:
        out["effective_error"] = str(exc)[:200]
    return out


_OFFLINE_SUB, _OFFLINE = _offline_requested(sys.argv[1:])
if _OFFLINE:
    sys.exit(_run_offline(_OFFLINE_SUB, sys.argv[1:]))

from lib import core, jobs, report, tools, work
from lib import metered as metered_mod
from lib import mapping as mapping_mod
from lib import mapdispatch
from lib import spec as spec_mod


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


def _active_enabled(args) -> bool:
    """--ports/--vhost/--crawl/--brute imply --active, as --help documents."""
    return bool(args.active or args.ports or args.vhost or args.crawl or args.brute)


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


def _icp_stage_inputs(codes: list, engines: str) -> dict:
    """Checkpoint identity of the icp stage (same rule as _subs_stage_inputs)."""
    usable, _ = core.split_engines(engines)
    inputs: dict = {"codes": codes}
    queries = core.uncover_query_identity("icp", usable)
    if queries:
        inputs["usable_engines"] = usable
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
                   "--no-onepass", "--active", "--ports", "--vhost",
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
    rs = None
    if spec.get("run_spec"):
        try:
            rs = spec_mod.RunSpec.from_json(json.dumps(spec["run_spec"]))
        except (ValueError, TypeError):
            rs = None
    if rs is None and spec.get("argv"):
        parsed = build_parser().parse_args(list(spec["argv"]))
        rs = spec_mod.from_cli(parsed)
    if rs is None:
        raise core.FindInfoError("stored job spec has no runnable identity")
    return rs


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

    Both the real resume and `run --resume ... --dry-run` call this, so the
    preview cannot describe a different target/scope/limits than the resume
    actually applies (F16). Pure: reads the stored spec dict and the parsed
    args, returns {argv, budget, task_timeout, run_spec, effective} or raises
    FindInfoError for an identity/schema violation. It does not touch state.

    Rules (docs par.4): only explicitly typed limit flags may patch the stored
    spec; an explicitly typed identity/scope/source flag that DIFFERS from the
    stored one is refused.
    """
    spec = dict(stored_spec or {})
    explicit = set(getattr(args, "_explicit", ()) or ())
    ident_typed = set(getattr(args, "_explicit_identity", ()) or ())
    # Defence in depth: a caller that did not go through main() (an embedding,
    # a test harness) may not have run _mark_explicit. The parsed namespace
    # still carries the typed values, so fall back to "the value differs from
    # the parser default" for the limit fields -- an explicit `--rounds 3` must
    # never be dropped because bookkeeping was skipped.
    _LIMIT_DEFAULTS = {"rounds": 1, "time_budget": 0.0, "task_timeout": 0.0,
                       "tool_timeout": 0, "force_stage": False}
    for f, default in _LIMIT_DEFAULTS.items():
        val = getattr(args, f, None)
        if val is not None and val != default:
            explicit.add(f)
    effective_rs = None
    if explicit or ident_typed:
        stored = _spec_from_stored(spec)
        if ident_typed:
            from_cli_spec = spec_mod.from_cli(args)
            changed = {f: (getattr(from_cli_spec, f, None),
                           getattr(stored, f, None))
                       for f in spec_mod.RunSpec.IDENTITY_FIELDS
                       if getattr(from_cli_spec, f, None) !=
                       getattr(stored, f, None)}
            if changed and any(f in ("name", "domain") or
                               getattr(args, f, None) not in
                               (None, False, "", (), [])
                               for f in changed):
                raise core.FindInfoError(
                    "resume rejected: identity/scope flags changed for an "
                    "existing job (start a new run instead): " +
                    json.dumps({k: v for k, v in changed.items()}, default=str))
        if explicit:
            requested = dataclasses.replace(
                stored,
                **{f: getattr(args, f, None) for f in explicit
                   if getattr(args, f, None) is not None})
            try:
                effective_rs = stored.resume_patch(requested)
            except ValueError as exc:
                raise core.FindInfoError("resume rejected: " + str(exc)) from None
    if effective_rs is not None:
        spec["argv"] = effective_rs.to_worker_argv()
        spec["budget"] = {"rounds": effective_rs.rounds,
                          "time_budget_sec": effective_rs.time_budget,
                          "task_timeout_sec": effective_rs.task_timeout,
                          "tool_timeout_sec": effective_rs.tool_timeout}
        spec["task_timeout"] = effective_rs.task_timeout
        if spec.get("run_spec") is not None:
            spec["run_spec"] = json.loads(effective_rs.to_json())
    spec["_effective_spec"] = (effective_rs if effective_rs is not None
                               else _spec_from_stored(spec))
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
    try:
        work.ensure_schema(store)
    except Exception as exc:
        core.log("work schema init failed: " + repr(exc)[:200])
    try:
        mapping_mod.ensure_schema(store)
    except Exception as exc:
        core.log("mapping schema init failed: " + repr(exc)[:200])
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
    summary["_ledger"] = ledger
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
                                   outdir=run_dir / "enscan", timeout=entity_timeout,
                                   supplier=getattr(args, "supplier", False),
                                   branch=getattr(args, "branch", False))
                if r.get("rc") == 124:
                    raise core.StageError(
                        "enscan timed out after " + str(entity_timeout) + "s",
                        result={"companies": len(r.get("companies", [])),
                                "icp": len(r.get("icp", [])),
                                "domains": len(r.get("domains", []))})
                if r.get("anchor_failed"):
                    # ENScan answered, but with companies that are NOT the one
                    # asked for (aiqicha returns a popular lookalike when the
                    # query misses). Nothing was stored, so this stage has no
                    # result of its own: reporting it as a plain success made a
                    # wrong entity look like a mapped target. A StageError
                    # records it as a coverage gap the agent must read.
                    raise core.StageError(
                        "enscan returned no entity matching the requested name "
                        "(rejected " + str(len(r.get("rejected") or [])) +
                        " unrelated result(s)" +
                        (": " + ", ".join((r.get("rejected") or [])[:3])
                         if r.get("rejected") else "") + ")",
                        result={"companies": 0, "icp": 0, "domains": 0,
                                "anchor_failed": True})
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
                    summary["_identity_ambiguous"] = {
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
            _ok_entity, _entity_res = _stage(
                store, run_dir, summary, "entity",
                {"name": args.name, "invest": args.invest, "deep": args.deep},
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
            summary["_approved_subject_refs"] = approved_refs
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
            summary["_approved_company_names"] = approved_names
            if approved_refs or approved_names:
                _write_status(run_dir, approved_subject_refs=approved_refs,
                              approved_company_names=approved_names)
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
            subject_refs = summary.get("_approved_subject_refs") or []
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
                approved_names = summary.get("_approved_company_names") or []
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
        if summary.get("_identity_ambiguous"):
            # docs par.8: launch NO downstream traffic on a guessed subject.
            # The gap is already recorded on the failed entity stage; skipping
            # straight to the verdict keeps every downstream stage out of
            # not_run (the run was never supposed to run them) while the
            # result carries the input-required next steps.
            summary["identity_ambiguous"] = summary.pop("_identity_ambiguous")
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
            for _private in ("_ledger", "_run_producers",
                             "_approved_subject_refs", "_approved_company_names",
                             "_run_public_id"):
                summary.pop(_private, None)
            core.write_jsonl(run_dir / "summary.jsonl", [summary])
            store.finish_run(run_id, summary)
            _write_status(run_dir, stage="done", state="completed",
                          stage_state="done", counts=summary["counts"],
                          result=summary["result"], coverage=coverage,
                          stage_index=1, stage_total=1)
            out(summary)
            return 5
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
            # The operator's rule: when ENScan anchors a real company but this
            # source filed NO domain, the run must not just die -- it must tell
            # the agent WHAT to search the internet engines for. A bare
            # "no seed domain" left the agent with nothing to act on, and the
            # anchored company (the one asset we DID establish) was thrown away.
            _anchor_names = list(summary.get("_approved_company_names") or [])
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
            unconfirmed: set = set()
            unsupported: set = set()
            for d in seeds:
                r = tools.t_subs(store, d, engines=args.engines,
                                 timeout=tool_timeout, ledger=summary.get("_ledger"))
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

        # 4. mapping -- the ONLY stage that may spend mapping quota (batch 1).
        # One question per (engine, domain seed) and per (engine, filing main
        # number); the task ledger decides whether it was already paid for, so
        # a second run, a later seed or a standalone `map` never asks twice.
        # Every other stage (certs/subs/dns/probe/...) is keyless: their
        # children get no credential at all (core.run strips them).
        # The stage runs only when the PLAN contains it: a domain-only run
        # (no seed subject, no filings) has nothing to map, and planning it
        # would manufacture a phantom gap no retry could close.
        if "mapping" in planned and not getattr(args, "no_mapping", False):
            _map_engines = args.engines
            _remap = bool(getattr(args, "remap", False))

            def _mapping():
                _seed_values = list(dict.fromkeys(list(named) + list(scope)))
                dom = mapdispatch.ask_all(
                    store, summary["_run_public_id"], "domain", _seed_values,
                    engines=_map_engines, remap=_remap, timeout=tool_timeout,
                    ledger=summary.get("_ledger"))
                icp = {"dispatched": 0, "reused": 0, "failures": [],
                       "truncated_sources": [], "skipped_engines": [],
                       "results": []}
                if icp_codes:
                    icp = mapdispatch.ask_all(
                        store, summary["_run_public_id"], "icp", icp_codes,
                        engines=_map_engines, remap=_remap, timeout=tool_timeout,
                        ledger=summary.get("_ledger"))
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
                   {"seeds": list(named) + list(scope), "codes": list(icp_codes),
                    "engines": args.engines, "remap": _remap},
                   args, _mapping,
                   lambda r: {k: r[k] for k in
                              ("domains", "ips", "dispatched", "reused",
                               "failures", "truncated_sources",
                               "unsupported_engines",
                               "unconfirmed_empty") if k in r} |
                   ({"unavailable_sources": r["unavailable_sources"]}
                    if r.get("unavailable_sources") else {}))

        # ---- discovery -> verify / reflow rounds -------------------------
        def dns_resumed() -> dict:
            hosts = [a["canonical"] for a in scoped_rows(0.4)
                     if core.source_tools(a.get("sources") or "") & _DNS_SOURCES]
            return {"resolved": len(hosts), "hosts": hosts, "resumed": True}

        # Per-name resolution record, kept for the whole run so round N+1 does
        # not re-query what round N already answered. NXDOMAIN is final; a
        # transient failure stays open and is retried (once per round).
        dns_states: dict = {}
        # Names a certificate named this round; merged into the next round's
        # dns input so a SAN is verified instead of merely recorded.
        cert_queue: set = set()

        def run_round(round_no: int) -> None:
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
                   resume=dns_resumed)
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
            for host in dns_resumed()["hosts"]:
                _attach(store, summary, "domain", host, producer="dns",
                        upstream="dns", route=None)
            _adopt_membership(store, summary, scope)
            # probe input is ALWAYS the full scoped store set (every resolved
            # row), never the ROW_LIMIT-truncated display list a tool returned
            dns_hosts = dns_resumed()["hosts"]
            summary["dns_hosts"] = len(dns_hosts)

            if not active:
                return
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
            _adopt_membership(store, summary, scope)
            after = len(scoped_domains(0.4))
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
        ledger = summary.get("_ledger")
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
        for _private in ("_ledger", "_run_producers",
                         "_approved_subject_refs", "_approved_company_names",
                         "_run_public_id"):
            summary.pop(_private, None)
        core.write_jsonl(run_dir / "summary.jsonl", [summary])
        store.finish_run(run_id, summary)
        # stage_total must never be smaller than what actually ran: a resumed
        # run replays stages and can legitimately report more entries than the
        # original plan, and percent > 100 reads as corruption.
        _done_count = len(done_stages) + len(skipped_stages)
        _stage_total = max(int(summary.get("_stage_total") or 0), _done_count)
        _write_status(run_dir, stage="done", state="completed", stage_state="done",
                      counts=counts, endpoints=endpoints,
                      result=summary["result"], coverage=coverage,
                      stage_index=_done_count,
                      stage_total=_stage_total)
        out(summary)
        return rc
    except Exception as exc:
        _write_status(run_dir, state="failed", error=repr(exc)[:500],
                      last_error={"type": type(exc).__name__, "message": str(exc)[:300]})
        raise
    finally:
        store.close()


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
                planned = _plan_stages(spec_mod.RunSpec(
                    name=rs.name, domain=rs.domain, task=rs.task,
                    active=active, ports=rs.ports, vhost=rs.vhost,
                    crawl=rs.crawl, brute=rs.brute, no_icp=rs.no_icp,
                    no_onepass=rs.no_onepass), active)
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
