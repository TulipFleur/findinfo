"""One versioned execution specification for every entry point.

Why this module exists
----------------------
The CLI, the background worker, deduplication and resume each described the
same run differently: the foreground path built a worker argv by hand, the
dedupe key hashed a subset of the flags, and resume trusted whatever limits it
was handed. Two flags added in different places would drift -- exactly the
"another flag list" problem docs/RELIABILITY-PLAN.md forbids.

RunSpec is the single conversion. It owns:

* from_cli -- capture every execution-affecting option of run;
* to_worker_argv -- the argv the worker re-parses (a round trip must
  preserve every option);
* dedupe_identity -- the target/collection identity, deliberately SEPARATE
  from limits: two runs for the same target with different limits are the
  same collection job (a caller can wait or act, and the difference is
  reported, never silently applied);
* resume_patch -- the only fields a resume may change on an existing job;
* diff -- what a caller would have to know when reusing an in-flight job
  with different limits.

It is a pure data layer: no tool execution, no credential loading, no store.
Legacy job.json reading stays in lib/jobs.py; this module only classifies what
a parsed spec means.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json

# Bumped when the field set changes meaning; readers reject unknown majors.
SCHEMA_VERSION = 1


@dataclasses.dataclass(frozen=True)
class RunSpec:
    """Every execution-affecting option of one run invocation."""

    # identity (what to collect -- reuse matches on this)
    name: str = ""
    domain: tuple[str, ...] = ()
    task: str = ""

    # requested execution shape (HOW to collect)
    active: bool = False
    ports: bool = False
    vhost: bool = False
    crawl: bool = False
    brute: bool = False
    brute_wordlist: str = "wordlists/sub.txt"
    brute_bandwidth: str = "3m"
    depth: int = 3
    invest: int = 51
    # the CLI parser defaults --deep to 1; the spec must agree (T20 round trip)
    deep: int = 1
    supplier: bool = False
    branch: bool = False
    entity_timeout: int = 1200
    engines: str = "fofa,quake,hunter,shodan,censys"
    top_ports: int = 1000
    max_seed: int = 5
    max_vhost_ips: int = 10
    no_icp: bool = False
    no_onepass: bool = False
    force_stage: bool = False
    rounds: int = 1
    time_budget: float = 0.0
    task_timeout: float = 0.0
    tool_timeout: int = 0

    # ---------------------------------------------------------------- identity
    @property
    def target_label(self) -> str:
        return self.name or (",".join(self.domain) if self.domain else "?")

    def dedupe_identity(self) -> str:
        """Stable hash of WHAT is collected, not how.

        Identity covers subject + explicit targets + task, nothing else: two
        submissions for the same target with different --rounds or
        --time-budget are the same collection and must reuse one job, with the
        difference reported through diff rather than silently applied.
        """
        blob = json.dumps(
            {"name": self.name, "domain": sorted(self.domain),
             "task": self.task},
            sort_keys=True, ensure_ascii=False)
        return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]

    # ---------------------------------------------------------------- diff
    def diff(self, other: "RunSpec") -> dict:
        """Fields where two specs of the SAME identity disagree.

        Returned as {field: {requested, in_flight}} for the reuse response.
        Empty when the two runs are interchangeable.
        """
        out: dict = {}
        for f in ("active", "ports", "vhost", "crawl", "brute", "supplier",
                  "branch", "depth",
                  "invest", "deep", "entity_timeout", "engines", "top_ports",
                  "max_seed", "max_vhost_ips", "no_icp", "no_onepass",
                  "rounds", "time_budget", "task_timeout", "tool_timeout",
                  "force_stage"):
            a, b = getattr(self, f), getattr(other, f)
            if a != b:
                out[f] = {"requested": a, "in_flight": b}
        return out

    # ---------------------------------------------------------------- argv
    def to_worker_argv(self) -> list[str]:
        """The argv a worker re-parses into the same spec.

        Defaults are omitted where the parser agrees, matching the existing
        _foreground_argv shape; a round trip through the real parser must
        return an equal spec (tested).
        """
        argv = ["run"]
        if self.name:
            argv += ["--name", self.name]
        for d in self.domain:
            argv += ["--domain", d]
        if self.active or self.ports or self.vhost or self.crawl or self.brute:
            argv.append("--active")
        if self.ports:
            argv.append("--ports")
        if self.vhost:
            argv.append("--vhost")
        if self.crawl:
            argv.append("--crawl")
        if self.brute:
            argv += ["--brute", "--brute-wordlist", self.brute_wordlist,
                     "--brute-bandwidth", self.brute_bandwidth]
        if self.supplier:
            argv.append("--supplier")
        if self.branch:
            argv.append("--branch")
        argv += ["--depth", str(self.depth), "--invest", str(self.invest),
                 "--deep", str(self.deep),
                 "--entity-timeout", str(self.entity_timeout),
                 "--engines", self.engines,
                 "--top-ports", str(self.top_ports),
                 "--max-seed", str(self.max_seed),
                 "--max-vhost-ips", str(self.max_vhost_ips)]
        if self.no_icp:
            argv.append("--no-icp")
        if self.no_onepass:
            argv.append("--no-onepass")
        if self.force_stage:
            argv.append("--force-stage")
        if self.rounds != 1:
            argv += ["--rounds", str(self.rounds)]
        if self.time_budget:
            argv += ["--time-budget", str(self.time_budget)]
        if self.tool_timeout:
            argv += ["--tool-timeout", str(self.tool_timeout)]
        if self.task_timeout:
            argv += ["--task-timeout", str(self.task_timeout)]
        if self.task:
            argv += ["--task", self.task]
        return argv

    # ---------------------------------------------------------------- resume
    RESUMABLE_LIMITS = frozenset((
        "rounds", "time_budget", "task_timeout", "tool_timeout",
        "force_stage"))
    IDENTITY_FIELDS = frozenset((
        "name", "domain", "task", "engines", "no_icp", "no_onepass",
        "active", "ports", "vhost", "crawl", "brute"))

    def resume_patch(self, requested: "RunSpec") -> "RunSpec":
        """The spec a resume settles on: same job, documented limit updates.

        Identity, scope, source selection and authority flags CANNOT be
        patched -- that requires a new run (docs/RELIABILITY-PLAN.md par.4).
        Raises ValueError when the caller tries.
        """
        changed = {f: (getattr(self, f), getattr(requested, f))
                   for f in self.IDENTITY_FIELDS
                   if getattr(self, f) != getattr(requested, f)}
        if changed:
            raise ValueError(
                "resume cannot change identity/scope/source fields: "
                + json.dumps({k: (list(v[0]) if isinstance(v[0], tuple) else v[0],
                                  list(v[1]) if isinstance(v[1], tuple) else v[1])
                              for k, v in changed.items()}, sort_keys=True))
        return dataclasses.replace(self, **{
            f: getattr(requested, f) for f in self.RESUMABLE_LIMITS
        })

    # ---------------------------------------------------------------- json
    def to_json(self) -> str:
        d = dataclasses.asdict(self)
        d["domain"] = list(self.domain)
        d["schema_version"] = SCHEMA_VERSION
        return json.dumps(d, sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_json(cls, blob: str) -> "RunSpec":
        d = json.loads(blob)
        version = d.pop("schema_version", SCHEMA_VERSION)
        if not isinstance(version, int) or version > SCHEMA_VERSION:
            raise ValueError("unsupported RunSpec schema_version: %r" % version)
        fields = {f.name for f in dataclasses.fields(cls)}
        unknown = sorted(set(d) - fields)
        if unknown:
            raise ValueError("unknown RunSpec fields: " + ",".join(unknown))
        if "domain" in d:
            d["domain"] = tuple(d["domain"] or ())
        return cls(**{k: v for k, v in d.items() if k in fields})


def _explicit_or(args, name, default):
    """A numeric option only takes its default when the caller did NOT type it.

    `getattr(...) or 1200` turned an explicitly typed 0 into 1200, so
    `--entity-timeout 0` ("no ceiling") silently became the default ceiling
    (F15). None/absent still means "use the default"; a real 0 or any other
    number is preserved verbatim.
    """
    val = getattr(args, name, None)
    if val is None or val == "":
        return default
    return val


def from_cli(args) -> RunSpec:
    """Build a RunSpec from a parsed run namespace (the single source)."""
    return RunSpec(
        name=getattr(args, "name", "") or "",
        domain=tuple(getattr(args, "domain", None) or ()),
        task=getattr(args, "task", "") or "",
        active=bool(getattr(args, "active", False)),
        ports=bool(getattr(args, "ports", False)),
        vhost=bool(getattr(args, "vhost", False)),
        crawl=bool(getattr(args, "crawl", False)),
        brute=bool(getattr(args, "brute", False)),
        supplier=bool(getattr(args, "supplier", False)),
        branch=bool(getattr(args, "branch", False)),
        brute_wordlist=getattr(args, "brute_wordlist", "wordlists/sub.txt"),
        brute_bandwidth=getattr(args, "brute_bandwidth", "3m"),
        depth=int(getattr(args, "depth", 3)),
        invest=int(getattr(args, "invest", 51)),
        deep=int(getattr(args, "deep", 2)),
        entity_timeout=int(_explicit_or(args, "entity_timeout", 1200)),
        engines=getattr(args, "engines",
                        "fofa,quake,hunter,shodan,censys"),
        top_ports=int(getattr(args, "top_ports", 1000)),
        max_seed=int(getattr(args, "max_seed", 5)),
        max_vhost_ips=int(getattr(args, "max_vhost_ips", 10)),
        no_icp=bool(getattr(args, "no_icp", False)),
        no_onepass=bool(getattr(args, "no_onepass", False)),
        force_stage=bool(getattr(args, "force_stage", False)),
        rounds=int(_explicit_or(args, "rounds", 1)),
        time_budget=float(_explicit_or(args, "time_budget", 0)),
        task_timeout=float(_explicit_or(args, "task_timeout", 0)),
        tool_timeout=int(_explicit_or(args, "tool_timeout", 0)),
    )
