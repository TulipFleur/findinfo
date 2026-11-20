# Reliable execution and delivery for agent consumers

Status: **implemented**. Batches A-G (typed results, RunSpec, work tables,
identity, job fencing, metered ledger, registry/docs) landed on baseline
`20dfca3`; the wiring batches that followed connected the runtime to every
new module: the main pipeline onto run membership / durable work / stage
invocations (`aa9a840`), launch/replay/resume onto the one RunSpec
(`61759f3`), billed provider calls onto the per-request ledger (`e7fa4be`),
the entity stage onto the subject gate (`cfaac5d`), wildcard probing onto
the unified evidence API (`8608489`), and the worker's state writes onto
the launch fence (`f9a4bf2`). This document is now the design record;
docs/DATA-MODEL.md describes the shipped tables and ledger.

Review date: 2026-11-20 (Asia/Shanghai). Baseline: `20dfca3`.

## 1. Baseline and objective

The working tree inspected for this design has returned to `20dfca3`. The
temporary integration inspected in the previous review is no longer present:
`lib/assets.py`, `lib/metered.py`, and `lib/templates.py` do not exist in this
baseline. The main pipeline DOES call `t_brute` and `t_icp`. Do not restore those
calls a second time or transplant the discarded integration wholesale.

The goal is a consumer agent that can explain, from persisted evidence:

1. which subject and scope it worked on;
2. which requested work executed, was reused, was unavailable, or remains;
3. why the job stopped and whether a retry can change the outcome;
4. what data was observed, when, and through which independent upstream;
5. what further work would consume traffic, requests, or quota.

Completing a bounded run does not prove that an organisation has no undiscovered
assets. Reports must state the scope, available sources, time, and limits of the
claim. Do not invent a numerical inventory coverage percentage without a known
denominator.

### Current issues versus planned capabilities

| Area | Current baseline | Design action |
|---|---|---|
| Stage execution | ICP/brute calls exist; plan and runner remain separately maintained | Introduce one stage registry without changing the initial execution order |
| Stage outcomes | `subs` summary projection drops its outcome; `_stage` supplies success by default | Preserve typed results before formatting a display summary |
| Completion | Final verdict does not consume every missing/partial stage | Compute the verdict from persisted obligations and work state |
| Reflow | Round input is reconstructed from the store; checkpoints lack a precise public-run work boundary | Add run membership and durable, deduplicated work items |
| Entity | Brand matching and `parent == input name` are fragile | Keep stable subject IDs and explicit anchor evidence |
| DNS | DoH wildcard probe records fake-IP rather than normal wildcard answers, with a different parent key | Unify wildcard evidence and resolver paths |
| Jobs | Resume has no matching start lock; default wait omits `reaped_by_host` | Lock and fence resumes; preserve actionable fields |
| Brief | Byte measurement happens before subsequent mutation and another serializer | Serialize once and enforce the actual stdout byte limit |
| Metered ledger | No unified query ledger in this baseline | Add it incrementally after ingestion and execution contracts |
| Tests | 47 test modules exist; the standard runner lists 44 | Register or explicitly classify every module |

This is an incremental change to the local Python CLI and SQLite runtime. It
does not require a daemon, external queue service, or a new agent framework.

## 2. Target execution model

```text
CLI -> RunSpec -> plan from StageRegistry
                   |
             identity / scope
                   |
          discovery stage adapters
                   |
           atomic record_observation
          /            |             \
    asset graph    run membership    work queue
                                        |
                              DNS / probe / enrich
                                        |
                              crawl / JS / reflow
                                        |
                              completion evaluator
                                        |
                         status / wait / brief / report
```

First preserve the current initial order:

```text
entity? -> onepass (passive adapter) -> certs -> subs -> brute? -> icp?
        -> [dns -> probe? -> ipagg? -> ports? -> vhost? -> crawl?/extract?]
```

Only after the contract and queue tests pass, schedule independent free
collectors concurrently. CT must have one logical owner: do not collect all CT
roots in a free batch and immediately collect them all again in a separate
stage. Existing public stage names can remain presentation aliases.

## 3. Module boundaries

| Module | Responsibility | Explicit boundary |
|---|---|---|
| `findinfo.py` | Parse CLI, dispatch, print results | No second handwritten copy of plan or verdict logic |
| `lib/spec.py` (new) | Versioned `RunSpec`, canonicalisation, identity hashes, legacy import | No tool execution or credential loading during pure planning |
| `lib/pipeline.py` (new) | Stage registry, adapters, result types, plan and verdict | Never infer execution success from display counts |
| `lib/work.py` (new) | Run membership, observations, work routing and leases | No network; uses the existing SQLite transaction discipline |
| `lib/targets.py` (new) | Subject references, typed scope, relation policy | A related asset is not an active-scope grant |
| `lib/metered.py` (new, later batch) | Provider requests, reuse, attempts, reservations and budgets | Every billed path must pass through it |
| `lib/core.py` | Existing store, process primitives and compatibility wrappers | Keep existing entry points while migrating their internals |
| `lib/tools.py` | Native-tool/provider adapters and normalisation | Emit all accepted observations before any display truncation |
| `lib/jobs.py` | Worker lifecycle, locks, fencing and wait | Does not decide whether inventory coverage is complete |
| `lib/report.py` | Views over persisted facts | Does not silently convert unknown or partial coverage into success |

Create modules when their implementation batch starts. Avoid creating empty
abstraction layers in the first patch.

## 4. One RunSpec for foreground, background, deduplication and resume

Use a versioned immutable execution specification. Persist public `run_id`
(the existing run-directory ID) separately from the legacy integer database
run ID. New tables use the public text ID consistently.

```python
RunSpec(
    schema_version=1,
    run_id=public_id,
    task=task,
    home=home,
    target=TargetSpec(name=raw_name, explicit_targets=targets),
    scope_policy=policy,
    stages=stage_options,
    sources=source_options,
    limits=limits,
    runtime=runtime_options,
)
```

The same conversion owns `from_cli`, `to_worker_spec`, `dedupe_identity`, and
`resume_patch`. A parser round trip must preserve every execution-affecting
option. Never maintain independent flag lists for these operations.

Separate the target/collection identity from the requested execution limits.
When an in-flight job matches the former but has different limits, return
`reused=true`, `effective_limits`, and `request_differences`; do not pretend the
new limits were applied. A caller can keep waiting or explicitly act on the
existing job. Do not silently change a running job's scope.

Resume may patch only the documented limit and force-stage fields. Changing a
subject, scope, source selection or authority policy requires a new run.
Persist a new attempt before launch and clear the previous attempt's verdict.

Old `job.json` containing argv remains readable: parse argv into RunSpec once,
record the imported format and preserve its semantics. Unknown formats return
a structured compatibility error, not guessed defaults.

## 5. One plan, explicit obligations, lossless stage results

A `StageSpec` declares `id`, `phase`, `dependencies`, `enabled_when`,
`input_selector`, `runner`, `input_fingerprint`, and coverage obligations.
The registry is a DAG inside a phase; the outer round scheduler handles reflow.
Validate missing runners, unknown dependencies, cycles and duplicate IDs before
starting tools.

Each dispatch has a unique `invocation_id`, including retries within the same
attempt. Index by `(run_id, attempt, stage_id, unit_key, input_revision)`.
`unit_key` identifies a root/source or a round as appropriate, and a work lease
references the invocation that owns it. Keep per-unit and per-dispatch history:
repeated rounds or retries must not overwrite each other's states in a map
keyed only by stage name.

```python
StageResult(
    stage_id="subs",
    state="partial",
    outcome="partial",
    disposition="executed",
    reason_code="source_timeout",
    retryable=True,
    counts={"observed": 120, "enqueued": 93},
    source_outcomes=[...],
    gaps=[...],
    input_fingerprint="...",
)
```

Keep execution state (`pending/running/succeeded/partial/failed/blocked/skipped`),
source outcome (the existing `OUTCOME_*` vocabulary), and disposition
(`executed/reused/disabled/no_input`) separate. Display formatting cannot
change any of them. A missing outcome from a new adapter is a contract error;
do not silently supply OK.

An empty successful provider answer is not an error. A missing optional key is
an unavailable capability, not a transient failure. A no-input downstream
stage is justified only after successful exhaustion of available upstreams;
remaining optional unavailable sources retain capability gaps but do not block
this disposition. Failed identity or failed discovery instead blocks dependent
work and must not turn downstream emptiness into completion.

Persist `stage_invocations` before dispatch and after completion. A checkpoint
is reusable only when its input, scope, adapter version, relevant capability
identity and freshness policy match. Partial/budget results remain usable but
cannot become successful checkpoints. Credential identity is an opaque
fingerprint, never a credential value.

Evaluation selects the effective invocation for the current attempt and input
revision. A reused success produces an explicit current-attempt invocation with
its original evidence reference. Historical partial/failed attempts remain
auditable, but cannot poison a later successful retry or be mistaken for the
current verdict.

## 6. Durable discovery and work routing

Add these tables through idempotent migrations in the existing task database:

| Table | Key and minimum data |
|---|---|
| `run_assets` | `(run_id, kind, canonical)`; first/last observation, scope revision |
| `observations` | ID; run, producer, independent upstream, asset key, subject reference, observed_at, evidence reference |
| `work_items` | ID; run, stage, asset key, input revision, status, attempts, retry_at, lease token/expiry, reason |
| `stage_invocations` | unique invocation ID; run/attempt/stage/unit/revision index; fingerprint, state, outcome, reason, counts |

`record_observation` must atomically upsert the asset, append the observation,
attach run membership and enqueue eligible downstream work. Use lower-level
transaction-aware store operations so this does not nest `BEGIN IMMEDIATE`.
Do not hold a database transaction while making a network request.

A producer must call this path for every accepted streamed row, before applying
stdout/sample limits. Adapt the existing store write paths; do not try to
recover all data from a truncated tool return value. Standalone commands retain
their existing behaviour when no run context is supplied. Propagate context
explicitly into worker adapters, including threaded collectors.

SQLite connections remain owned by their creating thread. Concurrent collectors
perform fetch/parse work and submit observations through a bounded channel;
the coordinator writes with its own Store connection and acknowledges committed
batches. Do not share the current `check_same_thread=True` connection across
collector threads. Flush pending writes before declaring a stage finished or
checking convergence. Keep the first implementation sequential until this
writer boundary is tested.

Routes are typed and policy-controlled:

- domain from CT, mapping, ICP, TLS SAN or JS -> DNS, when within resolution scope;
- verified domain/IP/endpoint -> probe, when active policy permits;
- changed verified IP evidence -> IP aggregation and enabled enrichment;
- new live URL -> crawl, when enabled and in scope;
- JS URL -> fetch/extract;
- related asset -> retained evidence and an optional passive-only frontier.

Deduplicate work by `(run_id, stage_id, kind, canonical, input_revision)`.
Revisions derive from meaningful input or policy changes, not a fresh timestamp
on every round. Re-observing the same source must not create endless work or
increase independent-source confidence repeatedly.

Lease work under a short `BEGIN IMMEDIATE` transaction. A crashed worker's
expired lease becomes eligible again; stale lease tokens cannot commit.
Results, generated work and acknowledgement of the input item commit together.
Resume reconstructs work from these rows, not process-local Python sets.
Migrate existing run-associated JS work through this same authority:
`Store.js_enqueue/js_claim/js_finish/js_stats` delegate to the new queue, or
use a one-time import with read-only compatibility views. Never keep two
independently claimable queues for the same work. Preserve pending/failed items
and explicitly attach only those whose run membership can be proved; unknown
legacy ownership requires explicit admission. Preserve standalone behaviour
without silently importing its global backlog into a new run.

Run-specific status, counts, brief and reports read run membership, including
explicitly attached reused evidence. They do not include every historical row
matching a suffix. Reuse records `attached_at` and its evidence origin while
preserving the original `observed_at`; replaying a cache must not claim a fresh
network observation. Global asset queries retain their explicit existing role.

The scheduler waits for in-flight producers before declaring convergence.
Distinguish scheduling quiescence from successful convergence and coverage.
Permanent failure, provider-blocked and scope-excluded are settled scheduling
states, not instructions to wait forever. Pending, delayed-retry and leased
work remain outstanding; wait until an eligible retry time or stop under a
named budget/deadline. Required permanent failures and budget-deferred work
produce partial coverage. Optional capability blocks retain their gaps under
the available-capabilities contract. Deliberate scope exclusions explain the
boundary without creating an obligation outside that policy. New IP, endpoint
or JS work counts too; domain-count stability alone is insufficient.

Persist budget-deferred, scope-excluded, provider-blocked and permanently
failed items separately from a successful empty answer. They contribute to
coverage explanations. A deferred backlog must not be renamed convergence.

## 7. Honest completion without breaking keyless runs

Derive all views from one evaluator. It reads obligations, invocation results,
queue state, limits and source capability gaps; it never infers success from
`elapsed` or `count > 0`.

Precedence:

1. Cancellation and hard timeout use their existing job semantics.
2. An unusable target or all required work failing -> `failed`, exit 1.
3. A required planned stage with no accountable result, a partial invocation,
   failed available source, unfinished work or exhausted required budget ->
   `partial`, exit 5. Name every reason in coverage.
4. All available obligations are satisfied and work is exhausted -> legacy
   `complete`, exit 0, with an explicit completion basis.

Preserve the existing keyless contract: absent OPTIONAL credentials do not
produce exit 5 or endless resume advice. Add these fields:

```json
{
  "result": {
    "status": "complete",
    "completion_basis": "available_capabilities"
  },
  "coverage": {
    "complete": true,
    "requested_complete": false,
    "unavailable": {"sources": ["example-provider"]},
    "claim_scope": "configured_scope_and_available_sources"
  }
}
```

`coverage.complete` retains its legacy operational meaning. The new
`requested_complete` is false when requested source coverage was unavailable.
Neither field asserts a complete organisation-wide inventory. Human delivery
and `brief` must expose those limits even when legacy status is complete.
If a source is explicitly designated required by a future policy, its absence
is a blocking gap; do not silently redefine every optional key as required.

Use explicit reason codes such as `planned_stage_not_run`, `source_timeout`,
`source_unavailable`, `work_pending`, `budget_exhausted`, `identity_ambiguous`,
and `scope_excluded`. Next steps classify whether waiting, retrying, supplying
input, changing a capability, or accepting the gap can help.

## 8. Subject identity and scope

Keep `brand -> legal subject -> domain/ICP -> observation` edges. Store subject
IDs and aliases separately from the original search string. ENScan output must
be filtered while retaining each entity's own assets; do not flatten all assets
and assign them to the first matching company.

Short brand matching can produce candidate subjects, not automatic ownership.
Explicit domains can seed a run independently. If identity is ambiguous and no
usable explicit seed exists, report `identity_ambiguous` plus input-required
next steps, and launch no downstream traffic. Keep the existing terminal-state
vocabulary; the attention requirement is a result field, not a new job state.

Represent scope as typed entries: domain suffix, exact IP, or exact endpoint.
Compare IP addresses AND ports for endpoint matches. Canonicalise IDN, IPv6 and
ports without resolving DNS. Preserve explicit ports throughout parsing,
deduplication, storage, probing, reporting and worker replay.

Evidence links do not all grant scope. Only explicit user scope and validated
subject anchors admitted by the run policy can do so. Same-IP, related-of,
same-issuer, certificate co-occurrence and supplier relationships are evidence,
not automatic grants. Recheck scope at network dispatch as well as ingestion.

## 9. DNS and wildcard evidence

Use one `WildcardEvidence` representation and parent-key function for dnsx,
system resolver and DoH. Probe multiple unpredictable names under the relevant
parent; do not insert an extra `wild.` label and later read another key.
Record ordinary A/AAAA/CNAME evidence from probes. Fake-IP detection is a
separate check, not the wildcard classifier.

The signature includes probe outcomes and ordinary address/CNAME sets. A
timeout or fake-IP response cannot establish a valid signature. Matching one
wildcard address is insufficient to discard a candidate with additional
independent A/AAAA/CNAME evidence; retain and label this mixed evidence.

Keep wildcard-like candidates in evidence with a reason instead of erasing
them. Do not auto-expand a guessed wildcard namespace into active work. An
explicit target remains visible even if its answers resemble the wildcard
signature; any further validation follows its existing active policy.

Persist DNS state with resolver profile, observed time and expiry. NXDOMAIN
requires an actual NXDOMAIN response: a filtered fake-IP, a timeout, NODATA or
a CNAME-only answer is not sufficient. Resolver changes, expiry or an explicit
forced refresh invalidate reusable negative evidence. Do not rerun known
answers every round simply because the loop advanced.

## 10. Metered requests and freshness

Introduce the ledger only after the ingestion contract is reliable. Inventory
all billed paths first: native mapping, relay/gateway, provider-enabled passive
collectors, ICP, and certificate queries on mapping services. If a native
collector cannot expose or exclude its billed providers, do not advertise its
invocation as quota-controlled; route those providers through explicit adapters.

Cache identity includes engine, provider/account fingerprint, endpoint,
normalised query, requested fields, sort, page size, page/cursor, API/adapter
query version and refresh generation. Never store credentials. Logical-query
progress retains page membership. Reuse requires the same generation, paging
specification and valid snapshot/cursor; increasing a row budget then fetches
missing pages. Changing page size cannot reuse old page numbers as if offsets
were unchanged. Expired pages or changed remote results require re-evaluation;
providers without stable snapshots disclose possible cross-page inconsistency.

Reserve an individual request and the run's request budget in one short
transaction before dispatch. Concurrent agents reuse a settled result or wait
for the request owner; they do not both call the provider. Persist response
evidence before releasing the claim. No network happens under the SQL lock.

Metered ownership uses `request_id`, generation and an owner token distinct
from ordinary work leases. Atomically increment the attempt and reserve budget
before dispatch; settlement validates ownership. Expired metered ownership
becomes uncertain, not automatically redispatchable. A late response is
retained against its original request and cannot overwrite another generation
or settle another owner's reservation.

Attempts are cumulative: `remaining = max_attempts - persisted_attempts`.
Retries and resumes do not reset that counter. Authentication and quota blocks
have provider/account identity and an appropriate retry condition or time.
A changed credential can be reconsidered without persisting its secret.

After a crash or timeout that may already have incurred a charge, mark the
request `uncertain`. Do not promise exactly-once remote billing or automatically
refund its reservation and send it again. Use a provider idempotency key when
supported; otherwise expose the uncertainty and require explicit refresh.

Proposed reusable-result TTL: 7 days for successful nonempty queries and 1 day
for successful empty queries, configurable per source. These are product
defaults, not provider guarantees. A truncated result resumes from known pages
when budget permits; it is not permanently treated as a complete answer.
Export observation timestamps and cache age.

Add an explicit `--refresh-metered` entry and request/row ceilings. A pure plan
shows cache hits, outstanding calls and unknown credit cost. Explicit refresh
is the user's opt-in; do not add an unrelated interactive confirmation loop.
Do not claim that a row limit is a money limit or fabricate provider prices.

## 11. Job and output contracts

Resume uses a per-run cross-process lock: reread state -> check liveness ->
allocate attempt and launch token -> persist queued spec -> spawn -> publish PID,
all before releasing the lock. The worker claims its launch token. A superseded
attempt/token cannot update state, acknowledge work, or publish a verdict.
Two simultaneous resumes produce one worker and one new attempt.

Validate ownership when claiming work and reserving metered budget in the same
transaction, then revalidate before each adapter/native/network dispatch.
Revocation stops further dispatch; it cannot retract an already in-flight
external operation. Reconcile that operation before retrying, using the metered
uncertainty rules when relevant. Cover launch failures after queued persistence
and after spawn but before PID publication; recovery must locate or fence the
original worker rather than blindly launch another.

Default wait preserves `reaped_by_host`, attempt, result, interruption,
terminal/timeout flags and a compact coverage reason list. `--full` only adds
detail, not essential decision fields.

The agent loops over bounded waits on the same run ID and can hand that context
to another session. A background worker does not wake a finished agent session.
If the host reaps detached processes, return that fact and choose the documented
live-parent/foreground fallback under a deadline; do not repeatedly respawn
background workers and call that recovery.

The consumer protocol is explicit:

```text
start once -> keep run_id, home, task and the last substantive sequence
  -> wait --run <same run_id> --timeout 30 [--since <sequence>]
     interrupted -> inspect reaped_by_host and the permitted recovery action
     terminal    -> deliver the persisted verdict, coverage and remaining work
     timed out   -> continue waiting on the same run; this is not a job timeout
     changed     -> update the cursor and inspect progress; keep the same run
```

Expose a structured `next_action`, `retryable`, and `next_retry_at` where
applicable, derived from persisted state rather than only a natural-language
command. A terminal partial run does not automatically resume: optional key
gaps and unchanged budget limits cannot improve by repeating the same attempt.
Transient retry advice must retain the cumulative attempt cap and backoff.
When a session cannot keep waiting, hand off run identity, storage context,
cursor and last known verdict. A later session rereads status before acting.
Automatic re-entry is possible only when the host supplies an explicitly
configured continuation/scheduler; do not imply that the Python tool provides
one or claim delivery while the result is still pending.

Persist the sequence of the last substantive change under the state lock.
`wait --since N` returns immediately when that sequence exceeds N, including
progress between calls. Heartbeat-only updates do not count. Old states lacking
this marker request a one-time resynchronisation instead of silently losing a
change.

Use one JSON-line encoder for stdout and brief measurement. Include all notes,
metadata, escape settings, separators and the final newline before measuring.
Truncate optional detail until the actual bytes fit. Define a bounded minimum
envelope: run identity, result, completeness flags, gap count, a bounded list of
reason codes, truncation flags and an artifact reference to full details. Long
scope lists and warning text can be shortened without losing counts or making
partial coverage look complete. Recompute `brief_bytes` until its
value and encoded length agree. Reject an impossibly small limit with a
structured argument error. No mutation is allowed after size enforcement.

## 12. Offline planning and the Meituan fixture

Add `run --dry-run`: parse RunSpec, apply supplied capability metadata, compile
the plan, list identity questions, stages, scope, budgets and possible requests.
It starts no job, creates no asset database, reads no credentials and performs
no external process or network operation. Missing live facts remain unknown.
Use `run_id: null` with an optional `plan_id/spec_hash`; never invent a live job
identity. Combining dry-run with background or resume remains read-only: an
existing job spec may be read to preview effective configuration, but no PID,
attempt, cancellation flag or job state changes.

This requires an early pure bootstrap: the CLI option schema, RunSpec and
registry metadata must be importable without importing `lib.core` or
`lib.tools` and their configuration bootstrap. Keep runner references lazy and
resolve them only for real execution. Use the same option definitions for dry
planning and normal dispatch; do not introduce another handwritten parser.
An offline plan validates the declared graph and reports runtime capabilities
as unverified, rather than importing collectors to pretend they were checked.

Add `doctor --offline`: inspect Python/platform, paths and file metadata without
tool execution, DNS, HTTP or key validation. Mark egress and runtime tool health
`not_checked`, never successful. Reachability and fake-IP verdicts use null or
not_checked rather than false, which would imply a failed check. Preserve
these distinctions in compact output. Default doctor retains its behaviour.

Development tests use a dedicated fixture loader and do not add a public
"mock collection" mode to the consumer workflow. The label is `美团`; ALL
subjects, domains, records, addresses and counts below are synthetic:

```text
Brand: 美团
Subjects: fixture-subject-A / fixture-subject-B
Roots: mt-a.example.com / mt-b.example.net
CT-only host: ct-only.mt-a.example.com
JS-only host: js-only.mt-a.example.com
Related host: partner.example.org
Address: 203.0.113.10
Endpoint: 203.0.113.10:8443
```

Use reserved example.com/example.net/example.org namespaces so the fixtures
exercise the real public-suffix/domain normalisation contract. Do not replace
the normaliser to admit otherwise rejected test names. These names still must
never reach a resolver or public service during offline tests.

| ID | Scenario | Required result |
|---|---|---|
| T01 | Registry stage has no runner, duplicate ID or cyclic dependency | Plan rejected before any adapter executes |
| T02 | Enabled ICP/brute invocation never reports a result | Partial; named gap; never complete |
| T03 | One mapping source succeeds and another available source times out | Preserve data and partial outcome; no successful checkpoint |
| T04 | Only an optional provider key is absent | No provider call, no endless resume, exit 0 if other obligations finish; requested_complete=false |
| T05 | Empty successful upstream leaves no probe input | Accountable no-input disposition; no invented failure |
| T06 | Brand has two plausible synthetic legal subjects, no explicit seed | Input-required result; no discovery or active dispatch |
| T07 | Accepted subject has a different display name from the search alias | Seed retained through subject ID, not string equality |
| T08 | CT is the only source of ct-only.mt-a.example.com | Exactly one DNS work item; discovery count is nonzero |
| T09 | JS is the only source of js-only.mt-a.example.com | DNS work survives restart and is drained in a later round |
| T10 | Worker crashes after observation commit but before tool completion | Membership and work remain; no lost output or duplicate work |
| T11 | Two runs use different seeds in the same task | No cross-run dispatch unless an explicit reusable-evidence import is recorded |
| T12 | Related SAN/domain or another IP with the same port | Kept as evidence; no scope grant or active dispatch |
| T13 | Bare IP and IP:port explicit targets | Preserve kind and port end to end; do not disappear through domain normalisation |
| T14 | DoH probes share ordinary wildcard answers; candidate may have additional evidence | Mark wildcard-only guesses; retain mixed A/AAAA/CNAME evidence; failed/fake probes establish no signature |
| T15 | Fake-IP, timeout, NODATA or CNAME-only response | Distinguish each from authoritative NXDOMAIN |
| T16 | Domain count is stable but endpoint/JS/retry work remains | No false convergence |
| T17 | Hard timeout expires during initial discovery | Worker stops and persists partial output and timeout reason |
| T18 | Concurrent resumes or launch interrupted before PID publication | One new attempt and worker; stale-token writes and new adapter dispatch rejected; no duplicate launch during recovery |
| T19 | Progress occurs between waits; later updates are heartbeats only | Since cursor sees the real change without heartbeat wakeups |
| T20 | All execution-affecting CLI options replay in worker | Foreground/background semantics match; differences reported on reuse |
| T21 | Chinese text, long warnings, many gaps at brief byte boundary | Actual stdout fits the declared ceiling, remains one valid JSON line |
| T22 | Two agents ask the same billed query concurrently | One provider dispatch; cumulative attempts and budget reservations correct |
| T23 | One prior failed attempt plus another retry | Total never exceeds the configured cumulative cap |
| T24 | Failure after possible provider billing, before local response commit | Uncertain request; no silent automatic second charge |
| T25 | Empty cache TTL expires, credential changes, or explicit refresh | Correct re-evaluation; no permanent stale-empty answer |
| T26 | Row budget or page size changes; old pages exist | Reuse valid pages only within the same generation/paging contract; no skipped ranges; disclose unstable snapshots |
| T27 | Native collector may silently call billed providers | Adapter configuration proves exclusion, or route is reported uncontrolled |
| T28 | Built package/copy installation | Includes all imported runtime modules; offline diagnostics work without egress |
| T29 | Partial attempt is repaired, or a valid checkpoint is reused | Current verdict reflects effective results; historical errors remain audit data |
| T30 | Cached evidence is attached to another run | Run views include only admitted evidence; original observation time is preserved |
| T31 | Parallel collectors emit enough data to cause backpressure | No cross-thread SQLite use, lost writes, premature completion or unbounded memory |
| T32 | Dry-run/offline doctor, including background/resume combinations | No outbound attempt, credential read, process, DB/job creation or job-state change; unknown checks stay unknown and plan run_id is null |
| T33 | Legacy JS pending/failed items are migrated and resumed | No lost work or double claim; unknown ownership is not silently attached to a different run |
| T34 | Metered owner expires; its late response races with explicit refresh | No automatic redispatch, cross-generation overwrite or settlement of another reservation |

The fixture runner must deny socket connection/resolution and external process
creation by default. Tests for job/process ownership separately allow only the
known local fake-worker executable/script, under the same socket guard in every
child. Never fall back to native scanners when a fake adapter is absent.
All test state and configuration are temporary. Imports must not load local
credential files. Assert zero denied outbound attempts as well as zero actual
outbound requests; a caught network exception is not an acceptable test pass.

## 13. Implementation batches and acceptance gates

| Batch | Ownership | Deliverable and exit gate |
|---|---|---|
| A | `findinfo.py`, `lib/pipeline.py`, related tests | Typed results, preserve subs outcome, strict missing/partial verdict; retain current stage calls and keyless contract; T01-T05 |
| B | `lib/spec.py`, CLI/job adapters | One RunSpec, explicit reuse differences, compatible job import and offline plan; T20, T32 |
| C | `lib/work.py`, core migrations and collector writes | Atomic membership/observation/work ingestion, run isolation, durable reflow and JS queue migration; T08-T11, T16, T29-T31, T33 |
| D | `lib/targets.py`, entity/DNS/probe adapters | Subject links, typed scope, IP/port preservation, common wildcard evidence; T06-T07, T12-T15 |
| E | `lib/jobs.py`, CLI output, `lib/report.py` | Resume lock/fencing, reliable wait cursor, identical measured/emitted brief; T17-T19, T21 |
| F | `lib/metered.py`, all provider adapters | Ledger, page reuse, cumulative attempts, uncertainty and bounded refresh; T22-T27, T34 |
| G | docs, tests runner, install/release checks | One stage inventory in docs, no unregistered tests, complete runtime manifest; T28 |

Implementation status (all wired into the runtime, tests green offline):

| Deliverable | Batch | Commit |
|---|---|---|
| Typed stage results, subs outcome preserved, strict verdict | A | `75059e9` |
| One RunSpec (from_cli/argv/dedupe/resume), dry-run, offline doctor | B | `904ebef` |
| run_assets/observations/work_items/stage_invocations tables + ingestion contracts | C | `8a54c12` |
| Subject gate, typed targets, unified wildcard evidence API | D | `2041ea2` |
| Fenced resume, claim_launch/fenced_write, verified wait cursor | E | `0c980e1` |
| Metered ledger with typed statuses and quota evidence | F | `21690fb` |
| StageRegistry validation, changelog/docs checks | G | `7191ae7` |
| Pipeline onto work tables: membership round inputs, invocations, JS adoption | W1 | `aa9a840` |
| Launch/replay/resume through RunSpec; identity changes refused | W2 | `61759f3` |
| Billed requests recorded per request; verdict/brief read the ledger | W3 | `e7fa4be` |
| Entity stage gates on resolve_entity_identity (identity_ambiguous) | W4 | `cfaac5d` |
| dnsx + DoH share one wildcard evidence table (no wild. label) | W5 | `8608489` |
| All worker state writes fenced (running/timeout/terminal) | W6 | `f9a4bf2` |

Batches should be small reviewable commits. Queue work depends on the typed
result contract; metered integration depends on reliable ingestion. Identity
helpers and output fixes can be developed separately, but one owner coordinates
edits to `findinfo.py` and `lib/tools.py`. Do not have multiple agents rewrite
those files simultaneously.

Migrations are additive and idempotent. Preserve existing asset tables and
old job/state reads. New execution metadata cannot be reconstructed faithfully
from old unscoped checkpoints: import only evidence tied to the requested scope
and record the reuse; otherwise mark historical coverage unknown and requeue
the missing work. A partial migration is an error, not an empty fresh database.

Keep public command names and the 0/1/2/4/5/124/130 exit-code meanings, including
4 for a missing tool. Add fields
without deleting the existing compact response shape. Existing `--time-budget`
remains a soft scheduling budget; do not silently reinterpret it as a whole-job
hard timeout. Document hard timeout semantics and test initial stages too.

Run the relevant meaningful tests for each batch, then the complete offline
suite before integration. Register every discovered test module or maintain an
explicit exclusion with a reason checked by CI. Compare foreground/background
CLI JSON, not only Python helper return values. Package validation must use
offline diagnostics and must not probe public services.

Update SKILL, tools reference, data model, troubleshooting and prompt examples
when their corresponding behaviour changes. Label current and proposed
behaviour clearly; documentation must not advertise an unimplemented module.

## 14. Copy-ready implementation-agent instruction

You are improving the local project E:\AI\skills\findinfo for consumer agents.
Read this design and verify the actual Git state before editing. The intended
baseline is 20dfca3; preserve unrelated changes and adapt if the tree changed.
The previously reviewed temporary assets/metered/templates integration is not
the baseline. Do not assume it still exists or reintroduce its code wholesale.

Implement batches A through G incrementally, in dependency order. Start by
preserving stage outcomes and correcting the verdict. Keep ICP and brute
working; they already execute in the baseline. Use one stage registry and
RunSpec, then introduce atomic run membership and durable work routing. Keep
subject identity, evidence relationships and network scope separate. Add a
metered ledger only after every producer can persist observations correctly.

Never execute doctor with egress checks, native collection tools, real DNS/HTTP
queries or paid provider requests during this task. Never read or print local
credentials. Validate with synthetic fixtures and injected adapters. The fixture
brand is 美团; fixture domains are under reserved example.com, example.net or
example.org, and all entity records are invented. No fixture output may be
presented as real Meituan assets.

Use tests T01-T34 as acceptance requirements, including zero attempted outbound
traffic. Isolate state and configuration, and prevent native-tool fallback.
Keep existing commands, persisted assets, readable old jobs and exit-code
contracts. A missing optional key is a coverage gap, not a failed stage.
Never claim an unbounded organisation-wide inventory is complete.

For every batch, report changed files, compatibility impact, relevant test
results and remaining acceptance IDs. Run the full offline suite at integration,
check the runtime package manifest and synchronise the affected user/agent
documentation. Do not publish or upload a release as part of implementation.
