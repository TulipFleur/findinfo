# Data model and confidence

> SKILL.md keeps only the reading essentials; this file holds the full data shapes, the confidence algorithm and the report field conventions.
> For command parameters see [TOOLS.md](TOOLS.md).

## 1. Asset graph (SQLite, `<home>/findinfo.db`)

```jsonc
// assets table
{
  "kind": "domain|ip|url|endpoint|company|icp",
  "canonical": "api.example.com",     // normalized primary key (unique)
  "parent": "example.com",
  "sources": "crt.sh,dnsx,httpx",     // who discovered it (provenance)
  "confidence": 0.95,                 // confidence, rules below
  "passivity": "passive|active",
  "attrs": { "status": 200, "title": "...", "tech": ["nginx"], "ip": "1.2.3.4" },
  "first_seen": "...", "last_seen": "..."
}

// endpoints table (input for vulnerability hunting)
{ "asset": "api.example.com", "method": "GET",
  "path": "/api/user/{n}", "params": "id,token", "status": 200 }
```

## 2. Confidence rules (computed automatically)

| Number of sources | confidence |
|---|---|
| 1 source | 0.4 ~ 0.5 |
| 2 independent sources | 0.7 |
| 3 or more (CT + mapping platforms + DNS) | 0.95 |
| ICP filing number returned directly by ENScan | 0.9 |
| vhost differing only in status code | 0.5 (needs manual review) |

**Threshold**: only `>= 0.7` enters the main graph; `0.4~0.7` is marked unverified.
Each command's `--min-conf` CLI default differs: `dns 0.4`, `probe 0.7`, `passive 0.0`
(the `assets` query defaults to 0.0). So to make `probe` test low-confidence assets you must pass `--min-conf 0.4` explicitly.

**Convention note**: `onepass` records carry a confidence computed from their "number of independent sources" (1 source ≤0.6 / 2 sources ≥0.7 / 3+ sources ≤0.95);
on storage we always take `max(existing, new)`, so an onepass high confidence is never pulled back down by local rules,
and genuinely new sources added later (`+dnsx`, `+httpx`) raise it further per the table above.
When `sources` reads `onepass:crtsh,rapiddns`, do not treat it as "1 source" — that record was already scored as 2 sources.

## 3. Report field conventions (`brief` / `report` / `report.json`)

**Scope determination**: without `--match`, the most recent `run`'s target domain is used automatically (`scope.auto=true`);
with neither, the whole store is covered and a warning is raised. When the store holds cross-engagement leftovers, the report counts records outside the target domain as
`domains_dropped` / `endpoints_noise`, lists them at the top of the HTML as "quarantined noise", and **excludes them from conclusions**.

**Provenance annotation (who found it)**: each host gets `discovered_by` (the raw sources string) and `provenance`
(a normalized tool list + readable labels, e.g. `dnsx resolver`, `onepass passive aggregation/RapidDNS`, `vhost Host collision`).
onepass's 15 upstream sources are not counted as 15 tools — `charts.sources` counts by tool; an asset confirmed by multiple tools gets a higher `confidence`.

**Priority scoring** (`score` capped at 99, `priority` high≥45 / medium≥18 / low≥1):
internal service +50, admin-looking title +20, sensitive path +25/+10, 401/403 +12, product fingerprint +8, parameters +6,
non-standard port +6, CDN -8. Scores are used only for ordering; **conclusions must be re-checked against the criteria in `reasons`**.

**brief's field budget**: `brief` contains only what decisions need — `counts`, `scope`, `environment.warnings`,
`coverage` (failed/not-run/unavailable stages with reasons; `source` says which run was read, `known=false` means
no run was read at all, **which does not mean there are no gaps**), `top_hosts` (the top 20 high-priority hosts by default, each with
`host`/`score`/`priority`/`reasons`/`provenance`), all `internal_services`, `leaks` counts plus the first few entries,
`next_steps`. Truncated arrays state their `kept` and `total` in `truncated` —
**seeing truncated does not mean the data is complete; conclusions must be phrased around the gaps it reports**.

**Display cap ≠ processing cap**: `assets` shows only 500 rows by default; the full set is in the store.
Lists in tool stdout are display samples only; the full set actually processed by each stage goes into the store, and downstream stages
(probe/ports/crawl/extract) pull the complete set from it. Coverage gaps caused by deliberate budgets (`--max-seed`/`--limit`/`--max-vhost-ips` etc.)
are called out explicitly in the summary/report.

```bash
python findinfo.py assets --kind domain --min-conf 0.7 --limit 5000
python findinfo.py assets --export runs/assets.jsonl        # full export (JSONL, streamable line by line)
```

To change the display cap: the environment variable `FINDINFO_ROW_LIMIT=2000`, or `limits.row_limit` in `config/config.json`.
Subprocess output is **consumed line by line** (`core.run_stream`), so memory does not grow with the number of results: measured, 120k lines raise it by only ~0.5 MB.

## 4. Run membership and durable work (work tables, same SQLite)

Since the reliability batches, four tables in the same database record per-RUN facts
(the asset graph stays shared; these decide whose reflow reads it). Runs are keyed by
their **public run-directory id** (the `run_id` every command prints), never the legacy
integer `runs.id`. All tables are created by idempotent migrations (`lib/work.py`).

```jsonc
// run_assets: membership -- which assets belong to THIS run
{ "run_id": "20261120-200000-mt-a.example.com",
  "kind": "domain", "canonical": "api.mt-a.example.com",
  "first_seen": "...", "last_seen": "..." }        // PK (run_id, kind, canonical)

// observations: one row per observation, independent upstream preserved
{ "run_id": "...", "producer": "certs", "upstream": "crt.sh",
  "kind": "domain", "canonical": "api...", "observed_at": "..." }
// re-observing through the SAME upstream is one witness, not two:
// observed_upstreams() dedups, so confidence never inflates on replay.

// work_items: durable, deduplicated downstream work (DNS/extract routes)
{ "run_id": "...", "stage": "dns", "kind": "domain",
  "canonical": "api...", "input_revision": 1,
  "status": "pending|running|done|failed|blocked",   // failed = retryable backoff
  "attempts": 1, "retry_at": null,
  "lease_token": "ts|id|attempt", "lease_expiry": "..." }   // UNIQUE (run,stage,kind,canonical,revision)

// stage_invocations: per-dispatch history (one row per (run,attempt,stage,unit))
{ "invocation_id": "run|2|subs|root|1", "run_id": "...", "attempt": 2,
  "stage": "subs", "unit_key": "root", "input_revision": 1,
  "input_fingerprint": "sha1-16", "state": "running|succeeded|partial|failed",
  "outcome": "ok|partial|timeout|...", "counts": "{...}",
  "started_at": "...", "finished_at": "..." }
```

Reading rules:

- **Round inputs come from `run_assets`**, not a fresh re-scope of the shared graph:
  a sibling run of the same root cannot feed this run's resolver. The pipeline
  adopts scoped graph rows into membership at seed time and after each stage, so a
  resumed run re-enters with its earlier attempt's discoveries.
- **A reused checkpoint records a `succeeded`/`reused` invocation** with its original
  evidence; a repaired retry becomes the effective invocation for its attempt (T29).
- **Outstanding work is not convergence**: `coverage.work_queue.outstanding`
  (pending+running+failed) feeds the verdict reason `work_pending`; a stable domain
  count with pending JS/endpoint work keeps the run `partial` (T16).
- **The JS bridge**: bundles the run itself queued adopt into `work_items`
  (stage `extract`) through `work.adopt_js_backlog`; the legacy global `js_queue`
  rows attach only with provable ownership (`work.import_js_queue`), so one run
  never drains another target's backlog (T33).

### Key semantics (ownership and honest reuse)

- `run_assets` rows are per run. Membership is reconciled from what THIS run's
  collectors stored; an asset that exists only because of an earlier run joins
  as `producer=reuse` with its ORIGINAL `observed_at` preserved -- it is never
  written as a fresh observation.
- `work_items` is the only claimable queue **in run mode**. `claim` honours
  `retry_at` (a failed item inside its backoff is not claimable), reclaims an
  expired `running` lease atomically, and mints a NEW token per claim: the old
  holder can neither write a result nor acknowledge. `commit_result` writes the
  result's membership + observations + the ack in one transaction under a
  valid lease.
- `stage_invocations` gets one row per dispatch (`dispatch_seq` orders them).
  A retry APPENDS; it never replaces the previous attempt's row, so history
  stays auditable. `effective_invocations` reads the latest dispatch of the
  current attempt; `invocation_history` returns every row.

## 5. Metered ledger (`<run_dir>/metered.jsonl`)

Every **billed** provider request appends exactly one JSON line (one row per REQUEST,
never per result row; free sources never touch it). Fields:
`ts, run_id, engine ("fofa-gateway"|"uncover"|...), input_hash, status
(ok|empty|truncated|quota|auth|failed), requested, returned, elapsed_sec,
[rc], [error], [quota {remaining, max, source}]`.

- `quota.remaining` is the best-known ceiling from the freshest provider answer;
  **None means unknown, never infinite**.
- `blocked_engines` lists engines whose LAST request was `quota` or `auth`
  (transport failures stay retryable) — the verdict's `quota_exhausted` reads
  this list, not just the stage payload.
- `unit` distinguishes observable facts: `provider_http` (an HTTP request we
  make ourselves) vs `native_dispatch` (one native-tool process whose internal
  per-provider fan-out is NOT observable). Neither is a price.
- Every dispatch gets its own `dispatch_id`; `replay=true` suppresses a
  duplicated log event, while a genuine second dispatch is a second row.
- `settled=false` (status `uncertain`) marks a dispatch whose billing outcome
  is unknown (crash/deadline). Recovery keeps it unsettled — it is never
  silently counted as a free call or as a charge.
- The run's `coverage.metered` block carries `totals`/`by_engine`/
  `blocked_engines`/`ledger_path`; `brief --run <id>` summarises the same block
  from the persisted file, so a later session answers "what would another round
  cost" without the process that spent it.

## 6. Reading conventions for old data

- **Task-name directories**: pure-ASCII task names keep their directories; old versions put every non-ASCII-named task into `tasks/default` (mixed in one store).
  After the fix, non-ASCII names map to their own `task-<hash>` directories. **The old default store is never touched**;
  to read it: `python findinfo.py --task default assets`.
- **Sources column**: the old format `onepass:crt.sh,rapiddns` (prefix only on the first token) is normalized automatically on read/merge to
  `onepass:crt.sh,onepass:rapiddns`; no manual migration needed.
- **Confidence recomputation**: on merge, confidence is recomputed deterministically from the number of independent upstreams. Scores historically inflated to 0.95 by the prefix bug but actually backed by only 2 upstreams
  are pushed back down to ≤0.9 on the next merge; a well-evidenced 0.95 (≥3 upstreams) is unaffected. No bulk store rewrites.
