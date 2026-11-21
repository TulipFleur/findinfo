# Troubleshooting and recovery

> SKILL.md §6 tells you "which row to check for this symptom"; here are the full tables: fault mapping,
> how to read `wait` returns, result-advancement branches, per-source outcome branches. Keep this file in sync with code changes.

## 1. Common faults

| Symptom | Cause | Fix |
|---|---|---|
| `{"error":"tool_missing"}` | Tool missing from `bin/<platform>/` (no PATH fallback) | `doctor` shows which one: Linux runs `scripts/setup-linux.sh`, Windows adds `bin/windows/*.exe`. Do not install tools yourself |
| `{"error":"scope_required"}` (exit 2) | A single-stage command would take its targets from the whole shared store: no `--scope`/`--domain`, or a scope with no valid name in it | Add `--scope <domain>` (passive/subs/icp/dns/probe/ipagg/ports) or `--domain <domain>` (vhost/crawl/extract), or give explicit targets; `--whole-store` only when every asset in the store is really meant |
| `ports` reports `skipped_private` | Store-derived IPs in private/reserved ranges are never scanned | Intended. Pass such an address with `--ip` to scan it deliberately |
| `entity` returns empty | `bin/config.yaml` has no Cookie, or it expired | `cp bin/config.example.yaml bin/config.yaml` and re-paste the aiqicha Cookie; or pass the seed domain directly with `--domain` |
| `subs` returns only a few results | No mapping-platform key configured (subfinder is the only route) | See `docs/API-KEYS.md`, or accept it (crt.sh still works). This is a coverage gap — `subs` **never records failed** for it, and do not `--resume` |
| `passive` returns only a few results | Only key-free sources available | Report the `per_source` statuses honestly |
| `dns` shows mass resolution failures | Public DNS blocked/poisoned | The system-DNS fallback is built in; if it still fails, check the network |
| `vhost` 0 hits | The IP really hosts a single site / the proxy blocks direct IP access | Switch to a direct egress; confirm the IP is not a CDN |
| `vhost` wordlist "has no effect" | The wordlist holds bare labels (dev/uat); without a base domain no Host can be built | Add `--domain <base>`; stderr prints the expanded "words -> hosts" count |
| `probe` times out on everything | WAF interception or a network issue | Lower `--min-conf` to shrink the target set, or change the egress IP |
| `brute` reports Npcap/socket errors | Npcap driver missing or no admin rights | Install Npcap (with the WinPcap-compatibility option) and run from an admin terminal; if impossible, skip and say so |
| `brute` yields an abnormal number of hits | The domain has wildcard resolution | Use `--wildcard advanced`, or filter after running `dns` |
| Wildcards creating fake assets | — | The `dns` stage already filters them and returns `wildcard`; never add domains by hand on top |
| A tool failed | Already retried internally per `limits.source_retries` (default 2, with backoff); still failing → `ok: false` | The stage is marked failed and writes no checkpoint (a re-run retries); other sources' results are kept |
| Over the display cap | `truncated: true` | Display-only truncation; downstream uses the full set from the store — never feed display samples back as input |
| New session, want to continue | — | Find the run_id with `runs` → `status --run <id>` restores the context (no reliance on the previous session's memory) |
| `run` exit code 5 | Finished but with failed stages (`result.status=partial`) | Read `coverage.failed_stages`; do not `--resume` gaps caused by missing keys |

## 2. How to read `wait` returns (branches the agent must follow)

| Return | Meaning | What to do |
|---|---|---|
| `timed_out: true` + `state: running` | Only **this wait window** ended; the job is still running | Keep `wait`ing on the same run_id; **do not restart, do not paste the same status again** |
| `changed: true` + `state: running` | Progress happened | You may give the user a one-line stage summary (stage name/counts), then keep waiting |
| `state: completed` | Finished | Read `result`/`coverage`, move to delivery |
| `state: failed` | Failed | Read `coverage.failed_stages` + `last_error`, retry with `run --resume <run_id>` |
| `state: cancelled` | Cancelled | State what was already collected; do not restart |
| `interrupted: true` + `reaped_by_host: true` | The host reaped the session-detached subprocess; background mode is unusable here | **Do not retry background**: run in the foreground within the same session (with `--task-timeout`), or host the worker under a surviving parent process |
| `interrupted: true` + `reaped_by_host: false` | The worker died (crash/power loss) | `run --resume <run_id>` resumes from checkpoints |

- `progress.percent` being **null** means the stage's total is unknown: you can only say "N rows processed", **never invent a percentage**.
- Re-submitting the same target in background mode returns `reused: true` + the same run_id: use it directly; do not start another.
- Address jobs **by run_id only** (`--run <run_id>`); never rely on "the most recent run".

## 3. Result-advancement rules (decide the next step from the actual result, do not stop at "started")

```bash
python findinfo.py --task myproj status --run <run_id>
```

| Situation | Criterion | Action |
|---|---|---|
| Coverage sufficient | `coverage.complete: true` | Move to delivery |
| Some stage failed | `coverage.failed_stages` non-empty | After reading the errors, retry with `run --resume <run_id>` (succeeded stages are skipped by checkpoints) |
| Stages still worth adding | `coverage.not_run_stages` non-empty | Fill in that stage (single-stage command, or `run` with switches), then `status` again |
| Round/time budget exhausted | `stop_reason: max_rounds / time_budget` | State clearly "coverage incomplete + the reason"; add `--rounds` and continue if needed |
| JS still pending analysis | `coverage.js_queue.pending > 0` | Keep running `extract`; this is not convergence |
| Sources unavailable | `coverage.unavailable` (missing key/tool) | Keep the results, list the gaps in the delivery, **never disguise them as "no assets"** |
| Empty result | `counts` empty and nothing failed | A valid empty result, not a failure |

## 4. Per-source outcome branches (judge by this table, invent nothing)

| What you see | Criterion | Action |
|---|---|---|
| A source found no assets | Stage `found: 0` + `ok: true` | A valid empty result, not a failure |
| A source failed transiently | Still `ok: false` after `limits.source_retries` retries | The stage is marked failed and writes no checkpoint (a re-run retries); other sources' results are kept |
| Key missing / quota exhausted | `coverage.unavailable`, `doctor.api_keys`, `fofa_gateway.remaining` | Record a coverage gap, **deliver as usual**, naming which routes are missing. **Do not `--resume`** — retries cannot conjure a key; a missing key never counts into `failed_stages` either |
| Wildcard pollution | `dns` returns `wildcard` | Already filtered, not stored; mention it under "data quality" |
| An engine returned nothing | `coverage.unavailable.unconfirmed_empty` | Report it as unconfirmed (uncover reports upstream errors the same way); not "no assets" and not a failure, do not `--resume` |
| An engine was not asked | `coverage.unavailable.unsupported_engines` | No query is known for it here; list it as a gap |
| An upstream answer was capped | `coverage.unavailable.truncated_sources` | More rows exist than were fetched (page budget / billed first page); list it as a gap |
| New in-scope domains | `rounds[i].new_domains > 0` | `--rounds` already feeds them into the next round; no manual steering needed |
| Related assets out of scope | `dropped_out_of_scope` / the brief's `leaks.domains` | Record as candidates only; never widen scope automatically |
| A tool failed | `stages[].failed` + `error` | Keep rc/error/existing artifacts; the stage does not count as completed |
| Over the display cap | `truncated: true` | Display-only truncation; downstream uses the full set from the store |
| Checkpoint hit | `skipped: true, resumed: true` | Downstream inputs were rebuilt from the store; do not skip later stages just because memory is empty |

## 5. Red lines

1. A successful background launch alone ≠ the task is complete.
2. Without new progress: no relaunching, no repeating the same status output.
3. Exit code 5 = finished but with failed stages (`result.status=partial`), not a success.
4. With a missing key, `--resume` never helps: what is missing is a credential; retrying cannot produce one.
