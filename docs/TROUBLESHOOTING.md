# Troubleshooting and recovery

> SKILL.md §6 tells you "which row to check for this symptom"; here are the full tables: fault mapping,
> how to read `wait` returns, result-advancement branches, per-source outcome branches. Keep this file in sync with code changes.

The default Agent request “collect XX assets” is one full background job with `--active --ports --vhost --crawl --background --rounds 3`. Missing mapping keys/Cookie do not reduce it to passive-only: skip the dependent sources, record gaps, and continue the keyless stages when trusted seeds exist. The CLI's flagless passive default is only a compatibility interface or an explicit passive-only request.

## 1. Common faults

| Symptom | Cause | Fix |
|---|---|---|
| `{"error":"tool_missing"}` | Tool missing from `bin/<platform>/` (no PATH fallback) | `doctor` shows which one: Linux runs `scripts/setup-linux.sh`, Windows adds `bin/windows/*.exe`. Do not install tools yourself |
| `{"error":"scope_required"}` (exit 2) | A single-stage command would take its targets from the whole shared store: no `--scope`/`--domain`, or a scope with no valid name in it | Add `--scope <domain>` (passive/subs/icp/dns/probe/ipagg/ports) or `--domain <domain>` (vhost/crawl/extract), or give explicit targets; `--whole-store` only when every asset in the store is really meant |
| `ports` reports `skipped_private` | Store-derived IPs in private/reserved ranges are never scanned | Intended. Pass such an address with `--ip` to scan it deliberately |
| `entity` returns empty | Cookie missing/expired or no trustworthy anchor | Continue from supplied domain seeds. For company-only input, use available search to verify an official root domain and pass `--domain`; do not guess or pick an ambiguous company. Ask for a seed only if verification fails. Cookie repair is optional for wider entity coverage |
| `entity` fails `enscan rc=1 ... (config missing/version_mismatch: <path>)` (ENScan: "没有找到配置文件" / "配置文件当前[V0.0] 程序需要[V0.7]") | ENScan reads `config.yaml` beside the binary; the file is absent, empty (`enscan -v` writes 0 bytes) or lacks `version: 0.7` | Copy `bin/config.example.yaml` (the binary's own layout, `version: 0.7` as a number) next to the binary; `doctor` → `enscan_config.state` must be `ok` |
| `certs` fails on many seeds quickly with "skipping it for the rest of this stage" | crt.sh / CertSpotter unreachable: after two seeds in a row fail on an upstream, the stage stops asking it | A coverage gap, not data loss: the stage is not checkpointed and the next run asks again; check egress to crt.sh / api.certspotter.com |
| mapping says `rate_limited` (FOFA relay: "请求过于频繁，当前限额 10 次/分钟") | Asked faster than the provider allows | The relay is paced at `limits.fofa_gateway_per_minute` (default 10) and a limited question waits `limits.mapping_rate_wait_sec` (60) and is asked again; one still limited is re-asked on the next run (no `--remap` needed) |
| `subs` returns only a few results | Keyless subfinder returned few names; paid mapping is a separate source | Continue DNS/probe/ports/vhost/crawl/extract on valid scoped inputs. Record missing mapping keys as source gaps; do not resume solely to obtain keys or stop at a passive report |
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
| Repeated `wait --since` calls | Continue from the returned `cursor`, rather than reusing the previous request's value | Pass each response's `cursor` into the next `--since`; heartbeat-only `seq` changes are not progress |
| `state: completed` | Finished | Read `result`/`coverage`, move to delivery |
| `state: failed` | Failed | Read `coverage.failed_stages` + `last_error`, retry with `run --resume <run_id>` |
| `state: cancelled` | Cancelled | State what was already collected; do not restart |
| `interrupted: true` + `reaped_by_host: true` | The host reaped the session-detached subprocess; background mode is unusable here | **Do not retry background**: run in the foreground within the same session (with `--task-timeout`), or host the worker under a surviving parent process |
| `interrupted: true` + `reaped_by_host: false` | The worker died (crash/power loss) | `run --resume <run_id>` resumes from checkpoints |

- `percent` in compact `wait` (or `progress.percent` in `status`) being **null** means the stage's total is unknown: say "N rows processed", **never invent a percentage**.
- Re-submitting the same target in background mode returns `reused: true` + the same run_id: use it directly; do not start another.
- Address jobs **by run_id only** (`--run <run_id>`); never rely on "the most recent run".

## 3. Result-advancement rules (decide the next step from the actual result, do not stop at "started")

```bash
python findinfo.py --task myproj status --run <run_id>
```

| Situation | Criterion | Action |
|---|---|---|
| Coverage sufficient | Terminal job with `coverage.complete: true` | Read `brief --run <id>`, run `report --run <id>`, and deliver the real HTML path |
| Some stage failed | `coverage.failed_stages` non-empty | After reading the errors, retry with `run --resume <run_id>` (succeeded stages are skipped by checkpoints) |
| Stages still worth adding | `coverage.not_run_stages` non-empty | Fill in that stage (single-stage command, or `run` with switches), then `status` again |
| Round/time budget exhausted | `stop_reason: max_rounds / time_budget` | State clearly "coverage incomplete + the reason"; add `--rounds` and continue if needed |
| JS still pending analysis | `coverage.work_queue.outstanding > 0` / `coverage.js_queue.pending > 0` | Not convergence: continue the same run when recovery/budget can advance it, otherwise state `partial` and the exact remaining work |
| Sources unavailable | `coverage.unavailable` (missing key/tool) | Continue available planned stages; after the job ends list the gaps in the HTML delivery statement, **never disguise them as "no assets"** |
| Empty result | `counts` empty and nothing failed | A valid empty result, not a failure |

## 4. Per-source outcome branches (judge by this table, invent nothing)

| What you see | Criterion | Action |
|---|---|---|
| A source found no assets | Stage `found: 0` + `ok: true` | A valid empty result, not a failure |
| A source failed transiently | Still `ok: false` after `limits.source_retries` retries | The stage is marked failed and writes no checkpoint (a re-run retries); other sources' results are kept |
| Key missing / quota exhausted | `coverage.unavailable`, `doctor.api_keys`, `fofa_gateway.remaining` | Record the missing route and continue the available keyless chain. Deliver after the job ends, naming the gap. Do not resume solely for credentials/quota; a missing mapping key alone never counts into `failed_stages` |
| Wildcard pollution | `dns` returns `wildcard` | Already filtered, not stored; mention it under "data quality" |
| An engine returned nothing | `coverage.unavailable.unconfirmed_empty` | Report it as unconfirmed (uncover reports upstream errors the same way); not "no assets" and not a failure, do not `--resume` |
| An engine was not asked | `coverage.unavailable.unsupported_engines` | No query is known for it here; list it as a gap |
| An upstream answer was capped | `coverage.unavailable.truncated_sources` | More rows exist than were fetched (page budget / billed first page); list it as a gap |
| New in-scope domains | `rounds[i].new_domains > 0` | `--rounds` already feeds them into the next round; no manual steering needed |
| Related assets out of scope | `dropped_out_of_scope` / the brief's `leaks.domains` | Record as candidates only; never widen scope automatically |
| `{"error":"scope_required"}` | `candidates`, `scope_source:"refused"` | The store mixes targets, so no scope could be inferred. Pick a name from `candidates` and re-run with `--scope`/`--domain`, or `--whole-store` on purpose. Policy: `scope.unscoped_reads` = `infer` (default) / `refuse` / `legacy` |
| A tool failed | `stages[].failed` + `error` | Keep rc/error/existing artifacts; the stage does not count as completed |
| Over the display cap | `truncated: true` | Display-only truncation; downstream uses the full set from the store |
| Checkpoint hit | `skipped: true, resumed: true` | Downstream inputs were rebuilt from the store; do not skip later stages just because memory is empty |
| No valid stage input | `skipped: true, reason: no_input` | A justified skip, not dispatched traffic. Keep subsequent stages eligible and report the actual reason |

## 5. Red lines

1. A successful background launch alone ≠ the task is complete.
2. Without new progress: no relaunching, no repeating the same status output.
3. Exit code 5 = finished but with failed stages (`result.status=partial`), not a success.
4. Do not resume solely for missing keys, and do not let those gaps end the remaining keyless stages early.
5. A passive summary or hand-written Markdown table is not the default delivery. Run `report --run <id>` and return its real `paths.html`; Markdown requires explicit `--with-md`.
