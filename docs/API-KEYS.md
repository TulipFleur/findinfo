# API Key Configuration Reference

> Every data source that needs credentials is registered here. **The core chain runs without any key** (see "Zero-config capabilities" at the end).
> Config file: `config/.env` (copy from `config/.env.example` and fill in); variable names are compatible with redtools/exploit_server.

> **Missing keys never decide a run's success or failure.** Keyless mapping engines are recorded as `unavailable` (a coverage gap);
> they never enter `coverage.failed_stages`, `run`'s exit code stays ≠5, and `uncover` is never launched with an empty key.
> After adding a key, re-running the same target really executes subs (the set of usable engines is part of the stage input hash, so old checkpoints cannot skip it).

## 1. Master table

| Variable | Source | Used in which step | Free tier | Signup | Consequence of not configuring |
|---|---|---|---|---|---|
| `FOFA_EMAIL` + `FOFA_KEY` | FOFA | **`mapping` stage / `map`** only | 200~300/month | https://fofa.info/userInfo | the fofa mapping route is skipped (a gap, never an error) |
| `QUAKE_TOKEN` | 360 Quake | **`mapping` / `map`** only | 3000/month | https://quake.360.net/quake/#/personalInfo | same, one route lost |
| `HUNTER_KEY` | QAX Hunter | **`mapping` / `map`** only | 100 credits/month | https://hunter.qianxin.com/home/userInfo | same |
| `ZOOMEYE_KEY` | ZoomEye | **`mapping` / `map`** only | 2000/month | https://www.zoomeye.org/profile | same |
| `CENSYS_API_TOKEN` + `CENSYS_ORGANIZATION_ID` | Censys | **`mapping` / `map`** only | 250/month | https://search.censys.io/account/api | one fewer mapping route (no query syntax known, so it is not asked) |
| `SHODAN_KEY` | Shodan | **`mapping` / `map`** only | very low | https://account.shodan.io/ | one route lost |
| `SECURITYTRAILS_KEY` | SecurityTrails | passive subdomains + historical DNS | 50/month | https://securitytrails.com/app/account/credentials | one route lost; historical DNS unavailable |
| `VIRUSTOTAL_KEY` | VirusTotal | passive subdomains | 4/min | https://www.virustotal.com/gui/my-apikey | one route lost |
| `URLSCAN_KEY` | urlscan.io | passive subdomains + crawled pages | 100/day | https://urlscan.io/user/profile/ | one route lost |
| `CHAOS_KEY` | PD Chaos | enterprise subdomain datasets | free | https://cloud.projectdiscovery.io/ | the chaos route is skipped |
| `MAPPING_API_INTERVAL_MS` | — | mapping-API throttle | — | — | default 1500ms; raise when rate-limited |
| **ENScan Cookie** (not an API) | aiqicha | Stage 1 entity anchoring | free | log in at aiqicha.baidu.com, copy via F12 | **Stage 1 completely unavailable** |

## 2. Special case: the ENScan Cookie

ENScan does not use API keys; it uses a browser Cookie. The location is fixed at **`bin/config.yaml`** (the program reads next to the exe):

```yaml
cookies:
  aiqicha: "BAIDUID=...; ..."   # * required: log in to aiqicha.baidu.com, then copy the whole Cookie line from F12 -> Network -> any request
```

Notes:
- The Cookie has a validity period (usually days to weeks); once it expires ENScan reports "no data" and it must be copied again
- **Concurrency must be 1**, or the account gets risk-controlled (this skill enforces serial access)
- Alternatives: a tianyancha Cookie (`tianyancha`), or fill `app.miit_api` to reverse-lookup ICP filings via ICP_Query

## 3. Configuration priority

```
real environment variables  >  config/.env  >  config/config.json  >  defaults
```

Three usage patterns:

```bash
# A. file (recommended, persistent)
cp config/.env.example config/.env && vim config/.env

# B. temporary (single command)
FOFA_KEY=xxx QUAKE_TOKEN=yyy python findinfo.py subs --domain example.com

# C. JSON (programmatic)
vim config/config.json
```

## 4. Zero-config capabilities (no key needed at all)

| Capability | Tool | Notes |
|---|---|---|
| 15-source parallel passive aggregation | onepass (bin/onepass.exe) | 8 sources are key-free; one command covers CT + several public passive DNS |
| Certificate-transparency subdomains | crt.sh / CertSpotter | **the most effective passive source, completely free** |
| DNS resolution + wildcard filtering | dnsx + system-DNS fallback | independent of public DNS availability |
| Liveness/fingerprint/IP mapping | httpx | core asset enrichment |
| CDN detection | cdncheck | bundled data |
| Port scanning | naabu | no key needed |
| Host collision | hostCollision (Host-header collision) + curl differential fallback | the step that actually yields internal services |
| Crawler / JS leaks | katana + built-in jsleak | no key needed |
| Company information | ENScan | needs only a Cookie, no key |

> In other words: **80% of asset mapping is achievable without any FOFA/Quake quota** — you only lose the "ICP filing reverse lookup", the widest horizontal-expansion route.

## 5. Which variable name reaches which tool

`config/.env` keeps one name per provider, but the bundled tools read different names. The mapping dispatcher injects
exactly the variables the called tool reads, and every other child gets **no credential at all**:

| Engine | `.env` key | uncover reads | onepass reads |
|---|---|---|---|
| FOFA | `FOFA_EMAIL` + `FOFA_KEY` | same | same |
| Quake | `QUAKE_TOKEN` | same | same |
| Hunter | `HUNTER_KEY` | `HUNTER_API_KEY` | `HUNTER_KEY` |
| Shodan | `SHODAN_KEY` | `SHODAN_API_KEY` | — |
| Censys | `CENSYS_API_TOKEN` + `CENSYS_ORGANIZATION_ID` | same | — |
| ZoomEye | `ZOOMEYE_KEY` | `ZOOMEYE_API_KEY` | — |
| VirusTotal / SecurityTrails / urlscan / Chaos | `*_KEY` | — | same |

Hunter is the trap: the old single map sent `HUNTER_TOKEN`, a name neither tool reads, so a configured Hunter key was
never used. Evidence for every row (binary strings + upstream source): [docs/MAPPING-QUERIES.md](MAPPING-QUERIES.md).

## 6. Quota and throttling conventions

**`-limit` is a spend ceiling, not a quality knob.** uncover PAGINATES on some engines, and the engine bills per page:

| Engine | One dispatch | Bill |
|---|---|---|
| quake | fixed `Size=100`, loops on a `Start` offset until the limit is passed | **100 credits per page** |
| fofa / shodan / hunter | one request, engine caps the rows | one |

Measured on a real quake account: `-limit 1` -> 100 credits and `-limit 100` -> 100. **A page costs the same however
many rows it returns**, so small limits save nothing — they only multiply round trips. The default therefore asks for
everything in ONE dispatch: `limits.mapping_rows` = **3000** (= quake's free monthly balance at 1 credit/row, i.e. 30
pages of 100). One question, one bill, no repeats.

Per-engine override when a plan allows more (or a balance needs protecting):

```json
{"limits": {"mapping_rows": 3000, "mapping_rows_quake": 3000}}
```

Each dispatch reports its `pages`. A response that fills the ceiling is reported `truncated`.

`limits.mapping_pages` (default 20) is a different thing: it is how many pages of a **free cursor API** onepass follows
(VirusTotal `links.next`, urlscan `search_after`), which costs no quota at all.

- Mapping APIs (FOFA/Quake/Hunter/ZoomEye) share `MAPPING_API_INTERVAL_MS`, default 1500ms
- Each (engine, question) is asked **once per task** (the `mapping` ledger). A second run, a later seed or a standalone
  `map` reuses the paid answer; `--remap` is the only way to ask again
- `uncover` is always given an explicit `-limit` (`limits.mapping_rows`, default **10000**). Its own default of 100
  silently truncated every query. The billing unit is the QUERY, not the row, so one full page costs the same as 100
  rows while collecting far more; a page that fills the ceiling is reported as `truncated_sources`, never as a
  complete answer
- A missing key, or a key the provider rejects (401/403), **skips that engine** for the rest of the task. It is never an
  error, never exit 5, and never retried
- On rate limiting (HTTP 429 / "frequently"): the source is marked `degraded` and the others continue; **quota is never burned on retries**
- Recommended per-run cap: `--max-seed 5` (number of seed domains), so one run cannot drain the quota over hundreds of domains
- Only **certificate transparency (CT)** responses are cached locally (`cache/certs/`, 7 days): re-runs of crt.sh / CertSpotter do not re-spend requests. Other stages (probe/subs/dns...) have no response cache; re-runs re-request

## 7. Security checklist

- [ ] `config/.env` is in `.gitignore` (already configured in this repo)
- [ ] Never write Cookies/Keys into `SKILL.md`, `docs/`, or logs
- [ ] If a key shows up in logs, check the `runs/` artifacts and delete them
- [ ] On shared machines, tighten permissions on `config/`
