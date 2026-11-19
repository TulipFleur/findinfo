# API Key Configuration Reference

> Every data source that needs credentials is registered here. **The core chain runs without any key** (see "Zero-config capabilities" at the end).
> Config file: `config/.env` (copy from `config/.env.example` and fill in); variable names are compatible with redtools/exploit_server.

> **Missing keys never decide a run's success or failure.** Keyless mapping engines are recorded as `unavailable` (a coverage gap);
> they never enter `coverage.failed_stages`, `run`'s exit code stays ≠5, and `uncover` is never launched with an empty key.
> After adding a key, re-running the same target really executes subs (the set of usable engines is part of the stage input hash, so old checkpoints cannot skip it).

## 1. Master table

| Variable | Source | Used in which step | Free tier | Signup | Consequence of not configuring |
|---|---|---|---|---|---|
| `FOFA_EMAIL` + `FOFA_KEY` | FOFA | ICP reverse lookup, passive subdomains, org lookup | 200~300/month | https://fofa.info/userInfo | ICP reverse lookup dead; one fewer subdomain route |
| `QUAKE_TOKEN` | 360 Quake | same | 3000/month | https://quake.360.net/quake/#/personalInfo | same, one route lost |
| `HUNTER_KEY` | QAX Hunter | same | 100 credits/month | https://hunter.qianxin.com/home/userInfo | same |
| `ZOOMEYE_KEY` | ZoomEye | same | 2000/month | https://www.zoomeye.org/profile | same |
| `CENSYS_ID` + `CENSYS_SECRET` | Censys | certificate/service mapping | 250/month | https://search.censys.io/account/api | one fewer certificate cross-check |
| `SHODAN_KEY` | Shodan | org lookup | very low | https://account.shodan.io/ | one route lost |
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

## 5. Quota and throttling conventions

- Mapping APIs (FOFA/Quake/Hunter/ZoomEye) share `MAPPING_API_INTERVAL_MS`, default 1500ms
- On rate limiting (HTTP 429 / "frequently"): the source is marked `degraded` and the others continue; **quota is never burned on retries**
- Recommended per-run cap: `--max-seed 5` (number of seed domains), so one run cannot drain the quota over hundreds of domains
- Only **certificate transparency (CT)** responses are cached locally (`cache/certs/`, 7 days): re-runs of crt.sh / CertSpotter do not re-spend requests. Other stages (probe/subs/dns...) have no response cache; re-runs re-request

## 6. Security checklist

- [ ] `config/.env` is in `.gitignore` (already configured in this repo)
- [ ] Never write Cookies/Keys into `SKILL.md`, `docs/`, or logs
- [ ] If a key shows up in logs, check the `runs/` artifacts and delete them
- [ ] On shared machines, tighten permissions on `config/`
