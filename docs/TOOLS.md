# findinfo Tool Usage Manual

> Command-level reference for AI agents. Each command = one tool:
> **stdout is exactly one line of JSON** (directly `json.loads`-able), **stderr is progress/warnings** (do not parse).
> Exit codes: `0` success / `2` business error / `4` tool missing / `1` unknown exception.
>
> **Agent invocation discipline**: for commands marked (ACTIVE) or taking >30s (run/entity/crawl/probe/ports/vhost/brute/subs)
> **long orchestration commands (`run`) must not run in the foreground** — use `run --background` to start in the background + `wait`/`status` bounded polling; hard waiting in the foreground will get killed by the tool timeout.
> The default Agent request “collect XX assets” uses one `run --active --ports --vhost --crawl --background --rounds 3`, not a foreground checklist. Single-stage examples below describe explicitly requested stage work; set `--tool-timeout` when invoking such a stage directly.
> When the host reaps detached processes (`wait` returns `reaped_by_host:true`), all commands can only run in the foreground.
> For multiple targets use `--task <name>` to isolate the asset graph; `--from-store` with `--scope <main domain>` limits the read range.

General conventions:

| Item | Description |
|---|---|
| Working directory | The directory containing SKILL.md (install location varies by client; scripts locate `bin/` relative to their own path) |
| Interpreter | any Python 3.10+ |
| Data persistence | Automatically written to `~/.findinfo/findinfo.db`, overridable via `FINDINFO_HOME`; the `db` field of `doctor` is authoritative |
| Idempotency | Re-discovering the same asset only updates `sources`/`last_seen`, no duplicates |
| Cache | CT responses only (`~/.findinfo/cache/certs/`, 7 days); other stages have no cache |
| Store reads | A single-stage command that takes its targets from the store (`--from-store`, or no explicit target) is scoped by `--scope <domain>` (passive/subs/icp/dns/probe/ipagg/ports) or `--domain <domain>` (vhost/crawl/extract), repeatable. With no scope flag the policy `scope.unscoped_reads` decides: `infer` (default) uses the store's **single** registrable domain and reports `"scope_source":"inferred"`; a store mixing targets is still refused; `refuse` never infers; `legacy` reads the whole store with a log line. A refusal exits `2` with `{"error":"scope_required","hint":...,"candidates":[...],"scope_source":"refused"}` and runs nothing; a scope with no valid name in it is refused the same way, never widened. `--whole-store` reads every asset on purpose (`"scope_source":"whole_store"`). Explicit targets (`--domain`/`--host`/`--ip`/`--url`/`--code`) need no scope |

---

## doctor — environment self-check

```bash
python findinfo.py doctor            # full check: tools, egress, keys
python findinfo.py doctor --offline  # read-only: no tool run, no DNS/HTTP, no key read
```

`--offline` reports egress, fake-IP state and credentials as `not_checked`
(never `false`, never "healthy"), lists tool presence from file metadata only,
and creates nothing: no home, no cache/runs, no SQLite. The check runs before
the runtime is imported, so it cannot read config or credentials.

**Output**

```json
{
  "python": "ok",
  "environment": {"python_version": "3.10.9", "python_ok": true, "python_required": ">=3.10",
                  "net_egress": {"probes": {"crt.sh": true, "rapiddns": true, "hackertarget": true},
                                 "any_reachable": true}},
  "tools": {
    "subfinder": {"present": true, "source": "bundle", "path": ".../bin/subfinder.exe", "version": "v2.17.0", "executable": true},
    "httpx":     {"present": true, "source": "bundle", "version": "v1.12.0", "executable": true},
    "enscan":    {"present": true, "source": "bundle", "version": "", "executable": true}
  },
  "tools_summary": {"total": 13, "in_bin": 13, "outside_bin": [], "missing": [],
                    "suspect": [], "not_executable": [], "all_in_bin": true},
  "api_keys": {"fofa": false, "quake": false, "hunter": false, "chaos": false},
  "bin_dir": "...", "db": "..."
}
```

**`source` / `tools_summary`**: `source` is always `bundle` — `core.tool()` only searches `bin/<platform>/`,
**with no `PATH` fallback and no flat `bin/` fallback** (`outside_bin` is therefore always empty; the field is kept only for old consumers).
`all_in_bin: true` is the machine-readable verdict "every bundled tool is in the skill directory AND executable" (count: `tools_summary.total`).

**`environment` (host prerequisites)**: `python_ok` = interpreter ≥3.10 (the code uses PEP 604 syntax; older versions die with SyntaxError);
`not_executable` = binaries present but **not executable** here (sandbox strips the exec bit / blocks unknown binaries → the entry gets `executable:false` + a reason hint);
`net_egress.any_reachable` = at least one of three passive sources reachable; all false means no egress, so passive collection cannot produce data.

**When to call it**: the first command of every session. All-false `api_keys` means only the key-free chain runs.

---

## entity — company → entity tree / ICP filings / domains

```bash
python findinfo.py entity --name "Example Corp" --invest 51 --deep 2
```

| Parameter | Default | Description |
|---|---|---|
| `--name` | required | company / brand name |
| `--invest` | 51 | keep only subsidiaries held at ≥ this ratio |
| `--deep` | 2 | equity penetration depth |
| `--out` | runs/enscan | output directory |

**Output**

```json
{
  "rc": 0, "json_files": 3,
  "companies": ["Example Corp Online Technology Co., Ltd.", "..."],
  "icp": ["京ICP备10210538号", "..."],
  "domains": ["example.com", "example.org", "..."],
  "apps": ["Example Corp"]
}
```

**Prerequisite**: the config next to the binary (`bin/<platform>/config.yaml`; a `bin/config.yaml` is copied there) must have `version: 0.7` and `cookies.aiqicha`. A missing or mismatched config is named in the stage error (`config missing: <path>`); `doctor` shows it under `enscan_config`.
**Brands**: a short brand that no legal name contains ("滴滴" vs 北京小桔科技集团有限公司) is anchored only when the report's company owns at least two apps / filed websites / WeChat accounts whose names contain it; the stage then says `anchor_basis: brand_evidence` and lists them in `brand_evidence`.
**Note**: eyeball `companies` before continuing (same-name noise).

**What lands in the store**: `company` (approved subjects only), `domain`, `icp`, and **`app`** (APP /
mini-program names from ENScan's `app` / `wx_app` / `wechat` fields). `app` rows were parsed and echoed in this
payload but never written before, so the brief / report / xlsx reported zero mini-programs for companies whose
ENScan answer listed a dozen.

**When ENScan cannot anchor the target at all** (aiqicha has no such keyword, or answers with lookalikes only) the
run does **not** stop: the company name is still the best search value there is, so the mapping engines are asked
`domain="<name>"` for it, their answer is stored as `mapping:name` under a name-derived subject reference, and the
normal seed path continues with whatever main domain came back. The stage result carries `name_probe` (answered /
attempted engines, skipped ones) so a total engine failure is still visible as a gap rather than a silent empty run.
If no engine could even be asked (no key, refused credential), the stage is marked `unavailable` with the reasons.

**When a subject IS anchored but filed no domain** the run does not stop with "no seed" either: it exits `2` with
`{"error":"seed_domain_required","candidates":["<company name>"],"queries":["icp=\"<name>\"","domain=\"<name>\""],"hint":"..."}`.
The company IS the search value — run the engines on it and seed the run with whatever comes back:

```bash
python findinfo.py map --name "<company name>" --kind icp      # or --kind domain
```

`map --name` asks the engines with the name verbatim (a Chinese company name is not passed through domain
canonicalisation, which would drop it); the quoted-term guard in `core.uncover_query` keeps it a single term.

---

## map — metered mapping (the ONLY quota-spending command)

```bash
python findinfo.py map --domain example.com
python findinfo.py map --domain example.com --engines fofa,quake --remap
python findinfo.py map --from-store --scope example.com        # reuse stored seeds/codes
```

Mapping is consolidated into ONE entry point: the `mapping` stage of `run` and the `map` command share a task-scoped
ledger, so **each (engine, question) is paid for at most once per task**. A question already answered in this task is
reused with its ORIGINAL observation time; `--remap` is the explicit opt-in to ask again. `icp` is a compatibility alias
of `map --icp`.

| Parameter | Default | Description |
|---|---|---|
| `--domain` | — | seed domain, repeatable |
| `--icp` | — | filing number, repeatable (`-1`/`-2` suffixes normalise to one question) |
| `--from-store` | false | take seeds/codes from the store (needs `--scope`) |
| `--engines` | fofa,quake,hunter,shodan | engines to ask; an engine with no key or no known syntax is listed as a gap, never silently dropped |
| `--name` | — | company name to search by (repeatable) — the escape hatch when ENScan anchors a subject but files no domain |
| `--kind` | domain | how to ask about `--name`: `domain="…"` or `icp="…"` |
| `--remap` | false | ask again even though this task already has the answer |
| `--scope` | — | limit `--from-store` reads to these suffixes |

**Output**

```json
{"stored": {"domain": 12, "ip": 3},
 "domains": {"dispatched": 2, "reused": 0, "failures": [], "skipped_engines": []},
 "truncated_sources": [], "coverage": {"questions": 2, "by_engine": {}},
 "note": "each engine+question is asked once per task; ..."}
```

**Every outcome is recorded, none is retried automatically.** A dispatch is one billed request: OK, EMPTY, TRUNCATED,
QUOTA, AUTH or FAILED. A key the provider rejects (`AUTH`) drops that engine for the rest of the task — the operator's
rule is "no key or a dead key -> skip", never an error and never an endless retry. `EMPTY` is a real answer (uncover
reports an upstream error the same way, so it is reported as `unconfirmed_empty`). A full page is `truncated`, not "that
is all there is". `uncover` is always given an explicit `-limit` (`limits.mapping_rows`, default 100 = one page); uncover's own
default is also 100 but the skill must state it, and a page that fills the ceiling is reported as truncated.

**No other command or stage holds a key**: `core.run` strips every known credential variable by default, so `httpx`,
`naabu`, `katana`, `dnsx` and friends run with no credential at all. Full evidence for each engine's query syntax and
credential variable name: [docs/MAPPING-QUERIES.md](MAPPING-QUERIES.md).

**Verifying a key / syntax** (runs unattended; one `-limit 1` query per engine):

```bash
python findinfo.py doctor --check-mapping --domain example.com
```

Reports `key_accepted` / `syntax_accepted` / `rows` / `error` per engine and writes nothing to the task ledger. It needs
no consent flag: this skill is driven by an agent, and the cost is bounded by construction (one row per engine).
`--yes-spend-quota` is still accepted for compatibility.

**How much it spends**: uncover pages at 100 rows on EVERY engine (verified in the bundled sources), so `-limit` is a
page budget, and one page does not cost the same everywhere. There is no global default: each engine carries its own
ceiling (`mapdispatch.ENGINE_LIMITS`) — quake 3000 (its whole free month at 1 credit/row), fofa/shodan/hunter 1000,
i.e. 30 / 10 / 10 pages. Override with `limits.mapping_rows_<engine>` (that engine only) or `limits.mapping_rows`
(one cap for all). A small limit saves nothing and only multiplies round trips. Each dispatch reports its `pages`; a
page that fills the ceiling is `truncated`.

**Collect all three kinds of asset in three passes** (a mapping platform cannot do all of them):

| # | Asset | Command | Source |
|---|---|---|---|
| 1 | domains + IPs | `map --domain X` | uncover (paid) |
| 2 | certificates (issuer / serial / validity / SAN) | `certs --domain X` | crt.sh → CertSpotter (free) |
| 3 | filings → domains/IPs | `map --icp "京ICP备…"` or `entity` | uncover / ENScan |

uncover's `Result` is `timestamp/source/ip/port/host/url` only — certificates and filing numbers are cut off at that
layer, so they cannot come from `map`. See [docs/MAPPING-QUERIES.md](MAPPING-QUERIES.md) §3.5 and the full
field matrix in [docs/MAPPING-SYNTAX.md](MAPPING-SYNTAX.md) (19 fields x 8 platforms).

---

## passive — 15-source passive aggregation (route 0 of stage 1B, onepass)

```bash
python findinfo.py passive --domain example.com
python findinfo.py passive --from-store --scope example.com --min-conf 0.7
python findinfo.py passive --domain example.com --sources crtsh,certspotter,rapiddns
bin/windows/onepass.exe sources   # Linux: bin/linux/onepass                 # list the 15 sources: id / key needed / ready
```

| Parameter | Default | Description |
|---|---|---|
| `--domain` | — | repeatable; omitted = read store domains ≥0.7 (needs `--scope`) |
| `--from-store` | false | explicitly take domains from the store (needs `--scope` or `--whole-store`) |
| `--scope` | — | scope of a store read, repeatable |
| `--sources` | all usable sources | comma-separated ids, see `onepass sources` |
| `--min-conf` | 0.0 | drop records below this confidence |
| `limits.mapping_pages` | 20 | pages followed per paged source (VirusTotal, urlscan); onepass clamps at 20 |

**Output**

```json
{"domains": [{"domain": "example.com", "count": 214,
  "sources_ok": 6, "sources_error": 2, "elapsed_ms": 4210,
  "per_source": [{"id": "crtsh", "status": "ok", "found": 120, "code": null}],
  "domains": [{"domain": "uat.example.com", "sources": ["crtsh", "rapiddns"],
               "confidence": 0.85}]}],
 "total": 214}
```

**Sources (15)**: crtsh / certspotter / hackertarget / rapiddns / anubis / alienvault /
threatminer / subdomain.center — 8 key-free; urlscan / virustotal / securitytrails /
chaos / fofa / quake / hunter need keys (a missing key auto-skips without error; `per_source` marks it `missing_key`).

**Paging (onepass ≥ 0.2)**: VirusTotal (`links.next`, same origin only) and urlscan (`search_after`) are paged up to 4 pages
(the onepass binary's own page budget, 1–20; 4 fits VirusTotal's free 4 requests/minute). FOFA, Quake and Hunter are **never paged
automatically** (every page spends quota): their first page is kept and the upstream total is reported instead. Each
`per_source` entry carries `pages`, `truncated` and `total`; a source whose upstream holds more rows than were fetched is
listed in `truncated_sources` (and, in a `run`, in `coverage.unavailable.truncated_sources`). A cap is a coverage limit,
not a failure: the outcome is unchanged.

**Confidence**: computed from the **number of independent sources** (1 ≤0.6, 2 ≥0.7, 3+ ≤0.95), stored with `sources`.
**Value**: one command covers 8 free sources, much faster on cold start than chaining `certs` + `subs`; `per_source` shows immediately which source is down today.

---

## certs — certificate transparency (route 1 of stage 1B)

```bash
python findinfo.py certs --domain example.com
```

**Output**

```json
{
  "domain": "example.com",
  "count": 128,
  "records": 4213,
  "domains": ["api.example.com", "dev.example.com", "uat.example.com", "..."]
}
```

**Sources**: crt.sh (primary) → CertSpotter (backup), with automatic failover.
**Value**: fully passive, zero quota, zero target contact — **the step to run first**. `-dev/-test/-uat` naming is the gold.

---

## subs — multi-source passive subdomains (route 3 of stage 1B)

```bash
python findinfo.py subs --domain example.com
python findinfo.py subs --from-store --scope example.com   # store domains >= 0.7 under the scope
```

| Parameter | Default | Description |
|---|---|---|
| `--domain` | — | repeatable |
| `--from-store` | false | use store domains |
| `--engines` | — | accepted for compatibility; **subs is passive and keyless** |

**Output**

```json
{
  "domain": "example.com",
  "count": 214,
  "domains": [
    {"domain": "api.example.com", "sources": ["crt.sh", "subfinder"], "confidence": 0.75}
  ]
}
```

**`subs` is passive and keyless**: it runs subfinder only, with an empty provider config (`-pc`), so it cannot spend a
mapping quota and holds no credential. Metered mapping lives in `map` / the `mapping` stage; keeping it here too is how one
seed was sent to FOFA three times per run. **It never errors out** for a missing key.

**Where the metered answer comes from.** Domains harvested by `mapping` are in the store before `subs` runs in a pipeline, and
`map --domain X` asks the paid engines once per task (see `map` below). Every engine answer is attributed as
`uncover:<engine>` in asset `sources`, so `subs` output and mapped rows never look like the same evidence. Query syntaxes,
credential variable names and their evidence: [docs/MAPPING-QUERIES.md](MAPPING-QUERIES.md).

---

## brute — DNS brute force (route 4 of stage 1B, **ACTIVE**)

Quickly fills in subdomains that passive sources miss. A stateless raw-packet engine based on ksubdomain, 1~2 orders of magnitude faster than per-query dnsx brute forcing.

    python findinfo.py brute --domain example.com
    python findinfo.py brute --domain example.com --wordlist wordlists/sub.txt --bandwidth 3m
    python findinfo.py brute --domain example.com --wordlist wordlists/submin.txt --bandwidth 5m
    python findinfo.py brute --domain example.com --wildcard advanced

| Parameter | Default | Description |
|---|---|---|
| --domain | required | target domain |
| --wordlist | wordlists/sub.txt | dictionary; a path, or a bare name `sub`/`submin`/`vhost` (auto-resolved under wordlists/) |
| --bandwidth | 3m | send-rate budget; lower is quieter, 2m~5m recommended |
| --wildcard | basic | wildcard-filter mode; use advanced in strict cases |

Output

    {"domain": "example.com", "count": 1,
     "records": [{"domain": "www.example.com", "a": ["172.66.147.243"]}]}

Prerequisites (important)

- Windows needs Npcap (check the WinPcap-compatible option during install); Linux needs libpcap
- Usually requires administrator/root (raw-packet sending)
- Built-in rate cap of 25000 pps; effectively governed by --bandwidth

**Bundled dictionaries (two tiers)**

| File | Entries | Positioning | Typical time (one domain, 3m) |
|---|---|---|---|
| `wordlists/sub.txt` | 174 | **high-value prefixes**: internal systems / middleware / CN-common (k8s, kibana, nacos, consul, harbor, sso, skywalking...) — words that are NOT in the generic top-10k | 10~30s |
| `wordlists/submin.txt` | 9990 | **full top-10k** (mitan dictionary normalized: lowercased, deduplicated, invalid labels dropped) | 2~5min |
| `wordlists/vhost.txt` | 145 | not a subdomain list — Host labels for vhost (needs `--domain` to append the base) | — |

Recommended order: run `brute --wordlist wordlists/sub.txt` first (fast, catches internal systems); once `--bandwidth` and wildcard behaviour look sane,
go full with `submin.txt`. The two tiers overlap on 157 entries; re-runs are absorbed idempotently by `Store`, producing no duplicate assets.

Division of labour with subs: subs finds subdomains that exist AND are indexed; brute finds ones that exist but nobody indexed. Complementary — run subs first, then brute.

---

## icp — ICP filing reverse lookup (alias of `map --icp`)

```bash
python findinfo.py icp --code "京ICP备10210538号"
python findinfo.py icp --from-store --scope example.com   # reuses the ICP numbers ENScan stored
```

**Output**

```json
{"codes": ["京ICP备10210538号"], "rows": 156, "domains": ["..."], "ips": ["..."]}
```

**Dependency**: at least one mapping-platform key. `icp` is a compatibility alias for `map --icp` (see `map` below): both
go through the same task ledger, so a filing this task already paid for is reused, never re-asked. One dispatch per engine,
each in its own syntax: fofa `icp="京ICP备10210538号"`, quake `icp:"…"`, hunter `icp.number="…"`; engines without an ICP
field (shodan, censys) are not asked and are listed in `unsupported_engines`. An engine that returns no rows is listed in
`unconfirmed_empty` (a gap, not an error); a non-zero exit is an `errors` entry naming its `engine`.
**Note**: filing numbers often carry `-1`/`-2` suffixes — they normalise to the principal number, so `…-1` and `…-2` are ONE
question, asked once. Query syntaxes, credential variable names and their evidence live in
[docs/MAPPING-QUERIES.md](MAPPING-QUERIES.md).
**Storage**: the filing number itself is stored as `assets(kind=icp, canonical="京ICP备…")` (sources `enscan`/`icp-seed`),
which is why `icp --from-store` can reuse numbers ENScan saved; domains/IPs from the reverse lookup land as `kind=domain`/`kind=ip` with confidence 0.9/0.5.

---

## dns — resolution + wildcard filtering (stage 1C)

```bash
python findinfo.py dns --from-store --scope example.com
python findinfo.py dns --domain example.com --min-conf 0.4
```

**Output**

```json
{
  "count": 87,
  "domains": [{"domain": "api.example.com", "a": ["1.2.3.4"], "cname": ["lb.example.net"]}],
  "wildcard": [{"parent": "example.com", "ip": "5.6.7.8"}],
  "system_fallback": 3
}
```

- non-empty `wildcard` = the domain has wildcard resolution; matching IPs were auto-removed (otherwise assets inflate a hundredfold)
- `system_fallback` = rows resolved via system DNS when public DNS failed (common on CN networks)

---

## probe — liveness / fingerprint / IP mapping (stage 2, **ACTIVE**)

```bash
python findinfo.py probe --from-store --scope example.com
python findinfo.py probe --host a.example.com --host b.example.com
```

**Output**

```json
{
  "count": 42,
  "rows": [{
    "host": "api.example.com", "url": "https://api.example.com",
    "status": 200, "title": "API Gateway", "tech": ["nginx", "Spring Boot"],
    "ip": "1.2.3.4", "cname": ["lb.example.net"], "port": "443",
    "length": 1024, "cdn": null, "webserver": "nginx"
  }]
}
```

**Core value**: the `ip` field builds the `domain↔IP` mapping (input for `ipagg`/`vhost`).
It also writes `status/title/tech` back into `assets.attrs` and records the landing page as an `endpoints` row.

---

## ipagg — IP aggregation and CDN removal

```bash
python findinfo.py ipagg --scope example.com      # IPs owned by in-scope domains
python findinfo.py ipagg --ip 1.2.3.4 --ip 1.2.3.5 # explicit IPs, no scope needed
```

**Output**

```json
{
  "ips": ["1.2.3.4", "1.2.3.5"],
  "cdn": {"1.2.3.5": "cloudflare"},
  "candidates": [
    {"ip": "1.2.3.4", "domains": ["api.example.com", "admin.example.com"], "reason": "shared-ip"}
  ],
  "count_candidates": 1
}
```

**Criterion**: an IP carrying **≥2 of your own domains** is a strong vhost signal. CDN IPs are removed (colliding on them only hits someone else's site).
**The output is `vhost`'s input.**

---

## ports — port scanning (**ACTIVE**)

```bash
python findinfo.py ports --ip 1.2.3.4 --top-ports 1000   # explicit targets, used as given
python findinfo.py ports --scope example.com             # public IPs owned by in-scope domains
```

Without `--ip`, the targets come from the store and are scoped by `--scope` (alias `--domain`) or `--whole-store`, or
inferred per `scope.unscoped_reads` (see the Store reads row). Only IPs **owned** by an in-scope domain (their `parent`)
are taken: an IP scraped out of a page/JS has no owner and an ICP-lookup IP is owned by a filing number, so neither is
scanned. Private, loopback, link-local, CGNAT, benchmark/fake-IP (198.18.0.0/15), reserved and multicast addresses are
skipped even when owned and returned in `skipped_private` — from the operator's machine they reach the operator's own
network, not the target. The filter lives in `tools.t_ports`, so the `run` pipeline obeys it too. Pass such an address
with `--ip` to scan it deliberately (an explicit address is used verbatim).

**Output**

```json
{"targets": ["1.2.3.4"], "count": 4,
 "rows": [{"ip": "1.2.3.4", "port": 80}, {"ip": "1.2.3.4", "port": 443}]}
```

Every open port is stored as `assets(kind=endpoint, canonical="1.2.3.4:8080")`.

---

## vhost — Host-header collision (core of stage 2, **ACTIVE**)

```bash
python findinfo.py vhost --ip 1.2.3.4 --from-store --domain example.com
python findinfo.py vhost --ip 1.2.3.4 --wordlist wordlists/vhost.txt --domain example.com        --ports 80,443,8080,8443
```

| Parameter | Default | Description |
|---|---|---|
| `--ip` | required | target IP |
| `--host` / `--from-store` | — | candidate Hosts (explicit, or store domains — a store read needs `--domain`) |
| `--wordlist` | — | dictionary; bare labels expand via `--domain` |
| `--domain` | registrable domains of the `--host` values | base domain for bare labels and scope of a store read, repeatable |
| `--ports` | 80,443 | comma-separated |
| `--threads` | 20 | concurrency |

**Wordlist semantics**: `wordlists/vhost.txt` holds **bare labels** (`dev`/`uat`/`jenkins`); a lone label is not a valid hostname.
`--domain example.com` expands each into `dev.example.com`, `uat.example.com`...; without `--domain`
the registrable domains of the hosts being collided are used (never every domain in the shared store). Entries containing
dots (`admin.example.com`) are used verbatim, never double-appended.

**Output**

```json
{
  "ip": "1.2.3.4", "tested": 63, "hits": 2, "skipped_live": 12, "tool": "hostCollision",
  "results": [{
    "ip": "1.2.3.4", "port": 443, "scheme": "https",
    "host": "jenkins.example.com", "status": 200, "len": 4021,
    "title": "Dashboard [Jenkins]", "len": 4021, "via": "hostCollision"
  }]
}
```

**How it works**: drives the bundled `hostCollision` (alwaystest18/hostCollision, 3-request differential):
no-Host baseline → random-label Host baseline → the real candidate; the two hidden baselines must agree before
the candidate's difference is judged. Bodies over 2000 chars are compared by edit-distance similarity (<85% counts as different), and hostname-echo noise is dropped.
**Candidate removal**: domains already confirmed live by probe (2xx~4xx) are skipped automatically (counted as `skipped_live`).
**HTTPS also rewrites SNI** (changing only the Host header is not enough — the TLS handshake would land on the default certificate).
**Environment**: requires direct connectivity to the target IP; behind an HTTP proxy/TUN it fails and automatically falls back to curl `--resolve`.
**This is where internal systems surface most easily**: Jenkins/GitLab/Nexus/Swagger and every kind of admin console.

---

## crawl — crawling (stage 3, **ACTIVE**)

```bash
python findinfo.py crawl --from-store --domain example.com --depth 3
python findinfo.py crawl --url https://app.example.com
```

**Output**

```json
{"count": 318, "rows": [{"url": "https://app.example.com/api/v1/user", "host": "app.example.com", "path": "/api/v1/user", "params": ["id"]}]}
```

Each URL becomes `endpoints(method, path_template, params)`; digits/UUIDs in paths normalize to `{n}`/`{uuid}`.

---

## extract — page/JS leak extraction (stage 3)

```bash
python findinfo.py extract --url https://app.example.com/static/app.js
python findinfo.py extract --from-run runs/xxx/crawl.jsonl
python findinfo.py extract --from-store --domain example.com   # reflow: the store's URL assets (recommended)
```

**Three inputs**: `--url` names one JS/page; `--from-run` reads a crawl JSONL artifact;
`--from-store` uses the store's `kind=url` assets directly (use this in the reflow loop — no need to know run-dir paths);
it needs `--domain` (or `--whole-store`) so another engagement's JS is never re-fetched.
At most 40 JS/JSON/map files fetched per call, with a 4 MB text budget (memory safety).

**Engine**: pure-Python regexes (`lib/jsleak.py`) extracting API paths, domains, IPs, secrets and sourcemaps — zero dependencies, runs anywhere.

**Output**

```json
{
  "count_domains": 5, "count_ips": 1, "fetched": 12,
  "api_paths": ["/api/v2/internal/order", "/api/v1/upload"],
  "secrets": {"aws_ak": ["AKIA..."], "jwt": ["eyJ..."]},
  "domains": ["internal.example.com", "api.example.com"],
  "ips": ["10.1.2.3"]
}
```

Extracts: domains, IPv4s, API paths, sourcemap references, common secret patterns (AWS/Aliyun/Tencent/GitHub/JWT/private keys/internal IPs).
**Output must reflow**: new domains → re-run `certs`/`subs`/`dns`; new IPs → re-run `ipagg`/`vhost`.

---

## assets — query / export the asset graph

```bash
python findinfo.py assets --kind domain --limit 50
python findinfo.py assets --kind icp                  # see the ICP numbers ENScan stored
python findinfo.py assets --kind app                  # APP / mini-programs ENScan named
python findinfo.py assets --min-conf 0.7 --export runs/assets.jsonl
python findinfo.py assets --export-xlsx out.xlsx      # one sheet per kind, 说明 sheet records scope
```

`--kind` covers `company` / `icp` / `domain` / `ip` / `url` / `endpoint` / `app`; `all` is the default
(`all` includes `app` now — it used to be parsed from ENScan and dropped before storage, so the mobile surface
never appeared in any output).

**Output**

```json
{
  "counts": {"domain": 128, "ip": 64, "url": 318, "icp": 3},
  "total": 50, "endpoints": 318,
  "rows": [{"kind": "domain", "canonical": "api.example.com", "sources": "crt.sh,dnsx,httpx", "confidence": 0.95, "attrs": {...}}]
}
```

`--export` writes JSONL, ready to feed vulnerability scanners.

---

## status — long-job progress (for polling)

```bash
python findinfo.py status                       # the most recent run
python findinfo.py status --run runs/20261117-131500-example.com
```

**Output**

```json
{
  "run_dir": "C:\\Users\\x\\.findinfo\\runs\\20261117-131500-example.com",
  "state": "running", "stage": "probe", "stage_state": "running",
  "alive": true, "heartbeat_age_sec": 12.4,
  "run_id": 7, "pid": 24116,
  "counts": {"domain": 412, "ip": 118}, "endpoints": 63,
  "summary": null
}
```

| Field | Meaning |
|---|---|
| `state` | the whole run's state: `running` / `queued` / `completed` / `failed` / `cancelled` (no `done` terminal state) |
| `stage` + `stage_state` | current stage; stage states are `running`/`done`/`skipped`/`failed` |
| `alive` | `state=running` AND heartbeat < 90s (pid also alive) → the process is alive; goes false when a long job hangs |
| `heartbeat_age_sec` | seconds since the last heartbeat (refreshed at every stage start/finish) |
| `counts` / `endpoints` | store asset counts — a direct read on whether anything was added |
| `summary` | after completion, identical to the run's stdout |

**Agent usage**: `run --background` returns a run_id, then loop `wait --run <id> --timeout 30` (a timeout only ends that window)
until `state=completed` (terminal states are only `completed`/`failed`/`cancelled`, **there is no `done`**) and take `summary`; on `state=failed` read `last_error`.

---
## wait — bounded wait (the standard way to wait on long jobs)

```bash
python findinfo.py wait --run <run_id> --timeout 30
python findinfo.py wait --run <run_id> --timeout 30 --since 12   # use the previous response's cursor
```

| Parameter | Description |
|---|---|
| `--run` | required; the run_id from the background launch (also accepts a run dir or prefix) |
| `--timeout` | per-call wait ceiling in seconds, default 30; returning on time is not failure |
| `--since` | compare against the previous response's `cursor` (`progress_seq`); without it wait for substantive progress after this call starts |
| `--full` | return the full payload (incl. coverage/run_dir); default is trimmed to cut polling tokens and latency |

**Return** (one JSON line, trimmed default ~340 bytes)

```json
{"run_id":"20261118-010612-example.com","state":"running","changed":true,"timed_out":false,
 "terminal":false,"alive":true,"interrupted":false,"stalled":false,"reaped_by_host":false,"seq":8,"progress_seq":7,"cursor":7,"waited_sec":0.2,
 "stage":"probe","stage_state":"running","stage_index":4,"stage_total":9,"percent":44.4,
 "counts":{"domain":128,"ip":64},"endpoints":37}
```

`--full` additionally returns `progress.elapsed_sec`, `coverage`, `run_dir`, `note`.

**`reaped_by_host`** (only meaningful when interrupted): `true` = the worker was reaped by the host before
running any Python (empty stderr.log) — background mode is unusable in that environment; switch to foreground `--task-timeout` or a live-parent-held worker;
`false` = an ordinary crash; `run --resume` continues from checkpoints.

- `timed_out: true` → **only this wait window ended**; keep waiting on the same run_id.
- `changed: true` / `terminal: true` → returned early (progress or terminal).
- Pass the returned `cursor` as the next `--since`, including after a timeout. It acknowledges the latest substantive progress in that response, so the next call does not repeat it. `seq` also counts heartbeat writes; a heartbeat alone does not set `changed`. Existing callers may pass a raw `seq`: only a later progress marker counts as new progress.
- `percent` being `null` = the stage's total is unknown (brute/crawl); never convert it to a percentage.
- Exit code is always `0` (a wait timeout is not an error); `2` when the run_id does not exist.
- Implementation: polls the persisted `progress_seq` every 50ms and returns on newer substantive progress or a terminal state. Legacy status files without that marker fall back to `seq`.

---

## cancel — cancel a running job

```bash
python findinfo.py cancel --run <run_id>
python findinfo.py cancel --run <run_id> --reason "user asked"
```

Writes a `cancel` marker then kills the process tree (Windows `taskkill /T`, POSIX process group), sets state to `cancelled`;
assets already collected stay in the store.

---

## runs — list recent runs (the session-recovery entry)

```bash
python findinfo.py runs --limit 10          # all recent runs
python findinfo.py runs --active            # only running jobs (check before launching to avoid duplicates)
python findinfo.py runs --state failed      # only failed ones
```

Returns `{"runs":[{"run_id","state","stage","alive","target","created","updated","exit_code","run_dir"}],"active":[...]}`.
**New-session recovery starts here**: once you have the run_id, `status --run <id>` restores target/scope/params/stages/artifacts/next steps.

---

## run — the full pipeline

**Agent default**: a natural-language asset collection request selects the full background command below. Given targets do not require a routine authorisation/subsidiary question; related companies require explicit user inclusion. The low-level CLI remains passive without active flags for compatibility, so a bare `run` is not the Agent full-collection default.

```bash
python findinfo.py --task example-com run --domain example.com --active --ports --vhost --crawl --background --rounds 3
python findinfo.py --task example-corp run --name "Example Corp" --active --ports --vhost --crawl --background --rounds 3
```

Only when the user explicitly requests passive-only:

```bash
python findinfo.py --task passive-project run --domain example.com --background  # user-requested passive-only
```

Missing mapping keys/Cookie skip only their dependent sources and remain coverage gaps; keep the available keyless discovery/DNS/probe/ports/vhost/crawl/extract stages running. Do not end at a passive summary or resume solely for a missing key. For company-only input without a usable anchor, the Agent uses available search to verify an official root domain, then supplies it with `--domain`; never guess or choose an ambiguous company. Ask for a seed only if verification fails. A stage with no valid input may report `no_input`, which is not a real dispatch.

| Parameter | Description |
|---|---|
| `--name` | company name (goes through ENScan) |
| `--domain` | seed domains directly (repeatable, or comma-separated `a.com,b.com`; skips ENScan); an invalid value is refused before a background worker starts |
| `--active` | enable the traffic-generating stages |
| `--ports` / `--vhost` / `--crawl` / `--brute` | append stages (imply `--active`; `--brute` needs Npcap) |
| `--max-seed` | seed-domain cap for onepass/certs/subs/brute; default `0` expands all approved seeds, positive N selects the first N; mapping/DNS/probe remain scoped independently |
| `--no-mapping` | disable paid mapping, including the entity name fallback; preserved in background jobs |
| `--no-icp` | skip ICP mapping questions while keeping domain mapping |
| `--remap` | explicitly re-ask stored mapping questions, including name fallback; preserved on worker replay; resume keeps the stored source policy |
| `--top-ports` | naabu preset: `100` or `1000` (default 1000); naabu refuses other numbers |
| `--max-vhost-ips` | cap on candidate IPs to collide (default 10) |
| `--dry-run` | compile the plan only: `run_id: null`, no db/home/process/credential, works with `--background`/`--resume` read-only |

`--domain` accepts hostnames and bare IPs. An explicit `IP:port` endpoint target
is **rejected with `unsupported_target_kind`** rather than silently reduced to
its host — this build's run path has no endpoint stage, and dropping the port
while reporting "no seeds" would hide what was asked for. Pass the bare IP or a
domain instead.

**Convergence**: a stable domain count is not convergence while
`coverage.work_queue.outstanding > 0` (this run's durable JS/DNS queue). The
run stays `partial` with reason `work_pending` until the queue drains; a
succeeded bundle is never re-opened, and HTML pages never enter the JS queue.

**Output (summary)**

```json
{
  "engagement": "demo", "active": false,
  "run_dir": "...\\runs\\20261117-131500-example-corp",
  "seed_domains": ["example.com"],
  "stages": [
    {"stage": "entity", "companies": 12, "icp": 3, "domains": 8},
    {"stage": "onepass", "found": 214},
    {"stage": "certs", "found": 128},
    {"stage": "subs", "found": 214},
    {"stage": "dns", "resolved": 87, "wildcard": 0}
  ],
  "counts": {"domain": 128, "ip": 64},
  "endpoints": 42
}
```


**Background mode (default Agent collection)**

```bash
python findinfo.py --task example-com run --domain example.com --active --ports --vhost --crawl --background --rounds 3
```

```json
{"run_id":"20261118-003129-example.com","state":"running","started":true,
 "pid":36532,"reused":false,"dedupe_key":"d7c9acb9fa9f5a62",
 "planned_stages":["onepass","certs","subs","mapping","dns","probe","ipagg","ports","vhost","crawl","extract"],
 "run_dir":".../runs/20261118-003129-example.com",
 "state_path":".../status.json","result_path":".../summary.jsonl",
 "log_path":".../stdout.log","error_log_path":".../stderr.log",
 "next":"python findinfo.py --task example-com wait --run 20261118-003129-example.com --timeout 30"}
```

- A standalone Python worker process (POSIX `setsid` / Windows `DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP`)
  that **does not depend on the tool call that launched it**; each run gets its own `status.json`/`summary.jsonl`/`stdout.log`/`stderr.log`.
- Re-submitting the same target (same task + params) while it runs returns `reused: true` + the original `run_id` — no duplicate collection.
- `--resume <run_id>` continues an existing run (reuses checkpoints); use it when the worker died (`interrupted` with `reaped_by_host:false`).
  **Never resume when `reaped_by_host:true`** — resume spawns another detached process that dies the same way on a reaping host; run in the foreground instead.
- Boundary: process survival ≠ session survival. A finished agent session is never woken automatically; re-enter the session and continue via `runs`/`status`;
  whether a run survives a reboot depends on the host registering it as a service — not guaranteed by this skill.

**Result and coverage (`result` / `coverage`)**

```json
"result": {"status":"complete|partial|failed","reason":"all_stages_done|stage_failed|
            "time_budget_exhausted|round_budget_exhausted|required_capability_missing",
           "run_id":"...","scope":["example.com"],"counts":{...},"endpoints":37,
           "elapsed_sec":812.0,"artifacts":{...}}
"coverage": {"planned_stages":[...],"done_stages":[...],"skipped_stages":[...],
             "failed_stages":[{"stage":"certs","error":"..."}],"not_run_stages":[...],
             "unavailable":{"missing_tools":[],"engines_without_key":["quake"],"blocking":false,
                            "unconfirmed_empty":["uncover:hunter"],"unsupported_engines":["censys"],
                            "truncated_sources":["onepass:virustotal"]},
             "rounds":[{"round":1,"new_domains":3,"stop":"continue"}],
             "stop_reason":"no_new_assets|max_rounds|time_budget",
             "budget":{"rounds":3,"rounds_used":3,"elapsed_sec":812.0},"complete":true}
```


**Source-level failures and gaps (never "no assets")**

| Situation | Return/field | Notes |
|---|---|---|
| Transient failure (timeout/rate-limit/5xx) | auto-retried `limits.source_retries` times (default 2, backoff 1.5s→3s); still failing → stage `ok: false` | the stage is marked failed and writes no done checkpoint; other sources' results are kept |
| Missing key | `coverage.unavailable.engines_without_key`, `doctor.api_keys` | marked `unavailable`, never disguised as "nothing found" |
| Engine returned no rows | `coverage.unavailable.unconfirmed_empty` (`uncover:<engine>`) | uncover reports an upstream error the same way: report it as unconfirmed, not as "nothing exists" |
| Engine has no known query | `coverage.unavailable.unsupported_engines` | that engine was not asked at all |
| Upstream answer capped | `coverage.unavailable.truncated_sources` (`onepass:<id>`) | more rows exist than were fetched (page budget, or a billed engine's first page); not a failure |
| Quota exhausted | `doctor.fofa_gateway.remaining` at zero | marked `quota_exhausted`, written into delivery gaps |
| Wildcard pollution | `dns`'s `wildcard: [{parent, ip}]` | matching names filtered, not stored; report the list under "data quality" |
| Empty result | stage `found: 0` with `ok: true` | a valid result, not a failure |
| Display truncation | `truncated: true` | display only; downstream stages and report both use the full store |

The retry budget is tunable: `config/config.json` → `limits.source_retries` (default 2, i.e. at most 3 attempts).

**Exit codes**: `0` completed with sufficient coverage | `5` finished but coverage incomplete (failed stages / exhausted budget / missing required capability) |
`1` every stage failed | `4` tool missing | `2` argument/business error | `130` cancelled.

**Reflow rounds**: `--rounds N` loops `dns→verify→extract` until "no new in-scope assets" or N rounds are used;
once `--time-budget` seconds pass no new round starts; the stop reason lands in `coverage.stop_reason`.

**Long jobs**: a typical `run` takes 5~40 minutes. Foreground execution blocks; the standard pattern is `--background` + `wait`.
**Checkpoints**: each finished stage writes a `steps` row (engagement+stage+input hash); the same input auto-skips on re-run (downstream inputs are rebuilt from scoped store queries); `--force-stage` forces a redo.
**Explicitly narrowed requests**: when the user chose passive-only earlier, a later full request can enable the active switches and reuse completed discovery checkpoints. The normal full request starts with all default switches in one job; it does not require a separate passive run.
**Failure semantics**: a stage whose tool failed (rc≠0/timeout) records `steps.status=failed` and a summary with `failed:true`; **a re-run retries it automatically**. Partial output is already stored and usable downstream. Exit code 5 means failed stages exist.
**Scope**: `run`'s active stages only touch `--domain`/entity-anchor seeds; out-of-scope domains found via ICP reverse lookup or JS leaks are stored and reported, never auto-promoted into active stages.
**Detail cap**: every stage returns at most 500 detail rows with `truncated: true` — a **display** cap; the full data is in the store and downstream stages (probe/crawl/extract) also read the full set (export via `assets --export`);
raise the cap with `FINDINFO_ROW_LIMIT` or `limits.row_limit` in `config/config.json`. Coverage gaps caused by deliberate budgets (e.g. `--max-seed` scanning only the first N seeds) are recorded in the summary's `coverage_limits`.

---


---

## clean — trim the shared asset graph

The asset graph is **globally shared without `--task`**; after several targets, `--from-store`
reads the previous targets' assets back in. Trim/isolate:

```bash
python findinfo.py clean --keep example.com --keep example.org --vacuum   # keep only this target
python findinfo.py clean --match example.com                       # delete only one target
python findinfo.py clean --all --vacuum                            # wipe everything
```

| Parameter | Description |
|---|---|
| `--keep X` | keep X and its subdomains, delete the rest (repeatable) |
| `--match X` | inverse: delete only X and its subdomains |
| `--kind` | limit to asset kinds (default all). **The endpoint table is hostname-keyed**: host-keyed endpoints are only deleted when kinds include `domain`/`endpoint` (or are omitted); `--kind ip` deletes only IP asset rows, leaving other assets' endpoints alone |
| `--all` | delete every asset and endpoint |
| `--vacuum` | reclaim disk (measured 163MB → 5MB) |

**Preventing pollution**: every single-stage store read is scoped or refused — `--scope X` for
passive/subs/icp/dns/probe/ipagg/ports, `--domain X` for vhost/crawl/extract; without one the command exits 2 with
`scope_required` instead of inheriting the previous target's assets. `--whole-store` is the explicit opt-in.

## report — human deliverables (HTML by default)

Shapes the asset graph into human-facing deliverables. It reads SQLite without collecting assets or sending packets, and writes the requested report files. The only default report file is `report.html`.
Agents read data via the `brief` command (one JSON line on stdout, no files); scripts wanting everything use `assets --export`.

**Scope is judged per asset kind**: domains by suffix; URLs by their parsed hostname; IPs by their owning domain (assets.parent) — a shared IP only means "some in-scope domain resolves to it", not exclusive ownership. **An explicit `--match` with no valid domain among it is a hard error** — never a silent full-store report. Without `--match` the latest run's target is used and a warning is emitted.

```bash
python findinfo.py --task example-com report --run <run_id> --match example.com --slug example
python findinfo.py report --match example.com --match example.org --slug example
python findinfo.py report --match example.com --with-md     # also write Markdown when requested
python findinfo.py report --print-md                       # explicitly echo Markdown in the JSON response; does not enable a .md file
python findinfo.py report --with-json --json-limit 40      # also write report.json (for scripts)
python findinfo.py report --out ./out --limit 80 --ep-limit 200
```

**Artifacts** (default `~/.findinfo/reports/<timestamp>-<slug>/`, with a `reports/latest` pointer to the most recent;
falls back to `reports/latest.txt` where Windows lacks symlink rights)

| File | Reader | Notes |
|---|---|---|
| `report.md` | humans / chat | tiered listing — **written only with `--with-md`** |
| `report.html` | humans | self-contained dark dashboard, no external JS/CSS/fonts, print styles — **always written** |
| `report.json` | scripts | full digest + provenance + `charts`; **written only with `--with-json`** |
| `report.brief.json` | scripts | 32 KB digest; **written only with `--with-brief`** (routine agent reads use the `brief` command) |

| Parameter | Description |
|---|---|
| `--match X` | target domain suffixes, repeatable; defaults to the latest `run`'s target |
| `--run <run_id>` | read this run's coverage; without `--match`, reuse its scope; Agent delivery should pass the collection run id |
| `--min-conf` | confidence floor for included hosts (default 0.4) |
| `--limit` / `--ep-limit` | host / endpoint detail caps (default 300 / 400) |
| `--json-limit` | cap arrays inside `report.json` (0 = no extra truncation) |
| `--out` / `--slug` | output directory / label |
| `--engagement` | which run's stage checkpoints to read (`stages` field) |
| `--with-json` / `--with-brief` | also write the machine files report.json / report.brief.json (off by default) |
| `--with-md` | also write report.md (off by default; HTML alone is the default) |
| `--print-md` / `--print-json` | explicitly include Markdown / the full digest in the stdout JSON response; neither selects an extra file |

**Output (one JSON line on stdout)**

```json
{
  "counts": {"domains_in_scope": 48, "live": 27, "interesting": 12, "internal_services": 4,
             "endpoints_in_scope": 6379, "endpoints_interesting": 153, "leak_domains": 8},
  "scope": {"match": ["example.com"], "auto": false},
  "paths": {"html": ".../report.html", "dir": ".../reports/example"},
  "warnings": ["detected 4 domains resolving into 198.18.0.0/15 (Clash/TUN fake-IP)..."],
  "next_steps": ["disable TUN and re-run dns/probe..."]
}
```

For Agent delivery, read `brief --run <run_id>`, execute `report --run <run_id>`, and link the actual returned `paths.html` with a short verdict/gap statement. Do not hand-write Markdown tables or a `.md` file instead of running `report`. `brief` prints its bounded JSON to stdout and writes no file; report machine files remain opt-in.

**report.json shape**: `schema` / `scope` / `counts` / `hosts[]` (`host`,`ip`,`status`,`title`,`tech`,
`priority`,`score`,`reasons[]`,`provenance[]`,`discovered_by`,`sensitive[]`,`params[]`) / `endpoints[]` /
`signals` (leaked secrets) / `ip_groups` / `provenance` (tool→asset counts) / `stages` / `next_steps` / `charts` / `truncated`.

---

## brief — the unified agent read API (store query → one JSON line on stdout)

Whenever an agent wants to know "what did this collection yield": query the store directly and print the same digest as
`report.brief.json` (counts / coverage gaps / top_hosts / internal_services / leaks / next_steps) as **one JSON line on stdout**,
**writing no files**. Scope semantics are identical to `report` (`--match` validation, `--run` scope fallback, cross-task refusal).

```bash
python findinfo.py --task <name> brief --match example.com      # the usual call
python findinfo.py brief --run <run_id>                # no --match: reuse the run's scope
python findinfo.py brief --match example.com --top 10         # top_hosts cap (default 20)
python findinfo.py brief --match example.com --max-bytes 8192 # byte ceiling (default 32 KB)
```

| Parameter | Description |
|---|---|
| `--match X` | target domain suffixes, repeatable; same semantics as report's `--match` |
| `--run <run_id>` | without `--match`, use that run's scope |
| `--top` / `--max-bytes` | top_hosts count (default 20) / payload byte ceiling (default 32768) |
| `--min-conf` / `--limit` / `--ep-limit` | same as report |
| `--engagement <run_id>` | explicitly pick which run's checkpoints to read; **`--run` wins when both are given** — this only applies without `--run` |

### Where coverage comes from (identical rules for `brief` and `report --with-brief`)

Coverage gaps live in each run's own state, not in the shared store. The read order is fixed:

1. `--run <run_id>` given: that run's coverage;
2. no `--run` but an explicit `--engagement` (other than the default `default`): that run's coverage;
3. only `--match` given: the newest run **in the current task whose scope intersects `--match`**;
4. nothing found: `coverage` becomes `{"source": "none", "known": false}` — never an empty list that looks like "no gaps".

So **whenever you have a run_id, use `brief --run <run_id>`**: a match-only call degrades to "guess the latest run"
and may read a different one than you think.

**Output (one JSON line on stdout — the entire product of the command)**: `schema: findinfo.brief/1`, `counts`, `scope`,
`environment.warnings`, `coverage`, `top_hosts` (each with `host`/`score`/`priority`/`reasons`/`provenance`),
`internal_services`, `leaks`, `next_steps`, `truncated` (kept/total of cut arrays).

`coverage` fields:

| Field | Meaning |
|---|---|
| `source` | which run id the coverage came from; `"none"` when no run was read |
| `known` | `true` = a run's coverage was really read; `false` = nothing was read, **which does NOT mean "no gaps"** |
| `failed_stages` | stages that ran and failed |
| `not_run_stages` / `skipped_stages` | planned stages with no results / stages skipped |
| `unavailable` / `unavailable_total` | per-item gaps (missing credentials, missing tools, exhausted quota...); only the first 40 are kept |
| `blocking` / `blocking_reason` | present only when a **blocking** gap exists (e.g. a required tool is missing), with the reason |
| `note` | explanation of non-blocking gaps (optional) |
| `hint` | remediation hint when `known=false` |

---

**Provenance**: a host's `discovered_by` keeps the raw sources string (e.g. `onepass:rapiddns,subfinder`),
and `provenance` normalizes it into a tool list with labels; onepass's many upstreams count as one tool.

---

## Combined usage

The recommended agent workflow is written once, in [prompts/AGENT.txt](../prompts/AGENT.txt) ([SKILL.md](../SKILL.md) §1.5 has its four essentials). It is not repeated here: the copy that used to be here had drifted into foreground single-stage commands that SKILL.md §5 forbids.
