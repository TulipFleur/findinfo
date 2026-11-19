# Linux deployment and running

> One skill codebase: Windows ships bundled `bin/windows/*.exe`; Linux needs **native binaries**.
> This page covers only the Linux side; command semantics are identical to Windows (see `docs/TOOLS.md`).
> **`scripts/setup-linux.sh` / `build-enscan.sh` ship only in the Linux release package**: the Windows package has neither (Windows uses the bundled `bin/windows/*.exe`).

## 0. Support matrix

| Item | Windows | Linux |
|---|---|---|
| all bundled tools | `bin/windows/*.exe` included | installed on-site by `scripts/setup-linux.sh` |
| client install | junction | symlink (`install.py` decides automatically) |
| port scanning / DNS brute | admin + Npcap | `CAP_NET_RAW` + libpcap |
| long jobs | foreground / `nohup` | systemd / tmux |
| killing children | `CREATE_NO_WINDOW` | n/a (the flag is a no-op on Linux) |

## 1. Quick start

~~~bash
cd <skill>                                  # the directory holding SKILL.md
bash scripts/setup-linux.sh --dry-run       # 1) resolve versions and URLs only, write nothing
bash scripts/setup-linux.sh                 # 2) install into <skill>/bin
bash scripts/setup-linux.sh --cap           # 3) or install to PATH and setcap in one go
python3 findinfo.py doctor                  # 4) should show every tool present
~~~

What the installer does: resolve the latest GitHub release → download → unpack → locate the executable → install into `<skill>/bin/linux` (fixed; no --prefix) → build onepass (cargo) / ENScan (go) → print sysctl advice.
It is **idempotent** — rerun any time; `--check` inspects without installing, `--only httpx,katana` installs just those.

**Exit codes and version tracking**: any required tool (subfinder/httpx/dnsx/naabu/katana/onepass) failing or missing → exit 1, so callers can decide "can it run after install"; optional-tool failures only WARN. Each successful install records `tool → tag` into `<prefix>/.installed-versions`; `--check` shows it (PATH-resident namesakes read "not recorded"; `doctor` cross-checks by probing the binary; `FOREIGN` = a same-named PATH binary that is a different tool). `bash scripts/build-onepass.sh` works from any cwd (paths resolve via BASH_SOURCE).

Tool sources (verified against these repos/assets):

| Tool | Repo | Asset |
|---|---|---|
| subfinder httpx dnsx naabu cdncheck uncover katana | projectdiscovery/* | `<tool>_<ver>_linux_amd64.zip` |
| chaos | projectdiscovery/chaos-client | `chaos-client_<ver>_linux_amd64.zip` |
| ksubdomain | knownsec/ksubdomain | `ksubdomain_linux.zip` |
| hostCollision | alwaystest18/hostCollision | `hostCollision_<ver>_linux_<arch>.tar.gz` |
| onepass | this repo's `rust/onepass` | `cargo build --release` |
| enscan | community mirror of ENScan_GO | `go build` |

## 2. Where things install: bin/linux (fixed)

`bin/` is split per platform so one codebase carries both Windows and Linux tools:

~~~text
bin/
├── windows/    ← 12 .exe files (preinstalled on Windows; doctor tracks 12)
├── linux/      ← ELF files (installed by setup-linux.sh)
└── config.example.yaml
~~~

**`core.tool()` looks ONLY in `bin/<current-platform>/` — no PATH fallback, no flat `bin/` fallback.**
That is deliberate: an ambient same-named binary may be a different version, a different build, or an
entirely different tool (Kali's `python3-httpx` drops a file named `httpx` into `/usr/bin/`).
Honouring one directory is what makes an agent's results reproducible on any machine.

So the install location is fixed at `<skill>/bin/linux` and `setup-linux.sh` no longer accepts `--prefix`.
A missing tool makes `doctor` report `tool not found in <skill>/bin/<platform>/`;
the only fix is to put the binary into that directory.

~~~bash
bash scripts/setup-linux.sh                        # install to bin/linux
bash scripts/setup-linux.sh --cap                  # also grant raw-socket capability
bash scripts/setup-linux.sh --check                # table: TOOL / STATUS / SOURCE / VERSION
~~~
## 3. Permissions: CAP_NET_RAW

`naabu` (SYN scanning) and `ksubdomain` (raw-packet brute force) need raw sockets; everything else (httpx/katana/dnsx/hostCollision) uses ordinary sockets and **needs no privilege**.

~~~bash
# Plan A (recommended): grant the capability to the binaries so normal users can run them
sudo setcap cap_net_raw+ep /usr/local/bin/naabu /usr/local/bin/ksubdomain
getcap /usr/local/bin/naabu

# Plan B: run as root
# Plan C: container
docker run --cap-add=NET_RAW --network=host ...
~~~

Without the grant: those two commands fail with socket/pcap errors, non-zero exit; **the rest of the pipeline is unaffected** (scripts/agents can skip them via `--no-...`).

## 4. System parameters (tune before going large)

~~~bash
ulimit -n 65535                                    # httpx -threads 50 × multiple processes
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.ipv4.tcp_tw_reuse=1                  # extract/crawl open many short connections
~~~

Memory budget (measured): the Python parent peaks at ≈ **rows × 1.6 KB** (60k rows ≈ 115 MB, 120k ≈ 208 MB);
add the Go children's own peaks (httpx can reach hundreds of MB on tens of thousands of targets). Size the machine at `rows × 2 KB + 1 GB`.

## 4.5 The fixed entry point (try this first)

After installing, pass variables instead of memorising subcommands:

```bash
bash scripts/findinfo.sh -t example.com                     # passive only
bash scripts/findinfo.sh -t example.com -a --vhost --crawl  # active
bash scripts/findinfo.sh -t example.com -m steps            # staged (passive split up)
bash scripts/findinfo.sh -t example.com -b                  # background, poll with --status
bash scripts/findinfo.sh -p ...                             # print the command without running it
```

The script finds the interpreter itself (`python3` first, then `python`); `FINDINFO_PYTHON=/path` overrides.
It still calls `findinfo.py` underneath — the data layer (dedup/confidence/SQLite/vhost collision/rate-limit cache/checkpoints) stays in Python;
bash only orchestrates and passes arguments.

## 5. Three ways to run

### 5.1 Interactive (manual triage)

~~~bash
tmux new -s recon
python3 findinfo.py doctor
python3 findinfo.py run --domain example.com --active --vhost
~~~

### 5.2 systemd (production/scheduled, recommended)

~~~bash
sudo useradd --system --home /var/lib/findinfo --shell /usr/sbin/nologin findinfo
sudo mkdir -p /var/lib/findinfo && sudo chown findinfo:findinfo /var/lib/findinfo
sudo cp deploy/findinfo@.service /etc/systemd/system/
sudo cp deploy/findinfo@.timer   /etc/systemd/system/
sudo tee /etc/findinfo.env >/dev/null <<'EOF'
FOFA_KEY=xxx
QUAKE_TOKEN=yyy
EOF
sudo chmod 600 /etc/findinfo.env
sudo systemctl daemon-reload
sudo systemctl start 'findinfo@example.com.service'     # run once manually
journalctl -u 'findinfo@example.com.service' -f
sudo systemctl enable --now 'findinfo@example.com.timer' # daily 04:17 passive refresh
~~~

The unit files already handle three things: `FINDINFO_HOME` points at `/var/lib/findinfo`, `TimeoutStartSec=3h` (long flows), `AmbientCapabilities=CAP_NET_RAW`.

## 6. Differences from Windows

| Point | Notes |
|---|---|
| Binary names | no `.exe` on Linux; `core.tool()` accepts both, `build-enscan.sh` renames per platform |
| Client install | `install.py` uses symlink on Linux (junction on Windows); no admin needed |
| Popups | Windows uses `CREATE_NO_WINDOW` to hide consoles; the concept does not exist on Linux |
| Npcap | replaced by libpcap (`apt install libpcap0.8`); `ksubdomain` still needs CAP_NET_RAW |
| curl | the curl fallback paths of `certs` / `extract` / `vhost` need the system `curl` |

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unpack failed` | unzip / tar missing | `apt install -y unzip tar` |
| `cannot get latest tag` / HTTP 403 | GitHub API rate limit (60/hour anonymous) | wait an hour, or download the release manually into bin/linux |
| `no cargo` / `no go` | toolchain missing | `apt install -y cargo golang`, or run with `--no-onepass --no-enscan` first |
| `setcap: Operation not permitted` | no privilege | use sudo; in containers add `--cap-add=NET_RAW` |
| `naabu` reports socket errors | no CAP_NET_RAW | see section 3 |
| `Bad substitution` | the script was run with `sh` | use `bash scripts/setup-linux.sh` |
| `python3: not found` | minimal image | `apt install -y python3` |
| `curl: command not found` | curl missing | `apt install -y curl` (`certs`/`extract` will fail) |
| `doctor` shows enscan missing | mirror unreachable / not built | passive and the other active stages are unaffected; build it when entity is needed |

## 8. Offline install

Install into the skill directory on a connected machine, then copy the whole directory to the target:

~~~bash
bash scripts/setup-linux.sh                        # on the connected machine, into <skill>/bin/linux
tar czf findinfo-linux.tar.gz -C <skill> bin/linux
# on the target machine
tar xzf findinfo-linux.tar.gz -C <skill>
chmod +x <skill>/bin/linux/*
bash scripts/setup-linux.sh --check
~~~

## 9. Uninstall

~~~bash
rm -f <skill>/bin/linux/{subfinder,httpx,dnsx,naabu,cdncheck,uncover,katana,chaos,ksubdomain,hostCollision,onepass,enscan}
rm -rf /var/lib/findinfo            # the asset store (~/.findinfo likewise)
# systemd
sudo systemctl disable --now 'findinfo@example.com.timer'
sudo rm -f /etc/systemd/system/findinfo@.{service,timer} /etc/findinfo.env
~~~

## 10. Performance and concurrency

- The orchestration layer is a single Python process — **no need** for asyncio/Gunicorn/Celery; concurrency lives in the Go/Rust children, and WAL + transactions keep the database safe under concurrent access.
- At large scale (>50k results) run stage by stage with `--from-store` resumes instead of one `run` to the end.
