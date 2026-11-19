# Cross-client install and differences

> One skill directory, three local clients, two loading mechanisms. Getting it wrong produces "it's in the directory but the agent cannot see it".

## 1. Mechanism matrix

This skill is used only inside **local client agents**: the agent process runs on the same machine as the `bin/<platform>/` binaries.
If a session lands in a remote sandbox (cloud Linux, remote container), the binaries in `bin/` do not belong to that system — out of scope.

| Client | Loading mechanism | Install location | What actually makes it work |
|---|---|---|---|
| **DSH / agents** | scans a skills directory | `~/.agents/skills/findinfo` | directory exists + `SKILL.md` has frontmatter |
| **Claude Code** | scans a skills directory | `~/.claude/skills/findinfo` | same (frontmatter `name` must equal the directory name) |
| **Codex CLI** | **reads a config.toml registry** | anywhere (recommend `~/.codex/skills/findinfo`) | `[[skills.config]]` in `~/.codex/config.toml` + `enabled = true` |

**Known pitfall (hit before)**: creating only a link in `~/.codex/skills/` leaves Codex completely blind;
and `[[skills.config]]` must carry BOTH `path` and `enabled` — a `path`-only entry invalidates the whole config (`codex doctor` reports `invalid data`).

## 2. One command does it (recommended)

```bash
python scripts/install.py            # links for all three clients + automatic Codex registration
python scripts/install.py --status   # per-client status + whether Codex is registered
python scripts/install.py --verify   # runs doctor on every client path
python scripts/install.py --uninstall# removes only what it created (incl. Codex de-registration)
python scripts/install.py --copy     # a real copy (= --mode copy) instead of a link
```

**What copy mode includes**: the code, wordlists, config templates, and every binary of the **current platform's** `bin/<platform>/` (self-contained, copyable to another machine); it excludes `.env`, `bin/config.yaml` (secrets never travel), `rust/target` (build artifacts), the **other platform's** bin directories, and `data/cache/runs` runtime state. The old version excluded all platform directories, producing a copy without a single binary — fixed.

For Codex it does three things: creates the link, inserts the registration block into `config.toml` (idempotent), and backs up `config.toml.findinfo.bak` before touching it.
De-registration restores the original file byte for byte (CRLF/LF preserved).

## 3. Per-client notes

### DSH / agents (`~/.agents/skills`)
- The canonical location of this repo; other clients may point at it.
- The skill list is injected by the host; editing `SKILL.md` takes effect after reopening the session.

### Claude Code (`~/.claude/skills`)
- Only the frontmatter `name` / `description` matter; a `name` that disagrees with the directory name fails to load.
- On Windows the Bash tool goes through Git Bash, so commands must be POSIX-compatible (all commands here are).
- The first active stage triggers an approval prompt; confirm the target scope before bulk-allowing.

### Codex (`~/.codex/config.toml`)
- The registration block:

```toml
[[skills.config]]
path = 'E:\AI\skills\findinfo\SKILL.md'
enabled = true
```

- `[skills] include_instructions` is a **global** switch and **must be true**: when false, Codex has the skill
  registered but never injects the instructions into context — observed behaviour: the agent answers "I cannot see this skill". To enable:
  ```bash
python scripts/install.py --enable-instructions   # global, affects all skills
```
  `--status` prints a `warning` when the value is false.
- After editing, run `codex doctor`; only `0 fail` means the config is valid.

### Other clients and prerequisites for local runs

- The command-line calls, bundled binaries and the asset store of this skill all live on the local machine — **use it only inside local client agent sessions**.
- The "session executes in a remote sandbox" mode is not supported: the `bin/` binaries would not match the target system.
- To move to another OS, take that platform's package (Windows package / Linux package, see [docs/LINUX.md](LINUX.md)) instead of making one package run cross-system.

## 4. Shared state

```text
~/.findinfo/            <- all Windows clients share one asset store
├── findinfo.db
├── runs/
└── cache/
```

- These local clients share `~/.findinfo`, so the asset graph is one and the same (idempotent merge).
- WSL has a different HOME (`/root/.findinfo`) and does not share with Windows; to cross systems use `assets --export` and import.

## 5. Quick self-check

```bash
python scripts/install.py --status   # directories/links/Codex registration/include_instructions
python scripts/install.py --verify   # run doctor on each client path (incl. tool count)
codex doctor | grep skills           # confirm Codex parsed the registration
```
