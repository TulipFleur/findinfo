# 跨客户端安装与差异

> 同一份 skill 目录，三个本地客户端两种加载机制。装错了会「目录里有、agent 看不见」。

## 1. 机制矩阵

本 skill 只在**本地客户端 Agent** 里用：Agent 进程与 `bin/<platform>/` 的二进制跑在同一台机器上。
会话若落到远端沙箱（云端 Linux、远程容器），`bin/` 里的二进制就不是那个系统的，不在支持范围内。

| 客户端 | 加载机制 | 安装位置 | 真正生效的开关 |
|---|---|---|---|
| **DSH / agents** | 扫描 skills 目录 | `~/.agents/skills/findinfo` | 目录存在 + `SKILL.md` 有 frontmatter |
| **Claude Code** | 扫描 skills 目录 | `~/.claude/skills/findinfo` | 同上（frontmatter 的 `name` 必须等于目录名） |
| **Codex CLI** | **读 config.toml 注册表** | 任意（建议 `~/.codex/skills/findinfo`） | `~/.codex/config.toml` 的 `[[skills.config]]` + `enabled = true` |

**关键坑（已踩过）**：只往 `~/.codex/skills/` 建链接，Codex 完全看不见；
而且 `[[skills.config]]` 必须同时有 `path` 和 `enabled`——只写 `path` 会让整份 config 失效（`codex doctor` 报 `invalid data`）。

## 2. 一条命令搞定（推荐）

```bash
python scripts/install.py            # 三客户端建链接 + Codex 自动注册
python scripts/install.py --status   # 每个客户端状态 + Codex 是否注册
python scripts/install.py --verify   # 在每个客户端路径上实跑 doctor
python scripts/install.py --uninstall# 只删自己创建的（含 Codex 反注册）
python scripts/install.py --copy     # 真实拷贝（= --mode copy）而不是链接
```

**copy 模式包含什么**：代码、wordlists、config 模板，以及**当前平台**的 `bin/<platform>/` 全部二进制（自包含，可拷去别的机器）；排除 `.env`、`bin/config.yaml`（密钥不外带）、`rust/target`（构建产物）、**其它平台**的 bin 目录和 `data/cache/runs` 运行态。旧版把三个平台目录全排除，拷出来的目录一个二进制都没有——已修复。

对 Codex 做三件事：建链接、往 `config.toml` 插入注册块（幂等）、改前备份 `config.toml.findinfo.bak`。
反注册会逐字节还原原文件（保留 CRLF/LF）。

## 3. 各客户端注意事项

### DSH / agents（`~/.agents/skills`）
- 本仓库的 canonical 位置，其他客户端都可以指向它。
- 技能列表由宿主注入，改 `SKILL.md` 后重开会话生效。

### Claude Code（`~/.claude/skills`）
- 只认 frontmatter 的 `name` / `description`；`name` 与目录名不一致会加载失败。
- Windows 上 Bash 工具走 Git Bash，命令必须 POSIX 兼容（本项目命令都是）。
- 首次跑主动阶段会触发审批；批量放行前先确认目标范围。

### Codex（`~/.codex/config.toml`）
- 注册块：

```toml
[[skills.config]]
path = 'E:\AI\skills\findinfo\SKILL.md'
enabled = true
```

- `[skills] include_instructions` 是**全局**开关，**必须为 true**：为 `false` 时 Codex 虽然注册了
  skill，但不会把说明注入上下文——实测 agent 会回答"看不到这个 skill"。开启：
  ```bash
python scripts/install.py --enable-instructions   # 全局，影响所有 skill
```
  `--status` 在该值为 false 时输出 `warning`。
- 改完跑 `codex doctor`，`0 fail` 才算配置有效。

### 其它客户端与本地运行的前提

- 本 skill 的命令行调用、内置二进制、资产库都在本机，**只在本地客户端 Agent 会话里用**。
- 不针对「会话在远端沙箱里执行」的模式做支持：那时 `bin/` 里的二进制与目标系统不是一套。
- 想换系统就换对应平台的包（Windows 包 / Linux 包见 [docs/LINUX.md](LINUX.md)），而不是让包跨系统跑。

## 4. 状态共享

```text
~/.findinfo/            ← 所有 Windows 客户端共享同一份资产库
├── findinfo.db
├── runs/
└── cache/
```

- 这些本地客户端共用 `~/.findinfo`，资产图是同一份（幂等合并）。
- WSL 是另一个 HOME（`/root/.findinfo`），与 Windows 不共享；跨系统用 `assets --export` 再导入。

## 5. 快速自检

```bash
python scripts/install.py --status   # 目录/链接/Codex 注册/include_instructions
python scripts/install.py --verify   # 每个客户端路径实跑 doctor（含工具数）
codex doctor | grep skills           # Codex 侧确认注册被解析
```
