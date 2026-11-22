# 测绘查询语法与凭据变量（依据记录）

本文记录每个测绘引擎**用什么查询语法**、uncover **读哪个环境变量**，以及每条结论的出处。
依据只来自两类离线材料：随包二进制的字符串、上游源码与官方文档。**没有任何一条来自真实请求**，
因此凡标注“待真实验证”的条目，需由操作员用 `doctor --check-mapping` 确认。

## 1. 唯一入口

- 带 key 的请求只发生在 `mapping` 阶段（run 流水线）与 `map` 命令。
- 同一任务内，每个「引擎 + 规范化问题」只问一次，记录在任务库 `mapping_ledger`。
- 其余阶段（`passive` / `subs` / `dns` / `probe` / `ports` / `vhost` / `crawl` / `extract`）**不带任何 key**：
  `core.run` 默认剥离已知密钥变量（见 §4）。

## 2. 环境变量名（按消费者）

旧实现用一张表给所有消费者注入同一个名字，于是多个已配置的 key 到不了真正读取它的工具。

| 引擎 | `.env` 键 | uncover 读取 | onepass 读取 | 依据 |
|---|---|---|---|---|
| FOFA | `FOFA_EMAIL` + `FOFA_KEY` | 同名 | 同名 | 二进制字符串 `FOFA_EMAIL`/`FOFA_KEY`；`rust/onepass/src/sources.rs` `Auth::Fofa` |
| Quake | `QUAKE_TOKEN` | 同名 | 同名 | `Auth::Header("X-QuakeToken", "QUAKE_TOKEN")` |
| Hunter | `HUNTER_KEY` | **`HUNTER_API_KEY`** | `HUNTER_KEY` | uncover 二进制含 `HUNTER_API_KEY` 且**不含** `HUNTER_TOKEN`；`sources.rs` `Auth::Query("api-key", "HUNTER_KEY")` |
| Shodan | `SHODAN_KEY` | `SHODAN_API_KEY` | — | uncover 二进制含 `SHODAN_API_KEY` |
| Censys | `CENSYS_API_TOKEN` + `CENSYS_ORGANIZATION_ID` | 同名 | — | uncover 二进制含两个名字；旧配置项 `apis.censys.key` 从来不存在 |
| ZoomEye | `ZOOMEYE_KEY` | `ZOOMEYE_API_KEY` | — | uncover 二进制含 `ZOOMEYE_API_KEY`；旧实现**完全不注入** |
| VirusTotal | `VIRUSTOTAL_KEY` | — | `VIRUSTOTAL_KEY` | `sources.rs` `Auth::Header("x-apikey", "VIRUSTOTAL_KEY")` |
| SecurityTrails | `SECURITYTRAILS_KEY` | — | `SECURITYTRAILS_KEY` | `sources.rs` `Auth::Header("APIKEY", ...)` |
| urlscan | `URLSCAN_KEY` | — | `URLSCAN_KEY` | `sources.rs` `Auth::Header("api-key", "URLSCAN_KEY")` |
| Chaos | `CHAOS_KEY` | — | `CHAOS_KEY` | `sources.rs` `Auth::Header("Authorization", ...)` |

实现位置：`lib/core.py` 的 `_consumer_env(consumer)`（**调用时求值**，不是导入时冻结）。

## 3. 查询语法

uncover 把 `-q` **原样**交给引擎，不做跨引擎翻译；因此每个引擎必须有独立模板，
没有模板的引擎**不派发**（猜语法只会得到静默的 0 条）。

| 引擎 | domain 问题 | icp 问题 | 依据 |
|---|---|---|---|
| FOFA | `domain="{value}"` | `icp="{value}"` | 二进制字符串 `domain=`、`icp"`；uncover `agents/fofa` |
| Quake | `domain:"{value}"` | `icp:"{value}"` | 二进制 `domain":"`、`icp"`；`agents/quake` |
| Hunter | `domain="{value}"` | `icp.number="{value}"` | 二进制 `domain="`；Hunter 官方语法中备案字段为 `icp.number`（**待真实验证**） |
| Shodan | `hostname:"{value}"` | —（无模板，不派发） | 二进制 `hostname":"`；Shodan 官方 `hostname:` 过滤器 |
| Censys / ZoomEye | —（无模板，不派发） | — | 语法证据不足，宁可不问 |

配置覆盖：`config/config.json` 的 `mapping.queries.<kind>.<engine>`。模板必须含 `{value}`，
否则加载时报错（`lib/core.py::_query_table`）。

**值的安全处理**：`uncover_query` 会剥离值内的 `"` 与 `\`，避免一个值把单个引用词变成另一个查询。

## 3.5 三次采集：域名 / 证书 / 备案号

操作员要求「域名、证书、备案号分三次测绘」。**这里必须说清一件事：测绘平台只能做第一次。**

uncover 的 `sources/result.go` 定义输出只有：

```go
type Result struct {
    Timestamp  Source  IP  Port  Host  Url   // Raw 不输出
}
```

每个引擎的响应结构体也只带这三样：

| 引擎 | 请求字段（硬编码） | 响应结构体 |
|---|---|---|
| quake | `Include: ["ip","port","hostname"]` | `hostname` / `ip` / `port` |
| fofa | `Fields = "ip,port,host"`（`Size = 100` 固定） | `[][]string` 三列 |
| shodan | 无字段参数 | `ip` / `port` / `hostnames` |
| hunter | 无字段参数 | `ip` / `port` / `domain` |
| zoomeye | `pagesize: 100` | `ip` / `port` / `hostname` |

所以**证书和备案号在 uncover 这一层就被截断了**，不是本项目丢的。三次采集的实际分工：

| 次序 | 数据 | 入口 | 来源 |
|---|---|---|---|
| ① 域名 | host / IP | `map --domain X` | uncover（付费） |
| ② 证书 | 签发者 / 序列号 / 有效期 / SAN | `certs --domain X` | crt.sh → CertSpotter（免费） |
| ③ 备案号 | 备案号 → 域名/IP | `map --icp "京ICP备…"` 或 `entity` | uncover / ENScan |

方向差异：测绘平台**不能返回某域名的备案号**，只能**用备案号反查域名**。「这个域名属于哪个备案」要走 `entity`（ENScan 的 `icp` 字段）或工信部查询。

### 每类的落库形态

| kind | canonical | parent | attrs |
|---|---|---|---|
| `domain` | 主机名 | 备案号（若是 ICP 反查所得） | url/status/title |
| `ip` | 地址 | 同上 | — |
| `cert` | `签发者\|序列号`（无序列号时用 CN） | 被查询的域名 | `cn` / `issuer` / `serial` / `not_before` / `not_after` / `entry` / `san` |
| `icp` | 备案号 | — | — |

证书此前**只提取其中的域名，证书本身被丢弃**；现在每张证书是一行 `kind=cert` 资产，`certs` 的返回值也带 `certs` 计数。

## 4. `-limit` 是**花费上限**，不是越大越好

- uncover 的 `-limit` 默认 **100**（`uncover -h` 原文：`limit the number of results to return (default 100)`）。
  旧实现从不设置它，于是每个查询静默截断在 100 条。
- 现在每次派发都显式传 `-limit`（配置 `limits.mapping_rows`，默认 **3000**）。

### 为什么默认只有一页

uncover 对各引擎的行为不同，**翻页的直接账单差异**已在真实账户上量到：

| 引擎 | uncover 的行为 | 一次派发的账单 |
|---|---|---|
| **quake** | `sources/agent/quake/quake.go` 固定 `Size=100`，用 `Start` 偏移**循环翻页**，直到 `numberOfResults > limit` | **每页 100 credit** |
| fofa / shodan / hunter | 单次请求，由引擎自己的单页上限决定行数 | 一次 |

实测（同一 quake 账户，同一问题）：

| `-limit` | 返回行数 | 扣费 |
|---|---|---|
| 1 | 10 | 100 |
| 100 | 0 | 0（该页无数据） |
| **10000** | 50 | **700**（= 7 页 × 100） |

即 `-limit 10000` 让 uncover 连翻 7 页、每页都计费。南开大学任务里看到的「9 次」就是
9 页，不是 9 个不同的问题——**账本只记了 1 个问题**。

**结论：一次拉满，不要小批量试探——但每个引擎的"满"不一样。**

uncover 在**所有**引擎上都是 100 行一页（源码核实），所以 `-limit` 是**页数预算**。
而一页的代价不同：fofa 按查询计费、quake 每页 100 credit 且免费月额度就是 3000。
用同一个数字套所有引擎，不是让一个引擎少拿，就是让另一个引擎烧光。

因此**没有全局默认**，每个引擎有自己的上限（`mapdispatch.ENGINE_LIMITS`）：

| 引擎 | 默认上限 | 页数 | 依据 |
|---|---|---|---|
| quake | 3000 | 30 | 免费月额度 3000 credit ÷ 1 credit/行 |
| fofa | 1000 | 10 | 按查询计费，uncover 固定 100/页 |
| shodan | 1000 | 10 | 付费计划按查询计费 |
| hunter | 1000 | 10 | 付费计划按页计费 |

覆盖顺序（`mapdispatch.mapping_limit(engine)`）：

1. `limits.mapping_rows_<engine>` —— 只影响该引擎
2. `limits.mapping_rows` —— 显式给所有引擎同一个上限
3. 该引擎自己的 `ENGINE_LIMITS`
4. `DEFAULT_LIMIT`（3000），仅当引擎不在表里

```json
{"limits": {"mapping_rows_quake": 5000, "mapping_rows_fofa": 2000}}
```

额度更少时应按余额**下调**，而不是靠反复小批量试探——小 limit 不省钱，只把同一次
花费拆成多次往返并增加拿不全的概率。

- 每次派发都会记录 `pages` 与 `credits`（quake 有免费额度查询接口，派发前后各读一次余额，
  实测值覆盖估算值），`metered.jsonl` 的 `requested` 记的就是页数，不再是恒定的 1。
- 返回行数达到上限时标记 `truncated`，进入 `coverage.unavailable.truncated_sources`（`uncover:<engine>`），
  不把"可能还有更多"读成"就这么多"。

## 5. 跳过策略（缺 key / key 失效）

操作员的规则：**没给 key，或旧 key 已不可用 → 跳过**，不报错、不反复重试。

| 情形 | 行为 |
|---|---|
| 没有 key | 引擎不派发；记入 `skipped_engines`（`no api key`），作为能力缺口 |
| provider 拒绝凭据（401/403） | 记入账本 `ST_AUTH`；本任务后续问题**不再派发**该引擎 |
| 上游报告语法错误 | 记入账本 `ST_FAILED`，不自动重试（`--remap` 才重问） |
| 配额耗尽 | 记入 `ST_QUOTA`，不自动重试 |

## 6. 操作员自助验证

```bash
python findinfo.py doctor --check-mapping --domain <你自己的域名>
```

- **无需确认即可执行**：本 skill 由 Agent 自动驱动，没有人工应答同意提示的环节；单次开销
  由构造保证有界（每引擎恰好一条 `-limit 1` 查询）。旧参数 `--yes-spend-quota` 仍然接受
  （忽略），已有命令行不会被破坏。
- 每个引擎各发一条 `-limit 1` 查询，逐引擎报告：`key_accepted`、`syntax_accepted`、`rows`、`error`。
- 结果**不写入任务测绘账本**：这是自检，不算本任务的测绘次数。

## 7. 待真实验证清单

以下结论来自离线证据（二进制字符串 / 上游源码），未用真实请求确认：

1. Hunter 的 `icp.number` 字段语法是否被当前 API 接受。
2. `CENSYS_ORGANIZATION_ID` 是否必需（只给 token 时 uncover 是否可用）。
3. ZoomEye 的 domain 查询语法（当前无模板，不派发）。
4. 各引擎 `-limit` 上限与计费口径是否与文档一致。

验证方式只有一条：`doctor --check-mapping --domain <域名>`（见 §6，无需同意开关）。
