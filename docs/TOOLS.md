# findinfo 工具使用说明书

> 面向 AI agent 的命令级参考。每个命令 = 一个 tool：
> **stdout 恰好一行 JSON**（可直接 `json.loads`），**stderr 是进度/告警**（不要解析）。
> 退出码：`0` 成功 / `2` 业务错误 / `4` 工具缺失 / `1` 未知异常。
>
> **Agent 调用纪律**：标注（ACTIVE）或耗时 >30s 的命令（run/entity/crawl/probe/ports/vhost/brute/subs）
> **禁止前台执行**——用 `run --background` 后台起 + `wait`/`status` 有界轮询，前台硬等会被工具超时 kill。
> 多目标用 `--task <名>` 隔离资产图；`--from-store` 配 `--scope <主域>` 限定读取范围。

通用约定：

| 项 | 说明 |
|---|---|
| 工作目录 | SKILL.md 所在目录（安装位置随客户端不同，脚本按自身路径定位 `bin/`） |
| 解释器 | 任意 Python 3.10+（如 `D:/yuyan/python/python.exe`） |
| 数据落库 | 自动写入 `~/.findinfo/findinfo.db`，可用 `FINDINFO_HOME` 覆盖；`doctor` 的 `db` 字段为准 |
| 幂等 | 同一资产重复发现只更新 `sources`/`last_seen`，不会重复 |
| 缓存 | API 响应缓存 `~/.findinfo/cache/`；CT 7 天、httpx 24h |

---

## doctor — 环境自检

```bash
python findinfo.py doctor
```

**输出**

```json
{
  "python": "ok",
  "tools": {
    "subfinder": {"present": true, "source": "bundle", "path": ".../bin/subfinder.exe", "version": "v2.17.0"},
    "httpx":     {"present": true, "source": "bundle", "version": "v1.12.0"},
    "enscan":    {"present": true, "source": "bundle", "version": ""}
  },
  "tools_summary": {"total": 14, "in_bin": 14, "outside_bin": [],
                    "missing": [], "suspect": [], "all_in_bin": true},
  "api_keys": {"fofa": false, "quake": false, "hunter": false, "chaos": false},
  "bin_dir": "...", "db": "..."
}
```

**`source` / `tools_summary`**：`bundle` = 解析到 `<skill>/bin`（自包含，推荐）；`path` = 从 `PATH` 借的，
可能根本不是同一个工具（Kali 的 `python3-httpx` 就占着 `/usr/bin/httpx`，此时会给 `suspect` + `hint`）。
`all_in_bin: true` 是“13 个工具全在 skill 目录”的机器可读结论。

**何时调**：每次会话第一条命令。`api_keys` 全 false 说明只能跑无 key 链路。

---

## entity — 企业 → 实体树/备案号/域名

```bash
python findinfo.py entity --name "美团" --invest 51 --deep 2
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--name` | 必填 | 企业/品牌名 |
| `--invest` | 51 | 只保留控股比例 ≥ 该值的子公司 |
| `--deep` | 2 | 股权穿透层数 |
| `--out` | runs/enscan | 产物目录 |

**输出**

```json
{
  "rc": 0, "json_files": 3,
  "companies": ["北京三快在线科技有限公司", "..."],
  "icp": ["京ICP备10210538号", "..."],
  "domains": ["meituan.com", "dianping.com", "..."],
  "apps": ["美团"]
}
```

**前置**：`bin/config.yaml` 必须填 `cookies.aiqicha`。失败时 stderr 会提示未配置 Cookie。
**注意**：`companies` 需人工过一遍再继续（同名公司噪音）。

---

## passive — 15 源被动聚合（阶段一B ⓪ 路，onepass）

```bash
python findinfo.py passive --domain meituan.com
python findinfo.py passive --from-store --min-conf 0.7
python findinfo.py passive --domain meituan.com --sources crtsh,certspotter,rapiddns
bin/onepass.exe sources                 # 看 15 个源的 id / 是否需要 key / 当前是否 ready
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--domain` | — | 可重复；省略时用库内 ≥0.7 域名 |
| `--from-store` | false | 显式从库内取域 |
| `--sources` | 全部可用源 | 逗号分隔 id，见 `onepass sources` |
| `--min-conf` | 0.0 | 过滤低于该值的记录 |

**输出**

```json
{"domains": [{"domain": "example.com", "count": 214,
  "sources_ok": 6, "sources_error": 2, "elapsed_ms": 4210,
  "per_source": [{"id": "crtsh", "status": "ok", "found": 120, "code": null}],
  "domains": [{"domain": "uat.example.com", "sources": ["crtsh", "rapiddns"],
               "confidence": 0.85}]}],
 "total": 214}
```

**数据源（15）**：crtsh / certspotter / hackertarget / rapiddns / anubis / alienvault /
threatminer / subdomain.center 共 8 个免 key；urlscan / virustotal / securitytrails /
chaos / fofa / quake / hunter 需 key（缺 key 自动跳过，不报错，`per_source` 里标 `missing_key`）。

**置信度**：按**独立源数**算（1 源 ≤0.6、2 源 ≥0.7、3 源以上 ≤0.95），随 `sources` 一起落库。
**价值**：一条命令覆盖 8 个免费源，冷启动比串 `certs` + `subs` 快得多；`per_source` 能直接看出哪个源今天挂了。

---

## certs — 证书透明（阶段一B ① 路）

```bash
python findinfo.py certs --domain meituan.com
```

**输出**

```json
{
  "domain": "meituan.com",
  "count": 128,
  "records": 4213,
  "domains": ["api.meituan.com", "dev.meituan.com", "uat.meituan.com", "..."]
}
```

**数据源**：crt.sh（主）→ CertSpotter（备）。失败自动降级。
**价值**：完全被动、零额度、零接触目标，**最该优先跑的一步**。`-dev/-test/-uat` 命名是重点。

---

## subs — 多源被动子域（阶段一B ③ 路）

```bash
python findinfo.py subs --domain meituan.com
python findinfo.py subs --from-store        # 对库内所有 ≥0.7 域名跑
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--domain` | — | 可重复 |
| `--from-store` | false | 用库内域名 |
| `--engines` | fofa,quake,hunter,shodan,censys | uncover 的引擎列表 |

**输出**

```json
{
  "domain": "meituan.com",
  "count": 214,
  "domains": [
    {"domain": "api.meituan.com", "sources": ["crt.sh", "subfinder"], "confidence": 0.75}
  ]
}
```

**降级行为**：没有测绘 key 时 `uncover` 会失败 → 只剩 subfinder（+chaos，若有 key），**不会报错中断**。

---

## brute — DNS 爆破（阶段一B ④ 路，**主动**）

快速补充被动源覆盖不到的子域。基于 ksubdomain 的无状态裸包引擎，比 dnsx 逐条爆破快 1~2 个数量级。

    python findinfo.py brute --domain example.com
    python findinfo.py brute --domain example.com --wordlist wordlists/sub.txt --bandwidth 3m
    python findinfo.py brute --domain example.com --wordlist wordlists/submin.txt --bandwidth 5m
    python findinfo.py brute --domain example.com --wildcard advanced

| 参数 | 默认 | 说明 |
|---|---|---|
| --domain | 必填 | 目标域 |
| --wordlist | wordlists/sub.txt | 字典；可写路径，或裸名字 `sub`/`submin`/`vhost`（自动解析到 wordlists/） |
| --bandwidth | 3m | 发包容忍带宽；越小越低调，建议 2m~5m |
| --wildcard | basic | 泛解析过滤基础模式，严格场景用 advanced |

输出

    {"domain": "example.com", "count": 1,
     "records": [{"domain": "www.example.com", "a": ["172.66.147.243"]}]}

前置条件（重要）

- Windows 需装 Npcap（安装时勾选 WinPcap 兼容模式），Linux 需 libpcap
- 通常需要管理员/root 权限（裸包发送）
- 内置速率上限 25000 pps，实际按 --bandwidth 控制

**内置字典（两级）**

| 文件 | 条数 | 定位 | 典型耗时（单域，3m 带宽） |
|---|---|---|---|
| `wordlists/sub.txt` | 174 | **高价值前缀**：内部系统 / 中间件 / 国内常见（k8s、kibana、nacos、consul、harbor、sso、skywalking…），这些词不在通用 top-10k 里 | 10~30s |
| `wordlists/submin.txt` | 9990 | **top-10k 全量**（mitan 字典归一化：小写、去重、剔除非法标签） | 2~5min |
| `wordlists/vhost.txt` | 145 | 不是子域字典，是 vhost 用的 Host 标签（需配合 `--domain` 拼基域） | — |

建议顺序：先 `brute --wordlist wordlists/sub.txt`（快，捞内部系统），确认 `--bandwidth` 与泛解析表现正常后，
再上 `submin.txt` 跑全量。两级字典有 157 条重叠，重复跑由 `Store` 幂等吸收，不会产生重复资产。

与 subs 的分工：subs 找"已存在且被收录"的子域；brute 找"存在但没人收录"的子域。两者互补，先跑 subs 再跑 brute。

---

## icp — 备案号反查（阶段一B ② 路）

```bash
python findinfo.py icp --code "京ICP备10210538号"
python findinfo.py icp --from-store           # 用 ENScan 存下的备案号
```

**输出**

```json
{"codes": ["京ICP备10210538号"], "rows": 156, "domains": ["..."], "ips": ["..."]}
```

**依赖**：至少一个测绘 key。查询语法：`icp="京ICP备10210538号"`。
**注意**：备案号常带 `-1` `-2` 后缀，主体号一起查更全。
**落库**：备案号本身写成 `assets(kind=icp, canonical="京ICP备…")`（来源 `enscan`/`icp-seed`），
所以 `icp --from-store` 能复用 ENScan 存下的号码；反查出的域名/IP 分别落 `kind=domain`/`kind=ip`，置信度 0.9/0.5。

---

## dns — 解析 + 泛解析过滤（阶段一C）

```bash
python findinfo.py dns --from-store
python findinfo.py dns --domain example.com --min-conf 0.4
```

**输出**

```json
{
  "count": 87,
  "domains": [{"domain": "api.example.com", "a": ["1.2.3.4"], "cname": ["lb.example.net"]}],
  "wildcard": [{"parent": "example.com", "ip": "5.6.7.8"}],
  "system_fallback": 3
}
```

- `wildcard` 非空 = 该域有泛解析，命中的 IP 已被自动剔除（否则资产会膨胀百倍）
- `system_fallback` = 公共 DNS 不可用时用系统 DNS 补解析的条数（国内网络常见）

---

## probe — 存活/指纹/IP 映射（阶段二，**主动**）

```bash
python findinfo.py probe --from-store
python findinfo.py probe --host a.example.com --host b.example.com
```

**输出**

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

**核心价值**：`ip` 字段建立 `域名↔IP` 映射（`ipagg`/`vhost` 的输入）。
同时把 `status/title/tech` 写回 `assets.attrs`，并把首页写成 `endpoints` 记录。

---

## ipagg — IP 聚合与 CDN 剔除

```bash
python findinfo.py ipagg
```

**输出**

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

**判据**：同一 IP 上挂了 **≥2 个自有域名** → 强 vhost 信号。CDN IP 被剔除（对其碰撞只会打到别人的站）。
**输出即 `vhost` 的输入**。

---

## ports — 端口扫描（**主动**）

```bash
python findinfo.py ports --ip 1.2.3.4 --top-ports 1000
```

**输出**

```json
{"targets": ["1.2.3.4"], "count": 4,
 "rows": [{"ip": "1.2.3.4", "port": 80}, {"ip": "1.2.3.4", "port": 443}]}
```

每个开放端口写入 `assets(kind=endpoint, canonical="1.2.3.4:8080")`。

---

## vhost — Host 头碰撞（阶段二核心，**主动**）

```bash
python findinfo.py vhost --ip 1.2.3.4 --from-store
python findinfo.py vhost --ip 1.2.3.4 --wordlist wordlists/vhost.txt --domain example.com        --ports 80,443,8080,8443
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--ip` | 必填 | 目标 IP |
| `--host` / `--from-store` | — | 候选 Host（库内域名） |
| `--wordlist` | — | 字典；裸标签按 `--domain` 展开 |
| `--domain` | 库内父域/基域 | 裸标签的基域，可重复 |
| `--ports` | 80,443 | 逗号分隔 |
| `--threads` | 20 | 并发 |

**字典语义**：`wordlists/vhost.txt` 里是**裸标签**（`dev`/`uat`/`jenkins`），单独一个标签不是合法 hostname。
`--domain example.com` 会把每条展开成 `dev.example.com`、`uat.example.com`…；不传 `--domain` 时
自动用库内域名的父域。含点的条目（`admin.example.com`）原样使用，不会被二次拼接。

**输出**

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

**原理**：调用内置 `hostCollision`（alwaystest18/hostCollision，3 次请求差分）：
无 Host 基线 → 随机标签 Host 基线 → 真实候选；两个隐性基线一致才认为基线稳定，
再比对候选差异。正文 >2000 字符用编辑距离相似度（<85% 判不同），并剔除页面回显 hostname 的噪声。
**候选剔除**：probe 已确认存活（2xx~4xx）的域名自动跳过（结果里 `skipped_live` 计数）。
**HTTPS 会同步修改 SNI**（只改 Host 头不够，TLS 握手就落到默认证书）。
**环境要求**：需要能直连目标 IP；走 HTTP 代理/TUN 的网络下会失败，此时自动降级 curl `--resolve`。
**这是最容易挖到内部系统的位置**：Jenkins/GitLab/Nexus/Swagger/各类后台。

---

## crawl — 爬取（阶段三，**主动**）

```bash
python findinfo.py crawl --from-store --depth 3
python findinfo.py crawl --url https://app.example.com
```

**输出**

```json
{"count": 318, "rows": [{"url": "https://app.example.com/api/v1/user", "host": "app.example.com", "path": "/api/v1/user", "params": ["id"]}]}
```

每个 URL → `endpoints(method, path_template, params)`，路径中的数字/UUID 归一化成 `{n}`/`{uuid}`。

---

## extract — 页面/JS 泄露提取（阶段三）

```bash
python findinfo.py extract --url https://app.example.com/static/app.js
python findinfo.py extract --from-run runs/xxx/crawl.jsonl
python findinfo.py extract --from-store        # 回流：直接用库里的 URL 资产（推荐）
```

**三种来源**：`--url` 指定单个 JS/页面；`--from-run` 读 crawl 的 JSONL 产物；
`--from-store` 直接用库里 `kind=url` 的资产（回流循环里用它，不必关心 runs 目录路径）。
每次最多抓 40 个 JS/JSON/map 文件，扫描文本有 4 MB 预算（防内存爆）。

**引擎**：纯 Python 正则（`lib/jsleak.py`）提取 API 路径、域名、IP、密钥和 sourcemap，零依赖、任何平台可跑。

**输出**

```json
{
  "count_domains": 5, "count_ips": 1, "fetched": 12,
  "api_paths": ["/api/v2/internal/order", "/api/v1/upload"],
  "secrets": {"aws_ak": ["AKIA..."], "jwt": ["eyJ..."]},
  "domains": ["internal.example.com", "api.example.com"],
  "ips": ["10.1.2.3"]
}
```

提取内容：域名、IPv4、API 路径、sourcemap 引用、常见密钥模式（AWS/Aliyun/Tencent/GitHub/JWT/私钥/内网 IP）。
**输出必须回流**：新域名 → 重跑 `certs`/`subs`/`dns`；新 IP → 重跑 `ipagg`/`vhost`。

---

## assets — 查询/导出资产图

```bash
python findinfo.py assets --kind domain --limit 50
python findinfo.py assets --kind icp                  # 看 ENScan 存下的备案号
python findinfo.py assets --min-conf 0.7 --export runs/assets.jsonl
```

**输出**

```json
{
  "counts": {"domain": 128, "ip": 64, "url": 318, "icp": 3},
  "total": 50, "endpoints": 318,
  "rows": [{"kind": "domain", "canonical": "api.example.com", "sources": "crt.sh,dnsx,httpx", "confidence": 0.95, "attrs": {...}}]
}
```

`--export` 写 JSONL，适合直接喂给漏洞扫描器。

---

## status — 长任务进度（轮询用）

```bash
python findinfo.py status                       # 最近一次 run
python findinfo.py status --run runs/20261117-131500-example.com
```

**输出**

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

| 字段 | 含义 |
|---|---|
| `state` | 整个 run 的状态：`running` / `done` / `failed` |
| `stage` + `stage_state` | 当前阶段；阶段态可为 `running`/`done`/`skipped`/`failed` |
| `alive` | `state=running` 且心跳 < 300s → 进程还活着；长任务卡死时它会变 false |
| `heartbeat_age_sec` | 距上次心跳秒数（每完成一个阶段/开始一个阶段都会刷新）|
| `counts` / `endpoints` | 库内资产数，可直接判断有没有新增 |
| `summary` | 完成后与 run 的 stdout 相同 |

**给 agent 的用法**：`run --background` 拿 run_id，然后 `wait --run <id> --timeout 30` 循环（超时只是本次窗口结束），
直到 `state=completed`（终态只有 `completed`/`failed`/`cancelled`，**没有 `done`**）再取 `summary`；`state=failed` 时看 `last_error`。

---
## wait — 有界等待（长任务的标准等待方式）

```bash
python findinfo.py wait --run <run_id> --timeout 30
python findinfo.py wait --run <run_id> --timeout 30 --since 12   # 只看 seq 变化
```

| 参数 | 说明 |
|---|---|
| `--run` | 必填，后台启动返回的 run_id（也接受 run 目录或前缀） |
| `--timeout` | 单次等待上限秒数，默认 30；到点返回，不代表失败 |
| `--since` | 与某个 `seq` 比较；不给则以"进入 wait 时的状态"为基线 |
| `--full` | 返回完整载荷（含 coverage/run_dir）；默认精简，减少轮询时的 token 与延迟 |

**返回**（一行 JSON，默认精简版 ~340 字节）

```json
{"run_id":"20261118-010612-example.com","state":"running","changed":true,"timed_out":false,
 "terminal":false,"alive":true,"interrupted":false,"stalled":false,"seq":7,"waited_sec":0.2,
 "stage":"probe","stage_state":"running","stage_index":4,"stage_total":9,"percent":44.4,
 "counts":{"domain":128,"ip":64},"endpoints":37}
```

`--full` 额外给出 `progress.elapsed_sec`、`coverage`、`run_dir`、`note`。

- `timed_out: true` → **只是本次等待窗口结束**，继续等同一个 run_id。
- `changed: true` / `terminal: true` → 提前返回（有进展或已结束）。
- `percent` 为 `null` = 该阶段总量未知（如爆破/爬取），不要换算成百分比。
- 退出码恒为 `0`（等待超时不是错误）；run_id 不存在时 `2`。
- 实现：50ms 轮询 `seq`，**有变化立即返回**，不做固定 sleep，所以频繁短 wait 不会拖慢流程。

---

## cancel — 取消在跑的任务

```bash
python findinfo.py cancel --run <run_id>
python findinfo.py cancel --run <run_id> --reason "user asked"
```

写 `cancel` 标记后杀进程树（Windows `taskkill /T`、POSIX 进程组），状态置 `cancelled`，
已采到的资产留在库里。

---

## runs — 列出最近的运行（会话恢复入口）

```bash
python findinfo.py runs --limit 10          # 全部最近运行
python findinfo.py runs --active            # 只看在跑的（启动前先查，避免重复采集）
python findinfo.py runs --state failed      # 只看失败的
```

返回 `{"runs":[{"run_id","state","stage","alive","target","created","updated","exit_code","run_dir"}],"active":[...]}`。
**新会话恢复靠它**：找到 run_id 后 `status --run <id>` 取回目标/范围/参数/阶段/产物/下一步。

---

## run — 全流程

```bash
python findinfo.py run --name "企业名"                          # 纯被动
python findinfo.py run --name "企业名" --active                  # + 存活探测
python findinfo.py run --name "企业名" --active --vhost --crawl  # + 内部服务 + 泄露回流
python findinfo.py run --domain example.com --active --ports
```

| 参数 | 说明 |
|---|---|
| `--name` | 企业名（走 ENScan） |
| `--domain` | 直接给种子域（可重复，跳过 ENScan） |
| `--active` | 启用产生流量的阶段 |
| `--ports` / `--vhost` / `--crawl` / `--brute` | 追加阶段（隐含 `--active`；`--brute` 需 Npcap） |
| `--max-seed` | 最多对几个种子域做证书/子域扩线（默认 5） |
| `--top-ports` | 端口扫描范围（默认 1000） |
| `--max-vhost-ips` | 最多碰撞几个候选 IP（默认 10） |

**输出（汇总）**

```json
{
  "engagement": "demo", "active": false,
  "run_dir": "...\\runs\\20261117-131500-美团",
  "seed_domains": ["meituan.com"],
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


**后台模式（长任务的推荐用法）**

```bash
python findinfo.py --task example-com run --domain example.com --active --vhost --crawl \
    --background --rounds 3
```

```json
{"run_id":"20261118-003129-example.com","state":"running","started":true,
 "pid":36532,"reused":false,"dedupe_key":"d7c9acb9fa9f5a62",
 "planned_stages":["certs","subs","icp","dns","probe","ipagg","vhost","crawl","extract"],
 "run_dir":".../runs/20261118-003129-example.com",
 "state_path":".../status.json","result_path":".../summary.jsonl",
 "log_path":".../stdout.log","error_log_path":".../stderr.log",
 "next":"python findinfo.py wait --run 20261118-003129-example.com --timeout 30"}
```

- 独立 Python 工作进程（POSIX `setsid` / Windows `DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP`），
  **不依赖发起它的那次终端调用**；每次运行的 `status.json`/`summary.jsonl`/`stdout.log`/`stderr.log` 独立。
- 同一目标（同 task + 同参数）已在跑时返回 `reused: true` + 原 `run_id`，不会重复采集。
- `--resume <run_id>` 续跑已有运行（复用断点）；工作进程已死（`interrupted`）时用它。
- 边界：进程存活 ≠ 会话存活。已结束的 Agent 会话不会被自动唤醒，需重新进入会话用 `runs`/`status` 接续；
  机器重启后能否自动续跑取决于宿主是否注册为系统服务，本 skill 不作保证。

**结果与覆盖（`result` / `coverage`）**

```json
"result": {"status":"complete|partial|failed","reason":"all_stages_done|stage_failed|
            "time_budget_exhausted|round_budget_exhausted|required_capability_missing",
           "run_id":"...","scope":["example.com"],"counts":{...},"endpoints":37,
           "elapsed_sec":812.0,"artifacts":{...}}
"coverage": {"planned_stages":[...],"done_stages":[...],"skipped_stages":[...],
             "failed_stages":[{"stage":"certs","error":"..."}],"not_run_stages":[...],
             "unavailable":{"missing_tools":[],"engines_without_key":["quake"],"blocking":false},
             "rounds":[{"round":1,"new_domains":3,"stop":"continue"}],
             "stop_reason":"no_new_assets|max_rounds|time_budget",
             "budget":{"rounds":3,"rounds_used":3,"elapsed_sec":812.0},"complete":true}
```


**来源层的失败与缺口（不是"没资产"）**

| 情况 | 返回/字段 | 说明 |
|---|---|---|
| 暂时失败（超时/限流/5xx） | 自动重试 `limits.source_retries` 次（默认 2，退避 1.5s→3s）；仍失败则阶段 `ok: false` | 该阶段记 failed、不写 done checkpoint；其它来源成果保留 |
| 缺 Key | `coverage.unavailable.engines_without_key`、`doctor.api_keys` | 标 `unavailable`，不伪装成"未发现资产" |
| 额度耗尽 | `doctor.fofa_gateway.remaining` 归零 | 标 `quota_exhausted`，写进交付缺口 |
| 泛解析污染 | `dns` 的 `wildcard: [{parent, ip}]` | 命中的名字已过滤、不入库；把该列表写进"数据质量" |
| 空结果 | 阶段 `found: 0` 且 `ok: true` | 有效结果，不是失败 |
| 展示截断 | `truncated: true` | 仅展示；下游阶段与 report 均取库里全量 |

重试预算可调：`config/config.json` → `limits.source_retries`（默认 2，即最多 3 次尝试）。

**退出码**：`0` 覆盖充分完成 ｜ `5` 跑完但覆盖不完整（有阶段失败/预算耗尽/必需能力缺失） ｜
`1` 全部阶段失败 ｜ `4` 工具缺失 ｜ `2` 参数/业务错误 ｜ `130` 被取消。

**回流轮次**：`--rounds N` 让 `dns→验证→提取` 循环到"没有新的范围内资产"或跑满 N 轮；
`--time-budget` 秒到达后不再开新一轮；停止原因写进 `coverage.stop_reason`。

**长任务**：`run` 典型耗时 5~40 分钟。前台运行会阻塞；标准做法是 `--background` + `wait`。
**断点**：每阶段完成后写 `steps` 表（engagement+stage+输入哈希），相同输入再跑会自动跳过（下游输入从限定范围的库查询重建），`--force-stage` 强制重跑。
**追加阶段**：先跑被动，再 `--active` / `--crawl` 只补对应主动阶段（已完成的按 checkpoint 跳过）。
**失败语义**：工具失败（rc≠0/超时）的阶段记 `steps.status=failed`、summary 带 `failed:true`，**重跑自动重试**；部分产出已入库、下游照常用。退出码 5 表示存在失败阶段。
**范围**：`run` 的主动阶段只触达 `--domain`/企业锚点种子；ICP 反查、JS 泄露等发现的范围外域名只入库报告，不自动进入主动阶段。
**明细上限**：所有阶段默认只回 500 条明细并置 `truncated: true`——这是**展示**上限；全量数据在库里，下游阶段（probe/crawl/extract）也从库取全量，与该上限无关（`assets --export` 导出）；
上限可用 `FINDINFO_ROW_LIMIT` 或 `config/config.json` 的 `limits.row_limit` 调整。人为预算（`--max-seed` 只扫前 N 个种子等）造成的覆盖缺口会记入 summary 的 `coverage_limits`。

---


---

## clean — 清理共享资产图

资产图在**不带 `--task` 时全局共享**，跑过多个目标后 `--from-store`
会把别的目标的资产一起读回来。清理/隔离命令：

```bash
python findinfo.py clean --keep hniu.cn --keep hniu.com --vacuum   # 只留本目标
python findinfo.py clean --match meituan.com                       # 只删某目标
python findinfo.py clean --all --vacuum                            # 全清
```

| 参数 | 说明 |
|---|---|
| `--keep X` | 保留 X 及其子域，其余全删（可重复） |
| `--match X` | 反向：只删 X 及其子域 |
| `--kind` | 限定资产类型（默认全部）。**端点表按主机名键控**：只有 kinds 含 `domain`/`endpoint`（或不传）时才连带删除对应主机名端点；`--kind ip` 只删 IP 资产行，别的资产的端点不动 |
| `--all` | 删除所有资产与端点 |
| `--vacuum` | 回收磁盘（163MB → 5MB 实测） |

**防止污染**：`passive/subs/dns/probe/vhost/extract --from-store` 都支持 `--scope X`
（vhost 用 `--domain`），只读该域下的资产。**开新任务时务必带上**，否则会继承上一个目标的资产。

## report — 最终交付（给 AI 的 json / 给人的 html）

把资产图整理成两套最终产物。**不改库、不发包**，纯读 SQLite。

**范围判定按资产类型**：域名按后缀；URL 先解析出主机名再判；IP 按其归属域名（assets.parent）判——共享 IP 只表示"该范围内有域名解析到它"，不是独占归属。**显式传入非法 `--match`（没有一个是合法域名）会直接报错退出**，不会静默退化成整库报告。未传 `--match` 时回落到最近一次 run 的目标并给出告警。

```bash
python findinfo.py report                                  # 范围 = 最近一次 run 的目标域
python findinfo.py report --match hniu.cn --match hniu.com --slug hniu
python findinfo.py report --print-md                       # 额外回显 markdown 正文
python findinfo.py report --json-limit 40                  # 截断 json 里的大数组（省 token）
python findinfo.py report --out ./out --limit 80 --ep-limit 200
```

**产物**（默认 `~/.findinfo/reports/<时间戳>-<slug>/`，并维护 `reports/latest` 指向最近一次；
Windows 无软链权限时退化为 `reports/latest.txt`）

| 文件 | 读者 | 说明 |
|---|---|---|
| `report.json` | agent / 脚本 | 完整结论 + 来源标注 + `charts`；单行紧凑 JSON |
| `report.md` | 人 / 对话 | 分级清单（高价值主机、内部服务、端点、泄露、下一步） |
| `report.html` | 人 | 自包含深色看板，无外部 JS/CSS/字体，带打印样式 |

| 参数 | 说明 |
|---|---|
| `--match X` | 目标域后缀，可重复；不给则回退最近一次 `run` 的 target |
| `--min-conf` | 入库主机的置信度门槛（默认 0.4） |
| `--limit` / `--ep-limit` | 主机 / 端点明细上限（默认 300 / 400） |
| `--json-limit` | cap `report.json` 里的数组（0 = 不额外截断） |
| `--out` / `--slug` | 输出目录 / 目录名标签 |
| `--engagement` | 读哪个 run 的阶段检查点（`stages` 字段） |
| `--print-md` / `--print-json` | 顺便把 md 正文 / 完整 digest 回显到 stdout |

**输出（stdout 一行 JSON）**

```json
{
  "counts": {"domains_in_scope": 48, "live": 27, "interesting": 12, "internal_services": 4,
             "endpoints_in_scope": 6379, "endpoints_interesting": 153, "leak_domains": 8},
  "scope": {"match": ["hniu.cn"], "auto": false},
  "paths": {"json": ".../report.json", "md": ".../report.md", "html": ".../report.html"},
  "warnings": ["检测到 4 个域名解析到 198.18.0.0/15（Clash/TUN fake-IP）…"],
  "next_steps": ["关闭 TUN 后重跑 dns/probe…"]
}
```

**report.json 结构**：`schema` / `scope` / `counts` / `hosts[]`（`host`,`ip`,`status`,`title`,`tech`,
`priority`,`score`,`reasons[]`,`provenance[]`,`discovered_by`,`sensitive[]`,`params[]`）/ `endpoints[]` /
`signals`（泄露密钥等）/ `ip_groups` / `provenance`（工具→资产数）/ `stages` / `next_steps` / `charts` / `truncated`。

**来源标注**：同一资产的 `discovered_by` 保留原始 sources 串（如 `onepass:rapiddns,subfinder`），
`provenance` 归一化成工具列表并配中文标签；onepass 的多个上游源只算一个工具。

---

## 组合用法（推荐给 agent 的工作流）

```bash
# 1. 自检
python findinfo.py doctor

# 2. 被动扩张（零风险，先跑满）
python findinfo.py entity --name "企业名"
python findinfo.py passive --from-store           # 15 源并行，最快的一条
python findinfo.py certs --domain 主域
python findinfo.py icp  --from-store
python findinfo.py subs --from-store
python findinfo.py dns  --from-store

# 3. 看一眼资产图，判断是否继续
python findinfo.py assets --kind domain --limit 20

# 4. 主动
python findinfo.py probe --from-store --min-conf 0.7
python findinfo.py ipagg
python findinfo.py vhost --ip <候选IP> --from-store

# 5. 回流
python findinfo.py crawl --from-store
python findinfo.py extract --url <js>

# 6. 交付（json 给 agent 读，html 给人看）
python findinfo.py report --match 主域
```
