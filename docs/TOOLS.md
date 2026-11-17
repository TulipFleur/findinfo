# findinfo 工具使用说明书

> 面向 AI agent 的命令级参考。每个命令 = 一个 tool：
> **stdout 恰好一行 JSON**（可直接 `json.loads`），**stderr 是进度/告警**（不要解析）。
> 退出码：`0` 成功 / `2` 业务错误 / `3` scope 拒绝 / `4` 工具缺失 / `1` 未知异常。

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
    "subfinder": {"present": true, "path": "...\\bin\\subfinder.exe", "version": "v2.17.0"},
    "httpx":     {"present": true, "version": "v1.12.0"},
    "enscan":    {"present": true, "version": ""}
  },
  "api_keys": {"fofa": false, "quake": false, "hunter": false, "chaos": false},
  "scope": {"engagement": "default", "enabled": false, "domains": [], "cidrs": []},
  "bin_dir": "...", "db": "..."
}
```

**何时调**：每次会话第一条命令。`api_keys` 全 false 说明只能跑无 key 链路。

---

## scope — 授权范围

```bash
python findinfo.py scope                          # 看当前范围
python findinfo.py scope --check api.example.com  # 测某个主机
```

**输出**

```json
{"host": "api.example.com", "allowed": true, "rule": "domain:example.com"}
```

范围文件 `config/scope.json`：

```json
{
  "engagement": "客户A-2026Q1",
  "domains": ["example.com"],
  "cidrs": ["203.0.113.0/24"],
  "deny": ["pay.example.com"]
}
```

- `domains`：后缀匹配（`example.com` 同时覆盖 `*.example.com`）
- `cidrs`：IP 段，主动扫描 IP 时必须命中
- `deny`：显式排除，优先级最高
- **`enabled=false`（文件不存在）时，主动命令仍然允许执行**——生产使用务必先建文件

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
    python findinfo.py brute --domain example.com --wildcard advanced

| 参数 | 默认 | 说明 |
|---|---|---|
| --domain | 必填 | 目标域 |
| --wordlist | wordlists/sub.txt | 字典（内置 200 个常见前缀） |
| --bandwidth | 3m | 发包容忍带宽；越小越低调，建议 2m~5m |
| --wildcard | basic | 泛解析过滤基础模式，严格场景用 advanced |

输出

    {"domain": "example.com", "count": 1,
     "records": [{"domain": "www.example.com", "a": ["172.66.147.243"]}]}

前置条件（重要）

- Windows 需装 Npcap（安装时勾选 WinPcap 兼容模式），Linux 需 libpcap
- 通常需要管理员/root 权限（裸包发送）
- 会触发 IDS/IPS 告警，仅在授权范围内使用
- 内置速率上限 25000 pps，实际按 --bandwidth 控制

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
| `--domain` | scope 域名 + 库内父域 | 裸标签的基域，可重复 |
| `--ports` | 80,443 | 逗号分隔 |
| `--threads` | 20 | 并发 |

**字典语义**：`wordlists/vhost.txt` 里是**裸标签**（`dev`/`uat`/`jenkins`），单独一个标签不是合法 hostname。
`--domain example.com` 会把每条展开成 `dev.example.com`、`uat.example.com`…；不传 `--domain` 时
自动用 scope 域名 + 库内域名的父域。含点的条目（`admin.example.com`）原样使用，不会被二次拼接。

**输出**

```json
{
  "ip": "1.2.3.4", "tested": 63, "hits": 2,
  "results": [{
    "ip": "1.2.3.4", "port": 443, "scheme": "https",
    "host": "jenkins.example.com", "status": 200, "len": 4021,
    "title": "Dashboard [Jenkins]", "server": "Jetty", "via": "socket"
  }]
}
```

**原理**：用候选 Host 请求同一 IP，比对与"随机不存在 Host 基线"的差异（状态码/长度/标题）。
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
```

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

---

## 组合用法（推荐给 agent 的工作流）

```bash
# 1. 自检 + 看范围
python findinfo.py doctor
python findinfo.py scope

# 2. 被动扩张（零风险，先跑满）
python findinfo.py entity --name "企业名"
python findinfo.py passive --from-store           # 15 源并行，最快的一条
python findinfo.py certs --domain 主域
python findinfo.py icp  --from-store
python findinfo.py subs --from-store
python findinfo.py dns  --from-store

# 3. 看一眼资产图，判断是否继续
python findinfo.py assets --kind domain --limit 20

# 4. 主动（确认 scope 后）
python findinfo.py probe --from-store --min-conf 0.7
python findinfo.py ipagg
python findinfo.py vhost --ip <候选IP> --from-store

# 5. 回流
python findinfo.py crawl --from-store
python findinfo.py extract --url <js>
```
