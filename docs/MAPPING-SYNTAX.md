# 测绘平台查询语法总表

本表用于配置 `mapping.queries.<kind>.<engine>`。**每个平台一套语法，uncover 不做翻译**：
`-q` 原样交给引擎，语法错了只会得到静默的 0 条。

出处：随包 `bin/<platform>/uncover.exe` 的 agent 源码（`uncover/sources/agent/*`）。
本文件只记录**语法**，不保证账号权限——权限见 `docs/API-KEYS.md`。

## 1. 本 skill 实际接入的引擎

`UNCOVER_ENGINE_KEYS` 决定哪些引擎会被派发：

| 引擎 | 有 query 模板 | 凭据来源 | 备注 |
|---|---|---|---|
| fofa | ✅ domain / icp | `FOFA_EMAIL` + `FOFA_KEY`，或网关 `base`+`key` | 网关走独立协议 |
| quake | ✅ domain / icp | `QUAKE_TOKEN` | 100 行/页，100 credit/页 |
| hunter | ✅ domain / icp | `HUNTER_API_KEY` | 免费账号无 openApi |
| shodan | ✅ domain | `SHODAN_API_KEY` | 无 ICP 字段 |
| zoomeye | ✅ domain | `ZOOMEYE_API_KEY` | 无 ICP 模板 |
| censys | ❌ 未配 | `CENSYS_API_TOKEN` + `CENSYS_ORGANIZATION_ID` | v2 语法差异大 |
| daydaymap | ✅ domain / icp | **`provider-config.yaml` 的 `daydaymap`**（非环境变量） | 单页可达 10000 |
| securitytrails / virustotal / chaos | ❌ | 仅 onepass 使用 | — |

## 2. 字段语法总表

### 通用维度

| 字段 | FOFA | Hunter | Quake | ZoomEye | DayDayMap | Shodan | Censys | Zero |
|---|---|---|---|---|---|---|---|---|
| IP | `ip="1.2.3.4"` | `ip="1.2.3.4"` | `ip:"1.2.3.4"` | `ip="1.2.3.4"` | `ip="1.2.3.4"` | `ip:1.2.3.4` | `host.ip: 1.2.3.4` | `ip="1.2.3.4"` |
| C 段 | `ip="1.2.3.0/24"` | `ip="1.2.3.0/24"` | `ip:"1.2.3.0/24"` | `cidr="1.2.3.0/24"` | `ip="1.2.3.0/24"` | `net:1.2.3.0/24` | `ip: 1.2.3.0/24` | `ip="1.2.3.0/24"` |
| 主机 | `host="example.com"` | `domain="example.com"` | `host:"example.com"` | `hostname="example.com"` | `domain="example.com"` | `hostname:example.com` | `dns.names: example.com` | `url=="example.com"` |
| 域名 | `domain="example.com"` | `domain="example.com"` | `domain:"example.com"` | `domain="example.com"` | `domain="example.com"` | `domain:example.com` | `dns.names: example.com` | `url=="example.com"` |
| 端口 | `port="80"` | `ip.ports="80"` | `port:"80"` | `port="80"` | `port="80"` | `port:80` | `services.port: 80` | `port="80"` |
| 标题 | `title="标题"` | `web.title="标题"` | `title:"标题"` | `title="标题"` | `web.title="标题"` | `http.title:"标题"` | `services.http.response.html_title: "标题"` | `title=="标题"` |
| 正文 | `body="内容"` | `web.body="内容"` | `body:"内容"` | `http.body="内容"` | `web.body="内容"` | `http.html:"内容"` | `services.http.response.body: "内容"` | `html_banner=="内容"` |
| 操作系统 | `os="Windows"` | `ip.os="Windows"` | `os:"Windows"` | `os="Windows"` | `ip.os="Windows"` | `os:Windows` | `os.product: Windows` | `os=="Windows"` |
| 应用 | `app="Nginx"` | `app.name="Nginx"` | `app:"Nginx"` | `app="Nginx"` | `app.name="Nginx"` | `product:Nginx` | `services.product: Nginx` | `component=="Nginx"` |
| 协议 | `protocol="http"` | `protocol="http"` | `protocol:"http"` | `service="http"` | `protocol.service="http"` | `_shodan.module:http` | `services.service_name: HTTP` | `service=="http"` |
| 备案号 | `icp="备案号"` | `icp.number="备案号"` | `icp:"备案号"` | 不支持 | `icp.number="备案号"` | 不支持 | 不支持 | `icp=="备案号"` |
| 国家 | `country="CN"` | `ip.country="CN"` | `country:"CN"` | `country="CN"` | `ip.country="CN"` | `country:CN` | `location.country_code: CN` | `country=="CN"` |
| 省份 | `region="北京"` | `ip.province="北京"` | `province:"北京"` | `subdivisions="beijing"` | `ip.province="北京"` | `region:北京` | `location.province: 北京` | `province=="北京"` |
| 城市 | `city="北京"` | `ip.city="北京"` | `city:"北京"` | `city="北京"` | `ip.city="北京"` | `city:北京` | `location.city: 北京` | `city=="北京"` |
| 图标哈希 | `icon_hash="mmh3"` | `web.icon="MD5"` | `favicon:"MD5"` | `iconhash="MD5"` | `web.icon="MD5"` | `http.favicon.hash:mmh3` | v3: `web.endpoints.http.favicons.hash_md5="MD5"`<br>v2: `services.http.response.favicons.md5_hash: "MD5"` | `icon="MD5"` |
| Server | `server="Nginx"` | `header.server="Nginx"` | `server:"Nginx"` | `http.header.server="Nginx"` | `web.server="Nginx"` | `http.server:Nginx` | `services.http.response.headers.server: Nginx` | `res_header=="Nginx"` |
| 状态码 | `status_code="200"` | `header.status_code="200"` | `status_code:"200"` | `http.header.status_code="200"` | `web.status_code="200"` | `http.status:200` | `services.http.response.status_code: 200` | `status_code="200"` |

**注意三处易错点**：

1. **Shodan 用冒号不带引号**：`hostname:example.com`、`port:80`、`http.title:"标题"`（含空格/中文才加引号）。
2. **Censys v3 与 v2 字段名不同**：v3 的 favicon 是 `web.endpoints.http.favicons.hash_md5`，v2 是 `services.http.response.favicons.md5_hash`。本 skill 只发 v3 语法（见 §4 的待验证项）。
3. **备案件只有 fofa/quake/hunter/daydaymap/zero 有字段**：shodan/censys/zoomeye 无 ICP 维度，`map --icp` 不会问它们（进 `unsupported_engines`）。

### 逻辑组合

| 平台 | 与 | 或 | 非 | 括号 |
|---|---|---|---|---|
| FOFA | `&&` 或空格 | `\|\|` | `!=` | 支持 |
| Hunter | `&&` | `\|\|` | `!=` | 支持 |
| Quake | `AND` 或空格 | `OR` | `NOT` | 支持 |
| ZoomEye | 空格 | `\|\|` | `!=` | 支持 |
| Shodan | 空格 | `OR` | `-` 前缀 | 支持 |
| Censys | `and` | `or` | `not` | 支持 |

例（找某个域名下非 443 且标题含"后台"的主机）：

```
FOFA    : domain="example.com" && port!="443" && title="后台"
Quake   : domain:"example.com" AND NOT port:"443" AND title:"后台"
Shodan  : hostname:example.com -port:443 http.title:"后台"
```

## 3. 本 skill 的现有模板

`lib/core.py::_DEFAULT_DOMAIN_QUERY` / `_DEFAULT_ICP_QUERY`：

| kind | fofa | quake | hunter | shodan | zoomeye | daydaymap |
|---|---|---|---|---|---|---|
| domain | `domain="{value}"` | `domain:"{value}"` | `domain="{value}"` | `hostname:"{value}"` | `domain="{value}"` | `domain="{value}"` |
| icp | `icp="{value}"` | `icp:"{value}"` | `icp.number="{value}"` | —（无模板） | —（无模板） | `icp.number="{value}"` |

覆盖方式（`config/config.json`）：

```json
{
  "mapping": {
    "queries": {
      "domain": {
        "zoomeye": "hostname=\"{value}\"",
        "daydaymap": "domain=\"{value}\""
      },
      "icp": {
        "daydaymap": "icp.number=\"{value}\""
      }
    }
  }
}
```

模板必须含 `{value}`，否则加载即报错（`core._query_table`）。

## 4. 待真实验证

以下结论来自离线源码/文档，未做真实调用：

1. **Hunter `icp.number`** 是否被当前 openApi 接受（`icp.number="备案号"`）。
2. **Censys 只给 token 不给 org id** 时是否可用（本 skill 发 v3 语法）。
3. **ZoomEye `domain="…"`** 是否等价于其 `site:` 语义——表中为通用写法，未配模板故未派发。
4. **DayDayMap `MaxSize=10000`** 是否真能一次返回 1 万条（源码如此，未实测）。
5. 各平台 `-limit` 与计费的对应关系（quake 已实测：100 credit/页）。

验证方式（会消耗额度，逐引擎 `-limit 1`）：

```bash
python findinfo.py doctor --check-mapping --domain <你的域名>
```

## 5. DayDayMap 的特殊之处

- **唯一单页可达 10000 行的引擎**（`MaxSize = 10000`），且 `pageSize = query.Limit`（limit 直接当页大小，不像其他引擎固定 100）。
- **凭据不在环境变量里**：uncover 从 `provider-config.yaml` 的 `daydaymap` 字段读（`sources/provider.go:129`），
  所以 `core.tool_env()` 注入环境变量对它无效。要接它必须写 provider-config 并让 uncover 用 `-pc` 指定。
- 当前**未接入**：无 query 模板，`map` 不会派发它。

## 6. 与 onepass 的分工

| | uncover（本表） | onepass |
|---|---|---|
| 用途 | 按查询语法做测绘 | 按域名聚合免费被动源 |
| 输入 | 完整查询语句 | 纯域名 |
| 输出 | `timestamp/source/ip/port/host/url` | 域名 + 来源 + 置信度 |
| 计费 | 按页/按查询 | 免费源不计费 |
| 引擎 | 上表 8 个 | 15 个（8 个免 key） |

两者**不要混用**：uncover 拿不到证书和备案号（`sources/result.go` 只有 5 个字段），证书走 `certs`，备案走 `map --icp`。
