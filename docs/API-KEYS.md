# API Key 配置存档

> 所有需要凭据的数据源集中登记在这里。**没有 key 也能跑核心链路**（见文末"零配置可用"）。
> 配置文件：`config/.env`（照 `config/.env.example` 复制填写），兼容 redtools/exploit_server 的变量命名。

## 一、总表

| 变量 | 数据源 | 用在哪一步 | 免费额度 | 申请地址 | 不配的后果 |
|---|---|---|---|---|---|
| `FOFA_EMAIL` + `FOFA_KEY` | FOFA | 备案号反查、被动子域、org 反查 | 200~300 条/月 | https://fofa.info/userInfo | 备案号反查失效，子域少一路 |
| `QUAKE_TOKEN` | 360 Quake | 同上 | 3000 条/月 | https://quake.360.net/quake/#/personalInfo | 同上一路失效 |
| `HUNTER_KEY` | 奇安信鹰图 | 同上 | 100 积分/月 | https://hunter.qianxin.com/home/userInfo | 同上 |
| `ZOOMEYE_KEY` | ZoomEye | 同上 | 2000 条/月 | https://www.zoomeye.org/profile | 同上 |
| `CENSYS_ID` + `CENSYS_SECRET` | Censys | 证书/服务测绘 | 250 次/月 | https://search.censys.io/account/api | 少一路证书交叉验证 |
| `SHODAN_KEY` | Shodan | org 反查 | 极低 | https://account.shodan.io/ | 少一路 |
| `SECURITYTRAILS_KEY` | SecurityTrails | 被动子域 + 历史 DNS | 50 次/月 | https://securitytrails.com/app/account/credentials | 少一路，历史 DNS 不可用 |
| `VIRUSTOTAL_KEY` | VirusTotal | 被动子域 | 4 次/分 | https://www.virustotal.com/gui/my-apikey | 少一路 |
| `URLSCAN_KEY` | urlscan.io | 被动子域 + 已抓页面 | 100 次/天 | https://urlscan.io/user/profile/ | 少一路 |
| `CHAOS_KEY` | PD Chaos | 企业子域数据集 | 免费 | https://cloud.projectdiscovery.io/ | chaos 那一路跳过 |
| `GITHUB_TOKEN` | GitHub | 阶段三 代码泄露 | 免费 | https://github.com/settings/tokens | 代码泄露环节跳过 |
| `MAPPING_API_INTERVAL_MS` | — | 测绘 API 节流 | — | — | 默认 1500ms，被限流时调大 |
| **ENScan Cookie**（非 API） | 爱企查 | 阶段一 实体锚定 | 免费 | aiqicha.baidu.com 登录后 F12 复制 | **阶段一完全不可用** |

## 二、特殊：ENScan 的 Cookie

ENScan 不走 API Key，走浏览器 Cookie。文件位置固定为 **`bin/config.yaml`**（程序读 exe 同目录）：

```yaml
cookies:
  aiqicha: "BAIDUID=...; ..."   # ★ 必填，登录 aiqicha.baidu.com 后从 F12 -> Network -> 任一请求的 Cookie 复制整行
```

注意：
- Cookie 有有效期（通常几天到几周），失效后 ENScan 会报无数据，需要重新复制
- **并发必须为 1**，否则账号会被风控（本 skill 已强制串行）
- 备选：天眼查 Cookie（`tianyancha`），或填 `app.miit_api` 用 ICP_Query 反查备案

## 三、配置优先级

```
真实环境变量  >  config/.env  >  config/config.json  >  默认值
```

三种用法：

```bash
# A. 文件（推荐，持久）
cp config/.env.example config/.env && vim config/.env

# B. 临时（单次命令）
FOFA_KEY=xxx QUAKE_TOKEN=yyy python findinfo.py subs --domain example.com

# C. JSON（程序化调用）
vim config/config.json
```

## 四、零配置可用（不需要任何 key）

| 能力 | 工具 | 说明 |
|---|---|---|
| 15 源并行被动聚合 | onepass（bin/onepass.exe） | 8 个源免 key，一条命令覆盖 CT + 多个公开被动 DNS |
| 证书透明子域 | crt.sh / CertSpotter | **最有效的被动源，完全免费** |
| DNS 解析 + 泛解析过滤 | dnsx + 系统 DNS 兜底 | 不依赖公共 DNS 可用性 |
| 存活/指纹/IP 映射 | httpx | 核心资产富化 |
| CDN 判别 | cdncheck | 内置数据 |
| 端口扫描 | naabu | 无需 key |
| Host 碰撞 | 内置 socket + SNI | 真正出内部服务的一步 |
| 爬虫 / JS 泄露 | katana + 内置 jsleak | 无需 key |
| 企业信息 | ENScan | 只需要 Cookie，不需要 key |

> 也就是说：**没有 FOFA/Quake 额度也能完成 80% 的资产测绘**，只是少了"备案号反查"这一条最宽的横向扩展路径。

## 五、额度与节流约定

- 测绘类 API（FOFA/Quake/Hunter/ZoomEye）共用 `MAPPING_API_INTERVAL_MS`，默认 1500ms
- 被限流（返回 429 / "frequently"）时：本 skill 会把该源标记 `degraded` 并继续用其他源，**不会重试烧额度**
- 单次 `run` 建议上限：`--max-seed 5`（种子域数量），避免一次跑几百个域把额度打光
- 所有 API 响应本地缓存 7 天（`cache/`），重复跑不重复扣额度

## 六、安全检查清单

- [ ] `config/.env` 已在 `.gitignore`（本仓库已配置）
- [ ] 不要把 Cookie/Key 写进 `SKILL.md`、`docs/`、日志
- [ ] 日志里若出现 key，检查 `runs/` 产物后删除
- [ ] 共享机器上把 `config/` 权限收紧
