# findinfo — 资产测绘 Skill

给一个企业名或域名，产出一张带来源与置信度的资产图，供后续漏洞挖掘使用。

## 工作流程

findinfo 分为两层：**资产采集流水线**负责发现、验证和扩展资产；**Agent 作业控制流程**负责启动长任务、有界等待、恢复和交付。

### 资产采集流水线

初始发现执行一次；后续验证与扩展按轮次运行，从 DNS 阶段接收新域名和待处理工作。

```mermaid
flowchart TD
    A["输入：企业名 / 域名"] --> B{"输入企业名？"}
    B -->|是| C["entity：实体锚定<br/>企业、备案、初始域名"]
    B -->|否| D["确定 scope 与种子域名"]
    C --> D

    subgraph Discover["初始发现"]
        D --> E["onepass：多来源被动聚合"]
        E --> F["certs：证书透明度"]
        F --> G["subs：子域与测绘平台"]
        G --> H["brute：DNS 字典发现 · 可选"]
        H --> I["icp：备案反查 · 有备案输入时"]
    end

    I --> J

    subgraph Round["验证与扩展：按预算执行多轮"]
        J["dns：解析验证、泛解析过滤"] --> K{"启用主动阶段？"}
        K -->|是| L["probe：HTTP 存活、指纹、端点"]
        L --> M["ipagg：共享 IP 聚合、CDN 过滤"]
        M --> N["ports：端口发现 · 可选"]
        N --> O["vhost：虚拟主机发现 · 可选"]
        O --> P["crawl：页面与 JS 爬取 · 可选"]
        P --> Q["extract：提取域名、IP、接口与发现"]
        Q --> R{"有新域名或 JS 待处理工作<br/>且预算允许？"}
        K -->|否| R
        R -->|是| J
    end

    R -->|否| S["汇总 result / coverage<br/>完成、部分完成、失败及原因"]
    S --> T["report / assets<br/>报告与资产导出"]
```

- `entity` 在输入企业名时执行；`onepass` 可通过 `--no-onepass` 关闭；ICP 反查需要备案输入，且未指定 `--no-icp`。
- `--brute`、`--ports`、`--vhost`、`--crawl` 按需开启，并隐含启用主动阶段；`extract` 跟随 `crawl`。跳过的可选节点不影响后续阶段执行。
- 回流从 DNS 开始，前面的初始发现不随轮次重复；轮数、时间预算和能力限制共同决定本次实际覆盖范围。
- 图中箭头表示执行顺序。资产库保存完整数据，各阶段从库中读取输入，stdout 的展示样本不作为下游的全量输入。

### Agent 长任务控制流程

采集由后台 worker 执行，Agent 保存任务上下文，通过 `wait` 有界等待，再根据状态与覆盖缺口决定继续、恢复或交付。

```mermaid
flowchart TD
    A["加载 Skill，理解目标与范围"] --> B["doctor：自检<br/>runs：检查已有作业"]
    B --> C["run --background：启动或复用作业"]
    C --> D["保存 task、home、run_id<br/>沿用返回的完整后续命令"]
    D --> E["wait：有界等待"]
    E --> F{"作业状态"}

    F -->|仍在运行| E
    F -->|失败或中断| G["status：读取错误、断点与覆盖缺口"]
    G --> H{"可以恢复？"}
    H -->|可以| I["run --resume<br/>必要时调整预算"]
    I --> E
    H -->|无法继续| J["交付已有成果与阻塞原因"]

    F -->|执行结束| K["检查 result 与 coverage"]
    K --> L{"还需要且能够补采？"}
    L -->|是| I
    L -->|否| M["生成报告并交付"]

    F -->|用户取消| N["停止执行，保留已有成果"]
```

- `wait` 超时只表示本次等待窗口结束，不能据此重复启动采集。
- `state=completed` 表示本次执行结束；仍需检查 `result/coverage`，区分完整完成与部分完成，并说明预算、来源和阶段缺口。
- 作业状态与断点持久化，便于换会话后查询和恢复。后台进程不会自动唤醒已经结束的 Agent 会话，进程能否持续存活也取决于宿主策略。
- 交付包括 JSON / Markdown / HTML 报告及按需导出的资产 JSONL，并注明目标、实际范围、统计、主要证据和结束原因。

## 执行环境前提（受限沙箱请先读）

skill 假定宿主满足三件事：**本地 Python ≥3.10**、**能执行仓库自带的原生二进制**（`bin/<platform>/`）、**有到被动数据源的网络出口**。跑在受限云沙箱里的 agent 可能三者都不满足——那样整个流水线不成立。一条命令验清：

    python findinfo.py doctor

看返回里的 `environment` 块：`python_ok`（版本）、`tools_summary.not_executable`（二进制被沙箱拦截时非空）、`net_egress.any_reachable`（出网）。任一不满足就到此为止，如实告知缺什么，不要硬跑。

## 快速开始

    cd <本目录>

    # Linux：先装原生二进制（Windows 用内置 bin/*.exe，跳过这步）
    bash scripts/setup-linux.sh --dry-run   # 看计划
    bash scripts/setup-linux.sh --cap       # 安装 + 授权 CAP_NET_RAW

    # 0) 安装到各客户端（Claude Code / Codex / DSH），只需一次
    python scripts/install.py --status
    python scripts/install.py

    # 1) 自检（工具 + Key）
    python findinfo.py doctor

    # 2) 配 Key（可选，不配也能跑 80%）
    cp config/.env.example config/.env
    #    ENScan 的 Cookie 单独配：
    cp bin/config.example.yaml bin/config.yaml   # 再填入 aiqicha Cookie

    # 3) 纯被动测绘（零接触目标；--task 隔离资产图，长命令建议后台）
    python findinfo.py --task 企业名 run --name "企业名"

    # 4) 主动阶段
    python findinfo.py run --name "企业名" --active --vhost --crawl

    # 5) 长任务：后台起 + 有界等待（不用 nohup，不阻塞会话）
    python findinfo.py run --domain example.com --active --vhost --crawl --background
    python findinfo.py wait  --run <run_id> --timeout 30
    python findinfo.py status --run <run_id>

    # 6) 交付：一套给人看（html/md），一套给 AI 读（json）
    python findinfo.py report --match example.com

    # 7) 导出全量（喂下游扫描器）
    python findinfo.py assets --export runs/assets.jsonl

    # 换会话/换人接手：靠 run_id 恢复，不依赖上次会话记忆
    python findinfo.py runs                # 列出最近运行（含 run_id / state）
    python findinfo.py status --run <run_id>   # 目标/范围/阶段/产物/下一步
    python findinfo.py run --resume <run_id>   # 断点续跑

## 让 Agent 使用这个 Skill

findinfo 是给 AI agent 调用的：装好之后，用一段提示词让 agent 自己去跑完整流程，
不需要人盯着敲命令。下面两种用法二选一。

### 用法一：一句话（最省事）

直接把下面这段发给 agent，把 `{{TARGET}}` 换成目标域名或企业名即可：

```text
用 findinfo skill 完整收集 {{TARGET}} 的资产。
1) 定位 skill 目录 → python findinfo.py doctor（要求 tools_summary.all_in_bin=true）
   → python findinfo.py runs --active 看有没有在跑的旧任务
2) 起任务：python findinfo.py --task {{TASK}} run --domain {{TARGET}} --active --vhost --crawl --background --rounds 3
   拿到 run_id（reused=true 说明已有在跑，直接用它的 run_id，不要再起一个）
3) 等待：python findinfo.py wait --run <run_id> --timeout 30，超时返回 running 只代表本次等待结束，
   继续等同一个 run_id；不要重启、不要提前宣布完成
4) 结果：state=completed → python findinfo.py status --run <run_id> 读 result/coverage；
   失败/中断 → run --resume <run_id> 断点续跑；预算用尽 → 如实说明覆盖不完整
5) 交付：python findinfo.py report --match {{TARGET}}，
   最终说明必须写清 结束原因（complete/partial/failed/cancelled）、已执行/失败/未执行阶段、覆盖缺口与产物路径
```

### 用法二：完整工作流（推荐，交给新会话 agent）

把 [`prompts/AGENT.txt`](prompts/AGENT.txt) 整份内容作为提示词投给 agent。它比一句话版多了：

- 快速路径 / 全面路径的分阶段命令（先 5 分钟内出第一版，再逐步加深）
- 结果推进判据：`wait` 超时、`state=failed`、`reused=true` 各自该怎么处理
- 回流循环规则：什么时候该再跑一轮、什么时候该收口
- 交付模板：报告该写哪些字段、证据怎么标注

### 需要哪些 API Key（可选项，不配也能跑 80%）

纯被动阶段（`onepass` / `certs` / `subs`）里的 onepass 有 8 个免 key 数据源，不配任何 key 也能出结果；
下面这些是**扩展覆盖**用的，按需申请。填进 `config/.env`（`cp config/.env.example config/.env`）。

| 用途 | 字段 | 申请地址 | 免费额度 |
|---|---|---|---|
| 爱企查 Cookie（企业锚定，`entity` 阶段必需） | `bin/config.yaml` → `cookies.aiqicha` | 登录 https://aiqicha.baidu.com → F12 → Network → 复制 Cookie 头 | 免费 |
| FOFA（备案反查 / 子域扩展） | `FOFA_EMAIL` + `FOFA_KEY` | https://fofa.info/userInfo | 200~300 次/月 |
| 360 Quake（备案反查 / 子域扩展） | `QUAKE_TOKEN` | https://quake.360.net/quake/#/personalInfo | 3000 次/月 |
| Hunter 鹰图（备案反查 / 子域扩展） | `HUNTER_KEY` | https://hunter.qianxin.com/home/userInfo | 100 积分/月 |
| Shodan（子域扩展，`subs` 默认引擎之一） | `SHODAN_KEY` | https://account.shodan.io/ | 极低，建议付费 |

```bash
cp config/.env.example config/.env
# 编辑 config/.env，填入：
#   FOFA_EMAIL=your@mail.com
#   FOFA_KEY=xxxxxxxx
#   QUAKE_TOKEN=xxxxxxxx
#   HUNTER_KEY=xxxxxxxx
#   SHODAN_KEY=xxxxxxxx

# 爱企查 Cookie 单独放（二进制自己读，不走 .env）：
cp bin/config.example.yaml bin/config.yaml
#   cookies:
#     aiqicha: "BAIDUID=xxxx; BDUSS=xxxx; ..."   # 整段 Cookie 头原样粘贴

python findinfo.py doctor   # 确认 api_keys 里对应项变成 true
```

> 两个文件都已在 `.gitignore` 里，不会被提交，也不会被 `install.py --copy` 复制到客户端目录。
> 空值 = 该数据源未启用，流水线跳过并在报告里记为覆盖缺口，不会报错。

> **爱企查 Cookie 只对 `entity`（企业锚定）有用。** 直接给域名（`--domain example.com`）时完全不需要它。

### 装到各客户端

agent 必须先「看得见」这个 skill 才会调用它。一条命令装到所有客户端：

```bash
python scripts/install.py            # DSH / Claude Code / Codex 一次性建链接 + 注册
python scripts/install.py --status   # 查每个客户端是否已装
python scripts/install.py --verify   # 在每个客户端路径上实跑 doctor
```

不同客户端的加载机制不一样（Codex 走 config.toml 注册表、Claude Desktop 只能走 MCP），
细节和常见坑见 [docs/CLIENTS.md](docs/CLIENTS.md)。

### 使用边界

`--active`、`--vhost`、`--crawl`、`--brute`、`--ports` 这些**主动阶段会真实向目标发包**。
只对自己有授权的目标启用；纯被动阶段（`onepass`/`certs`/`subs`/`icp`/`dns`）零接触目标。

## 文档

| 文件 | 内容 |
|---|---|
| SKILL.md | AI 使用说明：何时用、流程、硬规则、故障处理 |
| docs/TOOLS.md | 每个命令的参数、输出 JSON、示例、内置工具能力矩阵 |
| docs/API-KEYS.md | **哪些需要 key**、申请地址、免费额度、不配的后果 |
| docs/LINUX.md | Linux 部署：装二进制、CAP_NET_RAW、systemd、故障排查 |
| docs/CLIENTS.md | 跨客户端（DSH / Claude Code / Codex / Claude Desktop）加载机制与坑 |
| docs/DEVELOPMENT.md | **开发文档**：目录结构、回归测试怎么跑（日常使用不需要看） |
| prompts/AGENT.txt | **复制给 agent 的完整工作流提示词模板**（人工复制粘贴，不参与自动加载） |

最终交付长这样（`findinfo.py report` 产出的 html 看板，可打印成 PDF）：

![report 预览](docs/report-preview.png)

## 内置工具

二进制随仓库分发、开箱即用（Linux 端用 `scripts/setup-linux.sh` 安装），能力矩阵与每个命令的详细参数见 [docs/TOOLS.md](docs/TOOLS.md)；在场/可执行/版本自检用 `python findinfo.py doctor`。


## 核心设计

1. **确定性优先**：能工具化的不交给模型，所有工具返回结构化数据
2. **provenance + confidence**：每条资产记录谁发现的（采集工具+上游两层）、几个**独立上游**、可信度。同一上游（如 crt.sh）经不同采集入口只算一票；重复跑/乱序不会提升置信度
3. **幂等 + 增量**：findinfo.db 是唯一真值，重复跑只更新 sources
4. **被动/主动物理分离**：--active 之前不产生任何目标流量
5. **任务隔离**：`--task 名字` 各任务独立数据库；中文名会映射成稳定且可区分的目录（纯中文名 → `tasks/task-<hash>`，不会都落到 default）
6. **断点续跑**：阶段按输入哈希 checkpoint；`--active`/`--crawl` 追加运行时已完成阶段跳过并从库里重建输入。**阶段失败（如工具 rc=124）不写 done**，重跑会自动重试
7. **范围控制**：`run` 只主动触达 `--domain`/企业锚点给出的种子；ICP 反查、JS 泄露等发现的**范围外域名只入库报告，不自动扩大主动范围**。范围推导用公共后缀表（customer.co.uk 不会扩成 co.uk）

### 展示上限 ≠ 处理上限

工具 stdout 里的列表（默认最多 500 行）只是**展示样本**；阶段实际处理的全量都进了库，下游阶段（probe/ports/crawl/extract）从库里取完整集合。人为预算（--max-seed/--limit/--max-vhost-ips 等）造成的覆盖缺口会在 summary/report 里明说。

### 旧数据兼容与迁移

- **任务名目录**：纯 ASCII 任务名目录不变；旧版把中文名任务都落到 `tasks/default`（混在一个库里）。修复后中文名任务映射到 `task-<hash>` 独立目录。**旧 default 库不会被动过**，要访问它：`python findinfo.py --task default assets`。
- **来源列**：旧格式 `onepass:crt.sh,rapiddns`（仅首 token 带前缀）在读取/合并时自动归一为 `onepass:crt.sh,onepass:rapiddns`，无需手工迁移。
- **置信度重算**：合并时按独立上游数确定性重算。历史上因前缀 bug 虚高到 0.95、实际只有 2 个上游的分数，在下一次合并时会被压回 ≤0.9；证据齐全的 0.95（≥3 上游）不受影响。不做批量刷库。

## 运行状态与失败语义

- `findinfo.py status`：心跳（阶段每 30s 刷新 status.json）+ pid 判活；超过 90s 无心跳或进程不在即 `alive=false`。
- 阶段状态：`done`（成功）/ `failed`（工具失败，**部分结果仍保留**且下游可用，重跑自动重试）/ `skipped`（checkpoint 命中）。
- 退出码：0 成功 / 2 业务错 / 4 工具缺失 / 5 阶段失败（含部分结果）。

