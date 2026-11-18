# findinfo — 资产测绘 Skill

给一个企业名或域名，产出一张带来源与置信度的资产图，供后续漏洞挖掘使用。

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

## 文档

| 文件 | 内容 |
|---|---|
| SKILL.md | AI 使用说明：何时用、流程、硬规则、故障处理 |
| docs/TOOLS.md | 每个命令的参数、输出 JSON、示例 |
| lib/report.py | 最终交付生成器：`report` 的 json(给 AI) / md / html(给人) 三种产物 |
| docs/API-KEYS.md | **哪些需要 key**、申请地址、免费额度、不配的后果 |
| docs/LINUX.md | Linux 部署：装二进制、CAP_NET_RAW、systemd/Docker、故障排查 |
| docs/CLIENTS.md | 跨客户端（DSH / Claude Code / Codex / Claude Desktop）加载机制与坑 |
| prompts/AGENT.md | **给新会话 agent 的完整工作流提示词**（复制即用，含收敛判据） |

最终交付长这样（`findinfo.py report` 产出的 html 看板，可打印成 PDF）：

![report 预览](docs/report-preview.png)

## 内置工具（已全部下载到 bin/，无需联网安装）

| 类别 | 工具 |
|---|---|
| 企业信息 | ENScan_GO（源码编译，需 Cookie） |
| 子域 | onepass（Rust，15 源并行，8 源免 key）、subfinder、chaos、uncover（聚合 FOFA/Quake/Hunter/Shodan/Censys） |
| 爆破 | ksubdomain（无状态裸包，需 Npcap） |
| 域名 | crt.sh、CertSpotter（内置 HTTP 封装） |
| DNS | dnsx + 系统解析兜底 + 泛解析过滤 |
| 存活 | httpx（状态/标题/指纹/IP/CNAME） |
| 侦察 | cdncheck、naabu、tlsx |
| 碰撞 | hostCollision（Go，3 次请求差分，剔除 catch-all 误报） |
| 内容 | katana、gau、ffuf、jsleak（纯 Python） |

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

