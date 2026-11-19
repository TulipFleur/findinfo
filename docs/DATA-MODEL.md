# 数据模型与置信度

> SKILL.md 只留判读要点；这里是完整的数据形状、置信度算法与报告字段口径。
> 需要命令参数时看 [TOOLS.md](TOOLS.md)。

## 1. 资产图（SQLite，`<home>/findinfo.db`）

```jsonc
// assets 表
{
  "kind": "domain|ip|url|endpoint|company|icp",
  "canonical": "api.example.com",     // 归一化主键（唯一）
  "parent": "example.com",
  "sources": "crt.sh,dnsx,httpx",     // 谁发现的（provenance）
  "confidence": 0.95,                 // 置信度，规则见下
  "passivity": "passive|active",
  "attrs": { "status": 200, "title": "...", "tech": ["nginx"], "ip": "1.2.3.4" },
  "first_seen": "...", "last_seen": "..."
}

// endpoints 表（漏洞挖掘的输入）
{ "asset": "api.example.com", "method": "GET",
  "path": "/api/user/{n}", "params": "id,token", "status": 200 }
```

## 2. 置信度规则（自动计算）

| 来源数 | confidence |
|---|---|
| 1 个来源 | 0.4 ~ 0.5 |
| 2 个独立来源 | 0.7 |
| 3 个及以上（CT+测绘+DNS） | 0.95 |
| ENScan 备案号直出 | 0.9 |
| vhost 仅状态码不同 | 0.5（需人工复核） |

**阈值**：`>= 0.7` 才进主图；`0.4~0.7` 标 unverified。
各命令 `--min-conf` 的 CLI 默认值不同：`dns 0.4`、`probe 0.7`、`passive 0.0`
（`assets` 查询默认 0.0）。所以要让 `probe` 去测低置信资产，必须显式传 `--min-conf 0.4`。

**口径说明**：`onepass` 记录自带按「独立源数」算出的置信度（1 源 ≤0.6 / 2 源 ≥0.7 / 3 源+ ≤0.95）；
落库时统一取 `max(既有, 新值)`，因此 onepass 的高置信度不会被本地规则反向拉低，
后续 `+dnsx`、`+httpx` 这类真实新增来源再按上表抬升。
看到 `sources` 是 `onepass:crtsh,rapiddns` 时，别当成「1 个来源」——那条已按 2 源计过分。

## 3. 报告字段口径（`brief` / `report` / `report.json`）

**范围判定**：不给 `--match` 时自动回退最近一次 `run` 的目标域（`scope.auto=true`）；
两者都没有则覆盖整库并告警。库里有跨项目残留时，报告把不属于目标域的记录统计成
`domains_dropped` / `endpoints_noise`，在 HTML 顶部列为"已隔离噪声"，**不计入结论**。

**来源标注（谁发现它）**：每条主机给 `discovered_by`（原始 sources 串）和 `provenance`
（归一化工具列表 + 中文标签，如 `dnsx 解析`、`onepass 被动聚合/RapidDNS`、`vhost Host 碰撞`）。
onepass 的 15 个上游源不会算成 15 个工具，`charts.sources` 按工具计数；同一资产被多工具确认时 `confidence` 更高。

**优先级打分**（`score` 上限 99，`priority` high≥45 / medium≥18 / low≥1）：
内部服务 +50、标题像管理入口 +20、敏感路径 +25/+10、401/403 +12、产品指纹 +8、参数 +6、
非标准端口 +6、CDN -8。分数只用于排序，**结论要按 `reasons` 里的判据复核**。

**brief 的字段预算**：`brief` 只含决策要用的东西——`counts`、`scope`、`environment.warnings`、
`coverage`（失败/未执行/不可用的阶段及原因；`source` 说明读的是哪次 run，`known=false` 表示
根本没读到任何 run，**这不等于没有缺口**）、`top_hosts`（默认前 20 个高优先级，每条含
`host`/`score`/`priority`/`reasons`/`provenance`）、全部 `internal_services`、`leaks` 计数与前若干条、
`next_steps`。被截断的数组在 `truncated` 里写明 `kept` 和 `total`——
**看到 truncated 不等于数据完整，结论要按它说明的缺口表述**。

**展示上限 ≠ 处理上限**：`assets` 默认只显示 500 条，全量在库里。
工具 stdout 里的列表只是展示样本；阶段实际处理的全量都进了库，下游阶段
（probe/ports/crawl/extract）从库里取完整集合。人为预算（`--max-seed`/`--limit`/`--max-vhost-ips` 等）
造成的覆盖缺口会在 summary/report 里明说。

```bash
python findinfo.py assets --kind domain --min-conf 0.7 --limit 5000
python findinfo.py assets --export runs/assets.jsonl        # 全量导出（JSONL，逐行可流式）
```

调展示上限：环境变量 `FINDINFO_ROW_LIMIT=2000` 或 `config/config.json` 的 `limits.row_limit`。
子进程输出是**逐行消费**的（`core.run_stream`），内存不随结果条数增长：实测 12 万行只涨约 0.5 MB。

## 4. 旧数据的读取口径

- **任务名目录**：纯 ASCII 任务名目录不变；旧版把中文名任务都落到 `tasks/default`（混在一个库里）。
  修复后中文名任务映射到 `task-<hash>` 独立目录。**旧 default 库不会被动过**，
  要访问它：`python findinfo.py --task default assets`。
- **来源列**：旧格式 `onepass:crt.sh,rapiddns`（仅首 token 带前缀）在读取/合并时自动归一为
  `onepass:crt.sh,onepass:rapiddns`，无需手工迁移。
- **置信度重算**：合并时按独立上游数确定性重算。历史上因前缀 bug 虚高到 0.95、实际只有 2 个上游的
  分数，在下一次合并时会被压回 ≤0.9；证据齐全的 0.95（≥3 上游）不受影响。不做批量刷库。
