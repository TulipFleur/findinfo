# 故障与恢复

> SKILL.md §6 是「看到这个现象该查哪一行」；这里是完整表：故障对照、
> `wait` 返回判读、结果推进分支、来源级结果分支。改代码时同步这里。

## 1. 常见故障

| 现象 | 原因 | 处理 |
|---|---|---|
| `{"error":"tool_missing"}` | `bin/<平台>/` 里没有该工具（不回退 PATH） | `doctor` 看哪个缺：Linux 跑 `scripts/setup-linux.sh`，Windows 补 `bin/windows/*.exe`。不要自己装 |
| `entity` 返回空 | `bin/config.yaml` 没填 Cookie 或已过期 | `cp bin/config.example.yaml bin/config.yaml` 后重新粘贴 aiqicha Cookie；或改用 `--domain` 直接给种子域 |
| `subs` 只返回少量结果 | 没配测绘 key（只有 subfinder 一路） | 看 `docs/API-KEYS.md`，或接受现状（crt.sh 仍可用）。这是覆盖缺口，`subs` **不会因此记 failed**，也不要 `--resume` |
| `passive` 只有少量结果 | 只有免 key 源可用 | 如实报告 `per_source` 状态 |
| `dns` 大量解析失败 | 公共 DNS 被墙/污染 | 已内置系统 DNS 兜底；仍失败则检查网络环境 |
| `vhost` 命中 0 | 该 IP 上确实只有一个站点 / 走代理无法直连 IP | 换直连网络环境；确认 IP 不是 CDN |
| `vhost` 词表"没生效" | 词表里是裸标签（dev/uat），没给基域无法拼成 Host | 加 `--domain 主域`；stderr 会打印 "words -> hosts" 的展开数量 |
| `probe` 全部超时 | WAF 拦截或网络问题 | 降 `--min-conf` 减少目标，或换出口 IP |
| `brute` 报 Npcap/socket 错误 | 缺 Npcap 驱动或无管理员权限 | 装 Npcap（勾选 WinPcap 兼容），用管理员终端跑；跑不了就跳过并说明 |
| `brute` 命中数异常多 | 该域有泛解析 | 用 `--wildcard advanced`，或跑完 `dns` 再过滤 |
| 泛解析导致假资产 | — | `dns` 阶段已自动过滤并返回 `wildcard`；不要再手工加域名 |
| 工具失败 | 内部已按 `limits.source_retries`（默认 2 次，退避）重试；仍失败 → `ok: false` | 阶段记 failed、不写 checkpoint（重跑会重试），其它来源成果保留 |
| 超过展示上限 | `truncated: true` | 只是展示截断，下游用库里全量，别拿展示样本当输入 |
| 换了会话想接着干 | — | `runs` 找 run_id → `status --run <id>` 恢复上下文（不依赖上次会话记忆） |
| `run` 退出码 5 | 跑完但有阶段失败（`result.status=partial`） | 看 `coverage.failed_stages`；缺 key 导致的缺口不要 `--resume` |

## 2. `wait` 返回怎么判读（Agent 必守的分支）

| 返回 | 含义 | 该做什么 |
|---|---|---|
| `timed_out: true` + `state: running` | 只是**本次等待窗口**结束，任务仍在跑 | 继续 `wait` 同一个 run_id；**不要重启、不要重复贴同样的状态** |
| `changed: true` + `state: running` | 有进展 | 可以给用户一句阶段摘要（阶段名/计数），然后继续等 |
| `state: completed` | 结束 | 读 `result`/`coverage`，进交付 |
| `state: failed` | 失败 | 读 `coverage.failed_stages` + `last_error`，`run --resume <run_id>` 重试 |
| `state: cancelled` | 被取消 | 说明已采资产，不再重启 |
| `interrupted: true` + `reaped_by_host: true` | 宿主回收了脱离会话的子进程，后台模式在本机不可用 | **不要重试后台**：改同会话前台执行（配 `--task-timeout`），或用存活父进程托管 |
| `interrupted: true` + `reaped_by_host: false` | 工作进程死了（崩溃/断电） | `run --resume <run_id>`，断点续跑 |

- `progress.percent` 为 **null** 表示该阶段总量未知：只能说"已处理 N 条"，**不要编百分比**。
- 重复提交同一目标时后台模式返回 `reused: true` + 同一个 run_id：直接用，不要再起一个。
- 定位任务**只用 run_id**（`--run <run_id>`），不要依赖"最近一次运行"。

## 3. 结果推进规则（按实际结果决定下一步，不要停在"已启动"）

```bash
python findinfo.py --task myproj status --run <run_id>
```

| 情况 | 判据 | 动作 |
|---|---|---|
| 覆盖充分 | `coverage.complete: true` | 进交付 |
| 有阶段失败 | `coverage.failed_stages` 非空 | 读错误后 `run --resume <run_id>` 重试（成功阶段会被断点跳过） |
| 还有可补阶段 | `coverage.not_run_stages` 非空 | 补那个阶段（单阶段命令或 `run` 加开关），再 `status` |
| 轮数/时间预算用尽 | `stop_reason: max_rounds / time_budget` | 明确告知"覆盖不完整+原因"；必要时加 `--rounds` 续跑 |
| JS 还有待分析 | `coverage.js_queue.pending > 0` | 继续跑 `extract`，这不是收敛 |
| 来源不可用 | `coverage.unavailable`（缺 key/工具） | 保留成果，交付里列出缺口，**不要伪装成"没有资产"** |
| 空结果 | `counts` 空且无 failed | 是有效空结果，不是失败 |

## 4. 来源级结果的分支（照表判断，不要自己发明）

| 看到什么 | 判据 | 动作 |
|---|---|---|
| 来源没发现资产 | 阶段 `found: 0` + `ok: true` | 有效空结果，不是失败 |
| 来源暂时失败 | `limits.source_retries` 重试后仍 `ok: false` | 阶段记 failed、不写 checkpoint（重跑会重试），其它来源成果保留 |
| 缺 Key / 额度耗尽 | `coverage.unavailable`、`doctor.api_keys`、`fofa_gateway.remaining` | 记为覆盖缺口，**照常交付**，缺口里写明少哪几路。**不要 `--resume`** —— 重试变不出 key；缺 key 也不计入 `failed_stages` |
| 泛解析污染 | `dns` 返回 `wildcard` | 已被过滤不入库；写进"数据质量"说明 |
| 范围内新域名 | `rounds[i].new_domains > 0` | `--rounds` 已自动送入下一轮，无需手工指挥 |
| 范围外关联资产 | `dropped_out_of_scope` / brief 的 `leaks.domains` | 只记候选，不自动扩面 |
| 工具失败 | `stages[].failed` + `error` | 保留 rc/错误/已有产物，该阶段不算完成 |
| 超过展示上限 | `truncated: true` | 只是展示截断，下游用库里全量 |
| 断点命中 | `skipped: true, resumed: true` | 下游输入已从库重建，不要因内存为空跳过后续阶段 |

## 5. 红线

1. 只有后台启动成功 ≠ 任务完成。
2. 没有新进展时不要重复启动、不要反复输出同一状态。
3. 退出码 5 = 跑完了但有阶段失败（`result.status=partial`），不是成功。
4. 缺 key 时 `--resume` 永远不好转：缺的是凭证，重试变不出来。
