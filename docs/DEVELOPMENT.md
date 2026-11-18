# findinfo 开发文档

> 本文件面向**开发者/维护者**。日常使用请读 [`../SKILL.md`](../SKILL.md)，
> 让 Agent 跑完整流程请用 [`../prompts/AGENT.txt`](../prompts/AGENT.txt)。

---
## 1. 目录结构

```
findinfo/
├── SKILL.md            ← 本文件（AI 读这个决定怎么用）
├── findinfo.py         ← CLI 入口（23 个子命令）
├── prompts/AGENT.txt    ← ★ 复制即用的提示词模板（人工复制，不参与自动加载）
├── bin/                ← 按平台分目录：bin/windows/、bin/linux/（不支持 macOS）
│   ├── windows/        ← 12 个 .exe（Windows 预置；doctor 追踪 12 个）
│   ├── linux/          ← ELF（scripts/setup-linux.sh 安装）
│   └── config.example.yaml  ← ENScan Cookie 模板 → 复制成 bin/config.yaml
├── rust/onepass/       ← onepass 源码（15 源被动聚合，cargo build --release）
├── deploy/             ← systemd 模板（findinfo@.service / .timer）
├── lib/
│   ├── core.py         ← 配置/存储/归一化/缓存/限速/执行
│   ├── tools.py        ← 13 个阶段实现（全部返回结构化数据）
│   ├── jsleak.py       ← JS 泄露提取·正则引擎（零依赖）
│   └── report.py       ← 两种最终输出（json 给 AI / html+md 给人）+ 来源标注 + 优先级评分
├── config/
│   ├── .env.example    ← ★ API Key 存档模板
│   └── config.example.json
├── docs/
│   ├── API-KEYS.md     ← ★ 哪些需要 key / 申请地址 / 免费额度
│   ├── TOOLS.md        ← 每个命令的详细参数与输出示例
│   ├── LINUX.md        ← Linux 部署（二进制/CAP_NET_RAW/systemd）
│   └── CLIENTS.md      ← 各客户端加载机制差异与排错
├── wordlists/          ← 字典（brute / vhost 用，均为裸标签）
│   ├── sub.txt         ← 174 条高价值前缀（内部系统/中间件，先跑这个）
│   ├── submin.txt      ← 9990 条 top-10k 全量（mitan submin 归一化去重）
│   └── vhost.txt       ← 145 条 Host 标签（vhost 用，需 --domain 拼基域）
└── scripts/
    ├── findinfo.sh     ← ★ 固定入口（-t/-n/-a/--vhost/-b/--status）
    ├── install.py      ← ★ 跨客户端安装/状态/校验
    ├── setup-linux.sh  ← ★ Linux 装原生二进制 + setcap + 体检
    ├── build-onepass.sh← 重编 onepass（需 Rust 工具链）
    └── build-enscan.sh ← 重编 ENScan_GO（需 Go 1.23+）

状态目录（不在代码目录内，可被多个客户端共用；配置仍留在代码目录）
~/.findinfo/            ← 可用 FINDINFO_HOME 覆盖
├── findinfo.db         ← 资产图（SQLite，唯一真值）
├── runs/               ← 每次运行的产物（JSONL + status.json）
├── reports/            ← report 产物（json/md/html），latest 指向最近一次
└── cache/              ← API 响应缓存
```

> 兼容：若 `<skill>/data/findinfo.db` 已存在，会继续就地使用旧位置，不会迁移或丢弃数据。
> `config/`（`.env`、`bin/config.yaml`）始终跟代码目录走，不会被移动到用户目录，也不会被 `--copy` 复制到别处。



---

## 2. 回归验证（全部为模拟采集器，不碰真实目标、不耗配额）

```bash
pip install pytest       # 一次性：部分用例用 pytest 的 raises/monkeypatch/tmp_path
python -m tests          # 全套（Windows 与 WSL Kali 均已通过，Python >= 3.10）
```

> `tests/` 是**开发期自检**，不在运行时链路上（`findinfo.py`、`lib/`、`scripts/` 都不 import 它），
> `install.py --copy` 也不会把它装到客户端目录。消费者无需安装 pytest；没有 pytest 时
> `test_tool_resolution.py` / `test_tool_inventory.py` 会导入失败，其余用例照常运行。

| 验收项 | 用例 | 方式 |
|---|---|---|
| 1 首次任务：自检→采集→查询→交付 | `test_run_flow:test_first_pass_completes_and_reports_result` / `test_jobs:test_launch_returns_run_id_and_paths_immediately` | 进程内 cmd_run + 假 collector；真实子进程测 launch |
| 2 多次 wait 返回 running 后拿到完成 | `test_jobs:test_wait_returns_running_on_timeout_then_completes` / `test_progress_change_returns_early` | 假 entry（sleep）驱动的真进程 |
| 3 重复调用不重复创建 | `test_jobs:test_dedupe_reuses_inflight_job` / `test_run_flow:test_background_launch_reuses_inflight_job` | 同 dedupe_key → `reused: true` |
| 4 部分来源失败仍保留成果 | `test_run_flow:test_partial_stage_reports_gap_and_exit_5` / `test_missing_engine_key_is_coverage_gap` / `test_source_outcomes:*` | 假 collector ok=false / 无 key |
| 5 失败续跑 | `test_resume_after_failure:*` / `test_jobs:test_interrupted_detection_and_resume` | 两轮 cmd_run；kill 后 resume |
| 6 超展示上限仍完整处理 | `test_stages_and_dns:test_dns_501_records_all_reach_downstream` | 501 条结果，展示截断但下游全量 |
| 7 新资产回流与停止条件 | `test_run_flow:test_rounds_*` / `test_time_budget_stops_rounds_and_marks_partial` | rounds 循环 + 三种停止原因 |
| 8 多任务并发不串任务 | `test_jobs:test_concurrent_runs_do_not_share_state` | state/日志/产物互不干扰 |
| 9 会话恢复仅凭 run_id | `test_jobs:test_recovery_by_run_id_only` | 只用 run_id resolve + status |
| 10 文档与实现一致 | `test_docs_commands:*` | 解析文档命令逐条对 argparse 校验，并禁止 nohup |

**验证边界（如实区分）**：

- 已模拟验证：生命周期（spawn/wait/cancel/interrupt/resume）、状态机、result/coverage、回流停止条件、并发隔离、文档一致性。
- 已实测：Windows 与 WSL Kali 上真实 Python 子进程 spawn→wait→completed，以及 `runs`/`status --run` CLI 路径。
- 已在**真实目标**上跑通全流程（详见 `runs/REAL-TEST-NOTES.md`）：
  - hniu.cn/hniu.com：6359 域名 / 359 IP / 5680 端点，`complete: true`（7 阶段）
  - 含 entity 的重跑：8 阶段全 done，certs 因 crt.sh 超时失败 → 如实标 `partial`
  - meituan.com：7001 域名 / 12542 IP / 5083 端点，`complete: true`
  - 耗时参考：subs+dns+probe 在 7000 个域名规模下约 25~35 分钟；crawl 在 287 站点 depth=3 下约 17 分钟
- **未验证**：真实宿主保活（关终端/注销/重启）、macOS、小时级真实运行。不承诺"跨客户端退出后自动续跑"。
