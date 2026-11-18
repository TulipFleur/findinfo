# AGENT.md — 多 Agent 协作规则

> **本文件在会话启动时自动加载。任何 agent（Claude Code / Codex / Cursor / Copilot …）在修改本项目前必须先读完本文件。**
>
> 本项目**不止一个 agent 在并行迭代升级**。同一时刻可能有多个 agent 在改代码，彼此的上下文互不可见。
> 因此：**重大修改必须留下可追溯的记录，否则等同于没做。**

---

## 1. 强制约束：重大修改必须留记录

### 1.1 什么算"重大修改"（必须记录）

满足任意一条即必须写记录：

- 新增 / 删除 / 重命名**子命令或 CLI 参数**
- 改变**数据模型**：SQLite 表结构、`kind` 取值、字段含义、索引
- 改变**阶段顺序、失败语义、退出码**
- 改变**置信度 / provenance / scope / 去重**规则
- 新增 / 删除**外部工具或 API 依赖**
- 重构**跨模块调用关系**（`findinfo.py` ↔ `lib/*` ↔ `rust/onepass`）
- 修改 **install / setup / deploy / Docker** 流程
- 修改测试所守护的**不可破坏契约**
- 任何**会让文档与代码不一致**的改动（含修文档本身）

### 1.2 什么不算（无需记录）

- typo、注释、纯格式化
- 补齐不改变契约的测试
- 临时调试脚本（且必须清理）

### 1.3 何时写

**改完、验证通过之后立刻写**。不要攒到最后——会话可能被中断，未记录的改动就是下一个 agent 的陷阱。

---

## 2. 记录文件命名规则（唯一 + agent + 模型 + 时间）

### 2.1 位置

```
agent-records/
```

**不要**放在 `docs/`（那里是产品文档）或根目录（干扰加载）。

### 2.2 命名格式

```
<agent-slug>__<model-slug>__<YYYYMMDD-HHMMSS>__<uniq4>.md
```

四段用 **双下划线 `__`** 分隔，保证可被程序稳定拆分：

| 段 | 含义 | 示例 |
|---|---|---|
| `agent-slug` | agent 名称，小写、`-` 连接 | `claude-code`、`codex-cli`、`cursor` |
| `model-slug` | 模型名称，小写，去掉 `[]()` 等非法字符 | `opus-4-5`、`gpt-6`、`mythos-gw-6946973803` |
| `YYYYMMDD-HHMMSS` | 本地时间，精确到秒 | `20261118-005324` |
| `uniq4` | 4 位随机/递增标识，**防同秒撞名** | `a7f3` |

**唯一性由后两段共同保证**：时间精确到秒 + `uniq4` 冲突重试。写入前若目标文件已存在，**必须重新生成 `uniq4`**，绝不覆盖。

完整示例：

```
agent-records/claude-code__mythos-gw-6946973803__20261118-005324__a7f3.md
agent-records/codex-cli__gpt-6__20261118-010102__b8e1.md
```

### 2.3 用脚本生成（推荐）

```bash
python scripts/agent-record.py \
    --agent claude-code \
    --model mythos-gw-6946973803 \
    --summary "修复 --task 子命令后置导致 rc=2" \
    --files findinfo.py SKILL.md prompts/AGENT.md
```

脚本会自动完成：slug 化 → 时间戳 → 唯一性重试 → 按模板落盘 → 打印最终路径。
**不需要手写文件名**；手写容易撞名或格式不符。

---

## 3. 记录内容模板

```markdown
# <一句话变更标题>

- **Agent**: <agent> / **模型**: <model> / **时间**: <ISO8601>
- **会话标识**: <uniq4 或 run id>
- **性质**: 功能 / 修复 / 重构 / 文档 / 部署

## 改了什么
（按模块列，具体到文件与关键函数）

## 行为变化（对调用方 / 下游 agent 的影响）
（命令、参数、输出字段、退出码、数据模型 — 只写**发生了变化**的部分）

## 验证方式
（跑了什么：`python -m tests` 几个用例、哪些手工实测、结果如何）

## 未完成 / 风险 / 遗留
（明确写出没验证到的部分，别让下一个 agent 误以为已覆盖）

## 与其他 agent 的冲突点
（是否发现别人的并行改动、是否避开、是否需要人工裁决）
```

---

## 4. 并发协作约定

1. **改前先看**：`git status --short` + `ls agent-records/ | tail`，确认有没有别人正在改同一批文件。
2. **不改他人的记录**：`agent-records/` 下的文件是 **append-only 的历史**。发现别人记录有误，**新建一条**记录指出，不要编辑原文件。
3. **缩小写入面**：只改与本次任务相关的文件；不要顺手"整理"别人刚改过的模块。
4. **发现冲突就停下**：同一文件被并发修改且无法判断谁对时，**写一条记录说明冲突并交给人工裁决**，不要强行覆盖。
5. **文档与代码同批次提交**：改了行为就同一次提交里更新对应文档，避免"文档超前于代码"（本项目已有此问题）。
6. **清理临时产物**：调试用的临时目录（如 `.tmp_*`、测试用 `FINDINFO_HOME`）必须删除，不得留在仓库里。

---

## 5. Git 提交规则

本节定义**提交什么、怎么提交、怎么推送**。与第 1 节的「重大修改必须留记录」是两件事：记录管**可追溯**，本节管**入库**。

### 5.1 提交前自检（缺一不可）

1. **语法**：`python -m py_compile <改动的 .py 文件>`；改了 `rust/onepass/` 则 `cargo check`。
2. **测试**：`python -m tests` **必须 0 failed** 才提交。只跑了部分用例的，在记录里写明没跑哪些。
3. **文档同步**：改了行为就同一次提交更新 `SKILL.md` / `docs/*.md` / `prompts/AGENT.md` 中受影响的部分（见 4.5）。
4. **看清单**：`git status --short` 逐条确认，再 `git add`。不要盲目 `git add -A`。

### 5.2 必须入库 / 禁止入库

| 必须入库 | 禁止入库（已在 .gitignore） |
|---|---|
| 全部源码（findinfo.py、lib/、rust/、scripts/、tests/） | config/.env、config/config.json、bin/config.yaml（key / Cookie） |
| 文档（SKILL.md、AGENT.md、docs/、prompts/） | data/、runs/、cache/（运行态） |
| 配置模板（config/*.example.*、各工具 config.yaml 模板） | bin/*.exe、bin/*/、bin/*.gob（二进制与运行态） |
| wordlists/ | rust/onepass/target/（构建产物） |
| **agent-records/**（历史记录，见第 7 节） | __pycache__/、*.pyc、*.db-wal、*.db-shm |

**新增文件前先判断**：属于「别人拿到就能用」的（源码、模板、文档、记录）→ 入库；属于「本机跑出来的」（产物、日志、密钥、缓存）→ 补 .gitignore 再继续。

### 5.3 提交信息格式

```
<type>: <一句话说明>
```

- type 取值：feat / fix / docs / refactor / test / chore / perf
- 第一行不超过 72 字符，**英文**，动词开头，不要句号结尾
- 需要细节时第一行后空一行再写正文（- 列表），但**正文不替代** agent-records/ 记录
- 一次提交只做一件事：修 bug 与加功能不混在同一个 commit

示例：

```
fix: suppress console window when killing process tree

- taskkill/wmic calls in lib/core.py and lib/jobs.py missed CREATE_NO_WINDOW
- verified: pytest tests/test_jobs.py (9 passed)
```

### 5.4 分支与推送

1. **主干直推**：单人 / 少量 agent 并行时直接提交到 master，不强制 PR。
2. **并行改同一模块时**：先 `git pull --rebase`，冲突按第 4 节处理；确实无法判定时停下交人工。
3. **推送**：`git push origin master`。本机直连 GitHub 可能被 TUN 拦截，失败时加代理：

```bash
git -c http.proxy=http://127.0.0.1:7890 push origin master
```

4. **凭据**：由 Windows 凭据管理器（`credential.helper=manager`）提供，**禁止**把 token 写进 remote URL、脚本或任何入库文件。
5. **禁止强推共享分支**：`--force` 只允许在自己的实验分支使用；master 上的 `--force` 需要人工确认。

### 5.5 提交与记录的关系

```
改代码 → 跑测试 → 写 agent-records 记录 → git add（含记录）→ commit → push
```

**重大修改的记录必须和代码在同一个提交里**。记录单独一个提交会让 git log 出现「代码已改、记录迟到」的断层，失去溯源意义。

---

## 6. 每次会话的最小动作清单

- [ ] 读本文件
- [ ] `git status --short` 看当前未提交改动
- [ ] `ls agent-records/ | tail -5` 看最近谁改了什么
- [ ] 动手改
- [ ] 跑 `python -m tests`（必须 0 failed）
- [ ] 重大修改 → `python scripts/agent-record.py ...` 生成记录
- [ ] `git status --short` 逐条确认入库内容（禁止项见 5.2）
- [ ] 提交：`git add` 明确文件 → `git commit -m "type: ..."` → `git push origin master`
- [ ] 清理临时文件

---

## 7. 与其它文档的关系

| 文件 | 读者 | 作用 |
|---|---|---|
| **`AGENT.md`（本文件）** | **所有 agent** | **协作规则、记录约束、Git 提交规则** |
| `SKILL.md` | agent + 用户 | 本 skill 怎么用（产品说明） |
| `prompts/AGENT.md` | findinfo 的**使用者** agent | 资产测绘工作流提示词（与协作无关） |
| `docs/*.md` | 用户 / 运维 | 部署与排错 |
| `agent-records/*.md` | agent + 人工 | 历次重大修改的溯源记录 |

**`agent-records/` 必须纳入版本控制**——它是历史，不是临时产物。不要把它加进 `.gitignore`，也不要批量删除旧记录。