# AGENT.md 新增 Git 提交规则章节

- **Agent**: dsh-lead
- **模型**: deepseek-v4.1-flash
- **时间**: 2026-11-18T14:12:13+0800
- **会话标识**: da12
- **性质**: 文档

## 改了什么

涉及文件：

- `AGENT.md`
- `.gitignore`

- AGENT.md 新增第 5 节 Git 提交规则（自检/入库清单/提交信息格式/推送代理/与记录的关系），原 5、6 节顺延为 6、7 节
- 第 6 节会话清单补充入库确认与提交推送两步
- .gitignore 移除 agent-records/ 排除项：AGENT.md 第 7 节要求该目录纳入版本控制

## 行为变化（对调用方 / 下游 agent 的影响）

- 对下游 agent：新增义务——提交前跑 `python -m tests`（0 failed）、按 5.2 判断入库项、按 5.3 写提交信息、推送失败时加 `-c http.proxy=http://127.0.0.1:7890`
- 对仓库：`agent-records/` 恢复纳入版本控制，此前被误加进 `.gitignore` 的排除已移除
- 无代码行为变化（不改任何命令、参数、输出、退出码）

## 验证方式

- 人工核对 AGENT.md 章节编号连续（1~7 无跳号），第 5 节内部小节 5.1~5.5 完整
- 核对第 6 节清单与第 5 节条目一一对应
- `git status --short` 确认 `.gitignore` 生效后 `agent-records/` 变为可跟踪
- 未跑 `python -m tests`：本次仅改文档与 .gitignore，不涉及代码路径

## 未完成 / 风险 / 遗留

- 未在 CI 侧强制 5.1 的自检项（目前仅靠 agent 自觉），后续可加 pre-commit hook
- 5.4 里的代理端口 `127.0.0.1:7890` 是本机 Clash 默认值，换机器需调整
- 历史记录 `agent-records/claude-code__...6347.md` 此前未入库，本次一并纳入首个包含它的提交

## 与其他 agent 的冲突点

- 发现冲突：我此前误将 Git 提交规则写进 `prompts/AGENT.md`（那是使用者提示词，非协作规则），已还原该文件并从远端历史移除 commit `2859cec`（force-push）
- 发现规则冲突：本会话早前把 `agent-records/` 加入 `.gitignore`，与 AGENT.md 第 7 节「必须纳入版本控制」矛盾，已修正
- 无需人工裁决