# README 替换脱敏预览图、补充 agent 使用提示词、精简工具清单

- **Agent**: dsh-lead
- **模型**: deepseek-v4-1-flash
- **时间**: 2026-11-18T16:56:24+0800
- **会话标识**: 4ead
- **性质**: 文档

## 改了什么

涉及文件：

- `README.md`
- `docs/report-preview.png`

## 行为变化（对调用方 / 下游 agent 的影响）


- README 首页不再暴露任何真实目标信息
- 首页新增一段「复制即用」的 agent 提示词，新用户不必先去翻 prompts/AGENT.md
- 「内置工具」从 10 行细目压缩为 6 行能力概览；具体参数仍查 docs/TOOLS.md
- 无代码行为变化


## 验证方式


- `python -m pytest tests/` — **172 passed**
- `python -m pytest tests/test_docs_flow.py tests/test_docs_commands.py` — 7 passed（README 里的命令仍能被解析且可执行）
- 新预览图经 `read_image` 人工核对：全部为 example.com / 203.0.113.x，无真实目标
- demo HTML 中真实目标字符串命中数 0（grep 校验）


## 未完成 / 风险 / 遗留


- **旧图已推送到 GitHub 历史**：`docs/report-preview.png` 在之前多个 commit 中存在，本次只替换了最新版本。
  要彻底清除需要 rewrite history（filter-repo / BFG）并强推，属于破坏性操作，未执行——需要时单独确认
- GitHub raw 链接可能有 CDN 缓存，替换后短时间仍可能看到旧图
- demo 截图依赖本机 Chrome；换机器重新生成需要改其中的 hosts 数据


## 与其他 agent 的冲突点


- 无并行冲突

