# 移除 Docker 并同步全部工具数量/安装路径文档

- **Agent**: dsh-lead
- **模型**: deepseek-v4-1-flash
- **时间**: 2026-11-18T16:23:56+0800
- **会话标识**: d2e3
- **性质**: 文档

## 改了什么

涉及文件：

- `SKILL.md`
- `README.md`
- `docs/LINUX.md`
- `docs/TOOLS.md`
- `prompts/AGENT.md`
- `scripts/setup-linux.sh`
- `Dockerfile`
- `.dockerignore`

## 行为变化（对调用方 / 下游 agent 的影响）


- 文档层面：不再有任何地方声称 16/15 个工具，统一为 **13**
- `prompts/AGENT.md` 不再要求 `in_bin == 16`，agent 不会因为工具数变化误判为能力缺失
- 仓库根目录不再有 Dockerfile；`docs/LINUX.md` 只有 systemd 部署方式
- 代码行为无变化（本次只改文档与脚本提示语）


## 验证方式


- `python findinfo.py doctor` — `total: 13`，`all_in_bin: true`
- `python -m pytest tests/` — **167 passed**（首次全量跑出现 1 次 `test_worker_e2e` 偶发失败，单独重跑通过，二次全量全绿，判定为并发时序抖动与本次改动无关）
- `bash -n scripts/setup-linux.sh` — 语法通过
- 全仓库 grep `16 个|15 个工具|--prefix|Dockerfile|in_bin == 16` 已无残留（`docs/LINUX.md` 两处「不支持 --prefix」是解释性说明，保留）


## 未完成 / 风险 / 遗留


- **`bin/linux/` 仍缺 chaos 与 ksubdomain**：setup 清单里有、实际目录没有，Linux 侧 doctor 会报 missing。本次未处理（需联网下载）
- `jsluice` 不在 setup 清单中是**设计如此**（docs/TOOLS.md 已说明需用户自己 `go install`），不算缺陷
- 未加「工具清单一致性」测试：目前 doctor 清单 / setup 清单 / 各平台实际文件三处仍靠人工同步，建议后续加一个白名单式测试（把 jsluice 作为已知例外显式列出）
- `runs/` 下的历史运行记录（DELIVERY.md 里写「15 个工具」）未修改，属于当时快照


## 与其他 agent 的冲突点


- 上一轮误把 jsluice 当成可改版工具、擅自给 setup-linux.sh 加了 go install 分支，已 `git checkout` 完全撤回（用户指出 jsluice 是第三方工具，且 docs/TOOLS.md 明确写它不随脚本安装）
- 无其它 agent 并行改动

