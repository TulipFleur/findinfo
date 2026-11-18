# 移除未被调用的 tlsx/gau/ffuf 三个工具

- **Agent**: dsh-lead
- **模型**: deepseek-v4-1-flash
- **时间**: 2026-11-18T16:04:40+0800
- **会话标识**: e3ab
- **性质**: 重构

## 改了什么

涉及文件：

- `lib/tools.py`
- `lib/report.py`
- `scripts/setup-linux.sh`
- `docs/LINUX.md`
- `README.md`

## 行为变化（对调用方 / 下游 agent 的影响）


- `python findinfo.py doctor`: `tools_summary.total` 从 16 变为 **13**，`all_in_bin` 仍为 true
- 工具清单变化：不再检查 tlsx / gau / ffuf 是否存在
- `bin/windows/` 体积 374MB → **326MB**
- **无功能损失**：三者本来就没有调用点
  - `tlsx` 的用途被 `t_certs`（crt.sh + CertSpotter 的 CT 日志查询）严格覆盖，且后者含历史证书
  - `gau` 的历史 URL 被 katana 主动爬取 + uncover 多引擎聚合覆盖
  - `ffuf` 需要目录字典，且主动爆破与「纯被动优先」的设计取向冲突


## 验证方式


- `python findinfo.py doctor` — rc=0，13 个工具全 `source=bundle`，`missing=[]`，`all_in_bin=true`
- `python -m pytest tests/` — **167 passed**
- `bash -n scripts/setup-linux.sh` — 语法通过
- `python -m py_compile lib/tools.py lib/report.py` — 通过
- `grep -rn "tlsx|gau|ffuf"` 全仓库（排除 tests/agent-records）已无残留


## 未完成 / 风险 / 遗留


- **已部署的旧环境**：如果别的机器上 `bin/linux/` 里还留着这三个二进制，现在不会有任何东西调用它们，但也不会自动删除；需要手工清理
- `docs/TOOLS.md` 未逐条核对这三个工具（原文本来就没有它们的章节，无需改动）
- 若将来确实需要目录发现（ffuf 的唯一独有价值），应作为独立 `dir` 子命令接入并显式标注高噪音、需授权，而不是塞回工具清单


## 与其他 agent 的冲突点


- 无并行改动冲突
- 本次删除是用户明确要求（「移除」）

