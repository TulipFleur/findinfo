# 工具查找收紧为只认 bin/platform/，移除 macOS 支持

- **Agent**: dsh-lead
- **模型**: deepseek-v4-1-flash
- **时间**: 2026-11-18T15:01:28+0800
- **会话标识**: 7fdc
- **性质**: 重构

## 改了什么

涉及文件：

- `lib/core.py`
- `lib/tools.py`
- `scripts/setup-linux.sh`
- `scripts/install.py`
- `scripts/build-onepass.sh`
- `SKILL.md`
- `docs/LINUX.md`
- `tests/test_tool_resolution.py`
- `tests/__main__.py`


- `lib/core.py`: `tool()` 只查 `bin/<platform>/`，删除扁平 `bin/` 回退与 `shutil.which()` PATH 回退；`_platform_tag()` 对 darwin 直接 `RuntimeError`，不再返回 `"darwin"`
- `lib/core.py`: 补回 `skill_version()`（读 `VERSION` 文件）；此前未提交的版本在本次会话中被误 `git checkout` 清掉，已按 `tools.py` 的调用约定恢复
- `lib/tools.py`: `doctor` 删除 PATH/`outside_bin` 相关死分支，`source` 固定为 `bundle`，`bin_dir` 固定为 `BIN_PLATFORM`；`outside` 恒为空（保留输出字段兼容既有调用方）
- `scripts/setup-linux.sh`: 删除 `--prefix` 参数（安装位置固定 `bin/linux`）；`--check` 删除 PATH/FOREIGN 探测，只认 `bin/linux/<tool>`
- `scripts/install.py`: copy 模式的平台集合去掉 darwin
- `scripts/build-onepass.sh`: darwin 分支改为报错退出
- `SKILL.md` / `docs/LINUX.md`: 目录说明与安装章节同步（不再提 `--prefix`、`bin/darwin`）
- `tests/test_tool_resolution.py`（新增 6 例）: 锁定平台枚举、darwin 拒绝、PATH 不回退、扁平 bin 不回退、错误信息指向 bin/<platform>


## 行为变化（对调用方 / 下游 agent 的影响）


- `python findinfo.py doctor`: `tools[*].source` 只会是 `bundle`；`tools_summary.outside_bin` 恒为空列表；新增/恢复 `skill_version` 字段
- 缺工具时的报错文案改为 `tool not found in <abs bin/<platform>>: <name> -- install it into bin/<platform>/, then run: python findinfo.py doctor`
- `scripts/setup-linux.sh`: `--prefix` 参数**已移除**，传了会报未知参数；`--check` 不再显示 PATH 上的同名工具
- **行为收紧**：以前环境里碰巧装了同名工具（如 Kali 的 `/usr/bin/httpx`）会被静默使用；现在直接报 `tool not found`，必须补进 `bin/<platform>/`
- macOS 上 import `lib.core` 即抛 `RuntimeError`（此前会静默落到 linux 二进制）


## 验证方式


- `python -m pytest tests/` — **167 passed**（含新增 6 例）
- `python findinfo.py doctor` — rc=0，`skill_version=0.7.0`，16 个工具全部 `source=bundle`
- `bash -n scripts/setup-linux.sh scripts/build-onepass.sh` — 语法通过
- `python -m py_compile lib/core.py lib/tools.py scripts/install.py` — 通过
- 未在真实 Linux 上执行 `setup-linux.sh`（本机为 Windows）；见遗留


## 未完成 / 风险 / 遗留


- **`setup-linux.sh` 未在真实 Linux 环境实跑**：删除 `--prefix` 与 PATH 探测后，下载/安装/`--check` 三段的具体输出未验证；下一个 agent 有 Linux 环境时应跑一遍 `bash scripts/setup-linux.sh --check` 与全量安装
- `bin/linux/` 目前只有一个手工放入的 `hostCollision`，其余 14 个工具缺失；严格模式下 Linux 侧 `doctor` 会报 missing，需先跑安装器
- `hostCollision` 未在 `setup-linux.sh` 的下载清单里（走 alwaystest18/hostCollision release），但它不是文本工具，安装后需确认可执行权限
- `tools_summary.outside_bin` 保留但恒为空，属于为兼容而留的死字段，后续可考虑移除
- `VERSION` 文件此前未入库，本次一并纳入


## 与其他 agent 的冲突点


- 本次会话前期我误把 Git 规则写进 `prompts/AGENT.md`（使用者提示词），已还原并从远端历史移除 `2859cec`
- 修复过程中 `tools.write` 多次截断 `lib/core.py`，用 `git checkout --` 恢复时**连带清掉了原本未提交的 `skill_version()`**（`lib/tools.py` 已调用它，但 HEAD 的 core.py 没有实现）。已按 `VERSION` 文件约定补回，属于恢复而非新增
- 未发现其他 agent 的并行改动

