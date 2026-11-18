# 消费者安装不含 tests/，文档标注 pytest 与 Python 版本要求

- **Agent**: dsh-lead
- **模型**: deepseek-v4-1-flash
- **时间**: 2026-11-18T16:48:08+0800
- **会话标识**: 8c5a
- **性质**: 修复

## 改了什么

涉及文件：

- `scripts/install.py`
- `SKILL.md`

## 行为变化（对调用方 / 下游 agent 的影响）


- **消费者路径零变化**：`doctor`/`run`/`report` 等全部照常，不依赖 tests 或 pytest
- `install.py --copy` / `--mode copy` 生成的客户端目录**不再包含** `tests/`
- 开发者跑 `python -m tests` 前需要 `pip install pytest`（已写入 SKILL.md）
- 未装 pytest 时，`test_tool_resolution.py` / `test_tool_inventory.py` 会导入失败，其余用例照常


## 验证方式


- `python -m pytest tests/`（Windows） — **172 passed**
- `python3 -m py_compile lib/*.py findinfo.py scripts/*.py`（WSL Kali 3.13.7） — 全部通过
- `bash -n` 四个 shell 脚本（WSL Kali） — 全部通过，与 Windows 结果一致
- `python findinfo.py --help` / `doctor` — 正常
- `grep -rn "import tests|from tests" lib/ findinfo.py scripts/` — 无命中，确认运行时不用 tests
- **WSL 里 `python3 -m tests` 仍会在 import pytest 处中止**（本机未装 pytest），这是预期行为，已写入文档


## 未完成 / 风险 / 遗留


- **没有改成「无 pytest 时自动 skip」**：用户明确表示「消费者使用无影响就可以」，
  所以选择把 tests 移出消费者路径 + 文档写清依赖，而不是给测试代码加兼容层
- WSL Ubuntu 发行版为 Python 3.6.9，跑不了本项目（代码用 `str | None` 等 3.10+ 语法）；
  Kali 为 3.13.7 可用。最低版本要求已写进 SKILL.md
- WSL 下 `bin/linux` 的 13 个 ELF 未被实际调用验证（测试用的是模拟采集器）


## 与其他 agent 的冲突点


- `tests/__main__.py` 由另一个 agent（claude-code/glm-5-3）改过，本次未触碰其实现
- 无冲突

