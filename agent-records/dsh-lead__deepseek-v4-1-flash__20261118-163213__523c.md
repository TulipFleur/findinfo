# 补齐 Linux 端 chaos/ksubdomain，新增工具清单一致性测试

- **Agent**: dsh-lead
- **模型**: deepseek-v4-1-flash
- **时间**: 2026-11-18T16:32:13+0800
- **会话标识**: 523c
- **性质**: 功能

## 改了什么

涉及文件：

- `bin/linux`
- `scripts/setup-linux.sh`
- `tests/test_tool_inventory.py`
- `tests/__main__.py`

## 行为变化（对调用方 / 下游 agent 的影响）


- **双端一致**：`bin/windows/` 13 个 exe、`bin/linux/` 13 个 ELF，与 doctor 清单逐一对应，
  无多余、无缺失
- `setup-linux.sh --check` 现在会检查 jsluice（此前漏检，用户装了也不知道状态）
- 测试会在以下情况直接失败：下载表与 doctor 不同步、`--check` 漏项或多出、两端 bin 目录不一致
- 运行时行为无变化（补的是二进制文件与检查覆盖）


## 验证方式


- `python -m pytest tests/` — **172 passed**（含新增 5 例）
- 双端对照脚本：13/13 完全一致，`extra win: []`、`extra linux: []`
- `file bin/linux/ksubdomain` → ELF 64-bit LSB executable, x86-64（非 Windows 二进制误放）
- `bash -n scripts/setup-linux.sh` — 语法通过
- **未在真实 Linux 机器上执行**这两个二进制，只验证了架构正确


## 未完成 / 风险 / 遗留


- **chaos / ksubdomain 只做了架构校验，没有在 Linux 上实跑**：ksubdomain v0.7 是 2021 年的构建，
  依赖 libpcap 与 CAP_NET_RAW；chaos 需要 API key 才能出结果。建议在有 Linux 的环境跑一次
  `bash scripts/setup-linux.sh --check` 和 `ksubdomain -h`
- 下载走的是本机 Clash 代理（127.0.0.1:7890），二进制来自 GitHub 官方 release，未做哈希校验
- `bin/` 目录被 `.gitignore` 排除，这两个二进制**不会进仓库**；换机器仍需重新下载


## 与其他 agent 的冲突点


- `tests/__main__.py` 在本次会话期间被另一个 agent（claude-code/glm-5-3）改过（加了 monkeypatch fixture），
  我只在注册列表末尾追加一行，未改动其实现
- 期间对方还有 commit `a6e2727`、`3a2b7bd` 把我的工作区改动一并提交，内容无冲突

