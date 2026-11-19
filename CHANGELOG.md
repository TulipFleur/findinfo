# Changelog

本项目的对外变更记录，格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

每条都标注了对应的提交，可用 `git show <短哈希>` 核对。

## [Unreleased]

## [0.8.0] - 2026-11-19

### 破坏性变更

- **`report` 默认只写给人看的产物**（`report.md` + `report.html`）。以前它无条件写出
  `report.json` 和 `report.brief.json`，于是 Agent 交付时会多出一趟"写文件再读文件"，
  而数据本来就在库里。现在 JSON 需要显式索取：`--with-json` / `--with-brief`；
  stdout 的 `paths` 里也不再出现 `json` / `brief` 键。
  *迁移*：脚本里读 `report.json` 的调用改成 `report ... --with-json`；只想要 Agent 摘要的，
  不要读文件，直接 `python findinfo.py brief --run <run_id>`（stdout 一行 JSON ≤32 KB）。
  （`40970b7`）
- **单阶段命令的 `--tool-timeout` 成为统一契约**：`entity` / `certs` / `icp` / `passive` /
  `brute` / `subs` / `dns` / `probe` / `ipagg` / `ports` / `vhost` / `crawl` / `extract`
  这 13 个命令都接受 `--tool-timeout <秒>`（0 = 用工具自己的默认值），与 `run` 同名同义。
  以前只有 `run` 有，单阶段命令只能被工具的默认超时卡住。
  *迁移*：无需改动；只是现在可以给单个阶段设上限了。（`40970b7`）
- **`icp --from-store` 必须给范围**：ICP 表是跨项目共享的，不带范围会把别的项目的备案号
  一起反查出来。现在 `icp --from-store` 支持 `--scope <域后缀>`（可重复），与其他
  `--from-store` 命令一致。
  *迁移*：`icp --from-store` 后面补 `--scope example.com`；不补也能跑，但会把整张 ICP 表都喂给
  FOFA/Quake/Hunter。（`40970b7`）

### 新增

- `brief` 子命令：直接查库，向 stdout 打一行 JSON（≤32 KB），不落文件。是给 Agent 的读取接口，
  字段与老的 `report.brief.json` 一致，截断规则也一致（`--top` / `--max-bytes` 可调）。
  有 run_id 时用 `brief --run <run_id>`，`--match` 只在你不知道 run_id 时兜底。（`40970b7`）
- `report --brief-top` / `--brief-max-bytes`：控制附带摘要的条数与字节上限。（`40970b7`）
- `report --with-json` / `--with-brief`：显式索取机器可读产物。（`40970b7`）
- `scripts/build-release.py`：可复现的发布包构建脚本。文件清单是规则不是记忆——只打
  `git ls-files` + 当前平台的 `bin/<platform>/*`，排除开发物料、另一平台二进制与密钥；
  打包时固定 zip 内的时间戳与权限位，所以同一棵树上两次构建产出相同的字节；随后解包自检
  （无 `.pyc`/`__pycache__`/`.env`/`bin/config.yaml`、`VERSION` 与 `--version` 一致、
  `doctor` 能起来、每个内置工具都在包里），并写 `SHA256SUMS`。（`40970b7`）
- 13 个单阶段命令的 `--tool-timeout`（见"破坏性变更"）。（`40970b7`）
- `icp --scope`（见"破坏性变更"）。（`40970b7`）
- 文档分层：新增 `docs/DATA-MODEL.md`（资产图与置信度规则、报告字段口径、旧数据读取口径）
  与 `docs/TROUBLESHOOTING.md`（故障表、`wait` 判读表、结果推进表、红线），
  `SKILL.md` 只留"何时用 / 必跑闭环 / 硬规则 / 结果判读"。（`3226ebe`）

### 修复

- **缺 API Key 不再算阶段失败**：没有凭证的引擎只会失败，把它交给 `uncover` 会把一个能用的
  阶段变成"所有来源都失败"，run 以退出码 5 结束，Agent 于是对着一个重试永远修不好的问题
  反复 `--resume`。现在先按 `core.split_engines()` 分出可用引擎，只把有 key 的传给 `uncover`；
  没有可用引擎时把每个来源记成 `unavailable`（覆盖缺口），run 照常完成并交付。
  `combine_outcome()` 也把 `unavailable` 排到 `partial` 之下，覆盖缺口不再盖过真实失败；
  补上 key 后重跑不会被旧断点跳过（`usable_engines` 进了阶段输入哈希）。（`6ee0e1b`）
- **`doctor` 不会再拿路径当版本号**：老实现会在工具输出里取第一个像 `x.y.z` 的 token，于是
  安装目录名 `findinfo-0.7.2-windows` 被当成 enscan 的版本报出来。现在每个工具按采样到的
  真实输出配锚定正则（PD 家族的 `Current Version:`、`hostCollision -h` 的 banner 等），匹配前
  先剔除路径；识别不了就返回空版本并标 `version_unknown`，同时留 `version_raw` 供人判断。
  （`6ca04ea`）
- **`brief` 的覆盖缺口不再丢失**：`coverage` 是按 run 存的，只给 `--match` 时以前会读到空块，
  看起来像"没有任何缺口"。现在 `brief` / `report --with-brief` 共用一套解析顺序
  （`--run` → 非默认 `--engagement` → 最近一个同 scope 的 run → 空），输出里带 `source` 与
  `known`，`known=false` 时直接给出提示，不把"没读到"说成"没有缺口"。（`b29939b`）
- **超时不再被说成失败**：一个阶段的所有来源都撞到截止时间时，`combine_outcome()` 现在返回
  `timeout`（以前归 `failed`），`subs` 阶段两种情形都写不进断点，退出码仍是 partial。
  调用方据 `failed` / `timeout` 区分"要换目标"与"要放宽 `--tool-timeout`"。（`b29939b`）
- **测试 runner 覆盖新用例**：`brief` / 覆盖语义 / 零 key / 版本解析 / 发布包 五组用例进入
  `python -m tests` 的全量运行，不再靠"记得单独跑"。（`40970b7`、`b29939b`、`6ca04ea`、`6ee0e1b`）

### 安全

- 密钥脱敏：JS 泄露里识别出的 AK/SK 只输出"前缀 + 长度"（`_redact_secrets`），完整凭证
  不进 Agent 的上下文，也不进日志。（既有行为，`0.8.0` 起在文档里写明）
- 发布包永不携带密钥：`bin/config.yaml`（ENScan Cookie）、`config/.env`、`config/config.json`、
  `config/scope.json` 按路径排除，只带 `.example` 模板；`build-release.py` 的自检会再查一遍。
  （`40970b7`）
- `icp --from-store` 的范围约束（见"破坏性变更"）：共享的 ICP 表不再被无范围地全量反查，
  避免把别的项目的备案号发到第三方测绘平台。（`40970b7`）

### 文档

- `SKILL.md` 从 28030 B 压到 15266 B，`prompts/AGENT.txt` 从 19518 B 压到 11964 B：Agent 入口
  只留"何时用 / 必跑闭环 / 硬规则 / 结果判读"，参数细节、数据模型、故障表移入 `docs/`。
  体积由 `tests/test_docs_commands.py` 的预算测试守住。（`3226ebe`）
- `prompts/AGENT.txt` 的命令示例现在必须真的能跑：每条命令都带 `--task`，带 `--from-store`
  的必须带范围参数，前台只跑短命令、采集一律 `run --background`，主动阶段前必须过授权确认。
  这些由 `tests/test_docs_commands.py` 逐行检查。（`c424628`、`3226ebe`）
- `docs/CLIENTS.md`：Claude Desktop 的聊天 / Cowork 究竟能否加载第三方 skill、会话跑在本地还是
  云端，官方文档在现有网络下核实不了，如实标为"待确认"，只保留能确定的结论（Windows 包的
  `.exe` 在 Linux 沙箱里跑不了）。（`c424628`、`3226ebe`）
- `README.md` 改为面向人的介绍 / 安装 / 快速开始 / 文档索引，不再重复 Agent 规则。（`3226ebe`）
- 发布包与 `install.py --copy` 共用 `scripts/shipped.py` 的同一份清单，不再各写一套忽略规则；包内去掉运行时读不到的 `<tool>/config.yaml` 与 `subfinder/provider-config.yaml`。（`8518583`）
- `docs/DEVELOPMENT.md` 补发布包规则表与构建自检说明。（`6ca04ea`）

### 已知问题

- **`40970b7` 单独检出时不可用**：这个提交里 `findinfo.py` 已经调用 `core.engine_has_key()` /
  `core.split_engines()`，而这两个函数在同一个提交的 `lib/core.py` 里还不存在；
  `tests/__main__.py` 也注册了当时尚未提交的测试模块。历史已推送，不改写，只在此说明。
  请以 `v0.8.0` 为准。

## 发布前 / 0.7.2 及更早

本文件从 0.8.0 开始记录。0.7.2 及更早的改动见 `git log`（`v0.7.2` 之前未打 tag，
对应提交为 `e793464`）。

[Unreleased]: https://github.com/TulipFleur/findinfo/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/TulipFleur/findinfo/compare/e793464...v0.8.0
