# Changelog

本项目的对外变更记录，格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

每条都标注了对应的提交，可用 `git show <短哈希>` 核对。

## [Unreleased]

### 非 DNS 自动化修复（docs/NON-DNS-REPAIR.md）

- **JS 与租约**（`b542692`）。run 模式只以 work_items 调度/统计 JS，standalone
  沿用 Store.js_*；只把真实发现且允许的 JS 入队（HTML/JSON 不再是待办），成功项
  不重开；旧队列按可证明归属幂等迁移，未知归属保留并报告；claim 修好 retry_at、
  过期 running 回收、每次新 token，旧 token 不能写结果或确认；结果+membership+
  ack 在同一有效租约下提交，网络在事务外。
- **作业与等待**（`64439c0`）。首次启动也生成 attempt/token；状态读、token 校验、
  seq 与写入在同一锁内；pipeline 进度/心跳/终态都走围栏；旧 worker 存活时报占用
  而不另起；旧无 token 任务由控制入口迁移；wait 用持久化实质进展游标，compact/full
  都保留 attempt/terminal/reaped_by_host/gap。
- **资产归属**（`5b9196a`）。ENScan 按实体保留资产，只授予已批准主体；别名种子不再
  依赖 parent==搜索词；短品牌保守策略不放宽；历史复用标记 reuse 并保留原
  observed_at，不伪造当前观测，也不混入其他 run。
- **输出与配置**（`0bab11a`）。brief 合并全部字段后用最终 encoder 裁剪计量，
  brief_bytes 等于真实 stdout 字节（含换行，二进制写出避免 CRLF 差 1）；显式 0 保留；
  resume 只比较明确输入；dry-run resume 与实际恢复共用有效 spec；离线入口在 runtime
  导入前分流，不读配置、不建目录。
- **记录与操作**（`d8951dd`）。invocation 每次派发独立 ID、重试追加不覆盖、按真实
  dispatch_seq 排序；审计区分真实重复派发与日志重放、provider_http/native_dispatch
  单位、未结算状态；IP:port 目标明确报 unsupported_target_kind；同步 SKILL/AGENT/
  TOOLS/DATA-MODEL。
- **真实测试修正**（`b770666`；前序 docs 同步见 `8ad6493`；状态锁被慢速存活持有者误抢的修复见 `0853ce4`，changelog 补引见 `3e980b2`、`a2030be`、`2d60688`；方案与审查文档入库见 `9951c97`；brief 补带 run 自身判定（complete/partial_stages/result_status）见 `6fd7ab2`；changelog 补引见 `cbb209f`、`376473b`）。
- **页面标题按页面自身编码解码；新增 xlsx 导出**（`f6e48d6`、`0350465`）。hniu.cn 的 mail.mail.hniu.cn / xs.hniu.cn / mail.xs.hniu.cn 标题曾被存成 `������Ϣְҵ����ѧԺ`：页面是 GBK 且未声明 charset，httpx 按 UTF-8 解码产生 U+FFFD，属不可逆损坏。现按「页面声明 charset → utf-8 → gb18030 → cp936 → big5」解码；标题含 U+FFFD 的主机才额外取 `-irrb` 原始 body 重解；同时修掉 run/run_stream 固定 utf-8 读取原生工具输出（Windows 控制台 cp936）的同类问题；新增 `probe --repair-titles` 修复库内已损坏标题，不可达主机如实报告不猜。另新增 `assets --export-xlsx`：按资产类型分 sheet（域名/IP/URL/公司/备案/端点）并写说明页记录范围与计数；openpyxl 缺失时给结构化报错。对湖南信息职业技术学院
  实测发现并修复：旧任务 checkpoint 命中时因缺少 subject ref 丢种子；缺可选密钥时
  icp 被误判为阶段失败并导致 exit 5；resume 后 percent 超过 100；无 crawl/extract
  阶段时迁移的 108 条 open JS 变成无人消费的永久缺口。

### 接线批次（docs/RELIABILITY-PLAN.md 落地收尾）

- **W1：主流水线接入运行成员与持久工作队列**（`aa9a840`）。轮次输入改为读
  本 run 的 run_assets 成员（不再从共享图重新 scoped），兄弟 run 的资产不再
  喂进本 run 的解析器；种子落库 / entity 域 / cert SAN / dns 结果全部经
  attach_asset（成员+观测+下游工作单事务提交）；每个阶段派发写入
  stage_invocations（checkpoint 命中记 reused）；dns 阶段对自有工作项
  claim/finish（执行与跳过两条路径都结算）；extract 把本 run 排队的 JS
  bundle 收编进持久队列；未完成工作项进 coverage.work_queue，判定链新增
  work_pending（域名数稳定 ≠ 收敛）。
- **W2：启动/回放/resume 统一走 RunSpec**（`61759f3`）。删除手写
  _foreground_argv 与 argv 拼接合并：worker argv 来自
  RunSpec.from_cli().to_worker_argv()，job.json 存 run_spec；复用路径经
  diff 报告 request_differences（不把新限制悄悄套到运行中的作业）；
  resume 走 resume_patch 语义——显式限制字段可改，显式给出的
  身份/范围/引擎变更直接拒绝（退出码 2 + 结构化报错），裸 resume 逐字节
  回放原 argv。
- **W3：计费调用逐请求入账本**（`e7fa4be`）。run 持有一个
  MeteredLedger（run_dir/metered.jsonl，带公共 run id），t_subs/t_icp 的
  fofa 网关调用与 uncover 派发各记一行（每请求一行，绝不按结果行计）；
  免费来源不入账；verdict 的 quota 判定读账本的 blocked_engines（不再只靠
  stage 透传标志）；coverage.metered 与 `brief --run` 从落盘文件给出
  totals/by_engine/blocked_engines。
- **W4：entity 阶段接入主体门**（`cfaac5d`）。ENScan 正常返回但品牌命中
  多个可信主体且无显式种子时，报 identity_ambiguous（含候选与
  input-required next_steps）并在 discovery 之前停下（exit 5，自己的
  summary/verdict，下游阶段不算缺口）；显式种子或唯一命中照常通过。
- **W5：dnsx 与 DoH 共用一张 wildcard 证据表**（`8608489`）。DoH 路径不再
  探测 `wild.<parent>` 也不再用去掉首标签的探测名当键；两条路径都走
  doh.wildcard_probe_names（多次不可预测探测，无额外标签）+
  record_wildcard_probe（普通 A/CNAME 计签名，fake/超时不证明任何事），
  键统一为可注域名；候选地址全等于 wildcard 回声才过滤，带独立地址的
  混合证据保留；报告行带 parent/ip/cname/probes/signature。
- **W6：worker 状态写入全过围栏**（`f9a4bf2`）。worker_main 入场认领
  launch token 后，running 写入、硬超时判定、终态发布全部改走
  fenced_write；被替换的尝试中途不能覆盖新尝试的进度、不能盖上
  task_timeout 判定、终稿被整体丢弃并记日志；无 token 的旧 spec 保持
  原行为。

### 0.8.x 维护提交补录

- 收敛提取域名的范围与通配符探测的可信度，资产带上时间戳（`947bfaa`）。
- CHANGELOG 覆盖检查允许最新的两条提交暂时缺席（编辑本文件的提交不可能
  包含自己的哈希）（`d0ecfe7`）。
- 面向客户端的使用说明收窄为仅限本地代理场景（`b9967c5`）。

### 批次实施（docs/RELIABILITY-PLAN.md，基线 `20dfca3`）

- **A：阶段结果不再丢失，完成判定从义务推导**（`75059e9`）。`subs` 的阶段投影
  丢弃了自己算出的 outcome，`_stage` 于是默认补成 `ok`，一个部分成功（某引擎超时、
  其余正常）的 subs 被写成 succeeded + done 检查点，重跑永久跳过。现在投影带上
  outcome 和 sources；最终判定新增两个分支：`partial_stages`（执行了但自报未完成）
  和 `planned_stage_not_run`（计划内必需阶段没有产出）都判 `partial`/退出码 5，
  并在 reason 里点名阶段。缺 key 仍是覆盖缺口，不触发退出码 5（T02–T05）。
- **B：统一 RunSpec、`--dry-run` 与离线 doctor**（`904ebef`）。新增 `lib/spec.py`：
  from_cli / to_worker_argv / dedupe_identity（身份与限制分离：同目标不同限制复用
  同一作业，差异经 diff 报告而不悄悄生效）/ resume_patch（只允许 rounds 等限制字段的
  更新，身份/范围/引擎变更直接拒绝）/ json 往返与 schema 版本拒绝。
  `run --dry-run` 只做规划：run_id 为 null，不建库、不读凭据、不启动进程，与
  `--background`/`--resume` 组合保持只读。`doctor --offline` 不执行任何工具、
  不探测网络：出口/工具健康/凭据状态一律 `not_checked`（不是 false）。
  登记 p2 遗留的 `test_dns_coverage`、`test_fake_ip` 模块（T20/T32）。
- **C：运行成员、观测与持久工作队列**（`8a54c12`）。新增 `lib/work.py`：run_assets
  （按运行记录成员，两个 run 互不串扰）、observations（逐来源逐上游证据行，重观测
  加证人但不放大去重后的独立上游）、work_items（带租约 token/过期/重试的持久队列，
  唯一键防重复入队）、stage_invocations（逐尝试历史，修复后的尝试成为有效结果）。
  attach_asset 单事务原子提交资产+成员+观测+下游工作；claim 短事务发 token，过期
  token 不能提交（崩溃围栏）；legacy JS 队列只在归属可证明时迁移（T08–T11、T16、
  T29–T31、T33）。
- **D：主体门、类型化目标与统一 wildcard 证据**（`2041ea2`）。品牌短名匹配出的多个
  主体是候选而非自动归属：歧义时报 `identity_ambiguous` 并要求补输入，不自动选一个
  就开始探测；显式种子绕过歧义。seeds 按主体引用查找，改名不断链。相关 SAN/同 IP
  邻居只是证据，不扩大主动范围；裸 IP 与 ip:port 目标保端口到底。`lib/doh` 的
  wildcard API 统一 dnsx 与 DoH 两条路径的证据与键（此前 DoH 的键含探测标签，同一
  区域两份记录）；普通 A/CNAME 计入签名，fake/超时不证明任何事；带额外独立地址的
  候选保留而非抹除（T06、T07、T12–T15）。
- **E：带围栏的 resume 与经核实的等待游标**（`0c980e1`）。resume 全程持跨进程锁：
  状态重读、存活检查、attempt 递增、launch token 发布、排队落盘、spawn、PID 发布
  都在锁内完成，并发 resume 只产生一个新尝试和一个 worker；败者看到胜者的活作业并
  报告复用。worker 入场即认领 token，被替换的尝试退出码 4 且不碰任何状态；
  fenced_write 对每次状态变更重验 token（T17–T19、T21）。
- **F：计费请求账本**（`21690fb`）。新增 `lib/metered.py`：按请求（而非按结果行）
  追加的账本，类型化状态 ST_OK/EMPTY/TRUNCATED/QUOTA/AUTH/FAILED；status_of 一次性
  归类，下游不再重复猜字符串；fofa 网关的 remaining/maxQueries 原样归一到配额字段；
  quota_remaining 返回最新已知上限，None = 未知（不是无限）；blocked_engines 只列
  quota/auth（传输失败可重试，凭据被拒不许盲试）；同输入同状态的重复追加不重复计费，
  状态变化才是新支出；失败请求也入账（花了钱没拿到数据，不能从支出汇总里消失）
  （T22–T27、T34）。
- **G：阶段注册表与验收收口**（`7191ae7`，`b898a80` 修复项一并收口）。
  StageRegistry 在导入期校验：缺 runner、重名、依赖环、幻影阶段全部报错；
  `_plan_stages` 只能返回注册过的阶段名（T01）；文档与安装产物校验收口
  （T28）。

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
- 内部：提交对照检查只放过最新提交（它无法在自己的变更日志里写出自己的哈希），更早的都要在册。（`5cc8b1c`、`723103d`、`ec3ed32`）
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
