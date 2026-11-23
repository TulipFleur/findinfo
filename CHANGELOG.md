# Changelog

本项目的对外变更记录，格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

每条都标注了对应的提交，可用 `git show <短哈希>` 核对。

## [Unreleased]

### 发布包只装 agent 需要的文档

- **评审、方案和带日期的快照不进发布包**。`scripts/shipped.py` 新增 `is_dev_doc`：REVIEW-\*、
  CAPABILITY-REVIEW-\*、AUTOMATION-REPAIR、NON-DNS-REPAIR、RELIABILITY-PLAN、DEVELOPMENT、
  DIDI-COLLECTION-WORKFLOW 和 CHANGELOG 只留在源码仓库；`docs/` 下文件名带日期的文档一律不打包，
  以后新增的评审也不会混进来。这些文档描述的是某次提交时的代码，agent 读到“60/100、F01–F16”
  会把已修复的问题当成现状。仓库里它们顶部都加了“历史快照，不代表现状”的标注（本机安装直接读
  仓库，只排除发布包管不到）。README 不再链接包内没有的文件；新测试保证包内文档的相对链接都能
  在包内解析。
- **作业循环只写一份**。`prompts/AGENT.txt` 是唯一的分步循环；SKILL.md §1.5 只留四条要点和最小
  命令块；AGENT.txt 不再转述硬规则（改为指向 SKILL.md §0 / §1 / §5，转述迟早会和原文不一致），
  因此回到 12 KB 预算以内。TOOLS.md 末尾的 “Combined usage” 已经漂移成前台串行执行长命令
  （违反 SKILL.md §5 第 1 条），换成一行链接；滴滴流程文档里的循环副本同样换成指针。
- **SKILL.md 的判读细节移到 DATA-MODEL.md**：累计计数、复用答案的观测时间、JS 包与 HTML 的区别
  进入 §3 / §4；入口只留“`work_queue.outstanding > 0` 不算完成”和“truncated / known=false 不等于
  完整”两句并指向 DATA-MODEL。§2 的测绘语法链接改指 `docs/MAPPING-QUERIES.md`。

### 一次真实运行暴露的问题（2026-11-23 报告，`3e2abdd`）

- **ENScan 报告按真实结构解析**。一份 aqc 报告就是一家被查公司：`enterprise_info` 是主体，
  icp / app / wx_app / wechat / copyright 是它自己的资产，invest / partner 等是别的公司。
  过去每条带 `name` 的记录（APP、公众号、软著）都被当成公司，一份真实报告解析出 82 个
  "主体"，`company_name` 为空的 ICP 表因此谁都不归：用全称锚定成功，种子域名却是 0。
  现在 16 个备案域名、备案号和 APP 都归到被查公司；域名只取备案的 `domain`，不再把
  应用商店链接（apps.apple.com 等）当成公司域名——4 个字以上的 APP 名过去还可能
  通过名称门禁，把商店域名带进主动范围。
- **简称按自身资产锚定**。"滴滴"这样的简称不含于任何法定名称，名称门禁会全部拒绝。
  若报告里唯一的主体自己有至少 2 个 APP / 备案网站 / 公众号名称含该简称，就锚定它，
  entity 阶段标注 `anchor_basis: brand_evidence` 并列出 `brand_evidence`；没有这类证据的
  同名干扰项仍被拒绝。
- **ENScan 配置位置与模板**。ENScan 读取与可执行文件同目录的 `config.yaml`
  （`bin/<平台>/config.yaml`），文档与日志却一直写 `bin/config.yaml`。现在 ENScan 在 exe
  目录运行；只有 `bin/config.yaml` 时先复制过去。`bin/config.example.yaml` 改为与随附二进制
  内嵌模板同结构（`version: 0.7` 为数字，含 `user_agent` / `app` / `api` / `cookies`）。
  `doctor` 新增 `enscan_config`（位置、版本、Cookie 是否已填，不输出 Cookie）；配置缺失或
  版本不符时，entity 的阶段错误会写明。
- **测绘限流单独成态**。"请求过于频繁，当前限额 10 次/分钟"、429、rate limit 记为
  `rate_limited`（先于额度判断），不再记成失败：等一个窗口（`limits.mapping_rate_wait_sec`，
  默认 60 秒）后重问一次，仍被限流的问题下次运行自动重问，无需 `--remap`，也不会封禁引擎。
  FOFA 中转按自己的节奏发问（`limits.fofa_gateway_per_minute`，默认 10），单次行数不超过
  `limits.fofa_gateway_max_rows`（默认 2000）。
- **certs 不再因上游不通耗掉一小时**。`--tool-timeout 0` 过去被换算成 `--max-time 0` 加
  15 秒进程上限：慢但可用的 crt.sh 回答全部丢失，不通时每次尝试都耗满 15 秒。现在 0 即
  默认 60 秒，另加连接超时（`limits.http_connect_timeout`，默认 15 秒）。同一阶段里某个
  上游连续两个种子失败后不再询问；跳过的种子仍记为失败，阶段不写检查点，下次运行重试。
- **易用性**。`--domain a.com,b.com` 等同于重复传参；非法种子在后台任务启动前就被拒绝
  （退出码 2）；运行失败的原因写入 stderr，worker 结果带 `result.error`；`--top-ports`
  只接受 naabu 的预设 100 / 1000；naabu 失败时阶段错误附带它的 stderr。
- changelog 补引见 `a688189`、`c2ec2cf`。

## [0.9.0] - 2026-11-22

版本号提升与本节切分见 `97d9b55`。

本版把测绘收敛成唯一入口，修正计费口径与凭据判定，补齐 APP/小程序与「锚不到目标」两条资产面，并清理抽取噪声。含一次真实任务（南开大学，989 域名 / 106 存活 / 40,823 端点）暴露的十个缺陷。

### 结构调整

- **StageRegistry 成为真正的调度器**（`07f19ef`）。registry 移入 `lib/pipeline.py`，14 个阶段登记的
  是真实的阶段函数（原来全是 `lambda: None` 占位，生产代码从不调用）。每个阶段带
  `phase`：`seed` 在轮次前跑一次，`round` 每轮跑一次；运行时按 registry 顺序执行计划
  （`_plan_stages`）里的阶段，计划里出现未登记的阶段直接报错，不会被静默跳过。`icp`
  仍是展示用别名，由 mapping 派发，计划从不包含它。执行顺序与之前完全一致。
- **流水线拆成阶段函数**（`eb37643`）。`_run_pipeline` 从 1238 行缩成约 40 行的驱动；每个阶段是
  `lib.pipeline` 里一个以 `RunContext` 为参数的函数（entity / onepass / certs / subs /
  brute / mapping，以及每轮的 dns / probe / ipagg / ports / vhost / crawl / extract），
  阶段正文与原来一致。原先放在 `summary` 里、只有流水线自己用的私有键（`_ledger`、已批准
  主体的引用与名称、主体歧义判定）改为 `RunContext` 字段；`_stage` / `_attach` /
  `_adopt_membership` 读的 `_run_public_id`、`_run_producers`、`_stage_total` 保留在
  `summary` 里。`summary.jsonl` 和 stdout 的内容不变。
- **run 流水线移到 `lib/pipeline.py`**（`3c147bd`）。findinfo.py 只保留命令行层（参数解析、各子命令、
  后台启动与续跑）；`_run_pipeline` 以及只有它用到的检查点、心跳、状态写入、成员关系、
  计划与覆盖率/判定辅助函数原样搬入 `lib/pipeline.py`。findinfo 继续导出这些名字（就是
  同一个对象），`python findinfo.py …` 的用法、输出和 `__worker` 入口都不变；要改流水线
  行为，打桩点是 `lib.pipeline`。

### 能力评审修复（`716b622`，docs/CAPABILITY-REVIEW-2026-11-22.md）

- **`--no-mapping` / `--remap` 在每个入口都生效**。两者成为 `RunSpec` 字段：后台
  worker 的 argv 重放、`run --resume`、离线 `--dry-run` 预览都会带上，重放时不再
  丢失；按名称兜底同样遵守 `--no-mapping`，并把 `--remap` 传给付费派发。
- **`--max-seed` 默认 0，展开全部已批准种子**。正数仍是显式预算；旧任务里没有记录
  该字段的 spec 按当时的隐含上限 5 读取，升级不会扩大已有任务的范围。
- **`wait` 每次返回最新进度标记作为 `cursor`**，只有大于基线的标记才算新进展；
  心跳推进的 seq 不再被当成变化。
- **brief 用最终 stdout 编码器测量并裁剪**：长阶段错误、长 scope 也保证单行不超过
  上限，被清空的数组仍保留原始总数。
- 文档：SKILL.md 描述与流程、TOOLS / API-KEYS / TROUBLESHOOTING、AGENT.txt 的付费
  测绘步骤；新增能力评审报告与滴滴收集流程说明。

### 测绘每任务只做一次

- **测绘阶段合并、任务级账本、子进程免 key**（`6e190dc`）。来源：`37953fd`
  之后的改造。
  带 key 的请求只发生在唯一的 `mapping` 阶段（配套 `map` 命令）；同一任务内
  每个「引擎 + 规范化问题」只问一次，失败/配额/凭据被拒都记入任务账本且不自动
  重试，`--remap` 才是显式重问；复用结果保留原观测时间。`subs`/`passive` 改为纯
  免 key；`core.run` 默认不给子进程任何密钥（httpx/naabu 等拿不到），只有测绘
  派发按目标工具注入它真正读取的变量名（Hunter 对 uncover 是 `HUNTER_API_KEY`、
  对 onepass 是 `HUNTER_KEY` 等）。`uncover` 显式设置 `-limit`，满页标记截断。
  缺 key 或凭据被拒的引擎默认跳过并记为能力缺口，不报错、不反复重试。

### 仓库卫生与流水线拆分

- **流水线移入 `lib/pipeline.py` 并拆成阶段函数**（`3c147bd`、`eb37643`、`07f19ef`、`f8b7b62`）：
  `_run_pipeline` 由 1238 行缩为约 40 行驱动，14 个阶段登记真实函数（原为 `lambda: None` 占位），
  registry 成为真正的调度器并按 `phase`（seed/round）执行。
- **停止跟踪 9 个误提交的工具配置与一个伪路径**（`c02936e`）：ProjectDiscovery 二进制首次运行时
  会往当前目录写 `config.yaml`，`cdncheck/chaos/dnsx/httpx/katana/naabu/subfinder/uncover` 八个目录
  被误提交（`subfinder` 另含 `provider-config.yaml`），内容无任何密钥；`%SystemDrive%/` 是 shell 把
  未展开的环境变量当字面路径所建。两者均已忽略并在规则旁注明原因。

### 三次采集：域名 / 证书 / 备案号

- **测绘平台只能做第一次**。读随包 uncover 源码确认：`sources/result.go` 的 `Result` 只有
  `timestamp/source/ip/port/host/url`；各 agent 的请求字段也写死（quake `Include: ip,port,hostname`、
  fofa `Fields: ip,port,host`、hunter 只映射 `ip/port/domain`）。**证书与备案号在 uncover 这一层
  就被截断**，不可能从 `map` 拿到。因此三次采集分工：① 域名+IP 走 `map`（付费）；② 证书走
  `certs`（crt.sh→CertSpotter，免费）；③ 备案号走 `map --icp` / `entity`（备案号→域名的反向
  查询，而非「查域名的备案号」）。
- **证书成为一等资产**（原实现只取证书里的域名，证书本身丢弃）。`certs` 现在为每张证书写一行
  `assets(kind=cert)`，canonical 为 `CN|证书指纹前16位`（无指纹时退化为 CN|issuer|serial），
  attrs 带 `cn/issuer/serial/not_before/not_after/cert_sha256/tbs_sha256/revoked/san`，parent 为
  被查询域名；`certs` 返回值新增 `certs` 计数；`assets --kind cert` 与 xlsx 的「证书」sheet 均可查。
  CertSpotter 不发布 issuer，改存 `cert_sha256`/`tbs_sha256`/`revoked`（这三项才是跨源去重的依据）。
- **备案反查保留归属**。`store_results` 过去把域名/IP 写成无 parent 的行，报告无法说明某个主机属于
  哪个备案号；现在 mapping 结果携带「问句上下文」，ICP 反查所得以 `parent=<备案号>` 落库，
  source 也区分 `mapping:icp` / `mapping:domain`。
- **每个引擎单独定上限**（原为全局 3000）。uncover 在所有引擎上都是 100 行/页，所以 `-limit` 是
  页数预算；而一页的代价不同（fofa 按查询计费、quake 每页 100 credit）。移除全局默认，改为
  `mapdispatch.ENGINE_LIMITS`：quake 3000（= 免费月额度）、fofa/shodan/hunter 1000；覆盖顺序
  `mapping_rows_<engine>` > `mapping_rows` > 引擎自有上限 > `DEFAULT_LIMIT`。
- **页数估算按工具实际请求大小**。fofa 的 API 允许 `size=10000`，但 uncover 硬编码 `Size=100`，
  按 API 上限估算会把 10000 行算成 1 页；改用 `ENGINE_PAGE_MAX` 记录工具真正请求的行数。

### 实体与 APP 面补全

- **ENScan 的 APP / 小程序不再被丢弃**。`app` / `wx_app` / `wechat` 字段一直被解析并
  出现在阶段返回值里，却**从未落库**，于是 brief、report、xlsx 里 APP 数量恒为 0——
  一个 ENScan 报了十多个小程序的主体，在交付物里完全看不见。现在按
  `assets(kind=app)` 落库（含归属主体），`assets --kind app`、xlsx 的「APP/小程序」
  sheet 均可查。存储逻辑抽成 `tools.store_approved_entities()`，不必启动 ENScan
  二进制即可测试。
- **ENScan 锚不到目标时，改由引擎按名称收集主域名**（`425355c`）。过去 `anchor_failed`（aqicha
  无此关键词，或只返回同名干扰项）直接抛 `StageError` 结束，把唯一可用的事实
  （公司名）丢掉。现在不终止：用名称向各引擎发 `domain="<名称>"`，答案以
  `mapping:name` 落库并挂在由名称派生的主体引用下，再由正常种子流程接管；阶段结果
  带 `name_probe`（应答/尝试/跳过的引擎），全部引擎失败时标记 `unavailable` 而不是
  静默空跑。名称不经域名规范化（中文名会被整条丢掉），由 `uncover_query` 的引号
  剥离保证仍是单个词项。
- **ENScan 失败时保留按名称查到的种子**（`3537574`）。ENScan 非 0 退出且没写出 JSON（例如爱企查
  Cookie 失效）时同样锚不到目标，会改由引擎按名称询问；但随后的退出码检查抛出
  `StageError`，把引擎答到的主体一起丢掉，运行以 `seed_domain_required` 结束。现在
  entity 阶段仍记为失败（不写检查点，修好 Cookie 后重跑会再试 ENScan），引擎答到的
  域名照常作为种子继续收集，结果为 `partial`、退出码 5。
- **只锚定到主体、没有域名时给出可执行的下一步**。过去直接报 `no seed domain`
  并以退出码 2 结束，把唯一已确认的事实（公司）丢掉，Agent 无从下手。现在返回
  结构化错误 `seed_domain_required`：`candidates` 是已锚定的主体名，`queries`
  是可直接执行的引擎查询（`icp="<名称>"` / `domain="<名称>"`），`hint` 说明用
  `map --name` 去查再用返回结果做种子。新增 `map --name/--kind`：中文公司名不经过
  域名规范化（会被整条丢掉），由 `uncover_query` 的引号剥离保证仍是单个词项。

### 采集准确性修复

- **测绘引擎按各自语法逐个查询**（`fd9acda`）。uncover 会把 `-q` 原样发给每个引擎、不做语法转换；
  `subs` 过去把 Quake 语法 `domain:"x"` 一次性发给 fofa/quake/hunter/shodan/censys，
  `icp` 把 FOFA 语法 `icp="x"` 发给 quake/hunter，除一个引擎外都可能静默返回 0。
  现在每个有 key 的引擎单独派发：subs 用 fofa `domain="x"` / quake `domain:"x"` /
  hunter `domain="x"` / shodan `hostname:"x"`，icp 用 fofa `icp="…"` / quake `icp:"…"` /
  hunter `icp.number="…"`（fofa/quake/hunter 与 onepass 一致）；结果按
  `uncover:<engine>` 归属，计费记录按引擎分行。没有已知语法的引擎（subs 的 censys、
  icp 的 shodan/censys）不再盲发，记入 `unsupported_engines`；rc=0 且无结果的派发标记
  `confirmed: false` 并记入 `unconfirmed_empty`，经 `coverage.unavailable` 进入 brief。
  icp 的空结果不再算作阶段错误。查询模板进入 subs/icp 的 checkpoint 输入（仅有可用引擎时），
  已用旧查询完成的阶段会重跑。
- **单阶段命令读库必须带范围**。probe/dns/passive/subs/icp/ipagg/ports/vhost/crawl/extract
  在从共享资产库取目标时（`--from-store` 或未给显式目标），必须给 `--scope`（vhost/crawl/extract
  用 `--domain`），否则以 exit 2 和 `{"error":"scope_required"}` 拒绝执行；范围里没有合法域名
  同样拒绝，不再退化为全库。`--whole-store` 是显式全库开关。`ports` 新增 `--scope`
  （别名 `--domain`），从库中只取归属于范围内域名的公网 IP，私网/保留地址跳过并返回
  `skipped_private`（显式 `--ip` 照常使用）。`ipagg` 新增 `--scope`。`vhost --wordlist`
  未给 `--domain` 时用被碰撞主机的注册域，不再取全库域名。`Store.get_assets` 与
  `t_ipagg` 对 `.local` 等私有后缀的范围不再放宽为全库（新增 `core.canon_match`）。
- **onepass 0.2.0：翻页与截断上报**。VirusTotal（`links.next`，仅同源）与 urlscan
  （`search_after`）按页预算翻页；本 skill 默认取上限 20 页（`limits.mapping_pages`，
  口径是最大程度收集资产，免费游标页不额外计费），`--max-pages` 仍可 1–20；FOFA/Quake/Hunter 不自动翻页
  （每页消耗配额），改为报告上游总数。每个源返回 `pages`/`truncated`/`total`，被截断的源进入
  `truncated_sources` 与 `coverage.unavailable.truncated_sources`。Windows 二进制已重建；
  Linux 二进制需用 `scripts/build-onepass.sh` 重建。
- **查询语法可配置、显式上限、操作员自检**（`3b8ed81`）。每个引擎的查询模板可由
  `config/config.json` 的 `mapping.queries.<kind>.<engine>` 覆盖，模板缺少
  `{value}` 占位符在加载时报错（旧模板只对一个引擎正确，其余静默返回 0）；
  每条派发都显式传 uncover `-limit`，**它是花费上限而不是越大越好**：uncover 对
  quake 固定 `Size=100` 并用 `Start` 偏移循环翻页（`sources/agent/quake/quake.go`），
  每页计费。真实账户实测：`-limit 1` 扣 100、`-limit 100` 扣 100、`-limit 10000`
  在 50 行的答案上扣 **700**（7 页）。但**一页的成本与返回 10 条还是 100 条无关**，
  小 limit 不省钱、只是把同一次花费拆成多次往返并增加拿不全的概率。因此默认值
  **一次拉满 3000**（= quake 免费额度 3000 credit ÷ 1 credit/行，约 30 页），
  一个问题一次问完、一次付清、不重复；按引擎覆写用 `limits.mapping_rows_<engine>`，
  余额更少时按余额下调，而不是靠反复小批量试探。每次派发记录 `pages`；
  可选用 `limits.measure_credits` 在派发前后读余额得到实测值（默认关闭，避免多余请求）。
  满页标记 `truncated` 并进入 `coverage.unavailable.truncated_sources`。新增
  `doctor --check-mapping --domain X`：每引擎一条 `-limit 1` 最小查询，逐引擎报告
  key/语法是否被接受，不写任务账本。本 skill 由 Agent 自动驱动，**不设同意闸门**
  （单次开销由构造保证有界），旧参数 `--yes-spend-quota` 仍然接受但被忽略。
  依据（二进制字符串 + 上游源码 + 官方文档）与新文档
  `docs/MAPPING-QUERIES.md` 一并入库，无法离线确认的条目列为待真实验证。
- **读库策略 `scope.unscoped_reads`；APP/小程序落库；无域名时给出引擎查询**（`b17e97c`）。单阶段命令从共享库取目标而未给
  `--scope`/`--domain` 时按策略处理：`infer`（默认）在库中只有一个注册域时
  自动采用并输出 `scope_source:"inferred"`，库中混有多个目标仍拒绝；
  `refuse` 从不推断；`legacy` 读全库并打印告警（旧脚本兼容）。拒绝时输出
  `{"error":"scope_required","candidates":[...],"scope_source":"refused"}`，
  `candidates` 是库自身能给的候选注册域；输出一律带 `scope_source`
  （`explicit`/`inferred`/`whole_store`/`legacy`），调用方不会把推断范围误当
  显式范围。私网/保留地址过滤移入 `tools.t_ports`（`run` 流水线直接调用同一
  函数），`--ip` 显式给出的地址照旧原样使用。
- **抽取降噪与预算**（`7efc7e2`）：JS 拼接碎片、版本号假 IP、内网地址不再进入资产图；JS 抓取预算改为 `limits.js_fetch_limit`（默认 2000）；brief 补带 `coverage.metered`/`coverage.mapping`；`crawl 未运行` 假警告改按证据判断。
- 测试注册表收录 `test_mapping_queries` / `test_scope_policy`（`32d92fa`）；changelog 补引见 `0a79e51`、`74fc88a`、`8b834da`、`4d55eaa`、`9dc10a6`。
- **后台作业终态只有一个写者**（`504f3fb`）。pipeline 过去在每次运行结束时也写
  `state="completed"`，而后台 worker 还会带着 `exit_code` 再写一次；前者产生的
  帧里 `completed` 没有 `exit_code`，而 `wait` 把 completed 当终态，调用方会撞上
  一个真实终态里必然存在的字段缺失（worker e2e 约 1/6 复现）。现在后台由 worker
  单次围栏写入终态，前台由 pipeline 自己写并给出退出码。修复后连跑 18 次 0 失败。
- 文档示例全部补齐范围参数，并新增测试保证文档中的读库命令都带 scope。
- changelog 补引见 `2b79f90`。

## [0.8.1] - 2026-11-21

本版把 docs/NON-DNS-REPAIR.md（非 DNS 自动化修复）五个批次全部落地，并修正两轮真实任务暴露的缺陷。范围不含 DNS 解析器 / DoH / 泛解析 / DNS 到 probe 及相应完成判定。

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

- 忽略本地发布产物与草稿目录（`b28046a`）；0.8.1 解包发行版构建、版本号与
  changelog（`936ce79`）。
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

[Unreleased]: https://github.com/TulipFleur/findinfo/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/TulipFleur/findinfo/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/TulipFleur/findinfo/compare/e793464...v0.8.0
