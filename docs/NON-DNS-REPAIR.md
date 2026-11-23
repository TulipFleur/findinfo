# findinfo 非 DNS 修复方案与实施 Agent 提示词

> **历史方案，不代表现状。** 2026-11-21 基于 `8ad6493` 写的设计方案与实施提示词；“尚未实施”是当时的状态。当前行为以 `SKILL.md`、`prompts/AGENT.txt` 和 `docs/` 下的参考文档为准；之后的修复见 `CHANGELOG.md`。本文只在源码仓库保留，不进发布包。

日期：2026-11-21。权威目录：`E:\AI\skills\findinfo`。审查基线：`8ad6493bf6be387d03a91f4c594590f58d1c8360`。状态：设计方案，尚未实施业务代码修复。

## 1. 本轮边界与证据

用户要求暂时忽略 DNS。本方案排除 F02、F03、F11 以及解析器、DoH、泛解析和 DNS 到 probe 的业务策略调整。通用队列、状态锁、输入准入可能被多个阶段共用；可以修改这些共享机制，但必须记录影响，不借此修改 DNS 策略或启动真实请求。本轮验收中的外部阶段使用合成适配器。

最新版目录已确认，不再要求用户重复确认，也不以旧发布副本解释当前源码问题。实施前只记录实际 HEAD 和已有改动；若源码已变化，重新核对对应反例，不能机械套用行号。

| 条目 | 证据与定位 | 本轮处理 |
|---|---|---|
| F01 JS 双队列 | 真实 CLI 与持久队列已复现成功后仍 pending | 修复 |
| F04 租约与退避 | SQLite/真实函数反例；不是多小时实际任务实测 | 修复通用队列 |
| F05 worker 状态所有权 | 真实模块、状态文件、受控交错已复现；未测自然发生频率 | 修复，并新增 CLI 竞争验收 |
| F13 wait、F14 brief | 真实 CLI 已复现 | 修复 |
| F07 历史归因与统计 | 函数/存储反例 | 修复，并补 CLI 汇总验收 |
| F09 离线入口 | 目录副作用经 CLI 复现；配置加载是静态导入链结论 | 修复 |
| F15、F16 RunSpec/resume | 函数反例及静态接线证据 | 修复，补真实恢复预览验收 |
| F06、F10 实体/别名 | 前者是条件风险；后者含保守品牌策略与别名种子缺陷 | 保留保守策略，修归属与种子 |
| F17 调用记录与 Registry | 查询有函数级报错；普通主流程未调用该查询 | 修查询、历史保留与文档；不重写调度器 |
| F08 计费 | 审计契约和控制能力缺口；未证明实际错误扣费 | 修审计口径；完整预算控制单列 |
| F12 IP/endpoint | 输入支持范围与实际路径不一致 | 明确支持边界；本轮不扩展完整工作流 |

这些编号不代表相同数量的真实任务故障。不得据此声称实际美团资产已串目标、账户已错误扣费或所有普通 run 都会失败。

## 2. 实施顺序与模块边界

推荐顺序：A JS/租约 → B 作业恢复/wait → C 资产归属/历史 → D 输出/配置契约 → E 调用记录/审计/文档。A 与 B 的库实现可并行，涉及 `findinfo.py` 的集成由一个 Agent 负责，避免多人覆盖同一文件。批次测试不依赖未修复的其他批次；最终验收再组合运行。

### A. JS 工作必须能完成和恢复（F01、F04）

修改边界：`lib/work.py`、`lib/tools.py:t_extract`、`lib/core.py` 的现有队列接口及 `findinfo.py` 的 extract 集成/统计。

1. 为 `t_extract` 增加可选 run 上下文。有 run 时以现有 `work_items` 为唯一 JS 调度与统计来源；standalone 继续使用原 `Store.js_*`。统一 enqueue/claim/finish 的选路，同一工作不能双写后又双消费。
2. 删除将全部输入 URL 交给 `adopt_js_backlog` 的做法。由真实发现逻辑筛选 JS 及现有允许的相关资源；HTML 可用于发现资源，但不能作为未处理 JS 入队。保留现有 scope、资源大小和请求预算限制。
3. 以 `(run_id, stage, kind, canonical, input_revision)` 去重。相同 revision 的成功项保持 done；内容确需刷新时显式建立新 revision，不能每轮重新打开。
4. 网络获取和解析放在数据库事务外；提交 JS 结果、该结果的 run membership 与确认工作项时，在同一事务检查有效租约。旧 token 不得先写结果、再只在 ack 时被拒。限制到 JS 提交路径，不要求重写所有采集器。
5. 修正 `claim`：pending/failed 到 `retry_at` 后可领；running 到 `lease_expiry` 后可原子重领；每次领取新 token。读取与更新保持一个短事务，并发时一项只能被一个持有者领取。失败区分可重试和终止，累计尝试有明确上限；延期工作仍计 outstanding，终止失败进入 gap。
6. 迁移旧 JS 队列必须有原 run manifest、资源引用等归属证据，不能只按域名后缀认领。已完成记录不能重开；保留状态、尝试、错误和时间。迁移幂等，未知归属留在原处并报告。新 run 只读取选定后端；旧表保留供 standalone 兼容。

验收：

- 合成首页发现一个 JS，成功后本 run outstanding=0；首页不在 JS 队列；重复一轮不重复抓取成功项。
- 41 个资源、单批预算 40，后续轮次能处理剩余一个；预算耗尽时给出 partial/gap，不能假完成。
- claim 后中断，到期可以恢复；旧 token 无法改结果或状态；`retry_at` 前不能重领，到期后能领；两个并发领取者不能获得同一有效租约。
- 旧 done/pending/failed/unknown 混合迁移两次，done 不重开、unknown 不认领；另一 run 的 backlog 不影响本 run；standalone 行为兼容。

### B. 恢复所有权和 Agent 等待契约（F05、F13）

修改边界：`lib/jobs.py` 和 `findinfo.py` 的启动、resume、`_write_status`、`cmd_wait`。

证据边界：F05 已复现的是受控旧写竞争。不可变 spawn 身份与锁持有者是否被超时抢占，是静态发现后的新增检查点，须用下面的竞争验收确认，不能追加为已经发生的真实任务故障。

1. 首次启动与每次恢复均分配 attempt/token。启动子进程时传递不可变身份；worker 校验该身份后才能领取执行权，不能晚启动后读取最新 job.json 就冒充新 attempt。
2. 状态读取、token/attempt 检查、字段合并、seq 更新与文件替换在同一状态锁内完成。pipeline 进度、heartbeat、超时、取消与最终写入都走受保护接口；宿主管理操作有明确入口，空 token 不能成为任意绕过条件。
3. 固定锁顺序：若同时涉及去重、启动控制、状态，则按该顺序获取；普通 worker 只取状态锁。执行工具、等待进程退出时不持有状态锁。检查现有锁是否可能仅因超时就抢占存活持有者；如存在，先做本地竞争反例再最小修正。
4. 存活旧 worker 优先复用或报告占用；明确需要接管时，先确认旧 worker 退出再启动下一 attempt，不能仅改状态就假定已退出。状态 fence 不承诺撤回在途请求或保证外部调用 exactly-once。
5. 持久化最后一次实质变化的 seq。stage/counts/结果/终态等变化更新进展标记；纯 heartbeat 不更新。`wait --since N` 比较持久化标记，不能只与本次 wait 开始快照比较。旧状态无此字段时使用有说明的兼容行为，不能静默漏报。
6. `jobs.wait` 各返回分支都生成 attempt、terminal、reaped_by_host、result 和必要 gap/恢复字段；compact 与 full 只在大字段上有差别。布尔 false 也必须保留。
7. 兼容旧无 token job：旧进程仍存活时只复用或等待，不就地换 token。确认退出后，由持有启动控制锁的入口迁移、生成身份再启动；worker 不得自行补 token 或以空 token 放行。旧任务继续可读。

验收：

- 用 barrier 控制旧写与新 attempt 的交错，旧 heartbeat/阶段/终态写全部被拒，新状态保持不变。
- 延迟旧 worker 启动、同时提交两次 resume，只产生一个有效执行者；旧 worker 不能领取新身份。另覆盖首次启动、spawn 失败和旧 worker 仍存活。
- 两次真实 CLI wait 之间 stage/counts 已改变，携带旧 seq 立即报告 changed；只有 heartbeat 则不当进展。默认与 full 都含相同 attempt 和恢复决策字段。

### C. 资产必须归属正确，历史复用不能伪造新观测（F06、F07、F10）

修改边界：`lib/tools.py` 的 ENScan 解析/身份选择、`lib/work.py` 的 membership/observations、必要的 `Store` 写入边界，以及 pipeline 种子/汇总。

1. ENScan 按实体保留 `subject_ref/legal_name/aliases/domains/icp/evidence_ref`。优先使用来源主体 ID；没有时标明名称引用。不要先把多实体资产 flatten 后挂到第一个保留公司。
2. 分开解析、主体选择与资产提交。只有批准主体的资产可以授予 scope；未知归属作为候选证据保存。显式域名独立授权该域名，不等于批准所有返回主体。
3. pipeline 使用已批准主体的明确域名/备案集合，恢复时使用该 run 的持久化锚点和 membership。修复 `parent == args.name` 的别名种子依赖，保留 parent 的兼容展示用途。
4. 保留短品牌的保守准入；无法确认时输出候选及所缺输入，不用模糊子串自动放宽范围。
5. 用真实采集写入集合记录本 run 的 membership，不能用截断的展示列表代替。移除 `_adopt_membership` 全 scope 扫描后伪造当前 pipeline observation 的行为。可采用已有 Store 的局部写入收集或显式采集返回集合，选择改动较小的一种。
6. 历史复用保留原 observed_at/upstream/evidence_ref，另外记录 attached_at 和复用原因；仅附入 membership 不刷新观测时间。counts、endpoints、JS backlog 使用当前 run 集合，全库统计单列。老数据归属不明时标明未知，不倒推编造历史。

验收：

- 合成 A、B 两主体及独立资产，只批准 A 时，B 不能进入 A 的种子、scope 或主动工作；无匹配主体不提交已批准资产。
- 别名和法定名称不同但通过既定选择规则时，种子不丢失；空库与已有 parent 的库行为一致；多个候选时保持待选择状态。
- 同一 home 预置同后缀历史域和另一目标；未重新观测不得产生当前时间的假 observation。允许复用时明确标注且保留旧时间；另一目标不影响本 run 统计。

### D. 输出、RunSpec 与纯离线入口（F09、F14、F15、F16）

修改边界：`lib/core.py:emit`、`lib/report.py`、`lib/spec.py` 与 CLI 的 brief、resume、dry-run/bootstrap。

1. brief 先合并 coverage、metered、note 等完整对象，再裁剪；最终计量和 stdout 使用同一 encoder，包含 ASCII/UTF-8 策略、分隔符与末尾换行，并覆盖 Windows 的实际 stdout 编码和换行行为。最终 `brief_bytes` 等于真实字节数，之后不追加字段。文件输出也按实际写出格式计算，不能混用紧凑 JSON 和带缩进格式。
2. 裁剪长错误、warnings、scope 和 metered 时保留结果、gap 摘要、截断标记和全文引用。全局 minimal 模式不能剥除 brief 必需字段。过小或非法 max-bytes 明确拒绝；不能输出残缺 JSON 或静默超限。
3. RunSpec 只在未提供/None 时应用默认值，合法 `entity_timeout=0` 保持为 0；非法值明确拒绝。恢复只比较用户明确输入的身份字段，相同 domain 接受，未输入字段沿用存储值。
4. 实际 resume 和 resume dry-run 共用纯数据合并函数：加载 stored spec → 校验明确输入 → 应用允许的限制补丁 → 得到有效 spec → 规划。未知 schema 或损坏 spec 报兼容错误；仅缺少 run_spec 的旧 job 可按既有 argv 兼容导入。
5. 离线/dry-run 分支前移到 runtime 导入之前；仅保留标准库、纯 parser/RunSpec/规划逻辑。正常执行再加载 core/tools。离线预览只读指定任务元数据，不加载配置、不创建 home/cache/runs/SQLite，不执行工具或探测网络；能力显示 not_checked。确有必要才拆出纯逻辑模块，不能用仍提前导入 runtime 的空壳转调。

验收：

- 真实 brief CLI 输入合法长中文错误和合成 metered，在默认 ASCII 与 UTF-8 模式下均为单个完整 JSON；原始 stdout 字节不超限且与 brief_bytes 一致。覆盖 minimal 模式与非法上限。
- 显式 timeout=0 经 job→argv→CLI 仍为 0；同 domain 恢复通过，改变不可变身份被拒且 attempt 不增加。
- 已有主动任务的 dry-run resume 与实际恢复使用同一有效目标、scope、阶段和限制，且不改变状态文件。
- Python 入口安装 guard 后执行 dry-run/离线诊断，禁止配置读取、网络、原生进程、SQLite 和 mkdir；不存在的 home 执行后仍不存在。读取指定 job 的许可元数据不算配置读取。

### E. 调用记录、审计口径、输入声明和文档（F08、F12、F17）

1. `stage_invocations` 每次派发生成独立 invocation_id，重试不能 INSERT OR REPLACE 覆盖前次记录。若需排序字段，做向后兼容的增量迁移，使用真实存在的稳定顺序；修复 `effective_invocations ORDER BY id` 查询。有效结果按 run/attempt/stage/unit/revision 选取，旧尝试仍可审计。
2. Registry 目前不是生产调度来源。修正文档的完成声明，校验现有计划与实际阶段的一致性；本轮不把手工调度迁入新框架，也不为完成标记挂空 runner。
3. 计费审计为每次实际派发保留独立 dispatch/attempt 身份，区分“对同一次事件重复写日志”与“同查询真实派发两次”。后者不能被 query hash/状态去重吞掉。旧日志保持可读；只有开始没有结束的记录恢复后标为未结算，不能推断未收费。
4. 明确计数单位：直接可观测的 provider_http、原生工具 native_dispatch；uncover/onepass 的一次派发不能解释为一个上游 HTTP 请求或准确金额。onepass 的来源可观测范围和不可控边界必须输出，配置凭据不代表已发生调用或扣费。
5. 对可直接控制的后端，已明确 quota/auth blocked 后本轮不再派发该后端，其他后端可继续。不能观测内部派发的原生工具不能宣称已受逐后端控制；用户明确要求严格费用限制而该路径无法约束时，跳过并报告原因。
6. F12 不新增 IP/IP:port/IPv6 endpoint 完整工作流。核对公开输入承诺和现有支持路径：当前路径不能处理的输入在破坏性归一化前明确报告 unsupported_target_kind/具体限制；不能先丢端口再显示没有种子。已受支持的显式 URL 等路径保持兼容，不一律拒绝所有含端口输入。
7. 同步 `SKILL.md`、`prompts/AGENT.txt`、相关工具说明与完成标记。Agent 按后台启动→保存 run_id→有限时间 wait→依据 changed/terminal/gap 恢复或读取 brief 操作；等待不视为失败，不通过反复启动新 run 代替等待。

验收：同一 unit 重试保留两条 invocation；有效选择不引用不存在字段。相同查询实际派发两次审计为两次，同次日志重放不重复计数；原生派发标明单位，未结算记录恢复后仍未结算；quota/auth 后受控后端停止、其他后端继续。未支持目标在采集前明确拒绝。标准测试入口包含实际新增验收，不能只有一个未被 runner 执行的新测试文件。

## 3. 单列的后续能力

完整的跨进程预算预留、收费请求并发合并、分页缓存和外部扣费 exactly-once，不作为本轮默认交付。若后续需要，先单独定义额度单位、可控来源、失败结算与恢复语义，再实施。当前不能用缺少这些能力证明已发生费用故障，也不能继续标记为完整预算控制。

完整 IP/endpoint 收集入口及调度 Registry 统一同样单列。本轮先保证现有受支持流程可解释、可恢复、可验收。

## 4. 验证与完成要求

- 所有资产使用 `.example`、`.test` 等合成域和文档 IP；测试使用临时 home/数据库，不读取或修改真实配置与凭据，不清空用户任务和资产。
- 保留真实 CLI/parser、调度、Store、队列、状态写与 verdict；仅替换外部采集/传输适配器。竞争使用 barrier，退避使用受控时钟，不能靠长时间 sleep 碰概率。
- 从 Python 启动起阻止真实网络、解析和原生采集进程，并覆盖子进程。意外 guard 触发必须使对应验收失败，不能被上层捕获后仍计通过。专门测试 guard 本身的预期拦截除外。
- 每批提交可 review 的改动清单和针对性结果；通过后仅因新改动或相关失败扩大回归，不重复无关测试。本轮不运行需联网的 DNS 验证。
- 最终报告区分代码已改、真实 CLI 已验证、仅函数验证、尚需实际环境确认。不要把 fixture 的 complete 推广为真实全流程已经无缺陷，也不要因本轮未修的 DNS 项仍存在而宣称所有问题已清零。

## 5. 可直接交给实施 Agent 的提示词

```text
你负责修复 E:\AI\skills\findinfo 面向消费级 Agent 的自动化可靠性。
先阅读 docs/NON-DNS-REPAIR.md；审查基线为 8ad6493，但以当前工作区为准。
这是实施任务：完成范围内代码、兼容迁移、针对性验收和操作文档。

【范围】
暂不处理 DNS，包括解析器、DoH、泛解析、DNS 到 probe 及相关完成判定。
允许修通用 work 租约、状态锁和输入契约，但不要顺手修改 DNS 业务策略。
用户已确认最新版目录，不要再次要求确认目录，不要用旧发布包解释源码缺陷。
保留现有命令、历史资产/任务、兼容读取和退出码约定。保护工作区已有改动。

【按顺序实施】
A. JS：run 以 work_items 为唯一调度与统计来源；standalone 兼容 Store.js_*。
   由真实发现逻辑入队，移除全部 URL 的桥接；HTML 不变成 JS 待办。
   done 不重开，旧记录按明确归属幂等迁移，未知归属保留并报告。
   修 retry_at 与过期 running 回收，每次领取新 token；旧 token 不得写结果或确认。
   获取/解析在事务外，JS结果、membership与ack在有效租约保护下原子提交。
B. 作业：首次启动及恢复都有 attempt/token，spawn 向 worker 传不可变身份。
   状态读、身份校验、seq与写入在同一锁；进度/心跳/终态都不能绕过。
   旧 worker 存活时复用或报告占用，接管须确认退出；锁顺序统一。
   旧无token任务由控制入口在确认退出后迁移，worker不得自行补token或空token放行。
   wait 用持久化实质进展游标；两种输出均保留 attempt/terminal/reaped_by_host/gap。
C. 资产：保留逐实体资产对应，批准后才授予范围；别名种子不依赖 parent==搜索词。
   短品牌继续保守。历史复用保留来源和观察时间，另记附入时间；按当前 run 统计。
D. 契约：brief 所有字段合并后，用最终输出 encoder 裁剪并验证真实字节。
   RunSpec保留合法0，resume仅比较显式输入；dry-run与实际恢复共用有效spec。
   离线入口在runtime导入前分流，不读配置、不创建home/数据库；能力标not_checked。
E. 记录：修 invocation 查询/排序及重试覆盖；修审计去重、计数单位和未结算状态。
   明确原生工具的可观测边界；未支持的目标明确报错，不静默丢端口或种子。
   同步 SKILL.md、prompts/AGENT.txt、工具说明和完成标记。

【实现约束】
使用现有模块；确需拆分时只抽出有实际逻辑的纯模块。不要新建调度框架、
复制状态机，或为了让结果complete而清空队列、忽略outstanding、放宽实体授权。
完整预算控制、IP/endpoint新工作流、Registry统一不在默认交付内。
如并行分工，明确模块所有者，findinfo.py由一个集成者修改；不要回退他人改动。

【验收】
严格执行方案各批验收。必须保留真实CLI/parser/Store/队列/状态/verdict，
只替换外部适配器；函数测试补充边界，不能代替集成验收。
重点证明：成功JS归零；跨批预算能续跑；崩溃后租约可恢复；退避未到不领取；
旧token无写入权；并发恢复只有一个有效worker；wait不漏跨调用进展；
中文长brief真实stdout不超限；timeout=0保留；resume预览一致；
实体B不混入A；历史复用不伪造新观测；离线入口无配置/目录副作用。
使用合成资产、临时home、受控时钟/barrier，禁止真实网络和原生采集进程，
不得读取真实配置或凭据。意外guard触发不能吞掉后算通过。

【交付】
逐批给出改动文件、迁移兼容、实际命令和验证结果；最终列出已验证、
仅局部验证、尚需真实环境确认及暂缓项。不要新增随意的总分。
本任务不发布、不上传、不进行真实资产采集。完成可审查实现后交付。
```
