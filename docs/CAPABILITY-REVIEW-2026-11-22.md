# findinfo 收集能力评审：红队侦察与企业资产盘点

审查日期：2026-11-22（Asia/Shanghai）。目录：`E:\AI\skills\findinfo`。版本：`0.8.1`。提交：`425355c9865819c10d55dc78878bbed59043aab3`。

本报告只评价当前源码，不沿用上一轮 8ad6493 的缺陷作为当前事实。没有执行真实资产收集、DNS 查询、第三方 API、原生采集工具或读取实际配置/凭据。所有验证资产均为合成数据。本次为整体能力评价，包含 DNS 基础链路；上一轮“暂缓 DNS 修复”的实施边界仍有效，本报告不修改业务代码。

## 1. 总评与评分口径

**综合评分：75/100。**

定位：已经具有实际工程价值的公网资产侦察与线索整合工具，适合由 Agent 管理已知主体/根域的第一轮收集、验证和 Web 攻击面扩展。集团主体穷尽、跨根归属核验、深度前端分析和大规模发现保全尚不充分，不能以一次 complete 承诺“目标全部资产已经收齐”。

该分数是专家视角的实现能力评审，不是实测召回率、归属准确率或生产任务成功率。评分同时考虑生产接线、能力边界和离线证据；不会因为 README 列出工具名就给满分，也不把未承诺的漏洞利用能力作为缺陷。旧报告 60/100 偏重可靠性设计验收，与本表口径不同，不能用两个总分直接计算版本进步或退步。

| 维度 | 满分 | 得分 | 依据 |
|---|---:|---:|---|
| 被动发现与测绘来源 | 20 | 17 | 免钥聚合、CT、subfinder 与逐引擎 mapping 已接线；实际默认来源少于声明清单，上游效果未实测 |
| 主体覆盖与资产归属 | 15 | 10 | 逐主体隔离改善明显；集团关系扩展有限，名称兜底把搜索命中提升为批准种子 |
| 公网验证与基础画像 | 15 | 12 | HTTP、技术、证书、CDN、端口和 Host 差分有用；DoH 接线、端口/vhost候选存在覆盖边界 |
| Web/JS 深度扩展 | 15 | 10 | 有爬取、参数/接口/秘密线索和持久 JS 队列；正则为主，无动态执行和 source-map 回溯 |
| 回流与大目标覆盖 | 10 | 7 | 可多轮、续跑、预算和截断可见；默认根域/IP/轮数有限，部分线索未形成完整回流 |
| 证据、去重与交付 | 10 | 8 | 图、来源、时间、置信规则、报告和导出较完整；mapping逐资产证据与复用时间仍有损失 |
| Agent 长任务契约 | 10 | 7 | 后台、状态保护、恢复和有界等待有实质实现；参数重放、cursor和极端brief仍有缺口 |
| 成本与来源控制 | 5 | 4 | 付费映射集中、任务缓存、密钥隔离和额度状态可见；尚非跨进程严格预算控制 |
| **合计** | **100** | **75** | |

## 2. 两个专业视角的判断

### 红队前期侦察

最有价值的是把被动发现、存活画像、源站/IP候选、虚拟主机和前端线索串成一个可继续处理的图，并提供 Agent 能读的摘要。对一个已知且获准的根域，能够生成后续人工验证和漏洞挖掘的入口集合，而不只是一份子域名列表。

“内网服务发现”需要收敛表述：目前是从当前网络可达的 IP 上，尝试发现依赖特定 Host 路由的 Web 虚拟主机。它不等于具备内网可达性、横向发现、隧道或登录后资产发现能力。Jenkins/GitLab/Swagger 等标题、技术或路径是优先检查线索，报告中的高分也不是漏洞确认。

### 企业资产收集

最有价值的是逐主体资产、备案与域名关联、APP名称入库、共享资产图、来源去重和任务隔离。它适合作为已批准主体和已知范围的外部资产盘点底座。

“完整收集一个集团”的首要难点是先确定集团包含哪些主体、品牌、独立根域、历史实体和可批准资产。当前主要依赖 ENScan 的单一企业数据源与名称门禁，并未形成经过核验的集团关系图。即使某几个根域的子域名枚举充分，也不能证明集团根域和主体集合已穷尽。

## 3. 已经落地的收集能力

| 能力层 | 当前实际能力 | 实际价值与限制 |
|---|---|---|
| 主体与备案 | ENScan企业候选、域名/备案/APP，逐实体引用和批准后落库 | 避免把多主体JSON全部混挂；APP主要是名称资产，不等于已经逆向获得其API |
| 免费被动来源 | onepass当前默认8个免钥源、独立CT、免钥subfinder | 冷启动有实用性；8个来源不等于8个互相独立的数据集 |
| 付费mapping | 域名查询支持FOFA/Quake/Hunter/Shodan模板；备案查询支持FOFA/Quake/Hunter | 按引擎语法派发，缺钥匙/无语法/截断可见；不能把工具支持列表视为已成功调用 |
| DNS与验证 | 多探针泛解析证据、fake-IP过滤、系统fallback、DoH及httpx | 基础能力认真；有效结果到下游及暂态完成判定仍有接线问题 |
| HTTP画像 | 状态、标题、技术、IP/CNAME、CDN、favicon、证书与endpoint | 对攻击面优先级排序有价值；并不证明资产归属或漏洞存在 |
| IP/端口/vhost | CDN/WAF辅助过滤、共享IP候选、naabu端口、Host差分与curl fallback | 公网虚拟主机线索有用，候选选择和默认端口限制深度 |
| Web/JS | katana爬取、域/IP/API路径/参数/秘密线索、跨轮JS持久队列 | 队列已真实接入；语义分析与复杂前端覆盖仍较基础 |
| 交付 | SQLite图、关系/观测、置信规则、brief、md/html、JSONL/XLSX | 适合Agent摘要和下游工具；必须区分累计库、当前run、候选、已验证结果 |

关键源码：[逐主体解析](E:/AI/skills/findinfo/lib/tools.py:204)、[批准资产落库](E:/AI/skills/findinfo/lib/tools.py:511)、[免钥subs](E:/AI/skills/findinfo/lib/tools.py:1249)、[逐引擎模板](E:/AI/skills/findinfo/lib/core.py:620)、[mapping派发](E:/AI/skills/findinfo/lib/mapdispatch.py:353)、[httpx](E:/AI/skills/findinfo/lib/tools.py:1740)、[JS持久调度](E:/AI/skills/findinfo/lib/tools.py:2797)。

应正向计入的版本改进：旧JS双队列问题已改为run内work_items；租约回收与retry_at已有实现；状态token检查移入同一锁；首次启动有身份；brief使用最终encoder；离线入口在runtime前分流。不能继续把旧问题原样列为现状。

范围边界：当前生产路径未发现专门的代码组织/仓库搜索、云对象存储枚举、ASN/CIDR扩展或Wayback/CommonCrawl历史URL回填适配器。APP/小程序支持名称入库，尚无包解析和API逆向；sourceMappingURL能够识别，尚无下载与解析消费者。这些是后续扩展方向，不应作为项目已承诺但实现失败的功能扣分，也不能把JS里的密钥正则匹配等同于这些采集能力。

## 4. 真正限制收集质量的部分

### 4.1 公司名兜底提高了可启动性，但归属核验不足

ENScan不能锚定时，生产路径会按名称询问mapping，然后把返回域以 `mapping:name`、confidence=0.9、approved=True挂入名称派生的主体种子。默认走domain查询，并没有先证明该域的备案/主体确实属于用户目标。

这是一项有明确触发条件的归属风险，不代表已经观察到真实美团资产误归属。专业收集应先将这些命中作为候选，再用主体、备案、官网等证据批准；不能把搜索词来自用户等同于所有搜索结果已被用户确认。

位置：[名称询问](E:/AI/skills/findinfo/lib/mapdispatch.py:466)、[提升为批准种子](E:/AI/skills/findinfo/findinfo.py:2472)、[0.9落库](E:/AI/skills/findinfo/findinfo.py:2485)。

### 4.2 集团范围和默认预算限制比工具数量更重要

ENScan默认invest=51、deep=1，branch/supplier为选项；名称门禁仍较保守，别名和股权关系没有形成可逐实体扩展的批准图。默认只对前5个根域做onepass/CT/subs，默认1轮、vhost最多10个IP、top ports=1000。这些大部分可配置，也有coverage_limits，属于能力边界而非所有情况下的bug；但它们意味着默认一次运行不能承担“集团全量”的承诺。

onepass源码包含15个来源定义，当前默认生产路径实际为8个免钥来源。付费mapping单独运行；配置了VT、SecurityTrails等钥匙，不代表当前默认onepass会自动使用它们。来源包装不同也不能算独立佐证。

位置：[ENScan参数](E:/AI/skills/findinfo/lib/tools.py:549)、[根域预算](E:/AI/skills/findinfo/findinfo.py:2791)、[覆盖限制输出](E:/AI/skills/findinfo/findinfo.py:2809)、[默认参数](E:/AI/skills/findinfo/findinfo.py:4081)、[onepass生产调用](E:/AI/skills/findinfo/lib/tools.py:3058)。

### 4.3 主动验证不等于所有端口和隐藏站点已经穷尽

IPagg只把同一IP至少两个域名作为candidate；vhost默认以前10个IP、已有候选Host和80/443/8080/8443运行，并跳过已返回200–499的活域。naabu发现的新端口没有自动送入vhost，独占IP也没有统一的碰撞覆盖。ports无共享IP候选时回退scope IP，不能据此承诺所有CDN均被排除。

HTTP证书SAN已接入下一轮，这是实用加分项；端口TLS抓取虽实现，run调用没有传入scope且只提取count，其SAN尚未完整回流。

DoH结果以doh来源落库，但下游已解析来源集合不含doh；暂态DNS工作也仍可能按成功确认。这影响全链路验证覆盖。本轮不实施DNS修复。

位置：[候选筛选](E:/AI/skills/findinfo/lib/tools.py:1974)、[vhost输入](E:/AI/skills/findinfo/findinfo.py:3188)、[活域跳过](E:/AI/skills/findinfo/lib/tools.py:2347)、[HTTP证书回流](E:/AI/skills/findinfo/findinfo.py:3125)、[端口调用](E:/AI/skills/findinfo/findinfo.py:3176)、[DoH来源集合](E:/AI/skills/findinfo/findinfo.py:1545)。

### 4.4 JS能提供线索，深度语义与发现保全仍不足

JS提取以正则为主，没有AST/动态执行、可靠变量拼接恢复或实际source-map抓取。路径的HTTP方法等元数据有限。run固定传空crawl_rows，而JS提取预先按roots过滤domains，all_domains未被消费，所以实际抓取JS中的跨根相关域不能完整保留为候选。

还有两个静态可见的保全窗口：JS先commit_result标done，后到_finish_tail写真实资产/API endpoint；两步之间退出可能留下done却缺发现。多轮extract_findings.update会把后轮空api_paths/secrets覆盖到前轮汇总。这些尚未做中断端到端复现，不能称已经发生的数据丢失，但应优先于增加更多工具处理。

位置：[正则提取](E:/AI/skills/findinfo/lib/jsleak.py:54)、[run传参](E:/AI/skills/findinfo/findinfo.py:3259)、[done与tail边界](E:/AI/skills/findinfo/lib/tools.py:2835)、[后轮覆盖](E:/AI/skills/findinfo/findinfo.py:3267)。

### 4.5 资产“有记录”与“可解释归属”仍有距离

mapping结果压缩为kind/canonical后统一source=mapping，具体引擎、查询主体/备案、端口/协议等部分证据没有贯穿资产关系。缓存表保留旧observed_at，但缓存返回到pipeline再次upsert/attach时仍可能写入当前时间。置信度0.95是规则分数，不是统计测得的95%准确率。

run末尾部分counts/endpoints来自整个Store，brief/report主要按scope从全库读；适合展示累计盘点库，但不能直接描述为本次run新发现。大库get_assets默认上限100000，超过50个scope时先LIMIT后Python过滤，还存在规模边界。

位置：[mapping落库](E:/AI/skills/findinfo/lib/mapdispatch.py:542)、[缓存返回](E:/AI/skills/findinfo/lib/mapdispatch.py:375)、[当前时间写入](E:/AI/skills/findinfo/lib/core.py:2343)、[run汇总](E:/AI/skills/findinfo/findinfo.py:3367)、[report读取](E:/AI/skills/findinfo/lib/report.py:278)、[规则置信度](E:/AI/skills/findinfo/lib/core.py:1924)、[资产读取上限](E:/AI/skills/findinfo/lib/core.py:2424)。

## 5. 本轮离线验证与当前反例

### 验证方法

复制当前提交的文本代码到不含配置/凭据的临时目录；97个Python文件逐一SHA256与源目录一致，AST检查无语法错误。原生工具只放空名称占位，以覆盖工具存在分支，禁止真正执行。Python启动期guard阻止网络、DNS、配置访问和原生工具，并传递到Python子进程。实际外部适配器由测试替换，真实CLI、Store、队列和状态路径保留。

选择13个相关测试模块，共144个用例：**138通过、6因外部采集/进程控制路径未隔离而被guard阻断**。这些6项不算验证通过，也不能据此判定用户真实环境中的产品测试失败。起初4项被审查脚本的Windows命令行解析影响；修正审查脚本后仅重跑这4项，均通过。按guard事件携带的原测试ID归因，避免后台日志跨测试串算。

模块覆盖：JS/lease、jobs/wait、ownership、output/offline、audit/docs、mapping ledger/dispatch/queries、engine queries、store scope、scope policy、onepass truncation和title decoding。没有执行全部测试，更没有验证真实上游接口、真实供应商数据和多小时存活。

### 额外定点验证

| 场景 | 当前结果 | 证据边界 |
|---|---|---|
| 后台单独传`--no-mapping` | 原计划无mapping；实际持久化worker argv重放后no_mapping=False，计划重新包含mapping | 真实parser/启动准备/持久spec；spawn替换为空操作，没有启动真实worker或付费请求 |
| 后台单独传`--remap` | 请求为True，worker argv重放为False | 同上；未证明真实已扣费 |
| brief包含合法长中文阶段错误 | 上限32768，真实stdout与brief_bytes均为73586，rc0，单行合法JSON | 真实CLI与持久化状态；当前问题是裁剪不完整，旧编码差异已修复；不代表普通摘要均超限 |
| 连续三次CLI wait | 第二次看到进展；使用其返回cursor进行第三次wait，无变化仍changed=True，cursor未推进 | 真实CLI/本地状态，不发送网络；默认不传since的等待模式不由此判定失效 |
| 同一备案号`-1/-2`经真实模板渲染 | 两次不同查询、两次假原生派发，第二次没有复用 | 真实mapdispatch/mapping，core.run为记录适配器；不是两次真实扣费 |

额外定点验证与4项脚本修正重测均无guard拦截事件。

当前接口位置：[worker argv](E:/AI/skills/findinfo/findinfo.py:2010)、[RunSpec转换](E:/AI/skills/findinfo/lib/spec.py:120)、[wait cursor](E:/AI/skills/findinfo/lib/jobs.py:975)、[brief收缩退出](E:/AI/skills/findinfo/lib/report.py:1436)、[备案身份计算](E:/AI/skills/findinfo/lib/mapping.py:105)。

本机复现材料：`C:\Users\小鲨鱼\AppData\Local\Temp\findinfo-capability-20261122-1u5gtosz`。关键文件为`final_summary.json`、`final_results.json`、`probes.json`、`single_flags.json`和`long_brief.stdout.json`。均为合成数据，不含真实资产或凭据。

## 6. 专业使用建议与提高能力的优先级

1. **优先保准确性和控制契约。** 名称mapping命中先作为候选；后台no-mapping/remap必须完整重放；JS发现与完成标记一致提交，汇总按并集合并；交付区分库中累计、当轮验证和本次新增。
2. **再把已有线索真正消费完。** 完善端口证书SAN、naabu端口→vhost、JS跨根相关域、分页/截断继续策略；保留严格scope，不通过自动批准相关域提高表面数量。
3. **按目标形态设置预算。** 集团级先建立批准主体和根域清单，再明确max-seed/rounds/vhost IP与时间预算。展示截断、来源不可用和业务预算都进入交付，不把稳定域数解释为完整性证明。
4. **再扩展新信息面。** 登录态/动态页面、source-map与前端语义、历史URL、代码组织和云资产等应作为独立能力设计；不是把更多工具名加入列表即完成覆盖。
5. **建立可比较基准。** 用固定合成集团/域/IP/JS/端口集合测已知真值召回、误归属、请求次数、时间和恢复保全；另在获准环境测上游兼容及实际资源开销。以后对同一套基准评分，避免不同审查口径的总分相互比较。

完成条件应写成：“在约定主体、scope、来源、时间及请求预算内，已处理义务与剩余缺口都有证据。”不要写成“该集团全部互联网资产已收齐”。
