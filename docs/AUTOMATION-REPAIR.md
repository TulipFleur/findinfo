# 自动化修复方案：先确定运行入口，再修已复现闭环

> **历史方案，不代表现状。** 2026-11-21 基于 `8ad6493` 写的修复方案；“尚未修改业务代码”是当时的状态。当前行为以 `SKILL.md`、`prompts/AGENT.txt` 和 `docs/` 下的参考文档为准；之后的修复见 `CHANGELOG.md`。本文只在源码仓库保留，不进发布包。

日期：2026-11-21。源码基线：8ad6493。状态：方案，尚未修改业务代码。

当前范围更新：用户要求暂时忽略 DNS，后续实施以 [非 DNS 修复方案](NON-DNS-REPAIR.md) 为准。本文保留为前次完整审查的方案记录，其中 DNS 批次不属于当前授权实施范围。

版本定位补充：用户已确认最新版目录为 `E:\AI\skills\findinfo`。本次复核该目录 HEAD 仍为 8ad6493，关键运行文件哈希与前述离线复现一致。以下实施以此目录为准；旧发布副本仅作为构建身份的管理提示，不作为当前源码缺陷的归因，也不要求用户再次确认源码目录。

本方案替代一次性完成全部可靠性设计的做法。先处理可重复验证的故障；未完成的产品能力和依赖真实环境才能确认的问题单独列账，不混作同一级 bug。

## 1. 第零步：确认修改是否真正被使用

已知源码与旧发布目录同为 0.8.0，但实现不同；SKILL/AGENT 指令也未同步本轮改动。

1. 保存一次实际启动的 Python 路径、CLI 绝对路径、SKILL 绝对路径、home/task/run_id、attempt 和工具解析路径。只记录非敏感元数据。
2. 对源目录、安装链接/副本和发布副本比较运行模块哈希，不以 VERSION 相同推断代码一致。确认实际入口后再决定是否更新安装或重新构建；不删除旧任务和数据库。
3. 为构建产物生成不含凭据的 build-info，包含源提交及运行模块清单哈希；doctor/status/启动结果显示 build_id、skill_root、有效 home/task。独立副本应明确显示构建身份，不能依赖运行环境存在 .git。
4. 固定现有命令和配置做离线基线。测试必须完整走真实 CLI/调度/Store/verdict；只替换外部适配器，禁止联网和原生工具回退。正常对照与故障反例成对保留。

退出条件：确认实际运行的文件；未知项明确为未知，不推断用户一定用了旧发布包。

## 2. 第一批：DNS 不能错误完成

修改：findinfo.py 的 _dns、dns_resumed、DNS work 确认和最终收敛；必要时扩展 lib/tools.py:t_dns 的返回字段。

- 保留现有批量解析方式与旧输出字段，补全每个输入域的明确状态。
- resolved、权威 NXDOMAIN、策略认可的 wildcard 等可结算；transient_fail 保留待重试，NODATA/CNAME-only 不伪装 NXDOMAIN。
- 缺少逐域状态是契约错误；批次异常、timeout 或 partial 不能将整批任务以 ok=True 确认。
- probe 输入来自当前 run 的有效解析状态；DoH 与其他 resolver 使用相同规则。不能只给来源白名单添加 doh 后继续接受历史失效状态。
- 未处理暂态工作进入最终 partial/gap；未达到可重试时间或预算时停止并解释，不忙循环。

验收：相同 CLI 下 transient 不能返回 complete；NXDOMAIN 对照可以完成；DoH 成功域确实进入假 httpx，历史 NXDOMAIN 不进入。检查持久队列和最终输出，不能只检查 helper 返回值。

## 3. 第二批：JS 和租约完成闭环

修改：lib/work.py、lib/tools.py:t_extract、现有 Store.js_* 适配边界、findinfo.py 中的 JS 回流与统计。

- run 模式选择 work_items 为唯一可领取的 JS 状态源；t_extract 接收可选 run 上下文，直接 enqueue/claim/finish extract 工作。
- 删除 pipeline 对全部输入 URL 的 adopt_js_backlog；只把实际发现且允许处理的 JS 作为 JS 工作，不能把 HTML 或已成功的 JS 再建为 pending。
- 无 run 的 standalone 保持旧 js_queue 兼容。两个后端通过一个适配边界选择，同一工作不能同时在两套队列领取。
- 旧任务只在证明归属后迁入对应 run；done 不变回 pending，未知归属显式保留。不能用清空队列或跳过 outstanding 来让任务看起来完成。
- 原子回收 lease_expiry 已到期的 running 项；领取检查 retry_at、累计尝试与 owner token。结果和输入确认使用同一事务，旧 token 不得确认新租约。
- 使用当前 run 的 JS/work 统计，正常完成与恢复后都可归零。保留失败和预算延期原因。

验收：发现并成功处理一个 JS 后只执行一次且队列归零；相同参数无 JS 的对照同样可完成；领取后崩溃能恢复一次；未到 retry_at 不领取；旧 token 完成被拒；其他 run 的待办不影响本轮。

## 4. 第三批：恢复与输出契约

修改：lib/jobs.py、findinfo.py 的首次启动/resume/_write_status/cmd_wait/cmd_brief、lib/report.py 与 core.emit 的编码边界。

- 首次启动也分配 attempt/launch_token。恢复先拿运行启动锁，再拿状态锁；全项目统一这个锁顺序。读状态、验证 token、写状态在同一状态锁内完成，避免先检查后加锁。
- _write_status、heartbeat、阶段进度和最终 verdict 全部经过同一受保护入口。明确的宿主管理操作另列接口，不能靠空 token 随意绕过。
- resume 发现旧 worker 仍存活时复用或报告占用；需要停止时先确认退出，再启动下一 attempt。不能承诺撤回已经发送的外部请求。
- 同一状态锁内记录最后一次实质变化的 seq；wait --since 直接比较该标记。心跳不当进展，旧状态无标记时做一次显式同步。
- 默认 wait 与 full 都保留 attempt、reaped_by_host、terminal、result、必要 gap 信息；字段在底层生成，不能只修改 compact 白名单。
- 用同一 JSON-line encoder 处理最终完整对象；追加 metered/note 后再测量，计入 ASCII 转义、分隔符和换行。保留有界最小结果摘要及全文引用，再裁剪长文本。
- RunSpec 使用 None 判断缺省值，保留合法 0；resume 仅比较明确输入的身份字段；dry-run resume 预览真实存储 spec 与允许的 patch。

验收：真实状态文件的受控旧/新 worker 交错不能覆盖；跨两次 CLI wait 的变化立即可见；默认字段足够决定恢复；中文长错误下真实 stdout 不超限；timeout=0 前后台一致；相同身份字段重复输入不误拒。

## 5. 第四批：资产归属、历史复用与依赖环境

- 保留 ENScan 实体及其资产的对应关系；按 subject reference 取种子。短品牌可保守要求补充身份，不能为了跑通而放宽自动范围。
- 不断言所有集团成员都无关；无法证明归属的资产作为候选/相关证据，避免直接扩大主动范围。
- 显式复用历史证据时保留原始 observed_at、upstream，并记录 attached_at；run 输出按本轮成员统计。
- 在实际工具版本、来源权限、配置位置、网络模式未知时，先提供诊断结果。凭据不搬运到包中，不通过真实请求试错消耗额度。
- 收费模块当前按审计定义准确命名并显示统计口径。前置预算、跨进程请求复用、uncertain 是后续独立交付；不能用缺少这些能力证明已经错误收费。需要控制费用时，先明确排除无法观测的收费来源。
- 同步 SKILL/AGENT/TOOLS 的恢复、等待、缓存与完成判定说明，再更新完成标记和发布说明。

## 6. 可交给实施 Agent 的指令

```text
在 E:\AI\skills\findinfo 修复自动化。先阅读 docs/REVIEW-2026-11-21.md
第7节和本方案，确认实际Git状态、运行入口、构建身份及已有改动。

先完成第零步，再按前三批修复已复现的生产闭环。使用现有模块，
不要重新搭建框架、复制状态机或扩大功能范围。每批独立报告改动与证据。

保留现有命令、数据库、可读取的历史任务和退出码。迁移必须可解释，
不清空历史资产、不忽略待办、不把partial改成complete来让测试通过。

验证必须运行真实CLI/调度/Store/队列/verdict，只替换外部collector。
每个故障反例附正常对照，断言真实stdout、队列状态和调用次数。
测试无本地凭据，禁止网络与原生工具执行，也不得吞掉guard异常后算通过。

先把DNS暂态、JS完成归零、崩溃恢复和原子fence验证通过，再推进其他项。
计费与主体相关条目按证据区分已复现bug、设计缺口及条件风险。
不要仅因出现同版本旧包，就推断用户实际运行旧包。

同步Agent操作文档。每批列出已验证、尚未验证和需要实际环境才能确认的项。
本任务不发布或上传release，不进行真实资产采集。
```
