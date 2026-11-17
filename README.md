# findinfo — 资产测绘 Skill

给一个企业名或域名，产出一张带来源与置信度的资产图，供后续漏洞挖掘使用。

## 快速开始

    cd <本目录>

    # Linux：先装原生二进制（Windows 用内置 bin/*.exe，跳过这步）
    bash scripts/setup-linux.sh --dry-run   # 看计划
    bash scripts/setup-linux.sh --cap       # 安装 + 授权 CAP_NET_RAW

    # 0) 安装到各客户端（Claude Code / Codex / DSH），只需一次
    python scripts/install.py --status
    python scripts/install.py

    # 1) 自检（工具 + Key + 授权范围）
    python findinfo.py doctor

    # 2) 配 Key（可选，不配也能跑 80%）
    cp config/.env.example config/.env
    #    ENScan 的 Cookie 单独配：
    cp bin/config.example.yaml bin/config.yaml   # 再填入 aiqicha Cookie

    # 3) 纯被动测绘（零接触目标）
    python findinfo.py run --name "企业名"

    # 4) 主动阶段（需要授权范围）
    cp config/scope.example.json config/scope.json
    python findinfo.py run --name "企业名" --active --vhost --crawl

    # 5) 导出
    python findinfo.py assets --export runs/assets.jsonl

## 文档

| 文件 | 内容 |
|---|---|
| SKILL.md | AI 使用说明：何时用、流程、硬规则、故障处理 |
| docs/TOOLS.md | 每个命令的参数、输出 JSON、示例 |
| docs/API-KEYS.md | **哪些需要 key**、申请地址、免费额度、不配的后果 |
| docs/LINUX.md | Linux 部署：装二进制、CAP_NET_RAW、systemd/Docker、故障排查 |

## 内置工具（已全部下载到 bin/，无需联网安装）

| 类别 | 工具 |
|---|---|
| 企业信息 | ENScan_GO（源码编译，需 Cookie） |
| 子域 | onepass（Rust，15 源并行，8 源免 key）、subfinder、chaos、uncover（聚合 FOFA/Quake/Hunter/Shodan/Censys） |
| 爆破 | ksubdomain（无状态裸包，需 Npcap） |
| 域名 | crt.sh、CertSpotter（内置 HTTP 封装） |
| DNS | dnsx + 系统解析兜底 + 泛解析过滤 |
| 存活 | httpx（状态/标题/指纹/IP/CNAME） |
| 侦察 | cdncheck、naabu、tlsx |
| 碰撞 | 内置 Host+SNI 探测器（socket / curl 双模） |
| 内容 | katana、gau、ffuf、jsleak（纯 Python） |

## 核心设计

1. **确定性优先**：能工具化的不交给模型，所有工具返回结构化数据
2. **provenance + confidence**：每条资产记录谁发现的、几个来源、可信度
3. **幂等 + 增量**：data/findinfo.db 是唯一真值，重复跑只更新 sources
4. **scope 写在代码里**：主动工具内部强制校验，不靠 prompt 约束
5. **被动/主动物理分离**：--active 之前不产生任何目标流量

## 范围声明

仅用于**授权范围内**的资产测绘。主动阶段（probe / ports / vhost / crawl）会产生真实流量，未获得书面授权请只使用被动阶段。
