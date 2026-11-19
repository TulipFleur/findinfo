# Linux 部署与运行

> 同一份 skill 代码，Windows 用~~内置~~的 `bin/*.exe`，Linux 需要**原生二进制**。
> 本文只讲 Linux 侧的准备；命令语义与 Windows 完全一致（见 `docs/TOOLS.md`）。
> **`scripts/setup-linux.sh` / `build-enscan.sh` 只随 Linux 发布包分发**：Windows 包里没有它们（Windows 用内置 `bin/windows/*.exe`）。

## 0. 支持矩阵

| 项 | Windows | Linux |
|---|---|---|
| 全部内置工具 | `bin/windows/*.exe` 已内置 | `scripts/setup-linux.sh` 现场安装 |
| 装到客户端 | junction | symlink（`install.py` 自动判断） |
| 端口扫描 / DNS 爆破 | 管理员 + Npcap | `CAP_NET_RAW` + libpcap |
| 长任务 | 前台 / `nohup` | systemd / tmux |
| 终止子进程 | `CREATE_NO_WINDOW` | 无（该参数在 Linux 是 no-op） |

## 1. 快速开始

~~~bash
cd <skill>                                  # SKILL.md 所在目录
bash scripts/setup-linux.sh --dry-run       # ① 只解析版本和下载地址，不落盘
bash scripts/setup-linux.sh                 # ② 装到 <skill>/bin
bash scripts/setup-linux.sh --cap           # ③ 或装到 PATH 并顺便 setcap
python3 findinfo.py doctor                  # ④ 应看到 15/15 present
~~~

安装器做的事：解析 GitHub 最新 release → 下载 → 解包 → 找到可执行文件 → 装到 `<skill>/bin/linux`（固定，不支持 --prefix）→ 建 onepass（cargo）/ ENScan（go）→ 打印系统参数建议。
它是**幂等**的，随时可以重跑；`--check` 只体检不安装，`--only httpx,katana` 只装指定几个。

**退出码与版本追踪**：必需工具（subfinder/httpx/dnsx/naabu/katana/onepass）任一失败/缺失 → exit 1，调用方可以据此判定"装完能不能跑"；可选工具失败只 WARN。每次成功安装把 `工具 → tag` 记入 `<prefix>/.installed-versions`，`--check` 展示该版本（PATH 同名工具标"未记录"，`doctor` 按二进制实探交叉验证；`FOREIGN` 表示 PATH 上同名但不是该工具）。`bash scripts/build-onepass.sh` 支持从仓库根相对路径或绝对路径调用（路径基于 BASH_SOURCE 解析，cd 之后不失效）。

工具来源（脚本已按这些仓库/资产名验证过）：

| 工具 | 仓库 | 资产 |
|---|---|---|
| subfinder httpx dnsx naabu cdncheck uncover katana | projectdiscovery/* | `<tool>_<ver>_linux_amd64.zip` |
| chaos | projectdiscovery/chaos-client | `chaos-client_<ver>_linux_amd64.zip` |
| ksubdomain | knownsec/ksubdomain | `ksubdomain_linux.zip` |
| hostCollision | alwaystest18/hostCollision | `hostCollision_<ver>_linux_<arch>.tar.gz` |
| onepass | 本仓库 `rust/onepass` | `cargo build --release` |
| enscan | 社区镜像 ENScan_GO | `go build` |

## 2. 装到哪里：bin/linux（固定）

`bin/` 按平台分目录，同一份代码可以同时容纳 Windows 和 Linux 的工具：

~~~text
bin/
├── windows/    ← 12 个 .exe（Windows 预置；doctor 追踪 12 个）
├── linux/      ← ELF（setup-linux.sh 安装）
└── config.example.yaml
~~~

**`core.tool()` 只查 `bin/<当前平台>/`，没有 PATH 回退、没有扁平 `bin/` 回退。**
这是刻意的：环境里同名的二进制可能是别的版本、别的构建，甚至是完全不同的工具
（例如 Kali 的 `python3-httpx` 也往 `/usr/bin/httpx` 放了个同名文件）。
只认一个目录，agent 在任何机器上跑出来的结果才是可复现的。

因此安装位置固定为 `<skill>/bin/linux`，`setup-linux.sh` 不再接受 `--prefix`。
缺工具时 `doctor` 会报 `tool not found in <skill>/bin/<platform>/`，
修法只有一个：把二进制补进那个目录。

~~~bash
bash scripts/setup-linux.sh                        # 装到 bin/linux
bash scripts/setup-linux.sh --cap                  # 同时加 raw socket 能力
bash scripts/setup-linux.sh --check                # 表格：TOOL / STATUS / SOURCE / VERSION
~~~
## 3. 权限：CAP_NET_RAW

`naabu`（SYN 扫描）和 `ksubdomain`（裸包爆破）需要 raw socket；其余工具（httpx/katana/dnsx/hostCollision）用普通 socket，**不需要特权**。

~~~bash
# 方案 A（推荐）：给二进制单独授权，普通用户也能跑
sudo setcap cap_net_raw+ep /usr/local/bin/naabu /usr/local/bin/ksubdomain
getcap /usr/local/bin/naabu

# 方案 B：以 root 跑
# 方案 C：容器
docker run --cap-add=NET_RAW --network=host ...
~~~

没授权时的表现：这两个命令报 socket/pcap 错误，退出码非 0；**流水线其余阶段照常**（脚本/agent 可按 `--no-...` 跳过）。

## 4. 系统参数（大规模前必调）

~~~bash
ulimit -n 65535                                    # httpx -threads 50 × 多进程
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.ipv4.tcp_tw_reuse=1                  # extract/crawl 大量短连接
~~~

内存预算（实测口径）：Python 父进程峰值 ≈ **结果条数 × 1.6 KB**（60k 条约 115 MB，120k 条约 208 MB）；
再加上 Go 子进程自身峰值（httpx 几万目标时可达数百 MB）。机器内存按 `条数 × 2 KB + 1 GB` 估。

## 4.5 固定入口（推荐先用这个）

装完之后不用记子命令，传变量即可：

```bash
bash scripts/findinfo.sh -t example.com                     # 纯被动
bash scripts/findinfo.sh -t example.com -a --vhost --crawl  # 主动
bash scripts/findinfo.sh -t example.com -m steps            # 分阶段（被动拆开跑）
bash scripts/findinfo.sh -t example.com -b                  # 后台，配 --status 轮询
bash scripts/findinfo.sh -p ...                             # 只回显命令不执行
```

脚本自己找解释器（优先 `python3`，再 `python`）；`FINDINFO_PYTHON=/path` 可强制指定。
内部仍然调 `findinfo.py`——数据层（去重/置信度/SQLite/vhost 碰撞/限速缓存/断点）留在 Python，
bash 只负责编排和传参。

## 5. 三种跑法

### 5.1 交互（手工排查）

~~~bash
tmux new -s recon
python3 findinfo.py doctor
python3 findinfo.py run --domain example.com --active --vhost
~~~

### 5.2 systemd（生产/定时，推荐）

~~~bash
sudo useradd --system --home /var/lib/findinfo --shell /usr/sbin/nologin findinfo
sudo mkdir -p /var/lib/findinfo && sudo chown findinfo:findinfo /var/lib/findinfo
sudo cp deploy/findinfo@.service /etc/systemd/system/
sudo cp deploy/findinfo@.timer   /etc/systemd/system/
sudo tee /etc/findinfo.env >/dev/null <<'EOF'
FOFA_KEY=xxx
QUAKE_TOKEN=yyy
EOF
sudo chmod 600 /etc/findinfo.env
sudo systemctl daemon-reload
sudo systemctl start 'findinfo@example.com.service'     # 手动跑一次
journalctl -u 'findinfo@example.com.service' -f
sudo systemctl enable --now 'findinfo@example.com.timer' # 每天 04:17 被动刷新
~~~

单元文件里已经处理了三件事：`FINDINFO_HOME` 指向 `/var/lib/findinfo`、`TimeoutStartSec=3h`（长流程）、`AmbientCapabilities=CAP_NET_RAW`。

## 6. 与 Windows 的差异

| 点 | 说明 |
|---|---|
| 二进制名 | Linux 无 `.exe`；`core.tool()` 两种都认，`build-enscan.sh` 已按平台改名 |
| 客户端安装 | `install.py` 在 Linux 用 symlink（Windows 是 junction），无需管理员 |
| 弹窗 | Windows 用 `CREATE_NO_WINDOW` 防黑框；Linux 无此概念 |
| Npcap | 换成 libpcap（`apt install libpcap0.8`），`ksubdomain` 仍要 CAP_NET_RAW |
| curl | `certs` / `extract` / `vhost` 的 curl 降级路径依赖系统 `curl` |

## 7. 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| `解包失败` | 缺 unzip / tar | `apt install -y unzip tar` |
| `取不到 latest tag` / HTTP 403 | GitHub API 限流（匿名 60 次/时） | 等一小时，或手动下载 release 放进 bin/linux |
| `无 cargo` / `无 go` | 缺工具链 | `apt install -y cargo golang`，或 `--no-onepass --no-enscan` 先跑 |
| `setcap: Operation not permitted` | 未提权 | 用 sudo；容器加 `--cap-add=NET_RAW` |
| `naabu` 报 socket 错误 | 没有 CAP_NET_RAW | 见第 3 节 |
| `Bad substitution` | 用 `sh` 执行了脚本 | 用 `bash scripts/setup-linux.sh` |
| `python3: not found` | 精简镜像 | `apt install -y python3` |
| `curl: command not found` | 缺 curl | `apt install -y curl`（`certs`/`extract` 会失效） |
| `doctor` 显示 enscan 缺失 | 镜像源不可达/未编译 | 不影响被动与其余主动阶段；需要 entity 时再编 |

## 8. 离线安装

在有网的机器上装到临时目录，然后整目录拷到目标机：

~~~bash
bash scripts/setup-linux.sh                        # 先在有网机器装到 <skill>/bin/linux
tar czf findinfo-linux.tar.gz -C <skill> bin/linux
# 目标机
tar xzf findinfo-linux.tar.gz -C <skill>
chmod +x <skill>/bin/linux/*
bash scripts/setup-linux.sh --check
~~~~~~

## 9. 卸载

~~~bash
rm -f <skill>/bin/linux/{subfinder,httpx,dnsx,naabu,cdncheck,uncover,katana,chaos,ksubdomain,hostCollision,onepass,enscan}
rm -rf /var/lib/findinfo            # 资产库（~/.findinfo 同理）
# systemd
sudo systemctl disable --now 'findinfo@example.com.timer'
sudo rm -f /etc/systemd/system/findinfo@.{service,timer} /etc/findinfo.env
~~~

## 10. 性能与并发

- 编排层是单进程 Python，**不需要** asyncio/Gunicorn/Celery；并发全在 Go/Rust 子进程里，数据库 WAL + 事务保证读写安全。
- 大规模（>5 万结果）建议拆阶段跑并配合 `--from-store` 续跑，不要一条 `run` 吃到底。
