#!/usr/bin/env bash
# findinfo — 固定入口：传变量即可，不用记十几个子命令。
#
#   bash scripts/findinfo.sh -t example.com                    # 纯被动（零接触目标）
#   bash scripts/findinfo.sh -n "企业名"                        # 企业名 -> 实体树/备案/域名
#   bash scripts/findinfo.sh -t example.com -a --vhost --crawl  # 主动（探测/碰撞/爬取）
#   bash scripts/findinfo.sh -t example.com -b                  # 后台跑（不阻塞，立刻返回）
#   bash scripts/findinfo.sh --status                           # 看进度
#   bash scripts/findinfo.sh -t example.com -b --notify /path/hook.sh
#                                 # 后台跑，跑完自动执行 hook.sh（拿到 JSON 再继续干活）
#   bash scripts/findinfo.sh --task hniu -t hniu.cn            # 按任务隔离资产图
#   bash scripts/findinfo.sh --export runs/assets.jsonl         # 导出资产图
#
# 后台模式产物（~/.findinfo/last/<task>/，按任务隔离）：
#   out.json   stdout 那一行 JSON     err.log  stderr 进度
#   跑完即写 done（含 exit code）——agent 轮询或 hook 二选一。
#   目录按 --task（缺省 default）分开：两个并行任务的输出/完成标记互不覆盖。
# 退出码沿用 findinfo.py：0 成功 / 2 业务错 / 4 工具缺失 / 5 阶段失败。
set -uo pipefail

SKILL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${FINDINFO_PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
  done
fi
[ -n "$PY" ] || { echo "[findinfo] 缺少 python3（apt install -y python3）" >&2; exit 4; }

MODE=run
ACTIVE=0; PORTS=0; VHOST=0; CRAWL=0; BRUTE=0
TASK="${FINDINFO_TASK:-}"
BACKGROUND=0; PRINT_ONLY=0; DOCTOR=1
ENGINES="fofa,quake,hunter,shodan,censys"
MAX_SEED=5; TOP_PORTS=1000; DEPTH=3; MIN_CONF=0.7
TARGETS=(); NAME=""; STATUS=0; EXPORT=""; NOTIFY=""

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 && !/^#/ {exit}' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -t|--target)  TARGETS+=("$2"); shift 2 ;;
    --task)       TASK="$2"; shift 2 ;;
    -n|--name)    NAME="$2"; shift 2 ;;
    -a|--active)  ACTIVE=1; shift ;;
    --ports)      PORTS=1; shift ;;
    --vhost)      VHOST=1; shift ;;
    --crawl)      CRAWL=1; shift ;;
    --brute)      BRUTE=1; shift ;;
    -m|--mode)    MODE="$2"; shift 2 ;;
    --engines)    ENGINES="$2"; shift 2 ;;
    --max-seed)   MAX_SEED="$2"; shift 2 ;;
    --top-ports)  TOP_PORTS="$2"; shift 2 ;;
    --depth)      DEPTH="$2"; shift 2 ;;
    --min-conf)   MIN_CONF="$2"; shift 2 ;;
    -b|--background) BACKGROUND=1; shift ;;
    --notify)     NOTIFY="$2"; shift 2 ;;
    -p|--print)   PRINT_ONLY=1; shift ;;
    --no-doctor)  DOCTOR=0; shift ;;
    --status)     STATUS=1; shift ;;
    --export)     EXPORT="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "[findinfo] 未知参数: $1（--help 看用法）" >&2; exit 2 ;;
  esac
done

run() {
  if [ "$PRINT_ONLY" -eq 1 ]; then
    # 回显时不转义、不执行：方便直接复制粘贴
    echo "$@"
  else
    "$@"
  fi
}

PY_ARGS=()
[ -n "$TASK" ] && PY_ARGS+=(--task "$TASK")

if [ "$STATUS" -eq 1 ]; then run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} status; exit $?; fi
if [ -n "$EXPORT" ]; then
  run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} assets --export "$EXPORT" --min-conf "$MIN_CONF"; exit $?
fi

if [ ${#TARGETS[@]} -eq 0 ] && [ -z "$NAME" ]; then
  echo "[findinfo] 至少要给 -t <域名> 或 -n <企业名>" >&2; usage >&2; exit 2
fi
case "$MODE" in run|steps) ;; *) echo "[findinfo] --mode 只能是 run 或 steps" >&2; exit 2 ;; esac

if [ "$DOCTOR" -eq 1 ]; then
  if [ "$PRINT_ONLY" -eq 1 ]; then
    echo "[findinfo] doctor ...（-p 模式跳过实跑）" >&2
  else
    echo "[findinfo] doctor ..." >&2
    if ! "$PY" "$SKILL/findinfo.py" doctor >/dev/null 2>&1; then
      echo "[findinfo] doctor 失败：先修工具（bash scripts/setup-linux.sh --check）" >&2; exit 4
    fi
  fi
fi

ARGS=()
if [ -n "$NAME" ]; then ARGS+=(--name "$NAME"); fi
for t in ${TARGETS[@]+"${TARGETS[@]}"}; do ARGS+=(--domain "$t"); done
if [ "$ACTIVE" -eq 1 ]; then ARGS+=(--active); fi
if [ "$PORTS" -eq 1 ]; then ARGS+=(--ports); fi
if [ "$VHOST" -eq 1 ]; then ARGS+=(--vhost); fi
if [ "$CRAWL" -eq 1 ]; then ARGS+=(--crawl); fi
if [ "$BRUTE" -eq 1 ]; then ARGS+=(--brute); fi
ARGS+=(--engines "$ENGINES" --max-seed "$MAX_SEED" --top-ports "$TOP_PORTS" --depth "$DEPTH")

# 后台模式：写 ~/.findinfo/last/<task>/{out.json,err.log,done}，跑完可执行 --notify 脚本。
# done 文件是完成信号（agent 轮询它，比轮询 status.py 少一次 python 启动）。
# 目录按任务隔离：TASK 未指定时用 default。任务名原样用作目录名（含中文名），
# 文件系统支持这些字符；做 ASCII 清洗反而会把两个不同的任务静默合并。
TASK_TOKEN="${TASK:-default}"
bg_dir="${FINDINFO_HOME:-$HOME/.findinfo}/last/$TASK_TOKEN"
launch() {
  if [ "$BACKGROUND" -eq 1 ] && [ "$PRINT_ONLY" -eq 0 ]; then
    mkdir -p "$bg_dir"; rm -f "$bg_dir/done"
    (
      "$@" >"$bg_dir/out.json" 2>"$bg_dir/err.log"
      rc=$?
      echo "$rc" > "$bg_dir/done"
      if [ -n "$NOTIFY" ]; then
        # hook 拿到：$1=exit_code $2=out.json $3=err.log —— 失败也照常触发
        bash "$NOTIFY" "$rc" "$bg_dir/out.json" "$bg_dir/err.log" >/dev/null 2>&1 || true
      fi
    ) &
    echo "[findinfo] 已后台启动 (pid $!)；完成信号: $bg_dir/done；JSON: $bg_dir/out.json" >&2
    exit 0
  fi
  run "$@"
}

PY_ARGS=()
[ -n "$TASK" ] && PY_ARGS+=(--task "$TASK")

if [ "$MODE" = "steps" ]; then
  echo "[findinfo] mode=steps：先被动，逐阶段可查库" >&2
  if [ -n "$NAME" ]; then run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} entity --name "$NAME"; fi
  for t in ${TARGETS[@]+"${TARGETS[@]}"}; do
    run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} passive --domain "$t"
    run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} certs   --domain "$t"
    run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} subs    --domain "$t" --engines "$ENGINES"
    if [ "$ACTIVE" -eq 1 ] && [ "$BRUTE" -eq 1 ]; then
      run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} brute --domain "$t"
    fi
  done
  run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} icp --from-store
  run "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} dns --from-store
  if [ "$ACTIVE" -eq 1 ]; then
    launch "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} run "${ARGS[@]}"
  fi
else
  launch "$PY" "$SKILL/findinfo.py" ${PY_ARGS[@]+"${PY_ARGS[@]}"} run "${ARGS[@]}"
fi
