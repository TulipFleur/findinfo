#!/usr/bin/env bash
# findinfo — Linux 安装/体检脚本（幂等，可重复执行）
#
#   bash scripts/setup-linux.sh                     # 装到 <skill>/bin（与 core.tool 查找顺序一致）
#   bash scripts/setup-linux.sh --prefix /usr/local/bin --cap
#   bash scripts/setup-linux.sh --dry-run           # 只解析版本/打印下载地址，不落盘
#   bash scripts/setup-linux.sh --check             # 只体检已装工具
#   bash scripts/setup-linux.sh --minimal           # 跳过 gau/ffuf/chaos
#   bash scripts/setup-linux.sh --only httpx,katana
#
# 卸载：删掉 --prefix 下这些文件即可，脚本不写其他地方。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${ROOT}/bin"
ARCH=""
DRY=0
CHECK=0
FORCE=0
CAP=0
WITH_ENSCAN=1
WITH_ONEPASS=1
WITH_OPTIONAL=1
ONLY=""

log()  { printf '[setup] %s\n' "$*"; }
warn() { printf '[setup] WARN: %s\n' "$*" >&2; }
die()  { printf '[setup] ERROR: %s\n' "$*" >&2; exit 1; }

usage() { awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 && !/^#/ { exit }' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)  PREFIX="$2"; shift 2 ;;
    --arch)    ARCH="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --check)   CHECK=1; shift ;;
    --force)   FORCE=1; shift ;;
    --cap)     CAP=1; shift ;;
    --no-enscan)   WITH_ENSCAN=0; shift ;;
    --no-onepass)  WITH_ONEPASS=0; shift ;;
    --minimal)     WITH_OPTIONAL=0; shift ;;
    --only)    ONLY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1（--help 看用法）" ;;
  esac
done

# ---------------------------------------------------------------- 平台
uname_s="$(uname -s 2>/dev/null || echo unknown)"
case "$uname_s" in
  Linux) : ;;
  *)
    if [ "$CHECK" -eq 1 ]; then
      warn "当前是 $uname_s，非 Linux；--check 只体检不安装"
    elif [ "$DRY" -eq 1 ]; then
      warn "当前是 $uname_s，非 Linux；--dry-run 只输出计划（不下载不安装）"
    else
      die "本脚本只用于 Linux（当前 $uname_s）。Windows 直接用 bin\\*.exe；容器请看 Dockerfile。"
    fi
    ;;
esac

if [ -z "$ARCH" ]; then
  case "$(uname -m 2>/dev/null || echo x86_64)" in
    x86_64|amd64)   ARCH=amd64 ;;
    aarch64|arm64)  ARCH=arm64 ;;
    *)              ARCH=amd64 ;;
  esac
fi

need() { command -v "$1" >/dev/null 2>&1; }
need curl || die "缺少 curl（apt install -y curl）"

# JSON 解析优先 python3，其次 python（精简镜像里可能没有 python3 别名）
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || warn "没有 python 解释器，无法解析 GitHub API（安装: apt install -y python3）"

if [ "$CHECK" -eq 1 ]; then
  printf '%-12s %-10s %s\n' TOOL STATUS PATH
  miss=0
  for t in subfinder httpx dnsx naabu tlsx cdncheck uncover katana chaos gau ffuf ksubdomain onepass enscan; do
    p="$PREFIX/$t"
    [ -x "$p" ] || p="$PREFIX/$t.exe"
    if [ -x "$p" ]; then printf '%-12s %-10s %s\n' "$t" ok "$p";
    elif command -v "$t" >/dev/null 2>&1; then printf '%-12s %-10s %s\n' "$t" ok "$(command -v "$t")";
    else printf '%-12s %-10s %s\n' "$t" MISSING "-"; miss=$((miss+1)); fi
  done
  [ -f "$PREFIX/../findinfo.py" ] && [ "$(command -v python3)" != "" ] && \
    (cd "$ROOT" && python3 findinfo.py doctor 2>/dev/null | head -c 600; echo)
  exit 0
fi

# ---------------------------------------------------------------- 工具清单
# 名称|仓库|资产过滤|二进制名
if [ "$WITH_OPTIONAL" -eq 1 ]; then
  TOOLS="subfinder|projectdiscovery/subfinder|linux_${ARCH}.zip|subfinder
httpx|projectdiscovery/httpx|linux_${ARCH}.zip|httpx
dnsx|projectdiscovery/dnsx|linux_${ARCH}.zip|dnsx
naabu|projectdiscovery/naabu|linux_${ARCH}.zip|naabu
tlsx|projectdiscovery/tlsx|linux_${ARCH}.zip|tlsx
cdncheck|projectdiscovery/cdncheck|linux_${ARCH}.zip|cdncheck
uncover|projectdiscovery/uncover|linux_${ARCH}.zip|uncover
katana|projectdiscovery/katana|linux_${ARCH}.zip|katana
chaos|projectdiscovery/chaos-client|linux_${ARCH}.zip|chaos
gau|lc/gau|linux_${ARCH}.tar.gz|gau
ffuf|ffuf/ffuf|linux_${ARCH}.tar.gz|ffuf
ksubdomain|knownsec/ksubdomain|linux.zip|ksubdomain"
else
  TOOLS="subfinder|projectdiscovery/subfinder|linux_${ARCH}.zip|subfinder
httpx|projectdiscovery/httpx|linux_${ARCH}.zip|httpx
dnsx|projectdiscovery/dnsx|linux_${ARCH}.zip|dnsx
naabu|projectdiscovery/naabu|linux_${ARCH}.zip|naabu
tlsx|projectdiscovery/tlsx|linux_${ARCH}.zip|tlsx
cdncheck|projectdiscovery/cdncheck|linux_${ARCH}.zip|cdncheck
uncover|projectdiscovery/uncover|linux_${ARCH}.zip|uncover
katana|projectdiscovery/katana|linux_${ARCH}.zip|katana"
fi

api_get() { curl -fsSL --max-time 25 -H 'Accept: application/vnd.github+json' "$1" 2>/dev/null; }

json_field() { # 从 stdin 的 JSON 里取顶层字符串字段
  [ -n "$PY" ] || return 1
  "$PY" -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1" 2>/dev/null
}

latest_tag() { # repo -> tag
  api_get "https://api.github.com/repos/$1/releases/latest" | json_field tag_name
}

asset_url() { # repo tag filter -> browser_download_url
  api_get "https://api.github.com/repos/$1/releases/tags/$2" \
    | "$PY" -c '
import json,sys
tag, flt = sys.argv[1], sys.argv[2]
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for a in d.get("assets", []):
    if flt in a.get("name", ""):
        print(a.get("browser_download_url", ""))
        break
' "$2" "$3" 2>/dev/null
}

extract_pkg() { # pkg destdir
  case "$1" in
    *.zip)    (need unzip && unzip -oq "$1" -d "$2") || return 1 ;;
    *.tar.gz) tar xzf "$1" -C "$2" || return 1 ;;
    *)        return 1 ;;
  esac
}

pick_binary() { # dir name
  if [ -f "$1/$2" ] && [ -x "$1/$2" ]; then echo "$1/$2"; return 0; fi
  found="$(find "$1" -maxdepth 2 -type f -name "$2" -perm -u+x 2>/dev/null | head -1)"
  [ -n "$found" ] && { echo "$found"; return 0; }
  found="$(find "$1" -maxdepth 2 -type f -perm -u+x ! -name '*.txt' ! -name '*.md' 2>/dev/null | head -1)"
  [ -n "$found" ] && { echo "$found"; return 0; }
  return 1
}

mkdir -p "$PREFIX" || die "无法创建 $PREFIX"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failed=""
ok=0
while IFS='|' read -r name repo flt bin; do
  [ -n "$name" ] || continue
  case "$ONLY" in
    "") ;;
    *) case ",$ONLY," in *,$name,*) ;; *) continue ;; esac ;;
  esac
  log "---- $name ($repo)"
  tag="$(latest_tag "$repo")"
  if [ -z "$tag" ]; then warn "$name: 取不到 latest tag（网络或 API 限流），跳过"; continue; fi
  url="$(asset_url "$repo" "$tag" "$flt")"
  if [ -z "$url" ]; then warn "$name: $tag 没有匹配 '$flt' 的资产，跳过（可用 go install 自建）"; continue; fi
  log "     $tag -> $url"
  if [ "$DRY" -eq 1 ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 25 "$url")"
    log "     dry-run: HTTP $code"
    continue
  fi
  pkg="$TMP/$name.$(basename "$url")"
  if ! curl -fSL --max-time 300 -o "$pkg" "$url"; then warn "$name: 下载失败"; continue; fi
  rm -rf "$TMP/x_$name"; mkdir -p "$TMP/x_$name"
  if ! extract_pkg "$pkg" "$TMP/x_$name"; then warn "$name: 解包失败（缺 unzip/tar？）"; continue; fi
  src="$(pick_binary "$TMP/x_$name" "$bin")"
  if [ -z "$src" ]; then warn "$name: 解包后找不到可执行文件"; continue; fi
  if ! install -m 0755 "$src" "$PREFIX/$name"; then warn "$name: 安装到 $PREFIX 失败（需要写权限？用 --prefix 或 sudo）"; continue; fi
  log "     installed -> $PREFIX/$name"
  ok=$((ok+1))
done < <(printf '%s\n' "$TOOLS")
log "GitHub 二进制作业完成（本次安装 $ok 个）"

# ---------------------------------------------------------------- 自研二进制
if [ "$WITH_ONEPASS" -eq 1 ]; then
  if need cargo; then
    log "---- onepass（cargo build --release）"
    if [ "$DRY" -eq 1 ]; then log "     dry-run: 跳过编译"; else
      if bash "$ROOT/scripts/build-onepass.sh" >/dev/null 2>&1; then
        if [ -f "$ROOT/bin/onepass" ]; then install -m 0755 "$ROOT/bin/onepass" "$PREFIX/onepass"; fi
        log "     installed -> $PREFIX/onepass"
      else
        warn "onepass 编译失败（cargo 报错见 scripts/build-onepass.sh 输出）"
      fi
    fi
  else
    warn "无 cargo，跳过 onepass（apt install -y cargo 或 rustup 后重跑）"
  fi
fi

if [ "$WITH_ENSCAN" -eq 1 ]; then
  if need go; then
    log "---- enscan（go build，需联网拉源码）"
    if [ "$DRY" -eq 1 ]; then log "     dry-run: 跳过编译"; else
      if bash "$ROOT/scripts/build-enscan.sh" >/dev/null 2>&1; then
        src="$ROOT/bin/enscan"
        [ -f "$src" ] || src="$ROOT/bin/enscan.exe"
        [ -f "$src" ] && install -m 0755 "$src" "$PREFIX/enscan" && log "     installed -> $PREFIX/enscan"
      else
        warn "enscan 编译失败（entity 阶段不可用；被动/主动其余阶段不受影响）"
      fi
    fi
  else
    warn "无 go，跳过 enscan（entity 阶段不可用）"
  fi
fi

# ---------------------------------------------------------------- 能力与系统建议
if [ "$CAP" -eq 1 ] && [ "$DRY" -eq 0 ]; then
  if need setcap; then
    for t in naabu ksubdomain; do
      [ -x "$PREFIX/$t" ] || continue
      if [ "$(id -u)" -eq 0 ]; then
        setcap cap_net_raw+ep "$PREFIX/$t" && log "setcap ok: $t"
      elif need sudo; then
        sudo setcap cap_net_raw+ep "$PREFIX/$t" && log "setcap ok (sudo): $t"
      else
        warn "非 root 且无 sudo：手动执行 setcap cap_net_raw+ep $PREFIX/$t"
      fi
    done
  else
    warn "系统没有 setcap（apt install -y libcap2-bin），可用 root 直接跑"
  fi
fi

cat <<'EOF'

[setup] 建议的系统参数（大规模扫描前）:
  ulimit -n 65535
  sysctl -w net.ipv4.ip_local_port_range="1024 65535"
  sysctl -w net.ipv4.tcp_tw_reuse=1

[setup] 下一步:
  1) 授权范围:  cp config/scope.example.json config/scope.json   # 填 domains/cidrs
  2) API Key :  cp config/.env.example config/.env               # 可留空
  3) 企业信息:  cp bin/config.example.yaml bin/config.yaml        # 填 aiqicha Cookie
  4) 自检    :  python3 findinfo.py doctor
EOF

if [ "$DRY" -eq 0 ] && need python3 && [ -f "$ROOT/findinfo.py" ]; then
  log "doctor 结果："
  (cd "$ROOT" && python3 findinfo.py doctor 2>/dev/null | head -c 1200) || true
  echo
fi
exit 0
