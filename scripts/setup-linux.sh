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
#
# 退出码：0 必需工具全部就位 / 1 有必需工具缺失或安装失败（详见输出）。
# 必需（核心被动+主动链路）：subfinder httpx dnsx naabu katana onepass
# 可选：tlsx cdncheck chaos gau ffuf ksubdomain hostCollision enscan uncover
# 每次成功安装会记录版本到 $PREFIX/.installed-versions（工具 → tag），
# doctor 再按二进制实探版本，二者都可追溯。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 与 core.py 的平台布局一致：bin/linux、bin/windows、bin/darwin
PREFIX="${ROOT}/bin/linux"
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

# 必需 vs 可选：核心链路跑不起来才叫失败，缺可选工具只是提示
REQUIRED_TOOLS="subfinder httpx dnsx naabu katana onepass"
is_required() { case " $REQUIRED_TOOLS " in *" $1 "*) return 0 ;; *) return 1 ;; esac }

if [ "$CHECK" -eq 1 ]; then
  printf '%-12s %-10s %-8s %-12s %s\n' TOOL STATUS SOURCE VERSION PATH
  miss_req=0; miss_opt=0
  for t in subfinder httpx dnsx naabu tlsx cdncheck uncover katana chaos gau ffuf ksubdomain hostCollision onepass enscan; do
    ver=""
    p="$PREFIX/$t"
    [ -x "$p" ] || p="$PREFIX/$t.exe"
    if [ -x "$p" ]; then
      ver="$(grep -m1 "^$t " "$PREFIX/.installed-versions" 2>/dev/null | awk '{print $2}')"
      [ -n "$ver" ] || ver="(未知：安装清单无记录)"
      printf '%-12s %-10s %-8s %-12s %s\n' "$t" ok bundle "$ver" "$p"
      continue
    fi
    q="$(command -v "$t" 2>/dev/null || true)"
    if [ -n "$q" ]; then
      # PATH 上的同名文件可能是别家的（例：Kali 的 python3-httpx 也装了 /usr/bin/httpx）
      ident="$(timeout 8 "$q" -version 2>&1 | head -3 || true)"
      case "$ident" in
        *[Pp]roject[Dd]iscovery*|*v[0-9]*.[0-9]*.[0-9]*) printf '%-12s %-10s %-8s %-12s %s\n' "$t" ok path "(未记录)" "$q" ;;
        *) printf '%-12s %-10s %-8s %-12s %s\n' "$t" FOREIGN path "(未记录)" "$q" ;;
      esac
      if is_required "$t"; then
        case "$ident" in *[Pp]roject[Dd]iscovery*|*v[0-9]*.[0-9]*.[0-9]*) ;; *) miss_req=$((miss_req+1));; esac
      fi
    else
      printf '%-12s %-10s %-8s %-12s %s\n' "$t" MISSING - "-" "-"
      if is_required "$t"; then miss_req=$((miss_req+1)); else miss_opt=$((miss_opt+1)); fi
    fi
  done
  echo
  if [ -d "${ROOT}/bin/windows" ] || [ -d "${ROOT}/bin/darwin" ]; then
    echo "（bin/ 下还有其它平台目录：$(cd "${ROOT}/bin" && ls -d */ 2>/dev/null | tr '\n' ' ')）"
  fi
  echo "SOURCE: bundle = 已装到 $PREFIX；path = 来自 PATH（注意 FOREIGN 可能是同名但不同工具）"
  echo "VERSION: 来自 $PREFIX/.installed-versions 安装清单；PATH 安装无法追溯版本"
  [ "$miss_opt" -gt 0 ] && warn "缺少 $miss_opt 个可选工具（不影响核心链路）"
  if [ "$miss_req" -gt 0 ]; then
    warn "缺少 $miss_req 个必需工具（$REQUIRED_TOOLS）"
    exit 1
  fi
  [ -f "$PREFIX/../findinfo.py" ] && [ "$(command -v python3)" != "" ] && \
    (cd "$ROOT" && python3 findinfo.py doctor 2>/dev/null | head -c 600; echo)
  exit 0
fi

# ---------------------------------------------------------------- 工具清单
# 名称|仓库|资产过滤|二进制名
if [ "$WITH_OPTIONAL" -eq 1 ]; then
  TOOLS="subfinder|projectdiscovery/subfinder|subfinder_{ver}_linux_${ARCH}.zip|subfinder
httpx|projectdiscovery/httpx|httpx_{ver}_linux_${ARCH}.zip|httpx
dnsx|projectdiscovery/dnsx|dnsx_{ver}_linux_${ARCH}.zip|dnsx
naabu|projectdiscovery/naabu|naabu_{ver}_linux_${ARCH}.zip|naabu
tlsx|projectdiscovery/tlsx|tlsx_{ver}_linux_${ARCH}.zip|tlsx
cdncheck|projectdiscovery/cdncheck|cdncheck_{ver}_linux_${ARCH}.zip|cdncheck
uncover|projectdiscovery/uncover|uncover_{ver}_linux_${ARCH}.zip|uncover
katana|projectdiscovery/katana|katana_{ver}_linux_${ARCH}.zip|katana
chaos|projectdiscovery/chaos-client|chaos-client_{ver}_linux_${ARCH}.zip|chaos
gau|lc/gau|gau_{ver}_linux_${ARCH}.tar.gz|gau
ffuf|ffuf/ffuf|ffuf_{ver}_linux_${ARCH}.tar.gz|ffuf
ksubdomain|knownsec/ksubdomain|ksubdomain_linux.zip|ksubdomain
hostCollision|alwaystest18/hostCollision|hostCollision_{ver}_linux_${ARCH}.tar.gz|hostCollision"
else
  TOOLS="subfinder|projectdiscovery/subfinder|subfinder_{ver}_linux_${ARCH}.zip|subfinder
httpx|projectdiscovery/httpx|httpx_{ver}_linux_${ARCH}.zip|httpx
dnsx|projectdiscovery/dnsx|dnsx_{ver}_linux_${ARCH}.zip|dnsx
naabu|projectdiscovery/naabu|naabu_{ver}_linux_${ARCH}.zip|naabu
tlsx|projectdiscovery/tlsx|tlsx_{ver}_linux_${ARCH}.zip|tlsx
cdncheck|projectdiscovery/cdncheck|cdncheck_{ver}_linux_${ARCH}.zip|cdncheck
uncover|projectdiscovery/uncover|uncover_{ver}_linux_${ARCH}.zip|uncover
katana|projectdiscovery/katana|katana_{ver}_linux_${ARCH}.zip|katana
hostCollision|alwaystest18/hostCollision|hostCollision_{ver}_linux_${ARCH}.tar.gz|hostCollision"
fi

api_get() { # url body_file -> 打印 HTTP 状态码（000 = 网络不可达）
  local hdr=()
  [ -n "${GITHUB_TOKEN:-}" ] && hdr=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  curl -sSL --max-time 25 -o "$2" -w '%{http_code}' \
       -H 'Accept: application/vnd.github+json' "${hdr[@]}" "$1" 2>/dev/null || echo 000
}

json_field() { # 从 stdin 的 JSON 里取顶层字符串字段
  [ -n "$PY" ] || return 1
  "$PY" -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1" 2>/dev/null
}

latest_tag() { # repo -> tag；API 挂了就走 releases/latest 的 302（不需要 API）
  local tmp code tag=""
  tmp="$(mktemp)"
  code="$(api_get "https://api.github.com/repos/$1/releases/latest" "${tmp}")"
  if [ "${code}" = "200" ]; then
    tag="$(json_field tag_name < "${tmp}")"
  fi
  rm -f "${tmp}"
  if [ -z "${tag}" ]; then
    tag="$(curl -sSI --max-time 25 "https://github.com/$1/releases/latest" 2>/dev/null \
      | tr -d '\r' | awk -F'/tag/' '/^location:/ {print $2; exit}')"
    if [ -n "${tag}" ]; then
      [ "${code}" = "403" ] && warn "$1: GitHub API 限流（60/h，匿名共享出口 IP），已用 releases/latest 重定向拿到 ${tag}"
      [ "${code}" = "000" ] && warn "$1: API 不可达，已用 releases/latest 重定向拿到 ${tag}"
    fi
  fi
  printf '%s' "${tag}"
}

asset_url() { # repo tag template -> 可用 URL（构造 + HEAD 校验，不依赖 API）
  local repo="$1" tag="$2" tpl="$3" ver url code try
  ver="${tag#v}"
  url="https://github.com/${repo}/releases/download/${tag}/${tpl//\{ver\}/${ver}}"
  # HEAD 探测有时会被代理打断（000），重试一次再下结论
  for try in 1 2; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -L -I --max-time 30 "${url}")"
    [ "${code}" = "200" ] && { printf '%s' "${url}"; return 0; }
    sleep 2
  done

  # 命名不规律时再问一次 API（能通就用 API 的权威资产名）
  local tmp c2
  tmp="$(mktemp)"
  c2="$(api_get "https://api.github.com/repos/${repo}/releases/tags/${tag}" "${tmp}")"
  if [ "${c2}" = "200" ]; then
    url="$("$PY" -c '
import json, sys
tpl, arch, path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(1)
pre = tpl.split("{ver}")[0]
suf = tpl.split("{ver}")[1] if "{ver}" in tpl else tpl[len(pre):]
suf = suf.replace("{arch}", arch)
best = ""
for a in d.get("assets", []):
    n = a.get("name", "")
    low = n.lower()
    # never pick checksums / sbom / signature files as the binary payload
    if "checksum" in low or "sbom" in low or low.endswith((".txt", ".sig", ".sha256", ".intoto.jsonl")):
        continue
    if arch and arch not in n:
        continue
    if pre and not n.startswith(pre):
        continue
    if suf and not n.endswith(suf):
        continue
    best = a.get("browser_download_url", "")
    break
print(best)
' "${tpl}" "${ARCH}" "${tmp}")"
    rm -f "${tmp}"
    [ -n "${url}" ] && { printf '%s' "${url}"; return 0; }
  else
    rm -f "${tmp}"
  fi
  warn "   构造的 URL 不可用（HTTP ${code}）：${url}"
  return 1
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

failed_req=""
failed_opt=""
ok=0
record_version() { # tool tag -> 追加/更新 $PREFIX/.installed-versions
  local f="$PREFIX/.installed-versions"
  touch "$f" 2>/dev/null || return 0
  grep -v "^$1 " "$f" 2>/dev/null >"$f.tmp" || true
  mv "$f.tmp" "$f"
  echo "$1 $2" >> "$f"
}
while IFS='|' read -r name repo tpl bin; do
  [ -n "$name" ] || continue
  case "$ONLY" in
    "") ;;
    *) case ",$ONLY," in *,$name,*) ;; *) continue ;; esac ;;
  esac
  # 幂等但不浪费：已装好的直接跳过，--force 才重下（重下 350MB 很贵）
  if [ -x "$PREFIX/$name" ] && [ "$FORCE" -eq 0 ]; then
    log "---- $name: already installed, skip (use --force to re-download)"
    ok=$((ok+1))
    continue
  fi
  log "---- $name ($repo)"
  tag="$(latest_tag "$repo")"
  if [ -z "$tag" ]; then
    warn "$name: 取不到版本号（API 403/不可达，且 releases/latest 也失败）；离线安装见 docs/LINUX.md"
    if is_required "$name"; then failed_req="$failed_req $name"; else failed_opt="$failed_opt $name"; fi
    continue
  fi
  url="$(asset_url "$repo" "$tag" "$tpl")"
  if [ -z "$url" ]; then
    warn "$name: $tag 找不到资产 $tpl，跳过（可 go install 自建）"
    if is_required "$name"; then failed_req="$failed_req $name"; else failed_opt="$failed_opt $name"; fi
    continue
  fi
  log "     $tag -> $url"
  if [ "$DRY" -eq 1 ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 25 "$url")"
    log "     dry-run: HTTP $code"
    continue
  fi
  pkg="$TMP/$name.$(basename "$url")"
  if ! curl -fSL --max-time 300 -o "$pkg" "$url"; then
    warn "$name: 下载失败"
    if is_required "$name"; then failed_req="$failed_req $name"; else failed_opt="$failed_opt $name"; fi
    continue
  fi
  rm -rf "$TMP/x_$name"; mkdir -p "$TMP/x_$name"
  if ! extract_pkg "$pkg" "$TMP/x_$name"; then
    warn "$name: 解包失败（缺 unzip/tar？）"
    if is_required "$name"; then failed_req="$failed_req $name"; else failed_opt="$failed_opt $name"; fi
    continue
  fi
  src="$(pick_binary "$TMP/x_$name" "$bin")"
  if [ -z "$src" ]; then
    warn "$name: 解包后找不到可执行文件"
    if is_required "$name"; then failed_req="$failed_req $name"; else failed_opt="$failed_opt $name"; fi
    continue
  fi
  if ! install -m 0755 "$src" "$PREFIX/$name"; then
    warn "$name: 安装到 $PREFIX 失败（需要写权限？用 --prefix 或 sudo）"
    if is_required "$name"; then failed_req="$failed_req $name"; else failed_opt="$failed_opt $name"; fi
    continue
  fi
  record_version "$name" "$tag"
  log "     installed -> $PREFIX/$name ($tag)"
  ok=$((ok+1))
done < <(printf '%s\n' "$TOOLS")
log "GitHub 二进制作业完成（本次安装 $ok 个）"

# ---------------------------------------------------------------- 自研二进制
if [ "$WITH_ONEPASS" -eq 1 ]; then
  if need cargo; then
    log "---- onepass（cargo build --release）"
    if [ "$DRY" -eq 1 ]; then log "     dry-run: 跳过编译"; else
      if bash "$ROOT/scripts/build-onepass.sh" >/dev/null 2>&1; then
        if [ -f "$ROOT/bin/onepass" ]; then
          install -m 0755 "$ROOT/bin/onepass" "$PREFIX/onepass" && \
            record_version onepass "$(grep -m1 '^version' "$ROOT/rust/onepass/Cargo.toml" | sed 's/[^0-9.]*//g')"
        fi
        log "     installed -> $PREFIX/onepass"
      else
        warn "onepass 编译失败（cargo 报错见 scripts/build-onepass.sh 输出）"
        failed_req="$failed_req onepass"
      fi
    fi
  else
    warn "无 cargo，跳过 onepass（apt install -y cargo 或 rustup 后重跑）"
    failed_req="$failed_req onepass"
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
        failed_opt="$failed_opt enscan"
      fi
    fi
  else
    warn "无 go，跳过 enscan（entity 阶段不可用）"
    failed_opt="$failed_opt enscan"
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
  1) API Key :  cp config/.env.example config/.env               # 可留空
  2) 企业信息:  cp bin/config.example.yaml bin/config.yaml        # 填 aiqicha Cookie
  3) 自检    :  python3 findinfo.py doctor
EOF

if [ "$DRY" -eq 0 ] && need python3 && [ -f "$ROOT/findinfo.py" ]; then
  log "doctor 结果："
  (cd "$ROOT" && python3 findinfo.py doctor 2>/dev/null | head -c 1200) || true
  echo
fi

# ---------------------------------------------------------------- 退出码
# 0 = 必需工具全部就位；1 = 有必需工具安装失败（可选工具失败只提示）。
if [ -n "$failed_req" ]; then
  warn "必需工具安装失败：$failed_req（核心链路缺件，退出码 1）"
fi
if [ -n "$failed_opt" ]; then
  warn "可选工具安装失败：$failed_opt（不阻塞，按需补装）"
fi
[ -n "$failed_req" ] && exit 1
exit 0
