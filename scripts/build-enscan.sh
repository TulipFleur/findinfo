#!/usr/bin/env bash
# 重新构建 ENScan_GO（原 wgpsec/ENScan_GO 仓库已删除，使用社区镜像源码编译）
# 依赖：Go 1.23+
set -euo pipefail
export GOFLAGS=-mod=mod
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/_tmp/enscan_src"
mkdir -p "$ROOT/_tmp" "$ROOT/bin"
if [ ! -d "$SRC" ]; then
  git clone --depth 1 https://github.com/mssky9527/ENScan_GO.git "$SRC"
fi

# 输出名跟随平台：Windows 用 .exe，Linux/macOS 用无后缀（core.tool 两者都能找到）
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) OUT="$ROOT/bin/enscan.exe" ;;
  *)                    OUT="$ROOT/bin/enscan" ;;
esac

cd "$SRC"
go build -trimpath -ldflags "-s -w" -o "$OUT" .
echo "built: $OUT"
