#!/usr/bin/env bash
# 重新构建 ENScan_GO（原 wgpsec/ENScan_GO 仓库已删除，使用社区镜像源码编译）
# 依赖：Go 1.23+
set -euo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-mod=mod
export GOPROXY=https://proxy.golang.org,direct

SRC=_tmp/enscan_src
if [ ! -d "$SRC" ]; then
  git clone --depth 1 https://github.com/mssky9527/ENScan_GO.git "$SRC"
fi
cd "$SRC"
go build -trimpath -ldflags "-s -w" -o "$OLDPWD/bin/enscan.exe" .
echo "built: bin/enscan.exe"
