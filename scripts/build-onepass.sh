#!/usr/bin/env bash
# Rebuild the bundled Rust collector (bin/onepass.exe).
# Requires a Rust toolchain (https://rustup.rs). The binary is committed to the
# skill, so end users never need Rust.
#
# Works from any cwd, with relative or absolute invocation: paths are resolved
# once from BASH_SOURCE before any cd (after `cd`, $0 stops resolving relative
# to the original cwd -- the old script built into rust/bin by accident).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT/rust/onepass"
cargo build --release

# Install into the per-platform dir that core.tool() searches FIRST
# (bin/<platform>/). The old flat bin/ copy silently lost to a stale
# bin/<platform>/onepass(.exe) on every later call.
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$PLATFORM" in
  msys*|mingw*|cygwin*) PLATFORM="windows"; EXE="onepass.exe" ;;
  darwin)              echo "onepass: macOS not supported (windows/linux only)" >&2; exit 1 ;;
  *)                   PLATFORM="linux";    EXE="onepass" ;;
esac
DEST="$ROOT/bin/$PLATFORM"
mkdir -p "$DEST"
if [ -f target/release/onepass.exe ]; then
  cp -f target/release/onepass.exe "$DEST/onepass.exe"
elif [ -f target/release/onepass ]; then
  cp -f target/release/onepass "$DEST/onepass"
fi
# also refresh the legacy flat copy so old installs that resolve bin/ first
# are not left with a stale binary either
mkdir -p "$ROOT/bin"
cp -f "$DEST/$EXE" "$ROOT/bin/$EXE" 2>/dev/null || true
echo "built: $DEST/$EXE (+ flat copy $ROOT/bin/$EXE)"
