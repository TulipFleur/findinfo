#!/usr/bin/env bash
# Rebuild the bundled Rust collector (bin/onepass.exe).
# Requires a Rust toolchain (https://rustup.rs). The binary is committed to the
# skill, so end users never need Rust.
set -euo pipefail
cd "$(dirname "$0")/../rust/onepass"
cargo build --release
OUT="$(cd "$(dirname "$0")/.." && pwd)/bin"
mkdir -p "$OUT"
cp -f target/release/onepass.exe "$OUT/onepass.exe" 2>/dev/null ||
  cp -f target/release/onepass "$OUT/onepass"
echo "built: $OUT/onepass"
