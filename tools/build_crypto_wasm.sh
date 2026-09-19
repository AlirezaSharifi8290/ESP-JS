#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v clang >/dev/null 2>&1 || { echo "clang is required" >&2; exit 1; }
clang --target=wasm32 -O3 -flto -fno-builtin -nostdlib \
  -Wl,--no-entry,--export=pbkdf2_export_entry,--export=hmac_export_entry,--export=memory_base,--export-memory,--initial-memory=196608,--max-memory=196608 \
  -o "$ROOT/data/www/crypto.wasm" "$ROOT/tools/crypto/crypto_wasm.c"
echo "Built data/www/crypto.wasm"
