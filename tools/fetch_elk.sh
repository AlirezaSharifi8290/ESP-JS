#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/components/elk"
VERSION="Elk 3.0.0 — pinned commit 71a86fa2fef146696be9ae66715bf3f91d0a5f2c"
ELK_COMMIT="71a86fa2fef146696be9ae66715bf3f91d0a5f2c"
BASE="https://raw.githubusercontent.com/cesanta/elk/${ELK_COMMIT}"

mkdir -p "$DEST"
command -v curl >/dev/null 2>&1 || { echo "curl is required"; exit 1; }

curl -fL "$BASE/elk.c" -o "$DEST/elk.c"
curl -fL "$BASE/elk.h" -o "$DEST/elk.h"
printf 'Fetched Elk %s into %s\n' "$VERSION" "$DEST"
