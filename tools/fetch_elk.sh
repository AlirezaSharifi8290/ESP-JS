#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/components/elk"
VERSION="3.0.0 (master snapshot)"
BASE="https://raw.githubusercontent.com/cesanta/elk/master"

mkdir -p "$DEST"
command -v curl >/dev/null 2>&1 || { echo "curl is required"; exit 1; }

curl -fL "$BASE/elk.c" -o "$DEST/elk.c"
curl -fL "$BASE/elk.h" -o "$DEST/elk.h"
printf 'Fetched Elk %s into %s\n' "$VERSION" "$DEST"
