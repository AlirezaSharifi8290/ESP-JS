$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Get-Command clang -ErrorAction SilentlyContinue)) { throw 'clang is required' }
clang --target=wasm32 -O3 -flto -fno-builtin -nostdlib `
  '-Wl,--no-entry,--export=pbkdf2_export_entry,--export=hmac_export_entry,--export=memory_base,--export-memory,--initial-memory=196608,--max-memory=196608' `
  -o (Join-Path $Root 'data\www\crypto.wasm') (Join-Path $Root 'tools\crypto\crypto_wasm.c')
Write-Host 'Built data/www/crypto.wasm'
