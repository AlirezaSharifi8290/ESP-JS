$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Dest = Join-Path $Root 'components\elk'
$Version = 'Elk 3.0.0 — pinned commit 71a86fa2fef146696be9ae66715bf3f91d0a5f2c'
$ELK_COMMIT = "71a86fa2fef146696be9ae66715bf3f91d0a5f2c"
$base = "https://raw.githubusercontent.com/cesanta/elk/$ELK_COMMIT"

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Invoke-WebRequest -Uri "$Base/elk.c" -OutFile (Join-Path $Dest 'elk.c')
Invoke-WebRequest -Uri "$Base/elk.h" -OutFile (Join-Path $Dest 'elk.h')
Write-Host "Fetched Elk $Version into $Dest"
