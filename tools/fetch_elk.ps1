$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Dest = Join-Path $Root 'components\elk'
$Version = '3.0.0 (master snapshot)'
$Base = "https://raw.githubusercontent.com/cesanta/elk/master"

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Invoke-WebRequest -Uri "$Base/elk.c" -OutFile (Join-Path $Dest 'elk.c')
Invoke-WebRequest -Uri "$Base/elk.h" -OutFile (Join-Path $Dest 'elk.h')
Write-Host "Fetched Elk $Version into $Dest"
