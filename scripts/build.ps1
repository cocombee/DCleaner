param([ValidateSet('test','build','check','clippy')][string]$Action = 'build',[switch]$Release,[string[]]$CargoArguments = @())
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$vsRoot = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere) { $detected = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($detected) { $vsRoot = $detected } }
$compiler = Get-ChildItem -LiteralPath (Join-Path $vsRoot 'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
$sdk = Get-ChildItem -LiteralPath 'C:\Program Files (x86)\Windows Kits\10\Lib' -Directory | Sort-Object Name -Descending | Select-Object -First 1
if (-not $compiler -or -not $sdk) { throw 'Install Microsoft C++ Build Tools and Windows SDK, then retry.' }
$priorPath = $env:PATH; $priorLib = $env:LIB; $priorInclude = $env:INCLUDE
try {
  $env:PATH = (Join-Path $compiler.FullName 'bin\Hostx64\x64') + ';' + $priorPath
  $env:LIB = @((Join-Path $compiler.FullName 'lib\x64'),(Join-Path $sdk.FullName 'ucrt\x64'),(Join-Path $sdk.FullName 'um\x64')) -join ';'
  $sdkInclude = Join-Path 'C:\Program Files (x86)\Windows Kits\10\Include' $sdk.Name
  $env:INCLUDE = @((Join-Path $compiler.FullName 'include'),(Join-Path $sdkInclude 'ucrt'),(Join-Path $sdkInclude 'um'),(Join-Path $sdkInclude 'shared')) -join ';'
  Push-Location -LiteralPath $project
  try { if ($Release) { & cargo $Action --locked --release @CargoArguments } else { & cargo $Action --locked @CargoArguments }; if ($LASTEXITCODE -ne 0) { throw "cargo $Action failed ($LASTEXITCODE)" } } finally { Pop-Location }
} finally { $env:PATH = $priorPath; $env:LIB = $priorLib; $env:INCLUDE = $priorInclude }
