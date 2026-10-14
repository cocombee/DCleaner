param([Parameter(Mandatory=$true)][string]$SourceExecutable)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $SourceExecutable).Path
if ([IO.Path]::GetFileName($source) -ine 'dcleaner.exe') { throw 'Choose the DCleaner executable produced by the project build.' }
if (-not $env:LOCALAPPDATA -or -not $env:APPDATA) { throw 'The current user installation directories are unavailable.' }
$installDirectory = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\DCleaner'))
$destination = Join-Path $installDirectory 'DCleaner.exe'
$running = Get-CimInstance Win32_Process -Filter "Name='dcleaner.exe'" | Where-Object { $_.ExecutablePath -and [IO.Path]::GetFullPath($_.ExecutablePath) -ieq $destination }
if ($running) { throw 'Close the installed DCleaner before replacing its executable. No running operation was stopped.' }
New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
$staging = Join-Path $installDirectory ('DCleaner.install-' + [guid]::NewGuid().ToString('N') + '.tmp')
Copy-Item -LiteralPath $source -Destination $staging
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $staging -Algorithm SHA256).Hash) { throw 'The staged executable does not match the build.' }
Move-Item -LiteralPath $staging -Destination $destination -Force
$shortcutDirectory = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
New-Item -ItemType Directory -Path $shortcutDirectory -Force | Out-Null
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $shortcutDirectory 'DCleaner.lnk'))
$shortcut.TargetPath = $destination
$shortcut.WorkingDirectory = $installDirectory
$shortcut.Description = 'DCleaner'
$shortcut.IconLocation = $destination
$shortcut.Save()
[PSCustomObject]@{ Executable = $destination; Shortcut = (Join-Path $shortcutDirectory 'DCleaner.lnk'); Sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash }
