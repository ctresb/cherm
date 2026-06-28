# Cherm.chat official server installer for Windows (install_specification §9).
#
#   iex (irm https://cherm.chat/server-install.ps1)
#
# Windows/macOS server builds exist for development & small deployments; Linux is
# the primary production target (install_specification §5.2). Installs the server
# binary, creates an isolated directory tree, writes an initial config if missing
# (never overwrites — backs up first), and writes run/update helper scripts.
$ErrorActionPreference = "Stop"

$Base       = if ($env:CHERM_BASE_URL) { $env:CHERM_BASE_URL } else { "https://cherm.chat" }
$ServerHome = if ($env:CHERM_SERVER_HOME) { $env:CHERM_SERVER_HOME } else { "$env:LOCALAPPDATA\Cherm-Server" }
$Listen     = if ($env:CHERM_SERVER_ADDR) { $env:CHERM_SERVER_ADDR } else { "0.0.0.0:9000" }
$Public     = if ($env:CHERM_PUBLIC_ADDR) { $env:CHERM_PUBLIC_ADDR } else { "$env:COMPUTERNAME:9000" }
$Repo       = "https://github.com/cherm-chat/cherm"

function Info($m) { Write-Host "==> $m" -ForegroundColor Magenta }
function Die($m)  { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) { "AMD64" {"x64"} "ARM64" {"arm64"} default { Die "unsupported arch" } }
$platform = "windows-$arch"

try { $meta = Invoke-RestMethod -Uri "$Base/version.json" } catch { Die "could not fetch $Base/version.json" }
$version = $meta.server.version
if (-not $version) { Die "could not determine server version" }
Info "installing cherm-server v$version ($platform) into $ServerHome"

foreach ($d in @("bin","config","data","logs","backups")) { New-Item -ItemType Directory -Force -Path (Join-Path $ServerHome $d) | Out-Null }

$artifact = "cherm-server-$platform.exe"
$url      = "$Base/releases/server/$version/$artifact"
$tmp      = Join-Path $env:TEMP ("cherm-srv-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
$bin = Join-Path $tmp "cherm-server.exe"
Info "downloading $artifact"
try { Invoke-WebRequest -Uri $url -OutFile $bin } catch { Die "no server build for $platform at v$version" }
try { $want = (Invoke-RestMethod -Uri "$url.sha256").Split(" ")[0].Trim() } catch { Die "missing checksum; refusing to install" }
$got = (Get-FileHash -Algorithm SHA256 $bin).Hash.ToLower()
if ($want -ne $got) { Die "checksum mismatch" }
Info "verification: passed"

$target = Join-Path $ServerHome "bin\cherm-server.exe"
if (Test-Path $target) { Copy-Item $target (Join-Path $ServerHome ("backups\cherm-server." + (Get-Date -Format yyyyMMdd-HHmmss) + ".exe")) -Force }
Copy-Item $bin $target -Force

$cfg = Join-Path $ServerHome "config\server.json"
if (Test-Path $cfg) {
  Copy-Item $cfg (Join-Path $ServerHome ("backups\server.json." + (Get-Date -Format yyyyMMdd-HHmmss))) -Force
  Info "existing config preserved (backed up)"
} else {
@"
{
  "name": "Cherm Server",
  "public_address": "$Public",
  "repo_url": "$Repo",
  "description": "self-hosted Cherm relay",
  "contact": "",
  "reject_unofficial_clients": false,
  "allowed_client_hashes": []
}
"@ | Set-Content -Encoding UTF8 $cfg
  Info "wrote initial config $cfg"
}

@"
`$H = "$ServerHome"
& "`$H\bin\cherm-server.exe" --addr "$Listen" --db "`$H\data\cherm-server.db" --instance-key "`$H\data\instance.key" --config "`$H\config\server.json" --version "$version"
"@ | Set-Content -Encoding UTF8 (Join-Path $ServerHome "run-server.ps1")

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Cherm Server installed." -ForegroundColor Magenta
Write-Host "  Version: v$version"
Write-Host "  Binary:  $target"
Write-Host "  Config:  $cfg"
Write-Host "  Data:    $ServerHome\data   Logs: $ServerHome\logs"
Write-Host "  Listen:  $Listen   Public: $Public"
Write-Host ""
Write-Host "Run:  & '$ServerHome\run-server.ps1'"
Write-Host "Source & audit: $Repo"
