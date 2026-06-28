# Cherm.chat official client installer for Windows (install_specification §7).
#
#   iex (irm https://cherm.chat/install.ps1)
#
# Detects architecture, downloads the matching client artifact + its SHA-256,
# VERIFIES it, installs cherm.exe + cherm-core.exe into a user-local dir, and
# adds it to the user PATH. It never touches %USERPROFILE%\.cherm (wallet/config
# /plugins), so re-running is a safe upgrade.
$ErrorActionPreference = "Stop"

$Base       = if ($env:CHERM_BASE_URL) { $env:CHERM_BASE_URL } else { "https://cherm.chat" }
$InstallDir = if ($env:CHERM_INSTALL_DIR) { $env:CHERM_INSTALL_DIR } else { "$env:LOCALAPPDATA\Cherm\bin" }
$Repo       = "https://github.com/ctresb/cherm"

function Info($m) { Write-Host "==> $m" -ForegroundColor Magenta }
function Die($m)  { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# --- platform ---
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { "x64" }
  "ARM64" { "arm64" }
  default { Die "unsupported architecture $env:PROCESSOR_ARCHITECTURE" }
}
$platform = "windows-$arch"
Info "platform: $platform"

# --- latest version ---
try { $meta = Invoke-RestMethod -Uri "$Base/version.json" } catch { Die "could not fetch $Base/version.json" }
$version = $meta.client.version
if (-not $version) { Die "could not determine latest version" }
Info "latest Cherm Client: v$version"

$artifact = "cherm-client-$platform.zip"
$url      = "$Base/releases/client/$version/$artifact"
$tmp      = Join-Path $env:TEMP ("cherm-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
$zip = Join-Path $tmp $artifact

Info "downloading $artifact"
try { Invoke-WebRequest -Uri $url -OutFile $zip } catch { Die "no Windows build for $platform at v$version ($Repo/releases)" }

# --- verify SHA-256 ---
try { $want = (Invoke-RestMethod -Uri "$url.sha256").Split(" ")[0].Trim() } catch { Die "missing checksum; refusing to install unverified binary" }
$got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
if ($want -ne $got) { Die "checksum mismatch (want $want got $got)" }
Info "verification: passed"

# --- install ---
Expand-Archive -Path $zip -DestinationPath $tmp -Force
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item (Join-Path $tmp "cherm.exe")      (Join-Path $InstallDir "cherm.exe")      -Force
Copy-Item (Join-Path $tmp "cherm-core.exe") (Join-Path $InstallDir "cherm-core.exe") -Force

# --- PATH (user) ---
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
  $pathUpdated = "yes"
} else { $pathUpdated = "no" }

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Cherm Client installed." -ForegroundColor Magenta
Write-Host "  Version:      v$version"
Write-Host "  Path:         $InstallDir\cherm.exe"
Write-Host "  Verification: passed (SHA-256)"
Write-Host "  PATH updated: $pathUpdated"
Write-Host ""
Write-Host "Open a new terminal, then run:  cherm"
Write-Host "Official server: srv.cherm.chat:9000"
Write-Host "Source & audit:  $Repo"
