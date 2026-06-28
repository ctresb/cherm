#!/usr/bin/env bash
# Cherm.chat official server installer (install_specification §9–§12).
#
#   curl -fsSL https://cherm.chat/server-install.sh | bash
#
# Prepares a real server environment (not just a binary): installs cherm-server,
# creates an isolated directory tree (bin/config/data/logs/backups), writes an
# initial config if none exists (NEVER overwrites an existing one — it backs up
# first), installs run/update/status/logs/stop helper scripts, and optionally a
# systemd service. Config + data are preserved across updates.
#
# Env overrides:
#   CHERM_SERVER_HOME   install root         (default: /opt/cherm if root, else ~/.cherm-server)
#   CHERM_SERVER_ADDR   listen address       (default: 0.0.0.0:9000)
#   CHERM_PUBLIC_ADDR   public address       (default: <hostname>:9000)
#   CHERM_BASE_URL      release base         (default: https://cherm.chat)
#   CHERM_SERVICE=1     install systemd unit (requires root)
set -euo pipefail

BASE="${CHERM_BASE_URL:-https://cherm.chat}"
REPO="https://github.com/cherm-chat/cherm"
c_bold=$'\033[1m'; c_mag=$'\033[35m'; c_red=$'\033[31m'; c_grn=$'\033[32m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
info() { printf '%s==>%s %s\n' "$c_mag" "$c_off" "$*"; }
err()  { printf '%serror:%s %s\n' "$c_red" "$c_off" "$*" >&2; }
die()  { err "$*"; exit 1; }

_CLEANUP=""  # temp dir removed at EXIT (set in main); global so the trap can read
             # it after main() returns under `set -u`.
[ "$(id -u)" = "0" ] && IS_ROOT=1 || IS_ROOT=0
SERVER_HOME="${CHERM_SERVER_HOME:-$([ "$IS_ROOT" = 1 ] && echo /opt/cherm || echo "$HOME/.cherm-server")}"
LISTEN_ADDR="${CHERM_SERVER_ADDR:-0.0.0.0:9000}"
PUBLIC_ADDR="${CHERM_PUBLIC_ADDR:-$(hostname -f 2>/dev/null || hostname):9000}"

detect_platform() {
  local os arch
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=macos ;; *) die "unsupported OS $(uname -s)";; esac
  case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=x64 ;; *) die "unsupported arch $(uname -m)";; esac
  echo "${os}-${arch}"
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else die "no sha256 tool to verify download"; fi
}
fetch() { curl -fsSL "$1"; }
latest_server_version() {
  fetch "$BASE/version.json" 2>/dev/null \
    | tr ',' '\n' | grep -A2 '"server"' | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 \
    | sed -E 's/.*"([^"]+)"$/\1/'
}

main() {
  command -v curl >/dev/null || die "curl is required"
  local platform version; platform="$(detect_platform)"
  version="$(latest_server_version || true)"
  [ -n "${version:-}" ] || die "could not determine server version from $BASE/version.json"
  info "installing ${c_bold}cherm-server v${version}${c_off} (${platform}) into ${c_bold}${SERVER_HOME}${c_off}"

  mkdir -p "$SERVER_HOME"/{bin,config,data,logs,backups}

  # Download + verify the server binary.
  local artifact="cherm-server-${platform}"
  local url="$BASE/releases/server/${version}/${artifact}"
  local tmp; tmp="$(mktemp -d)"; _CLEANUP="$tmp"; trap 'rm -rf "${_CLEANUP:-}"' EXIT
  info "downloading ${artifact}"
  curl -fsSL "$url" -o "$tmp/cherm-server" || die "no server build for ${platform} at v${version}"
  local want got
  want="$(fetch "${url}.sha256" 2>/dev/null | awk '{print $1}' || true)"
  [ -n "${want:-}" ] || die "missing checksum ${url}.sha256 — refusing to install unverified binary"
  got="$(sha256_of "$tmp/cherm-server")"
  [ "$want" = "$got" ] || die "checksum mismatch (want $want got $got)"
  info "verification: ${c_grn}passed${c_off}"

  # Back up an existing binary before replacing.
  if [ -f "$SERVER_HOME/bin/cherm-server" ]; then
    cp -p "$SERVER_HOME/bin/cherm-server" "$SERVER_HOME/backups/cherm-server.$(date +%Y%m%d-%H%M%S)" || true
  fi
  install -m 0755 "$tmp/cherm-server" "$SERVER_HOME/bin/cherm-server"

  # Config: create only if missing; otherwise preserve (and back up before touch).
  local cfg="$SERVER_HOME/config/server.json"
  if [ -f "$cfg" ]; then
    cp -p "$cfg" "$SERVER_HOME/backups/server.json.$(date +%Y%m%d-%H%M%S)"
    info "existing config preserved (backed up)"
  else
    cat > "$cfg" <<JSON
{
  "name": "Cherm Server",
  "public_address": "${PUBLIC_ADDR}",
  "repo_url": "${REPO}",
  "description": "self-hosted Cherm relay",
  "contact": "",
  "reject_unofficial_clients": false,
  "allowed_client_hashes": []
}
JSON
    info "wrote initial config ${cfg}"
  fi

  write_helpers "$version"
  maybe_systemd
  print_summary "$version"
}

write_helpers() {
  local version="$1"
  cat > "$SERVER_HOME/run-server.sh" <<EOF
#!/usr/bin/env bash
# Run the Cherm relay in the foreground (dev / simple mode).
set -euo pipefail
H="${SERVER_HOME}"
exec "\$H/bin/cherm-server" \\
  --addr "${LISTEN_ADDR}" \\
  --db "\$H/data/cherm-server.db" \\
  --instance-key "\$H/data/instance.key" \\
  --config "\$H/config/server.json" \\
  --version "${version}" \\
  --no-attest
EOF

  cat > "$SERVER_HOME/status.sh" <<EOF
#!/usr/bin/env bash
H="${SERVER_HOME}"
echo "binary : \$H/bin/cherm-server"
echo "config : \$H/config/server.json"
echo "data   : \$H/data"
echo "logs   : \$H/logs"
"\$H/bin/cherm-server" --version >/dev/null 2>&1 || true
pgrep -af cherm-server || echo "(not running as a bare process — check systemd/docker)"
EOF

  cat > "$SERVER_HOME/logs.sh" <<EOF
#!/usr/bin/env bash
tail -n 200 -f "${SERVER_HOME}/logs/cherm-server.log" 2>/dev/null || echo "no log file yet"
EOF

  # The graceful update flow (install_specification §12): broadcast maintenance
  # (SIGUSR1 → 60s client countdown + drain + exit), swap the verified binary,
  # restart. Preserves config + data.
  cat > "$SERVER_HOME/update-server.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
H="${SERVER_HOME}"
BASE="${BASE}"
plat() { local o a; case "\$(uname -s)" in Linux) o=linux;; Darwin) o=macos;; esac; case "\$(uname -m)" in arm64|aarch64) a=arm64;; x86_64|amd64) a=x64;; esac; echo "\${o}-\${a}"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "\$1"|awk '{print \$1}'; else shasum -a 256 "\$1"|awk '{print \$1}'; fi; }
ver=\$(curl -fsSL "\$BASE/version.json" | tr ',' '\n' | grep -A2 '"server"' | grep -o '"version"[^,]*' | head -1 | sed -E 's/.*"([^"]+)"\$/\1/')
[ -n "\$ver" ] || { echo "could not read latest version"; exit 1; }
art="cherm-server-\$(plat)"; url="\$BASE/releases/server/\$ver/\$art"
tmp=\$(mktemp -d); trap 'rm -rf "\$tmp"' EXIT
echo "==> downloading + verifying cherm-server v\$ver"
curl -fsSL "\$url" -o "\$tmp/new" || { echo "download failed"; exit 1; }
want=\$(curl -fsSL "\$url.sha256" | awk '{print \$1}'); got=\$(sha "\$tmp/new")
[ "\$want" = "\$got" ] || { echo "checksum mismatch; aborting (server keeps running)"; exit 1; }
pid=\$(pgrep -f "\$H/bin/cherm-server" | head -1 || true)
if [ -n "\$pid" ]; then
  echo "==> announcing maintenance (clients show a 60s countdown) + graceful stop"
  kill -USR1 "\$pid" || true
  # Wait for the server to finish its warning window + exit.
  for i in \$(seq 1 75); do kill -0 "\$pid" 2>/dev/null || break; sleep 1; done
fi
cp -p "\$H/bin/cherm-server" "\$H/backups/cherm-server.\$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
install -m 0755 "\$tmp/new" "\$H/bin/cherm-server"
# A hardened server refuses to start in release mode without a release key OR
# --no-attest. Older run-server.sh files predate that flag, so self-heal them
# (add --no-attest after --version) to keep the update from bricking the server.
if [ -f "\$H/run-server.sh" ] && ! grep -q -- '--no-attest\|--release-secret' "\$H/run-server.sh"; then
  sed -i -E 's/(--version "[^"]*")/\1 --no-attest/' "\$H/run-server.sh" 2>/dev/null || true
fi
echo "==> binary replaced; restarting"
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^cherm-server'; then
  systemctl restart cherm-server || sudo systemctl restart cherm-server
else
  nohup "\$H/run-server.sh" >>"\$H/logs/cherm-server.log" 2>&1 &
fi
echo "==> updated to v\$ver. Clients reconnect automatically."
EOF

  chmod +x "$SERVER_HOME"/{run-server.sh,update-server.sh,status.sh,logs.sh}
}

maybe_systemd() {
  [ "${CHERM_SERVICE:-0}" = "1" ] || return 0
  [ "$IS_ROOT" = "1" ] || { err "CHERM_SERVICE=1 requires root; skipping service install"; return 0; }
  command -v systemctl >/dev/null 2>&1 || { err "systemd not found; skipping service install"; return 0; }
  cat > /etc/systemd/system/cherm-server.service <<EOF
[Unit]
Description=Cherm relay server
After=network.target

[Service]
Type=simple
ExecStart=${SERVER_HOME}/run-server.sh
Restart=always
RestartSec=2
# Maintenance/update uses SIGUSR1 (broadcast + graceful stop); allow it.
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now cherm-server
  info "systemd service cherm-server installed and started"
}

print_summary() {
  local version="$1"
  cat <<EOF

${c_bold}${c_mag}Cherm Server installed.${c_off}

  Version:    v${version}
  Binary:     ${SERVER_HOME}/bin/cherm-server
  Config:     ${SERVER_HOME}/config/server.json
  Data:       ${SERVER_HOME}/data
  Logs:       ${SERVER_HOME}/logs
  Listen:     ${LISTEN_ADDR}
  Public:     ${PUBLIC_ADDR}

Commands:
  ${SERVER_HOME}/run-server.sh        # run in foreground
  ${SERVER_HOME}/update-server.sh     # safe update (60s maintenance, graceful)
  ${SERVER_HOME}/status.sh            # show paths + process
  ${SERVER_HOME}/logs.sh              # tail logs

Next steps:
  1. Edit ${SERVER_HOME}/config/server.json (name, public_address, policy)
  2. Point DNS for your public address at this machine
  3. Open the listen port (${LISTEN_ADDR##*:}/tcp)
  4. Start it: ${SERVER_HOME}/run-server.sh   (or: CHERM_SERVICE=1 as root for systemd)

${c_dim}Source & audit: ${REPO}${c_off}
EOF
}

main "$@"
