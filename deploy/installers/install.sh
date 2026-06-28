#!/usr/bin/env bash
# Cherm.chat official client installer (install_specification §7).
#
#   curl -fsSL https://cherm.chat/install.sh | bash
#
# Audit-friendly path (recommended for the cautious):
#   curl -fsSL https://cherm.chat/install.sh -o install.sh
#   cat install.sh
#   bash install.sh
#
# What it does: detect OS/arch, download the matching client artifact + its
# SHA-256, VERIFY it, install `cherm` + `cherm-core` into a user-local bin dir
# (no root), add it to PATH when needed, and print what it did. It never touches
# your wallet/config/plugins (~/.cherm), so re-running it is a safe upgrade.
set -euo pipefail

BASE="${CHERM_BASE_URL:-https://cherm.chat}"
PRODUCT="Cherm Client"
REPO="https://github.com/cherm-chat/cherm"

# Default install dir: on Termux (Android) prefer $PREFIX/bin (writable + already
# on PATH); elsewhere a user-local bin dir (no root needed).
default_install_dir() {
  if [ -n "${TERMUX_VERSION:-}" ] && [ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ]; then
    echo "$PREFIX/bin"
  else
    echo "$HOME/.local/bin"
  fi
}
INSTALL_DIR="${CHERM_INSTALL_DIR:-$(default_install_dir)}"

_CLEANUP=""  # temp dir to remove at EXIT (set in main); kept global so the trap
             # can read it after main() returns under `set -u`.
c_bold=$'\033[1m'; c_mag=$'\033[35m'; c_dim=$'\033[2m'; c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
say()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "$c_mag" "$c_off" "$*"; }
err()  { printf '%serror:%s %s\n' "$c_red" "$c_off" "$*" >&2; }
die()  { err "$*"; exit 1; }

# --- platform detection -----------------------------------------------------
detect_platform() {
  local os arch
  case "$(uname -s)" in
    Darwin) os=macos ;;
    Linux)  os=linux ;;
    *) die "unsupported OS '$(uname -s)'. Cherm supports macOS and Linux (Windows: use install.ps1)." ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64)  arch=x64 ;;
    *) die "unsupported CPU architecture '$(uname -m)'." ;;
  esac
  echo "${os}-${arch}"
}

# --- helpers ----------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

sha256_of() { # file -> hex
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else die "no sha256 tool (sha256sum/shasum) available to verify the download"; fi
}

fetch() { curl -fsSL "$1"; }            # to stdout
download() { curl -fsSL "$1" -o "$2"; } # to file

latest_version() {
  # First "version" in version.json is the client version.
  fetch "$BASE/version.json" 2>/dev/null \
    | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 \
    | sed -E 's/.*"([^"]+)"$/\1/'
}

# --- install ----------------------------------------------------------------
main() {
  need curl; need uname; need tar; need mktemp

  local platform; platform="$(detect_platform)"
  info "platform: ${c_bold}${platform}${c_off}"

  local version; version="$(latest_version || true)"
  [ -n "${version:-}" ] || die "could not determine the latest version from $BASE/version.json"
  info "latest ${PRODUCT}: ${c_bold}v${version}${c_off}"

  local artifact="cherm-client-${platform}.tar.gz"
  local url="$BASE/releases/client/${version}/${artifact}"
  local sha_url="${url}.sha256"

  local tmp; tmp="$(mktemp -d)"; _CLEANUP="$tmp"; trap 'rm -rf "${_CLEANUP:-}"' EXIT
  info "downloading ${artifact}"
  download "$url" "$tmp/$artifact" || die "no build for ${platform} at v${version} (artifact not found). See $REPO/releases."

  # Verify SHA-256 against the published sidecar (verification MUST pass).
  local want got
  want="$(fetch "$sha_url" 2>/dev/null | awk '{print $1}' || true)"
  [ -n "${want:-}" ] || die "could not fetch checksum ${sha_url} — refusing to install unverified binary"
  got="$(sha256_of "$tmp/$artifact")"
  if [ "$want" != "$got" ]; then
    die "checksum mismatch (expected $want, got $got) — refusing to install"
  fi
  info "verification: ${c_grn}passed${c_off} (sha256 ${got:0:16}…)"

  # Extract (tarball contains: cherm, cherm-core).
  tar -xzf "$tmp/$artifact" -C "$tmp"
  [ -f "$tmp/cherm" ] && [ -f "$tmp/cherm-core" ] || die "archive missing cherm/cherm-core binaries"

  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$tmp/cherm" "$INSTALL_DIR/cherm"
  install -m 0755 "$tmp/cherm-core" "$INSTALL_DIR/cherm-core"

  # PATH: add INSTALL_DIR if it isn't already reachable.
  local path_updated="no"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) : ;;
    *) ensure_on_path "$INSTALL_DIR" && path_updated="yes" ;;
  esac

  print_summary "$version" "$path_updated"
}

# Append INSTALL_DIR to the user's shell rc (guarded; never duplicates).
ensure_on_path() {
  local dir="$1" rc=""
  case "${SHELL:-}" in
    *zsh)  rc="$HOME/.zshrc" ;;
    *bash) rc="$HOME/.bashrc" ;;
    *) rc="$HOME/.profile" ;;
  esac
  local line="export PATH=\"$dir:\$PATH\"  # added by cherm install.sh"
  if [ -f "$rc" ] && grep -qF "added by cherm install.sh" "$rc"; then return 0; fi
  printf '\n%s\n' "$line" >> "$rc" || return 1
  return 0
}

print_summary() {
  local version="$1" path_updated="$2"
  cat <<EOF

${c_bold}${c_mag}${PRODUCT} installed.${c_off}

  Version:      v${version}
  Path:         ${INSTALL_DIR}/cherm
  Core:         ${INSTALL_DIR}/cherm-core
  Verification: passed (SHA-256)
  PATH updated: ${path_updated}

Run:
  ${c_bold}cherm${c_off}
EOF
  if [ "$path_updated" = "yes" ]; then
    say ""
    say "${c_dim}Open a new terminal (or 'source' your shell rc) so 'cherm' is on PATH.${c_off}"
  fi
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) : ;;
    *) say "${c_dim}If 'cherm' is not found, run it as: ${INSTALL_DIR}/cherm${c_off}" ;;
  esac
  say ""
  say "Connect to the official server from the app: add  ${c_bold}srv.cherm.chat:9000${c_off}"
  say "${c_dim}Source & audit: ${REPO}${c_off}"
}

main "$@"
