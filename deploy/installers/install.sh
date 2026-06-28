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
REPO="https://github.com/ctresb/cherm"

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

# ---------------------------------------------------------------------------
# Look & feel — mirrors the cherm.chat landing terminal: magenta→pink palette,
# the ◜◝◞◟ quadrant spinner, and the ▰▱ download bar. All animation is gated on
# an interactive terminal, so `curl | bash` logs, CI, and NO_COLOR stay clean.
# ---------------------------------------------------------------------------
CHERM_TTY=0; HAS_TRUECOLOR=0; SPIN_DELAY=0.1
c_mag=''; c_pink=''; c_grn=''; c_mut=''; c_dim=''; c_red=''; c_bold=''; c_off=''
init_style() {
  [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ] || return 0
  CHERM_TTY=1
  c_bold=$'\033[1m'; c_off=$'\033[0m'
  case "${COLORTERM:-}" in
    truecolor|24bit) HAS_TRUECOLOR=1 ;;
  esac
  if [ "$HAS_TRUECOLOR" = 1 ]; then
    c_mag=$'\033[38;2;238;0;255m'    # #ee00ff
    c_pink=$'\033[38;2;255;0;123m'   # #ff007b
    c_grn=$'\033[38;2;49;208;122m'   # #31d07a
    c_mut=$'\033[38;2;154;156;166m'  # #9a9ca6
    c_dim=$'\033[38;2;98;100;109m'   # #62646d
    c_red=$'\033[38;2;255;77;79m'
  else
    c_mag=$'\033[35m'; c_pink=$'\033[95m'; c_grn=$'\033[32m'
    c_mut=$'\033[37m'; c_dim=$'\033[2m';  c_red=$'\033[31m'
  fi
  # Some minimal shells (busybox) only accept integer sleeps; fall back so the
  # animation stays correct instead of busy-looping.
  sleep 0.1 2>/dev/null && SPIN_DELAY=0.1 || SPIN_DELAY=1
}
hide_cursor() { [ "$CHERM_TTY" = 1 ] && printf '\033[?25l' || true; }
show_cursor() { [ "$CHERM_TTY" = 1 ] && printf '\033[?25h' || true; }

say()  { printf '%s\n' "$*"; }
info() { printf '  %s==>%s %s\n' "$c_mag" "$c_off" "$*"; }
ok()   { printf '  %s✓%s  %s\n' "$c_grn$c_bold" "$c_off" "$*"; }
err()  { printf '%serror:%s %s\n' "$c_red" "$c_off" "$*" >&2; }
die()  { show_cursor; err "$*"; exit 1; }

# A magenta→pink gradient ▰ rule (the landing's signature). Falls back to a flat
# magenta bar without truecolor.
gradient_bar() {
  local n=${1:-28} i r b
  if [ "$HAS_TRUECOLOR" != 1 ]; then
    printf '%s' "$c_mag"; for ((i=0;i<n;i++)); do printf '▰'; done; printf '%s' "$c_off"; return
  fi
  for ((i=0;i<n;i++)); do
    r=$(( 238 + (255-238)*i/(n-1) ))
    b=$(( 255 + (123-255)*i/(n-1) ))
    printf '\033[38;2;%d;0;%dm▰' "$r" "$b"
  done
  printf '%s' "$c_off"
}

header() {
  if [ "$CHERM_TTY" != 1 ]; then printf '== %s installer ==\n\n' "$PRODUCT"; return; fi
  printf '\n'
  printf '  %s%s◜◝%s   %s%sCHERM%s %s· client%s\n'   "$c_bold" "$c_mag" "$c_off" "$c_bold" "$c_pink" "$c_off" "$c_dim" "$c_off"
  printf '  %s%s◟◞%s   %send-to-end encrypted · the relay only sees ciphertext%s\n' "$c_bold" "$c_mag" "$c_off" "$c_mut" "$c_off"
  printf '  '; gradient_bar 30; printf '\n\n'
}

# ◜◝◞◟ spinner over a running PID; resolves to ✓ (or ✗) and returns its exit.
spin() { # pid label
  local pid=$1 label=$2; local frames=(◜ ◝ ◞ ◟) i=0 rc
  if [ "$CHERM_TTY" != 1 ]; then
    info "$label"; set +e; wait "$pid"; rc=$?; set -e; return "$rc"
  fi
  hide_cursor
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r  %s%s%s  %s\033[K' "$c_mag$c_bold" "${frames[i % 4]}" "$c_off" "$label"
    i=$(( i + 1 )); sleep "$SPIN_DELAY"
  done
  set +e; wait "$pid"; rc=$?; set -e
  show_cursor
  if [ "$rc" -eq 0 ]; then printf '\r  %s✓%s  %s\033[K\n' "$c_grn$c_bold" "$c_off" "$label"
  else printf '\r  %s✗%s  %s\033[K\n' "$c_red$c_bold" "$c_off" "$label"; fi
  return "$rc"
}

# Run a command behind a spinner, surfacing its output only on failure.
run_spin() { # label cmd...
  local label=$1; shift
  if [ "$CHERM_TTY" != 1 ]; then info "$label"; "$@"; return $?; fi
  local log; log="$(mktemp)"; local rc
  ( "$@" ) >"$log" 2>&1 & local pid=$!
  set +e; spin "$pid" "$label"; rc=$?; set -e
  [ "$rc" -ne 0 ] && sed 's/^/      /' "$log" >&2
  rm -f "$log"; return "$rc"
}

# ▰▱ download bar driven by ACTUAL bytes (Content-Length vs the growing file).
fsize() { stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || wc -c <"$1" 2>/dev/null || echo 0; }
content_length() { curl -fsSLI "$1" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="content-length:"{n=$2} END{if(n)print n}'; }
draw_bar() { # done total width
  local done=$1 total=$2 width=$3 pct=0 fill i s='' e=''
  [ "$total" -gt 0 ] 2>/dev/null && pct=$(( done * 100 / total )); [ "$pct" -gt 100 ] && pct=100
  fill=$(( pct * width / 100 ))
  for ((i=0;i<fill;i++));     do s+='▰'; done
  for ((i=fill;i<width;i++)); do e+='▱'; done
  printf '\r  %s%s%s%s%s  %s%3d%%%s\033[K' "$c_mag" "$s" "$c_dim" "$e" "$c_off" "$c_bold" "$pct" "$c_off"
}
download_pretty() { # url out label
  local url=$1 out=$2 label=$3 width=24 rc total
  info "$label"
  if [ "$CHERM_TTY" != 1 ]; then curl -fsSL "$url" -o "$out"; return $?; fi
  total="$(content_length "$url" || true)"
  curl -fsSL "$url" -o "$out" & local pid=$!
  hide_cursor
  if [ -n "${total:-}" ] && [ "$total" -gt 0 ] 2>/dev/null; then
    while kill -0 "$pid" 2>/dev/null; do draw_bar "$(fsize "$out")" "$total" "$width"; sleep "$SPIN_DELAY"; done
    set +e; wait "$pid"; rc=$?; set -e
    [ "$rc" -eq 0 ] && draw_bar "$total" "$total" "$width"; printf '\n'
  else
    local frames=(◜ ◝ ◞ ◟) i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r  %s%s%s  receiving…\033[K' "$c_mag$c_bold" "${frames[i % 4]}" "$c_off"; i=$(( i + 1 )); sleep "$SPIN_DELAY"
    done
    set +e; wait "$pid"; rc=$?; set -e; printf '\r\033[K'
  fi
  show_cursor
  return "${rc:-0}"
}

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

# Extract + install the two binaries (run behind the spinner). Returns non-zero
# with a message on any problem so the caller can abort.
do_install() { # tmp artifact dir
  local tmp=$1 artifact=$2 dir=$3
  tar -xzf "$tmp/$artifact" -C "$tmp"
  [ -f "$tmp/cherm" ] && [ -f "$tmp/cherm-core" ] || { echo "archive missing cherm/cherm-core binaries"; return 1; }
  mkdir -p "$dir"
  install -m 0755 "$tmp/cherm" "$dir/cherm"
  install -m 0755 "$tmp/cherm-core" "$dir/cherm-core"
}

# --- install ----------------------------------------------------------------
main() {
  init_style
  trap 'show_cursor' EXIT
  need curl; need uname; need tar; need mktemp

  header

  local platform; platform="$(detect_platform)"
  info "platform · ${c_bold}${platform}${c_off}"

  local version; version="$(latest_version || true)"
  [ -n "${version:-}" ] || die "could not determine the latest version from $BASE/version.json"
  info "latest ${PRODUCT} · ${c_bold}v${version}${c_off}"

  local artifact="cherm-client-${platform}.tar.gz"
  local url="$BASE/releases/client/${version}/${artifact}"
  local sha_url="${url}.sha256"

  local tmp; tmp="$(mktemp -d)"; _CLEANUP="$tmp"; trap 'show_cursor; rm -rf "${_CLEANUP:-}"' EXIT

  download_pretty "$url" "$tmp/$artifact" "downloading ${artifact}" \
    || die "no build for ${platform} at v${version} (artifact not found). See $REPO/releases."

  # Verify SHA-256 against the published sidecar (verification MUST pass).
  local want got
  want="$(fetch "$sha_url" 2>/dev/null | awk '{print $1}' || true)"
  [ -n "${want:-}" ] || die "could not fetch checksum ${sha_url} — refusing to install unverified binary"
  got="$(sha256_of "$tmp/$artifact")"
  if [ "$want" != "$got" ]; then
    die "checksum mismatch (expected $want, got $got) — refusing to install"
  fi
  ok "verified · sha256 ${c_dim}${got:0:16}…${c_off}"

  run_spin "installing cherm + cherm-core" do_install "$tmp" "$artifact" "$INSTALL_DIR" \
    || die "install failed"
  ok "installed ${c_mag}→${c_off} ${INSTALL_DIR}/cherm"

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
  printf '\n'
  printf '  '; gradient_bar 30; printf '\n'
  printf '  %s%s%s installed%s  %sv%s%s\n\n' "$c_bold" "$c_mag" "$PRODUCT" "$c_off" "$c_dim" "$version" "$c_off"
  printf '    %sbinary%s   %s/cherm\n'      "$c_mut" "$c_off" "$INSTALL_DIR"
  printf '    %score%s     %s/cherm-core\n' "$c_mut" "$c_off" "$INSTALL_DIR"
  printf '    %sverified%s %ssha256%s\n'    "$c_mut" "$c_off" "$c_grn" "$c_off"
  printf '    %spath%s     %supdated: %s%s\n' "$c_mut" "$c_off" "$c_dim" "$path_updated" "$c_off"
  printf '\n  run  %s%s❯%s %scherm%s\n' "$c_pink" "$c_bold" "$c_off" "$c_bold" "$c_off"
  if [ "$path_updated" = "yes" ]; then
    say ""
    say "  ${c_dim}Open a new terminal (or 'source' your shell rc) so 'cherm' is on PATH.${c_off}"
  fi
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) : ;;
    *) say "  ${c_dim}If 'cherm' is not found, run it as: ${INSTALL_DIR}/cherm${c_off}" ;;
  esac
  say ""
  say "  Add the official relay in-app:  ${c_bold}srv.cherm.chat:9000${c_off}"
  say "  ${c_dim}Source & audit: ${REPO}${c_off}"
  printf '  '; gradient_bar 30; printf '\n'
}

main "$@"
