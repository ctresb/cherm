#!/usr/bin/env bash
# Publish official Cherm plugins to R2 (bucket: cherm-plugins, served at
# https://plugins.cherm.chat/{plugin}/...).
#
# Object layout (R2 key == URL path):
#   pastel-theme/manifest                 -> latest manifest (what clients see)
#   pastel-theme/package                  -> latest package
#   pastel-theme/releases/<ver>/manifest  -> per-version manifest
#   pastel-theme/releases/<ver>/package   -> per-version package
#   index                                 -> store catalog {"plugins":[...]}
#
# The "current" pointers + index default to v1.0.0. Re-run with `1.1.0` to
# publish the live update (adds the clock widget) so plugin update detection can
# be tested end to end:
#
#   ./publish-plugins.sh 1.0.0      # initial publish
#   ./publish-plugins.sh 1.1.0      # ship the live update
set -euo pipefail

BUCKET="cherm-plugins"
HERE="$(cd "$(dirname "$0")" && pwd)"
CURRENT="${1:-1.0.0}"
TS="$(date +%s)000"

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
put() { # key file
  wrangler r2 object put "${BUCKET}/$1" --file="$2" --content-type=application/json --remote >/dev/null 2>&1 \
    && echo "  put  $1"
}

# Emit a pastel-theme manifest for a given version + package file to stdout.
manifest() { # version package_file permissions_json
  local ver="$1" pkg="$2" perms="$3"
  cat <<JSON
{
  "name": "pastel-theme",
  "display_name": "Pastel Theme",
  "version": "${ver}",
  "kind": "theme",
  "category": "official",
  "description": "A soft pastel color theme for the Cherm TUI, maintained by Cherm.",
  "author": "Cherm",
  "license": "AGPL-3.0",
  "source_url": "https://github.com/cherm-chat/cherm/tree/main/deploy/plugins/pastel-theme",
  "permissions": ${perms},
  "min_client": "0.1.0",
  "package_sha256": "$(sha256 "$pkg")",
  "updated_ts": ${TS}
}
JSON
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> pastel-theme: building manifests"
manifest "1.0.0" "$HERE/pastel-theme/v1/package.json" '["tui.theme"]'             > "$work/m1.json"
manifest "1.1.0" "$HERE/pastel-theme/v2/package.json" '["tui.theme","tui.widget"]' > "$work/m2.json"

echo "==> uploading release objects"
put "pastel-theme/releases/1.0.0/manifest" "$work/m1.json"
put "pastel-theme/releases/1.0.0/package"  "$HERE/pastel-theme/v1/package.json"
put "pastel-theme/releases/1.1.0/manifest" "$work/m2.json"
put "pastel-theme/releases/1.1.0/package"  "$HERE/pastel-theme/v2/package.json"

echo "==> setting current pointers to v${CURRENT}"
case "$CURRENT" in
  1.0.0) cur_m="$work/m1.json"; cur_p="$HERE/pastel-theme/v1/package.json" ;;
  1.1.0) cur_m="$work/m2.json"; cur_p="$HERE/pastel-theme/v2/package.json" ;;
  *) echo "unknown version $CURRENT (expected 1.0.0 or 1.1.0)"; exit 1 ;;
esac
put "pastel-theme/manifest" "$cur_m"
put "pastel-theme/package"  "$cur_p"

echo "==> building store index"
jq -n --slurpfile m "$cur_m" '{plugins: $m}' > "$work/index.json"
put "index" "$work/index.json"

echo "done. current pastel-theme = v${CURRENT}"
