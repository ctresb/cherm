#!/usr/bin/env bash
# Publish the Cherm distribution to R2 (bucket: cherm-dist, served at
# https://cherm.chat/...): install scripts, version metadata, and release
# artifacts (binaries + SHA-256 sidecars).
#
#   ./publish-dist.sh           # upload scripts + version.json + whatever
#                               # artifacts are staged under deploy/dist/releases
set -euo pipefail

BUCKET="cherm-dist"
HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(grep -o '"version"[^,]*' "$HERE/dist/version.json" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"

put() { # key file content-type
  wrangler r2 object put "${BUCKET}/$1" --file="$2" --content-type="$3" --remote >/dev/null 2>&1 \
    && echo "  put  $1  ($3)"
}

echo "==> installers + metadata"
put "install.sh"         "$HERE/installers/install.sh"         "text/x-shellscript"
put "install.ps1"        "$HERE/installers/install.ps1"        "text/plain"
put "server-install.sh"  "$HERE/installers/server-install.sh"  "text/x-shellscript"
put "server-install.ps1" "$HERE/installers/server-install.ps1" "text/plain"
put "version.json"       "$HERE/dist/version.json"             "application/json"

# Sign the primary artifacts (tarballs / binaries) with the project release key.
# The client self-updater verifies these with its EMBEDDED public key, so a
# compromised origin can't forge an update (set CHERM_RELEASE_SECRET_B64 for a
# real release; defaults to the public dev key).
echo "==> signing artifacts (detached Ed25519 .sig)"
shopt -s nullglob
for f in "$HERE"/dist/releases/client/"$VERSION"/* "$HERE"/dist/releases/server/"$VERSION"/*; do
  case "$f" in
    *.sha256|*.sig) : ;;                                  # don't sign sidecars
    *) go run "$HERE/tools/sign.go" "$f" ;;
  esac
done

echo "==> release artifacts (v${VERSION})"
for f in "$HERE"/dist/releases/client/"$VERSION"/* "$HERE"/dist/releases/server/"$VERSION"/*; do
  rel="${f#$HERE/dist/}"
  case "$f" in
    *.sha256) ct="text/plain" ;;
    *.sig)    ct="text/plain" ;;
    *.tar.gz) ct="application/gzip" ;;
    *.zip)    ct="application/zip" ;;
    *)        ct="application/octet-stream" ;;
  esac
  put "$rel" "$f" "$ct"
done

echo "done. version=${VERSION}"
