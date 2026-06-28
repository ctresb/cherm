# Cherm distribution, plugin store & deployment

This directory holds everything that turns the source tree into the live
`cherm.chat` product: the installers, the Cloudflare edge worker, the R2 publish
scripts, the official `pastel-theme` plugin, and the server deployment for
`srv.cherm.chat`. It implements `install_specification.md` and the store half of
`architecture_specification.md`.

## Live endpoints

| URL | what | backed by |
|---|---|---|
| `https://cherm.chat/install.sh` · `/install.ps1` | client installers | Worker → R2 `cherm-dist` |
| `https://cherm.chat/server-install.sh` · `/server-install.ps1` | server installers | Worker → R2 `cherm-dist` |
| `https://cherm.chat/version.json` | release metadata (client update check) | R2 `cherm-dist` |
| `https://cherm.chat/releases/...` | binaries + SHA-256 sidecars | R2 `cherm-dist` |
| `https://plugins.cherm.chat/index` | store catalog | R2 `cherm-plugins` |
| `https://plugins.cherm.chat/{plugin}/manifest` · `/package` · `/releases/{v}/...` | plugin objects | R2 `cherm-plugins` |
| `https://plugins.cherm.chat/submit` | community submission (→ unaudited) | Worker |
| `srv.cherm.chat:9000` | official relay (raw TCP, **DNS-only** A record) | Hetzner Docker |

`cherm.chat` + `plugins.cherm.chat` are Cloudflare Worker custom domains
(`deploy/worker`). `srv.cherm.chat` is a **DNS-only A record** to the Hetzner IP —
the Cherm wire protocol is raw length-prefixed TCP, which Cloudflare cannot
proxy, so the client connects straight to the origin on port 9000.

## Layout

```
deploy/
  installers/      install.sh / install.ps1 / server-install.sh / server-install.ps1
  worker/          cherm-edge.js + wrangler.toml  (the cherm.chat + plugins.cherm.chat worker)
  plugins/         pastel-theme (v1, v2) + publish-plugins.sh
  server/          cherm-docker.sh  (operate the srv.cherm.chat container)
  dist/            version.json + staged release artifacts (releases/<kind>/<ver>/...)
  publish-dist.sh  upload installers + version.json + artifacts to R2 (cherm-dist)
```

## Build & publish a release

```sh
# 1. Build artifacts (macOS arm64 client built natively; linux server via Docker)
make build                                   # cherm-core (Rust) + cherm (Go)
# stage the client tarball + sha into deploy/dist/releases/client/<ver>/
#   tar -czf cherm-client-macos-arm64.tar.gz cherm cherm-core
#   shasum -a 256 ...tar.gz | awk '{print $1}' > ...tar.gz.sha256
# build the linux server binary on a linux host (or Docker) and stage it under
#   deploy/dist/releases/server/<ver>/cherm-server-linux-x64 (+ .sha256)

# 2. Publish distribution to R2 (cherm-dist) -> served at cherm.chat
cd deploy && ./publish-dist.sh

# 3. Publish plugins to R2 (cherm-plugins) -> served at plugins.cherm.chat
cd deploy/plugins && ./publish-plugins.sh 1.0.0     # current pastel-theme = v1.0.0
#                    ./publish-plugins.sh 1.1.0     # ship the live update (adds clock widget)

# 4. Deploy / update the edge worker
cd deploy/worker && wrangler deploy
```

Every artifact has a published `.sha256`; both installers refuse to install if
the checksum is missing or mismatched.

### Update signing (trust anchor)

`publish-dist.sh` also produces a detached **Ed25519 `.sig`** over each artifact
(`deploy/tools/sign.go`). The client self-updater (`cherm --update` /
`/update-now`) verifies that signature against a release public key **embedded in
the binary** *before* installing — so the auto/unattended update path does not
trust the download origin. A same-origin `.sha256` alone is not a trust anchor
(an attacker controlling the host swaps both); the **signature** gates the
install, and `CHERM_BASE_URL` is therefore safe to keep (a hostile mirror cannot
forge a valid signature). Set `CHERM_RELEASE_SECRET_B64` to sign with a real
release key (the matching public key must be embedded as `releasePublicKeyB64`
in `tui/update.go`); the default is the public dev key, which proves the
mechanism but is not a production trust root (same honest scope as the 🟡
software attestation tier).

## The official server (srv.cherm.chat)

Deployed on the Hetzner host as a **Docker container** (no root / systemd needed —
just the `docker` group), isolated under `~/cherm`, publishing `0.0.0.0:9000`.
It bypasses the host's Traefik entirely (Traefik is HTTP-only; Cherm is raw TCP),
so it does not touch any existing service.

```
~/cherm/
  build/      backend source + Dockerfile (multi-stage rust → debian-slim)
  config/server.json   operator metadata + client policy (preserved across updates)
  data/       cherm-server.db + instance.key (the stable server identity)
  cherm-docker.sh      run | status | logs | maintenance | update | stop
```

Operate it:

```sh
~/cherm/cherm-docker.sh status        # container + recent logs
~/cherm/cherm-docker.sh maintenance   # announce + graceful stop (auto-restarts)
~/cherm/cherm-docker.sh update        # rebuild image, then graceful restart
```

The server shows the **🟡 software (yellow)** attestation tier — a genuine
official release hash signed by the project key, which is the honest verdict for
a normal VPS (a 🟢 green TEE tier needs an AWS Nitro enclave). See
[ATTESTATION.md](../ATTESTATION.md).

### Update / maintenance flow (install_specification §12)

`cherm-docker.sh maintenance` runs `docker exec cherm-server kill -USR1 1`. The
server then:

1. broadcasts a `Maintenance` event with a deadline to every online client —
   clients render a **local 60-second countdown** (not 60 chat messages) and
   enter "waiting for server";
2. stops accepting new connections (drains);
3. waits the warning window, then exits cleanly;
4. `--restart always` (or a rebuilt image, for `update`) brings it back with the
   same `instance.key` (stable identity) and the same `cherm-server.db`;
5. clients reconnect automatically and show "server updated".

> Use `docker exec … kill -USR1 1`, **not** `docker kill -s USR1` — the latter
> marks the container manually-stopped and suppresses the restart policy.

## Plugin submissions

The store backend forces every submission to `community_unaudited` and re-checks
permissions (deny-by-default) before storing it in R2. Optionally set a
`SUBMIT_TOKEN` secret on the worker (`wrangler secret put SUBMIT_TOKEN`) and the
client `CHERM_SUBMIT_TOKEN` env to gate submissions. See
[PLUGIN_POLICY.md](../PLUGIN_POLICY.md).

## Environment overrides (testing)

| var | used by | effect |
|---|---|---|
| `CHERM_BASE_URL` | installers | release base (default `https://cherm.chat`) |
| `CHERM_INSTALL_DIR` | install.sh | client install dir (default `~/.local/bin`) |
| `CHERM_PLUGINS_URL` | cherm-core | plugin store base (default `https://plugins.cherm.chat`) |
| `CHERM_UPDATE_URL` | cherm-core | client update metadata (default `https://cherm.chat/version.json`) |
| `CHERM_SUBMIT_TOKEN` | cherm-core | submission auth header |
