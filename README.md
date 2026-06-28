<p align="center">
  <img src="docs/assets/cherm-logo.svg" alt="cherm.chat" width="520">
</p>

<p align="center">
  Private terminal chat. End-to-end encrypted messages. Dumb relay. Local encrypted vaults. Verifiable server builds.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-ff007b"></a>
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2021-ee00ff">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.26-ff007b">
</p>

# cherm.chat

`cherm.chat` is a private terminal chat app built around a simple rule: the server relays ciphertext and nothing else.

The client owns identity, sessions, vaults, plugins, update checks, and message crypto. The relay stores only what it needs to deliver offline encrypted messages. Clients verify the server's claimed build before connecting, with an honest green/yellow/red attestation model instead of fake software-only guarantees.

## What it does

- Runs as a Bubble Tea terminal UI with a Rust core process behind it.
- Encrypts DMs with Olm and groups with Megolm through Matrix's audited `vodozemac` crate.
- Keeps each server in its own encrypted SQLCipher vault under `~/.cherm/servers/<id>/vault.db`.
- Uses challenge-response login. No passwords. Each `(user, server)` pair has its own device identity.
- Lets users compare safety numbers to catch key-substitution attacks by a malicious relay.
- Supports DMs, groups, chat leave notices, server switching, updates, and a declarative plugin store.
- Lets anyone run a relay server, while clients show whether the server is TEE-attested, software-signed, or unsigned.

## Install

macOS / Linux:

```sh
curl -fsSL https://cherm.chat/install.sh | bash
```

Windows:

```powershell
iex (irm https://cherm.chat/install.ps1)
```

Audit-friendly install path:

```sh
curl -fsSL https://cherm.chat/install.sh -o install.sh
less install.sh
bash install.sh
```

The installer detects OS/arch, downloads the matching artifact, verifies SHA-256, and installs `cherm` plus `cherm-core` into `~/.local/bin`. It does not touch `~/.cherm`, so rerunning it is the normal upgrade path.

Start it:

```sh
cherm
```

The official `cherm.chat` server is already in the server list. Select it and pick a username. Press `a` to add another server, or `x` to remove one from the list.

## Updating

The client checks for official updates on launch and shows an opt-in banner. It never updates silently.

```sh
cherm --update
cherm --version
```

The updater verifies a detached Ed25519 signature over the artifact against the public release key embedded in the client. SHA-256 sidecars catch corruption; the signature is the trust anchor. The current embedded default is the public dev release key, proving the mechanism. Production releases should embed a key whose secret is held by the project alone.

## Build from source

Requirements:

- recent Rust toolchain
- Go `1.26` or newer
- `make`

Build everything:

```sh
make build
```

Run backend tests:

```sh
make test
```

Clean build artifacts:

```sh
make clean
```

First Rust build can take a while because SQLCipher is vendored and built from source through `rusqlite`.

## Run locally

Terminal 1, start a relay:

```sh
make server
```

Default bind: `0.0.0.0:9000`.

Custom bind:

```sh
SERVER_ADDR=0.0.0.0:4000 make server
```

Terminal 2, start the TUI:

```sh
make run
```

`make run` builds the Rust backend and Go TUI, then starts `tui/cherm` with `CHERM_CORE` pointing at `backend/target/release/cherm-core`.

## Architecture

![cherm.chat architecture infographic](docs/infographic/cherm-architecture/cherm-architecture.png)

| Layer | Owns | Does not own |
|---|---|---|
| `tui/` | Terminal screens, input, command rendering, plugin/update UI | keys, ciphertext internals, vault storage |
| `backend/core/` | identities, sessions, message crypto orchestration, vaults, update/plugin clients, IPC | terminal presentation |
| `backend/server/` | registration directory, prekey store, ciphertext queue, attestation metadata | plaintext, client keys, message bodies |
| `backend/proto/` | shared wire and IPC message types | runtime behavior |
| `backend/crypto/` | Olm/Megolm wrapping, vault key derivation, crypto tests | network or UI state |
| `backend/attest/` | AWS Nitro quote verification and software signature verification | policy UI |

## Attestation model

Before connecting, the client asks the server to attest what it is running.

| Verdict | Meaning | User posture |
|---|---|---|
| Green | AWS Nitro TEE quote matches the official build. | Safe to connect, within Nitro's trust model. |
| Yellow | Software signature matches an official release hash. | Useful signal, but the operator can still run different code. |
| Red | Unsigned, unknown, or mismatched code claim. | Connect anyway only after an explicit countdown. |

Pure software cannot prove its own integrity. A server operator can patch a binary to report any hash. TEE attestation is the only tier here that makes the running-code claim hard to forge, and it still depends on the TEE vendor. Details live in [ATTESTATION.md](ATTESTATION.md).

## Privacy model

What Cherm protects today:

- message content in transit and at rest on the client;
- local chat history through per-server encrypted vaults;
- account login without server-side passwords;
- pairwise identity checks through safety numbers;
- relay storage limited to ciphertext needed for offline delivery.

What it does not fully hide yet:

- who talks to whom;
- timing;
- message sizes;
- server membership;
- group forward secrecy after a member leaves, until the next rekey.

Metadata privacy needs more work: sealed sender, padding, transport anonymity, and stronger group rekeying. The current scope is documented in [PRIVACY.md](PRIVACY.md).

## TUI commands

| Command | Action |
|---|---|
| `/dm <user>` | Start or open a 1:1 chat. |
| `/group <name> <user> ...` | Create a group chat. |
| `/store` | Browse and install plugins. |
| `/submit` | Submit a plugin to the official store. |
| `/update` | Check for a newer client. |
| `/menu` | Open server, ping, server switch, and docs actions. |
| `/help` | Show commands and key reference. |
| `/quit` | Exit. |
| anything else | Send a message to the open chat. |

Key controls:

| Key | Action |
|---|---|
| `Tab` | Switch focus. |
| `↑` / `↓` | Move selection. |
| `Enter` | Open, confirm, or send. |
| `Esc` | Open menu or go back. |
| `x` on chat list | Leave selected chat after confirmation. |

Messages render with a fixed prefix:

```text
[bob][28/06/26 - 14:03:21]> hey there
[you][28/06/26 - 14:03:25]> hello!
[✣ System][28/06/26 - 14:05:10]> alice left the chat.
```

`System` and `Server` are reserved names, case-insensitive. Users cannot register them.

## Plugins

Plugins are declarative packages, not arbitrary code. A theme is a plugin that ships palette data. Widgets follow the same sandboxed data model.

The official store lives at `plugins.cherm.chat`. `/store` shows each package with a trust tier before install:

| Tier | Meaning |
|---|---|
| Official | Maintained or approved by Cherm. |
| Community audited | Public source reviewed and accepted by Cherm. |
| Community unaudited | Submitted, not reviewed yet. Shown as risky. |

Plugin permissions are deny-by-default. Wallet access, where present, is read-only and granular: status, address, balance, and fiat conversion. Plugins cannot read keys or seed phrases, sign transactions, broadcast transactions, touch the confirmation UI, bypass notifications, or impersonate system UI.

Installed plugin packages are checked by SHA-256. Installed plugins show `update ↑` when a newer version exists. Full rules: [PLUGIN_POLICY.md](PLUGIN_POLICY.md).

## Server operation

Run a local server through `make server`, or install a hosted relay:

```sh
curl -fsSL https://cherm.chat/server-install.sh | bash
```

Docker and release-publishing notes live in [deploy/README.md](deploy/README.md).

Important server flags:

| Flag | Purpose |
|---|---|
| `--addr <host:port>` | Bind address. |
| `--db <path>` | SQLite database path. |
| `--no-attest` | Advertise unsigned tier. Clients show red. |
| `--release-secret <b64>` | Sign a software attestation with a release key. |
| `--instance-key <path>` | Persist server instance identity. |
| `--version <str>` | Advertise build/version string. |
| `--config <path>` | Load operator metadata and client-hash policy. |

Example config:

```json
{
  "name": "Cherm Main",
  "repo_url": "https://github.com/cherm-chat/cherm",
  "description": "official relay",
  "contact": "ops@cherm.chat",
  "reject_unofficial_clients": false,
  "allowed_client_hashes": ["<official cherm-core build hash>"]
}
```

`reject_unofficial_clients` is a deterrent, not a cryptographic guarantee. A client can lie about its own hash unless it is also running inside a client-side TEE.

## Project map

| Path | Purpose |
|---|---|
| `Makefile` | Build, run, test, and clean entrypoints. |
| `tui/` | Go Bubble Tea terminal client. |
| `backend/` | Rust workspace for core, server, protocol, crypto, and attestation. |
| `backend/core/src/vault.rs` | Local encrypted vault handling. |
| `backend/core/src/session.rs` | Client session and chat state. |
| `backend/core/src/plugins.rs` | Plugin store/install/update client logic. |
| `backend/core/src/update.rs` | Client update check and install flow. |
| `backend/server/src/` | Relay server, directory, queues, config, and attestation provider. |
| `deploy/installers/` | Client and server install scripts. |
| `deploy/worker/` | Cloudflare Worker edge for release/install routes. |
| `deploy/plugins/` | Plugin publishing assets and sample `pastel-theme`. |
| `docs/assets/` | README assets copied out of app/web paths. |
| `PROTOCOL.md` | Wire protocol and contracts. |
| `PRIVACY.md` | Threat model and privacy scope. |
| `ATTESTATION.md` | TEE/software attestation design. |
| `PLUGIN_POLICY.md` | Plugin trust tiers and sandbox rules. |

## Commands

| Command | Purpose |
|---|---|
| `make build` | Build Rust backend release binaries and `tui/cherm`. |
| `make server` | Build backend and run `cherm-server` on `0.0.0.0:9000`. |
| `SERVER_ADDR=0.0.0.0:4000 make server` | Run relay on another address. |
| `make run` | Build and run the terminal UI against `127.0.0.1:9000`. |
| `CHERM_SERVER=host:port make run` | Run TUI against a specific relay. |
| `make test` | Run Rust backend tests with `cargo test`. |
| `make clean` | Remove Rust build outputs and generated TUI binaries. |

## Docs

- [PROTOCOL.md](PROTOCOL.md): protocol messages, framing, and contract details.
- [PRIVACY.md](PRIVACY.md): privacy guarantees, gaps, and threat model.
- [ATTESTATION.md](ATTESTATION.md): AWS Nitro and software-signature attestation tiers.
- [PLUGIN_POLICY.md](PLUGIN_POLICY.md): plugin manifest rules, trust tiers, permissions, and store policy.
- [deploy/README.md](deploy/README.md): release artifacts, installers, Cloudflare Worker routes, Docker server setup.

## Security scope

Cherm is honest about what is done and what is still open.

- The relay never receives plaintext or client private keys.
- Client vaults are SQLCipher databases. The local master key is file-based at `~/.cherm/master.key` with `0600` permissions.
- `CHERM_PASSPHRASE` / Argon2id hardening is planned, not the default documented flow here.
- DMs get Olm forward secrecy and post-compromise recovery properties.
- Groups use Megolm. That is efficient, but group keys are not rotated on member leave yet.
- Attestation does not replace safety-number verification.
- The software attestation tier is only a signed build claim. Use green TEE attestation when the server operator must prove the running code.

## License

MIT. See [LICENSE](LICENSE).
