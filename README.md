# cherm.chat

A private, end-to-end-encrypted **terminal chat**. The server is a dumb relay
that only ever forwards opaque ciphertext — it cannot read your messages. Your
history lives on your own machine in a **per-server encrypted vault**. Anyone
can run a server, and clients **attest** a server's code before trusting it.

```
 ┌─────────────┐   stdio NDJSON   ┌──────────────┐   TCP frames    ┌────────────┐
 │  tui (Go)   │ ───────────────▶ │  core (Rust) │ ──────────────▶ │  server    │
 │  bubbletea  │ ◀─────────────── │  vodozemac   │ ◀────────────── │  (Rust)    │
 └─────────────┘   events         │  + vaults    │   Deliver       └────────────┘
   presentation only              └──────────────┘   relay only
```

- **`tui/`** — Go [bubbletea](https://github.com/charmbracelet/bubbletea) TUI.
  Presentation only; it never touches keys or ciphertext.
- **`backend/core`** — Rust client engine: per-server identities, Olm/Megolm
  sessions, attestation client, and the encrypted SQLite vaults. The TUI spawns
  it and talks over stdin/stdout.
- **`backend/server`** — Rust relay: registration directory, prekey store, and
  an encrypted store-and-forward queue + an attestation provider. Never holds
  client keys; never sees plaintext.
- **`backend/proto`** — the shared wire protocol.
- **`backend/crypto`** — message-layer crypto wrapping Matrix's audited
  **vodozemac** (Olm + Megolm) plus vault-key derivation. Unit-tested.
- **`backend/attest`** — 3-tier server attestation: a real pure-Rust **AWS Nitro**
  TEE quote verifier + software-signature tier. Unit-tested.

Contract & design: **[PROTOCOL.md](PROTOCOL.md)**, **[PRIVACY.md](PRIVACY.md)**,
**[ATTESTATION.md](ATTESTATION.md)**.

## How it works

- **Forward-secret messaging.** DMs use **Olm** (a Signal-style Double Ratchet:
  forward secrecy + post-compromise / self-healing security). Groups use
  **Megolm** (a per-sender ratchet), with each sender's group key shared to
  members over their pairwise Olm session. We don't hand-roll a ratchet — we use
  the audited `vodozemac` crate. See [PRIVACY.md](PRIVACY.md).
- **Identity & login.** Each `(you, server)` has its own keypair (a vodozemac
  device). The Ed25519 key is your permanent identity; login is challenge-
  response (no passwords). Compare **safety numbers** (shown in the chat header)
  to defeat a key-substituting server.
- **Usernames** are 1–16 chars, `a-z A-Z 0-9` only, **unique** and **immutable**
  per server.
- **Server attestation (3 tiers).** Before connecting, the client asks the
  server to attest its code and shows an honest verdict:
  - 🟢 **green** — a hardware **TEE** (AWS Nitro) proves the running code matches
    the official build. *Safe to connect.*
  - 🟡 **yellow** — only a **software signature** (a genuine official release
    hash, signed by the project key). Does **not** prove the server actually runs
    it. A *learn more* link explains the levels.
  - 🔴 **red** — **unsigned**, or the hash doesn't match the official **public
    codebase** (clickable). *Connect anyway* is gated behind a 10-second
    countdown.

  Why three? **Pure software can't prove its own integrity** — an operator can
  patch a binary to report any hash. Only a TEE makes it unforgeable (and that
  trusts the TEE vendor). See [ATTESTATION.md](ATTESTATION.md). The levels are
  documented at `https://cherm.chat/signatures`.
- **Per-server encrypted vaults.** Each server's history + sessions live in
  `~/.cherm/servers/<id>/vault.db`, a **SQLCipher** (AES-256) database — nothing
  readable hits disk, not even metadata. The relay only queues ciphertext long
  enough to deliver it offline.

## Build

Requires a recent Rust toolchain and Go ≥ 1.26. (The client vault uses
SQLCipher, vendored + built from source — first build takes a couple of minutes.)

```sh
make build      # backend (release) + the `tui/cherm` binary
```

## Run

Start a relay server in one terminal:

```sh
make server                 # 0.0.0.0:9000, software-signature tier (dev key)
# host your own / change port:  SERVER_ADDR=0.0.0.0:4000 make server
```

Server flags: `--addr`, `--db`, `--no-attest` (advertise the unsigned tier —
clients show red), `--release-secret <b64>` (sign with a real release key),
`--instance-key <path>`, `--version <str>`, `--config <path>`. The genuine TEE
(green) tier is produced by deploying the official image in an **AWS Nitro
enclave**.

`--config <path>` is a JSON file of operator settings (nothing hardcoded):

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

The metadata (`name`/`repo_url`/…) is shown to users on the verdict screen so
they can see what codebase the server **claims** to run. Set
`reject_unofficial_clients: true` to only admit clients whose build hash is in
`allowed_client_hashes` (a deterrent — a client can lie about its hash; only a
client-side TEE would make it unforgeable).

Start the TUI (per user):

```sh
make run
```

You land on the **servers** screen. Press `a` to **add a server**, type
`host:port`, and the client attests it and shows the 🟢/🟡/🔴 verdict. Choose
**Connect** (or **Connect anyway** after the countdown for red), then pick your
username for that server. Each server keeps its own account and encrypted vault.

### TUI commands

| command | action |
|---|---|
| `/dm <user>` | start (or open) a 1:1 chat |
| `/group <name> <user> …` | create a group |
| `/menu` | server / ping / change server / docs |
| `/help` | command + key reference |
| `/quit` | exit |
| *(anything else)* | send to the open chat |

`Tab` switches focus, `↑/↓` select, `Enter` opens/sends, `Esc` opens the menu /
goes back. With the **chat list focused**, press **`x`** to leave the selected
chat — a *Leave this chat?* confirmation appears (Cancel by default); only on
**Leave** does it happen. Leaving notifies the other side with a system line and
removes the chat from your list:

```
[✣ System][28/06/26 - 14:05:10]> alice left the chat.
```

System notices come from the reserved **`System`** identity. The usernames
`System` and `Server` (case-insensitive) are reserved and can never be
registered, so no user can impersonate a system/server identity.
`/dm <your-own-name>` is rejected. Messages render as:

```
[bob][28/06/26 - 14:03:21]> hey there
[you][28/06/26 - 14:03:25]> hello!
```

The `[name][date - time]>` prefix is bold; the body is normal white (per-user
colors are reserved for a future premium tier, not surfaced today). The UI uses
a magenta→pink accent palette on a near-black base.

## Security notes & honest scope

- **Content** is protected by Olm/Megolm (forward secrecy; post-compromise
  security for DMs, not for groups — a Megolm trade-off). **Metadata** is not:
  the relay still sees who talks to whom, when, and sizes. Real metadata privacy
  needs sealed-sender + padding + transport anonymity (future work).
- **Attestation honesty:** the software tier is a *deterrent* an operator can
  bypass (replay the official signed hash while running other code). Only the
  TEE tier is unforgeable, and it trusts the TEE vendor (AWS). The AWS Nitro
  Root-G1 is embedded and was fingerprint-verified.
- **Verify safety numbers** out-of-band; attestation doesn't replace that.
- **Vault key management** is file-based (`~/.cherm/master.key`, `0600`); it
  protects against disk theft, not malware running as you. A passphrase mode
  (Argon2id via `CHERM_PASSPHRASE`) is a planned hardening step.
- A `is_premium` flag (always `false`) and a per-message color hook are wired
  for a future "choose your colors" subscription; not surfaced today.
- MVP gaps tracked in the docs: **Megolm group keys are not rotated when a
  member leaves** (the leaver keeps the old session key, so they could still
  read *future* messages sent on it until the next rekey), sealed-sender, and
  outbox delivery acks. (Olm now re-establishes on a fresh prekey, handling the
  leave/re-contact and basic "glare" cases.)
