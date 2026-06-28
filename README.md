# cherm.chat

A private, end-to-end-encrypted **terminal chat**. The server is a dumb relay
that only ever forwards opaque ciphertext — it cannot read your messages. Your
history lives on your own machine. Anyone can run a server, so the network is
federated.

```
 ┌─────────────┐   stdio NDJSON   ┌──────────────┐   TCP frames    ┌────────────┐
 │  tui (Go)   │ ───────────────▶ │  core (Rust) │ ──────────────▶ │  server    │
 │  bubbletea  │ ◀─────────────── │  crypto + db │ ◀────────────── │  (Rust)    │
 └─────────────┘   events         └──────────────┘   Deliver       └────────────┘
   presentation only                client engine                   relay only
```

- **`tui/`** — Go [bubbletea](https://github.com/charmbracelet/bubbletea) TUI.
  Presentation only; it never touches keys or ciphertext.
- **`backend/core`** — Rust client engine: identity, crypto, the server
  connection, and your local SQLite message history. The TUI spawns it as a
  subprocess and talks to it over stdin/stdout.
- **`backend/server`** — Rust relay server: registration directory + an
  encrypted store-and-forward queue. Never holds keys; never sees plaintext.
- **`backend/proto`** — the shared wire protocol (one source of truth).
- **`backend/crypto`** — all client-side cryptography (Ed25519 + X25519 +
  XChaCha20-Poly1305), unit-tested.

The full wire/IPC/crypto contract is in **[PROTOCOL.md](PROTOCOL.md)**.

## How it works

- **Identity & login.** On first run the core generates an Ed25519 keypair (an
  SSH-like key) stored at `~/.cherm/identity.json`. The public key is your
  permanent identity. Login is challenge-response: the server sends a random
  nonce, you return an Ed25519 signature. No passwords.
- **Usernames** are 1–16 characters, `a-z A-Z 0-9` only, **unique**, and
  **immutable** — one name is bound to one keypair forever.
- **Encryption.** 1:1 messages use an anonymous sealed box (ephemeral X25519
  ECDH → HKDF → XChaCha20-Poly1305). Groups use a shared symmetric key handed
  to each member sealed to their key. The relay only forwards the resulting
  ciphertext.
- **History** is stored as plaintext in `~/.cherm/cherm.db` on your computer
  only. The server keeps queued ciphertext just long enough to deliver it to an
  offline recipient, then deletes it.

## Build

Requires a recent Rust toolchain and Go ≥ 1.26.

```sh
make build      # builds backend (release) + the `tui/cherm` binary
```

## Run

In one terminal, start a relay server:

```sh
make server                       # listens on 0.0.0.0:9000
# or: SERVER_ADDR=0.0.0.0:4000 make server
```

In another terminal (per user), start the TUI:

```sh
make run                          # connects to 127.0.0.1:9000 by default
# or point at another server / host your own:
CHERM_SERVER=chat.example.com:9000 make run
```

First launch asks you to pick your username (remember: permanent). After that
you land in the chat view.

### TUI commands

Type in the input box at the bottom:

| command | action |
|---|---|
| `/dm <user>` | start (or open) a 1:1 chat |
| `/group <name> <user> <user> …` | create a group |
| `/menu` | open the menu (server, ping, change server, docs) |
| `/help` | show the command + key reference |
| `/quit` | exit |
| *(anything else)* | send to the currently open chat |

Navigation: `Tab` switches focus between the chat list and the input box,
`↑/↓` move the selection, `Enter` opens the highlighted chat, `Esc` opens the
menu (and goes back).

The **menu** (`/menu` or `Esc`) shows the server you're on, live ping, and your
identity, and lets you change server (reconnects on the spot) or open the docs
in your browser. The docs URL defaults to `https://cherm.chat/docs`; override
it with `CHERM_DOCS`.

You can't start a chat with yourself — `/dm <your-own-name>` is rejected.

The UI uses a magenta→pink accent palette on a near-black base; message text
stays white (per-user colors are reserved for a future premium tier and are
not surfaced today).

Messages render as:

```
[bob][28/06/26 - 14:03:21]> hey there
[you][28/06/26 - 14:03:25]> hello!
```

The `[name][date - time]>` prefix is bold; the message body is normal weight.

## Security notes & scope

- The relay sees routing metadata (who relays to whom and when) — this is
  inherent to a store-and-forward relay — but never message content or keys.
- This is an MVP. The sealed-box scheme gives per-message key separation but
  not a full double-ratchet (no post-compromise security yet); group
  membership changes don't yet rotate the group key. See PROTOCOL.md.
- A `is_premium` flag exists in the server schema (always `false` for now) and
  the message events carry a reserved per-message color hook, wired for a
  future "choose your colors" subscription. It is intentionally not surfaced in
  the UI today.
