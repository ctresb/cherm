# cherm.chat protocol

cherm.chat is an end-to-end-encrypted terminal chat. A **relay server** only
forwards opaque ciphertext between users; it can never read message content.
Anyone can run a server, so the wire format below is the contract that makes
the network federated (requirement 13).

```
 ┌─────────────┐   stdio NDJSON   ┌──────────────┐   TCP frames    ┌────────────┐
 │  tui (Go)   │ ───────────────▶ │  core (Rust) │ ──────────────▶ │ server     │
 │  bubbletea  │ ◀─────────────── │  crypto+db   │ ◀────────────── │ (Rust)     │
 └─────────────┘   events         └──────────────┘   Deliver       └────────────┘
   presentation only                client logic                     relay only
```

The Go TUI never touches keys or ciphertext. All crypto, networking and local
history live in the Rust `core`.

---

## 1. Identity & cryptography

Defined and unit-tested in `backend/crypto`. Do not reinvent — call this API.

- **Identity** = an Ed25519 signing key (identity/auth anchor) + an X25519 key
  (for ECDH). Stored locally at `~/.cherm/identity.json`, mode `0600`. The
  Ed25519 public key binds one username to one person forever (req 6, 7).
- **Auth** = challenge-response. Server sends a random 32-byte nonce
  (base64). Client signs the **raw decoded nonce bytes** with Ed25519 and
  returns the base64 signature. Server verifies against the stored `ed_pub`.
- **1:1 message / key distribution** = sealed box:
  `seal(recipient_dh_pub, plaintext) -> ephemeral_pub(32)||nonce(24)||ct`,
  decrypted with `Identity::unseal`.
- **Group message** = random 32-byte group key + `group_encrypt` /
  `group_decrypt` (XChaCha20-Poly1305, `nonce(24)||ct`). The group key is
  delivered to each member once, sealed to their X25519 key.

Crypto API (all `pub` in `cherm_crypto`):
```
Identity::generate() -> Identity
Identity::{ed_public,dh_public}(&self) -> [u8;32]
Identity::{ed_public_b64,dh_public_b64}(&self) -> String
Identity::sign(&self,&[u8]) -> [u8;64] ; sign_b64(&self,&[u8]) -> String
Identity::{to_json,from_json}            // persistence
Identity::unseal(&self,&[u8]) -> Result<Vec<u8>>
verify(&[u8;32],msg,&[u8;64]) -> bool ; verify_b64(ed_pub_b64,msg,sig_b64) -> bool
seal(&[u8;32],&[u8]) -> Result<Vec<u8>> ; seal_b64(dh_pub_b64,&[u8]) -> Result<String>
unseal(&StaticSecret,&[u8]) -> Result<Vec<u8>>
gen_group_key() -> [u8;32]
group_encrypt(&[u8;32],&[u8]) -> Result<Vec<u8>> ; group_decrypt(...)
b64_encode(&[u8]) -> String ; b64_decode(&str) -> Result<Vec<u8>>
```

---

## 2. Wire protocol (core ⇄ server)

TCP. Each message is a **4-byte big-endian length** + that many bytes of JSON.
Types & framing helpers live in `backend/proto` (`cherm_proto`): use
`write_msg` / `read_msg`, and the `ClientMsg` / `ServerMsg` enums verbatim.

`ClientMsg` (client → server), `#[serde(tag="type")]`:

| variant | fields | meaning |
|---|---|---|
| `Register` | `username, ed_pub, dh_pub, machine_id` | create immutable identity; auto-authenticates the connection on success |
| `AuthBegin` | `username` | start login → server replies `Challenge` |
| `AuthFinish` | `username, signature` | base64 Ed25519 sig over decoded nonce |
| `Lookup` | `username` | fetch a peer's public keys |
| `Send` | `to:[String], msg_type, payload, group_id?, client_ts` | relay ciphertext to recipients |
| `Pull` | — | request queued offline messages |
| `Ping` | — | liveness |

`ServerMsg` (server → client), `#[serde(tag="type")]`:

| variant | fields |
|---|---|
| `Challenge` | `nonce` (base64, 32 bytes) |
| `AuthOk` | `uuid, username` |
| `UserInfo` | `username, uuid, ed_pub, dh_pub` |
| `Deliver` | `from, to:[String], msg_type, payload, group_id?, server_ts, client_ts` |
| `Ok` | `detail?` |
| `Error` | `code, message` (codes in `cherm_proto::errcode`) |
| `Pong` | — |

`payload` is **always** base64 opaque ciphertext. `msg_type` is one of:
`"msg"` (1:1 sealed box), `"group_invite"` (sealed box wrapping the group key
+ group metadata JSON), `"group_msg"` (group_encrypt blob). Timestamps are unix
**milliseconds** (`i64`).

### Auth / registration sequence
```
register:  C→ Register{username, ed_pub, dh_pub, machine_id}
           S→ AuthOk{uuid, username}        (or Error: username_taken / key_already_registered / username_invalid)
login:     C→ AuthBegin{username}
           S→ Challenge{nonce}
           C→ AuthFinish{username, signature = sign(base64_decode(nonce))}
           S→ AuthOk{uuid, username}        (or Error: auth_failed / unknown_user)
           S→ (then flushes any queued Deliver frames)
```

### Send / relay
For each name in `to`: server builds a `Deliver{from = authed user, ...}`. If
the recipient has a live connection it is pushed immediately; otherwise the
frame is stored in the server **outbox** and flushed on their next login/Pull.
The server stores only ciphertext frames, never plaintext or keys.

---

## 3. Server storage (`cherm-server.db`, sqlite)

Only what requirement 5 allows: identity directory + an ephemeral relay queue.
```
users(  uuid TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,      -- immutable, [a-zA-Z0-9]{1,16}
        ed_pub TEXT UNIQUE NOT NULL,        -- identity anchor → "who is who"
        dh_pub TEXT NOT NULL,
        machine_id TEXT NOT NULL,           -- device fingerprint (req 5)
        is_premium INTEGER NOT NULL DEFAULT 0,   -- always 0 for now (req 17)
        created_ts INTEGER NOT NULL )
outbox( id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT NOT NULL,            -- username
        frame TEXT NOT NULL,                -- JSON ServerMsg::Deliver (ciphertext)
        ts INTEGER NOT NULL )
```
Registration rejects a taken username (req 7) or an already-registered key.
Usernames are validated with `cherm_proto::valid_username`.

---

## 4. IPC protocol (tui ⇄ core)

The Go TUI spawns `cherm-core` as a child process and speaks **newline-
delimited JSON** (one object per line): commands on the core's **stdin**,
events on the core's **stdout**. The core's **stderr** is logs (TUI may ignore).

Chat id convention: a DM's `chat` id is the peer's username (`kind:"dm"`); a
group's `chat` id is its uuid (`kind:"group"`). `ts` is unix millis. The TUI
formats time locally as `DD/MM/YY - HH:MM:SS`.

### Commands (tui → core stdin)
```
{"cmd":"status"}
{"cmd":"register","username":"alice","server":"127.0.0.1:9000"}
{"cmd":"connect","server":"127.0.0.1:9000"}      // auth with stored identity, then pull offline
{"cmd":"list_chats"}
{"cmd":"start_dm","username":"bob"}               // resolve keys, ensure DM chat exists
{"cmd":"create_group","name":"devs","members":["bob","carol"]}
{"cmd":"history","chat":"bob","limit":200}
{"cmd":"send","chat":"bob","text":"hi"}
{"cmd":"ping"}                                    // measure server round-trip
{"cmd":"quit"}
```

`start_dm` with your own username is rejected with an `error` event
(`code:"self_dm"`).

### Events (core → tui stdout)
```
{"event":"ready","registered":true,"username":"alice"}       // once at startup
{"event":"status","connected":bool,"registered":bool,"username":string|null}
{"event":"registered","username":"alice","uuid":"..."}
{"event":"connected","username":"alice","uuid":"..."}
{"event":"disconnected","reason":"..."}
{"event":"chats","chats":[{"id":"bob","kind":"dm","title":"bob","last_ts":123}]}
{"event":"history","chat":"bob","messages":[{"from":"bob","text":"hi","ts":123,"outgoing":false}]}
{"event":"message","chat":"bob","from":"bob","text":"hi","ts":123,"outgoing":false,"color":null}
{"event":"error","message":"...","code":"..."}
{"event":"info","message":"..."}
{"event":"pong","rtt_ms":12,"server":"127.0.0.1:9000"}   // reply to a ping
```

`outgoing:true` → the TUI renders the sender label as `you` (req 16). The
optional `color` field is reserved for premium (req 17): the core always sends
`null`/omits it for now and the TUI renders all text white.

---

## 5. Local client storage (`~/.cherm/cherm.db`, sqlite)

History lives only on the user's machine (req 10). The core stores the
plaintext it sent/received so the user keeps a readable log.
```
meta(key TEXT PRIMARY KEY, value TEXT)            -- username, uuid, server addr
contacts(username TEXT PRIMARY KEY, uuid TEXT, ed_pub TEXT, dh_pub TEXT)
chats(id TEXT PRIMARY KEY, kind TEXT, title TEXT, group_key TEXT, created_ts INTEGER)
chat_members(chat_id TEXT, username TEXT)
messages(id INTEGER PRIMARY KEY AUTOINCREMENT,
         chat_id TEXT, sender TEXT, body TEXT, ts INTEGER, outgoing INTEGER)
```

---

## 6. Message bubble rendering (TUI, req 16)

Exact format, header bold, body normal, all white for now:
```
[bob][28/06/26 - 14:03:21]> hey there
[you][28/06/26 - 14:03:25]> hello!
```
The `[name][DD/MM/YY - HH:MM:SS]> ` prefix is bold; the message body is normal
weight. No colors yet (premium-gated; not surfaced in the UI).
