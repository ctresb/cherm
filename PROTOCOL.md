# cherm.chat protocol (v2)

End-to-end-encrypted terminal chat. A **relay server** only forwards opaque
ciphertext; it can never read message content. Anyone can run a server; clients
**attest** a server's code before trusting it (see ATTESTATION.md) and keep a
separate **encrypted vault** per server.

```
 ┌─────────────┐   stdio NDJSON   ┌──────────────┐   TCP frames    ┌────────────┐
 │  tui (Go)   │ ───────────────▶ │  core (Rust) │ ──────────────▶ │  server    │
 │  bubbletea  │ ◀─────────────── │  vodozemac   │ ◀────────────── │  (Rust)    │
 └─────────────┘   events         │  + vaults    │   Deliver       └────────────┘
   presentation only              └──────────────┘   relay only
```

The Go TUI never touches keys or ciphertext. All crypto, networking, attestation
and history live in the Rust `core`. Companion docs: **PRIVACY.md** (Olm/Megolm,
vaults) and **ATTESTATION.md** (3-tier server attestation).

## 1. Cryptography — call the crates, don't reinvent

Message layer in `cherm_crypto` (wraps audited **vodozemac**; see PRIVACY.md):

```
Device::generate() / ed25519_b64() / curve25519_b64() / fingerprint()
Device::sign_b64(&[u8])                       // challenge-response auth
Device::generate_one_time_keys(n)->Vec<(key_id,curve_b64)> / mark_published()
Device::start_session(peer_curve_b64, peer_otk_b64) -> OlmSession           // outbound DM
Device::create_inbound(peer_curve_b64, olm_type:u8, body:&[u8]) -> (OlmSession, Vec<u8>)
Device::{to,from}_pickle_encrypted(&[u8;32])  // at-rest persistence
OlmSession::encrypt(&[u8]) -> (olm_type:u8, body:Vec<u8>) / decrypt(u8,&[u8]) / session_id()
GroupSender::new()/session_key_b64()/encrypt(&[u8])->Vec<u8>/message_index()  // outbound Megolm
GroupReceiver::from_session_key_b64(s)/decrypt(&[u8])->(Vec<u8>,u32)          // inbound Megolm
server_id(addr) / derive_vault_key(&master,server_id) / vault_key_sqlcipher(&key) / gen_master_key()
verify_ed25519_b64(pub,msg,sig) / b64_encode / b64_decode / fingerprint_of(ed_b64)
```

Attestation in `cherm_attest` (see ATTESTATION.md): `Attestation`, `Tier`,
`Verdict`, `verify(att,nonce,now_ms,&Official)->VerifyResult`,
`official::pinned()`, server providers `build_software/build_unsigned`,
`ReleaseKey`, `InstanceKey`, `build_hash()`.

## 2. Wire protocol (core ⇄ server)

TCP, length-prefixed JSON (4-byte big-endian length + JSON). Use
`cherm_proto::{read_msg, write_msg}` and the enums verbatim.

`ClientMsg` (`#[serde(tag="type")]`):

| variant | fields | meaning |
|---|---|---|
| `AttestRequest` | `nonce` | request attestation (run FIRST, pre-auth) |
| `Register` | `username, ed25519, curve25519, machine_id` | create immutable identity; auto-authenticates |
| `AuthBegin` | `username` | start login → `Challenge` |
| `AuthFinish` | `username, signature` | base64 Ed25519 sig over the **raw decoded** nonce |
| `PublishPrekeys` | `one_time_keys:[{key_id,curve25519}]` | upload one-time keys |
| `FetchPrekeys` | `username` | fetch a peer's bundle (consumes one OTK) |
| `Send` | `to:[String], msg_type, payload, group_id?, client_ts` | relay ciphertext |
| `Pull` | — | request queued offline messages |
| `Ping` | — | liveness |

`ServerMsg` (`#[serde(tag="type")]`):

| variant | fields |
|---|---|
| `AttestResponse` | `attestation` (JSON of `cherm_attest::Attestation`) |
| `Challenge` | `nonce` (base64, 32 bytes) |
| `AuthOk` | `uuid, username` |
| `PrekeyBundle` | `username, uuid, ed25519, curve25519, one_time_key_id?, one_time_key?` |
| `Deliver` | `from, to:[String], msg_type, payload, group_id?, server_ts, client_ts` |
| `Ok` | `detail?` · `Error` | `code,message` · `Pong` | — |

`payload` is opaque base64. `msg_type`:
- `"olm"` — an Olm message (DM text). Encoded `"<olm_type>.<base64 body>"`.
- `"olm_group_key"` — an Olm message whose plaintext is a group-key share JSON
  `{group_id,name,session_key,sender_curve,members:[...]}` (distributes a Megolm
  session key over the pairwise Olm channel).
- `"megolm"` — a Megolm group message (base64 of `GroupSender::encrypt`), with
  `group_id` set.

### Sequence
```
attest:   C→ AttestRequest{nonce=32B b64}      S→ AttestResponse{attestation}
          (client verifies → green/yellow/red BEFORE registering)
register: C→ Register{username, ed25519, curve25519, machine_id}
          S→ AuthOk{uuid,username}             (auto-authed) | Error
          C→ PublishPrekeys{...}               (upload OTKs)
login:    C→ AuthBegin{username} S→ Challenge{nonce}
          C→ AuthFinish{username, sign(b64decode(nonce))} S→ AuthOk → flush outbox
dm setup: C→ FetchPrekeys{username:bob} S→ PrekeyBundle{...,one_time_key}
          → Device::start_session → first Send{to:[bob],msg_type:"olm",...}
```
Relay/outbox semantics unchanged: deliver to online recipients (skip `from`),
else queue in the outbox and flush on next login/Pull.

## 3. Server storage (`cherm-server.db`)

```
users(  uuid PK, username UNIQUE, ed25519 UNIQUE, curve25519, machine_id,
        is_premium INTEGER DEFAULT 0, created_ts )           -- public keys only
prekeys(id PK AUTOINCREMENT, username, key_id, curve25519, used INTEGER DEFAULT 0)
outbox( id PK AUTOINCREMENT, recipient, frame, ts )          -- ciphertext frames
```
`FetchPrekeys` returns one unused OTK and marks it used (delete-on-handout).
Server attestation: on `AttestRequest` it builds `build_software` (default,
holding `ReleaseKey` + a persisted `InstanceKey`) — or `build_unsigned` with
`--no-attest`, or the TEE path on a Nitro deployment. Flags:
`--addr --db --no-attest --release-secret <b64> --instance-key <path> --version`.

## 4. IPC protocol (tui ⇄ core) — multi-server

Newline-delimited JSON over the core's stdin (commands) / stdout (events).
The core manages **many servers**; chat commands act on the **active** server.

### Commands (tui → core)
```
{"cmd":"list_servers"}
{"cmd":"check_server","server":"host:port"}        // connect pre-auth, attest, verify
{"cmd":"connect","server":"host:port"}             // make active; auth if username exists
{"cmd":"register","server":"host:port","username":"alice"}   // create identity+vault on a server
{"cmd":"switch_server","server":"host:port"}       // change active server
{"cmd":"list_chats"} {"cmd":"history","chat":id,"limit":200}
{"cmd":"start_dm","username":"bob"} {"cmd":"create_group","name":"x","members":[...]}
{"cmd":"send","chat":id,"text":"hi"} {"cmd":"ping"} {"cmd":"quit"}
```
`start_dm` of your own username → `error` (`code:"self_dm"`).

### Events (core → tui)
```
{"event":"ready","servers":[...],"has_master":true}
{"event":"servers","servers":[{"id","addr","tier","verdict","username":string|null,"active":bool}]}
{"event":"attest","server":addr,"verdict":"green|yellow|red","tier":"unsigned|software|tee",
   "reason":...,"build_hash":...,"fingerprint":...,
   "public_codebase_url":...,"signatures_url":...}
{"event":"need_username","server":addr}            // connected, attested, no account yet
{"event":"registered","server":addr,"username":...,"uuid":...}
{"event":"connected","server":addr,"username":...,"active":true}
{"event":"disconnected","server":addr,"reason":...}
{"event":"chats","server":addr,"chats":[{"id","kind","title","last_ts"}]}
{"event":"history","chat":id,"messages":[{"from","text","ts","outgoing"}]}
{"event":"message","chat":id,"from","text","ts","outgoing":bool,"color":null}
{"event":"fingerprint","username":bob,"fingerprint":"...."}    // peer safety number
{"event":"error","message":...,"code":...} {"event":"info","message":...}
{"event":"pong","rtt_ms":N,"server":addr}
```
`color` stays `null` (premium-gated). The verdict drives the add-server UI
(🟢 Cancel/Connect; 🟡 + learn-more `signatures_url` + Cancel/Connect;
🔴 + clickable `public_codebase_url` + Cancel/Connect-anyway[10s countdown]).

## 5. Local storage — one encrypted vault per server

Master key at `~/.cherm/master.key` (`0600`, 32 random bytes). Per server a
directory `~/.cherm/servers/<server_id>/` (`server_id = cherm_crypto::server_id(addr)`)
containing `vault.db`, a **SQLCipher** database opened with
`PRAGMA key = vault_key_sqlcipher(derive_vault_key(master, server_id))`. Nothing
readable hits disk — not even metadata. Schema:
```
meta(key PK, value)                              -- username, uuid, server addr, account_pickle
contacts(username PK, uuid, ed25519, curve25519)
olm_sessions(peer PK, pickle)                    -- encrypted Olm session pickles
chats(id PK, kind, title, created_ts)
chat_members(chat_id, username)
group_out(group_id PK, pickle)                   -- our outbound Megolm pickle
group_in(group_id, sender, pickle, PRIMARY KEY(group_id,sender))  -- inbound Megolm pickles
messages(id PK AUTOINCREMENT, chat_id, sender, body, ts, outgoing)
```
The vodozemac `Account` is stored as an encrypted pickle in `meta`. (The pickle
helpers already AEAD-encrypt; inside SQLCipher this is defense-in-depth.)

## 6. Message bubble rendering (TUI)

Exact format — prefix bold, body normal, all white (premium-gated color hook):
```
[bob][28/06/26 - 14:03:21]> hey there
[you][28/06/26 - 14:03:25]> hello!
```
`[name][DD/MM/YY - HH:MM:SS]> ` is bold via `time.UnixMilli(ts).Format("02/01/06 - 15:04:05")`.
