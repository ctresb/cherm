# cherm.chat privacy & cryptography

Goal: the server can **never** read messages, and a key compromise should not
unlock past or (for DMs) future traffic. We use Matrix's audited **vodozemac**
crate (Olm + Megolm) rather than hand-rolling a ratchet.

## What we adopted (and from where)

Learned from the Signal Protocol (X3DH / Double Ratchet / Sealed Sender) and
Matrix (Olm / Megolm). We use **vodozemac 0.10** (Apache-2.0, Least-Authority
audited) for the message layer:

- **DMs → Olm** (a Double Ratchet, Signal-derived): per-message keys
  (**forward secrecy**) + DH ratchet (**post-compromise / self-healing**
  security). Bootstrapped by a prekey handshake using published one-time keys —
  the same async pattern as X3DH: the server stores only *public* prekeys, so
  you can message an offline peer.
- **Groups → Megolm** (a sender-key ratchet, like Matrix): each member runs an
  outbound group session whose key ratchets forward every message (forward
  secrecy). The session key is shared to each member **over a pairwise Olm
  session** (so distribution is itself E2E). We rotate the group session on
  every member removal and on a bounded message-count / wall-clock limit to
  bound exposure. Megolm trades post-compromise security for one-encrypt-to-many
  efficiency — a deliberate, documented trade-off.

## Identity & keys

Each **(user, server)** has its own vodozemac `Account` (device identity):

- an **Ed25519** identity key — the immutable anchor; signs the server login
  challenge (challenge-response, no passwords) and is the basis of the
  user-visible **safety-number fingerprint**.
- a **Curve25519** identity key + a replenished pool of **one-time keys** — the
  prekey bundle the server publishes so others can start an Olm session offline.

The server stores per user: uuid, username, ed25519 + curve25519 identity keys,
machine_id, `is_premium` (always 0), and a queue of one-time keys. It stores
**only public keys and opaque ciphertext** — never private keys or plaintext.

## Wire payloads (inside the existing `Send`/`Deliver` relay envelope)

`payload` stays opaque base64 to the server. `msg_type`:

- `olm` — an Olm message (DM, or a Megolm session-key share). Encodes
  vodozemac `OlmMessage::to_parts() = (type, body)`.
- `megolm` — a Megolm group message (`MegolmMessage::to_bytes()`), with
  `group_id` set.

Prekeys are managed with dedicated control messages (not relayed):

```
C -> PublishPrekeys { one_time_keys: { key_id: curve25519_b64, ... } }
C -> FetchPrekeys { username }
S -> PrekeyBundle { username, ed25519, curve25519, one_time_key_id?, one_time_key? }   // OTK consumed
```

## At-rest: per-server encrypted vaults

History lives only on your machine, one **encrypted vault per server** at
`~/.cherm/servers/<server_id>/vault.db` — a **SQLCipher** (AES-256) database;
nothing readable touches disk, not even metadata (chat names, timestamps). The
vodozemac `Account` and all Olm/Megolm sessions are stored as
**encrypted pickles** inside that vault. The vault key is derived per server
from a local master key (`~/.cherm/master.key`, `0600`) via keyed BLAKE3;
`CHERM_PASSPHRASE` (Argon2id) can replace the file as a future hardening step.
Honest limit: file-based key management protects against disk theft, not against
malware running as your user.

## Honest limits (do not over-promise)

- **Metadata**: the relay still sees who talks to whom, when, and message sizes.
  Olm/Megolm hide *content*, not the social graph. Real metadata privacy needs
  sealed-sender + padding + transport anonymity (future work).
- **Active MITM**: "the server can never read messages" holds only if identity
  keys are verified out-of-band. A server that controls the prekey directory can
  substitute keys unless users compare **safety numbers** (fingerprints shown in
  the TUI). Attestation reduces, but does not replace, this.
- **Post-compromise security** exists for DMs (Olm), **not** for groups
  (Megolm), and only between compromise windows; a live-compromised endpoint
  reads everything.
- **Endpoint trust**: none of this defends a compromised device.
