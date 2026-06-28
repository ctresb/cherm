//! cherm.chat wire protocol.
//!
//! This crate is the single source of truth for the framing and message
//! types exchanged between a cherm client (the Rust `core`) and a cherm
//! relay `server`. It is transport-agnostic at the type level; the helper
//! functions implement length-prefixed framing over any tokio byte stream.
//!
//! Framing: every message is a 4-byte big-endian unsigned length followed by
//! that many bytes of UTF-8 JSON. This makes the protocol trivial to
//! re-implement so anyone can host their own server (requirement 13).
//!
//! IMPORTANT: the server only ever sees the `payload` field as opaque
//! base64-encoded ciphertext. It never holds keys and cannot decrypt
//! message content (requirement 11/12). Routing metadata (who talks to whom)
//! is necessarily visible to the relay.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol version advertised by clients and servers.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted frame size (16 MiB) — guards against memory-exhaustion.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Maximum accepted size of a relayed ciphertext `payload` (base64), well below
/// [`MAX_FRAME`]. Every legitimate Olm/Megolm payload — a chat message, a system
/// notice, or a group-key share carrying the roster — is far smaller than this.
/// Capping it bounds the per-message memory a relay must queue per recipient and
/// removes a 16 MiB-per-message amplification vector (a slow/offline recipient
/// could otherwise be made to buffer many near-`MAX_FRAME` blobs).
pub const MAX_PAYLOAD: usize = 128 * 1024;

/// Maximum number of recipients a single `Send` may fan out to. A group broadcast
/// legitimately lists its whole roster here; this caps the per-`Send` work (and
/// thus the amplification an authenticated sender can force from one rate-limited
/// action) while staying comfortably above any realistic group size.
pub const MAX_RECIPIENTS: usize = 1024;

/// Constraints on usernames (requirements 8 & 9).
pub const USERNAME_MAX: usize = 16;

/// Returns true if `name` is a valid username: 1..=16 chars, `[a-zA-Z0-9]` only.
pub fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= USERNAME_MAX
        && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Usernames reserved for internal system / server identities. Regular users
/// may never register, rename to, or be displayed as these — they are reserved
/// for system messages, announcements and server-level events. Compared
/// case-insensitively so neither `System` nor `system` (etc.) can be claimed.
pub const RESERVED_USERNAMES: &[&str] = &["system", "server"];

/// True if `name` collides with a reserved system/server identity (case-insensitive).
pub fn is_reserved_username(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    RESERVED_USERNAMES.contains(&lower.as_str())
}

/// True if `name` is a valid AND non-reserved username (the rule for registration).
pub fn is_registerable_username(name: &str) -> bool {
    valid_username(name) && !is_reserved_username(name)
}

/// Group access modes (group access control). Stored per group in the owner's
/// vault and mirrored to members in the Megolm key-share so every client can
/// display the mode. Enforcement is owner-side: the owner decides whether to
/// hand out the Megolm key, which is the real gate — not the group key itself.
pub mod access_mode {
    /// Anyone with a valid invite/group key joins immediately, no approval.
    pub const OPEN: &str = "open";
    /// Anyone with a valid key may *request* to join; the owner must accept them
    /// (`/accept <username>`) before they are added.
    pub const APPROVAL: &str = "approval";
    /// Only the owner can add users (by username); a valid key alone never joins.
    pub const INVITE_ONLY: &str = "invite_only";

    /// All recognized modes, for validation + UIs.
    pub const ALL: &[&str] = &[OPEN, APPROVAL, INVITE_ONLY];

    /// True if `m` is a recognized access mode.
    pub fn valid(m: &str) -> bool {
        ALL.contains(&m)
    }
}

/// Logical `msg_type` strings exchanged in [`ClientMsg::Send`] / [`ServerMsg::Deliver`].
/// The relay treats every one as opaque routing metadata; only clients interpret
/// the (encrypted) payloads. The group-control types ride the same envelope so no
/// server change is needed to add group access control.
pub mod msgtype {
    /// A 1:1 Olm message; plaintext is the chat text.
    pub const OLM: &str = "olm";
    /// An Olm message whose plaintext is a Megolm group-key share (JSON).
    pub const OLM_GROUP_KEY: &str = "olm_group_key";
    /// A 1:1 "left the chat" notice over Olm.
    pub const OLM_SYSTEM: &str = "olm_system";
    /// A Megolm group message; plaintext is the chat text.
    pub const MEGOLM: &str = "megolm";
    /// A group "left the chat" notice over Megolm.
    pub const MEGOLM_SYSTEM: &str = "megolm_system";
    /// A join request a prospective member sends (Olm) to the group owner;
    /// plaintext is `{group_id, group_key}`.
    pub const GROUP_JOIN: &str = "group_join";
    /// The owner's reply (Olm) denying a join, with a human-readable reason;
    /// plaintext is `{group_id, reason}`.
    pub const GROUP_JOIN_DENIED: &str = "group_join_denied";
    /// A moderation/membership event the owner broadcasts (Megolm) to the group;
    /// plaintext is `{kind, who, ...}` (see core::net).
    pub const GROUP_EVENT: &str = "group_event";
}

/// One published one-time prekey: an id and its base64 Curve25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeKey {
    pub key_id: String,
    pub curve25519: String,
}

/// Messages sent from a client to the relay server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMsg {
    /// Register a brand-new immutable identity. Fails if the username is
    /// taken or this key is already registered under another name.
    Register {
        username: String,
        /// base64 Ed25519 identity key (immutable anchor + auth/signing).
        ed25519: String,
        /// base64 Curve25519 identity key (peers start Olm sessions to this).
        curve25519: String,
        /// Informational device fingerprint (e.g. hostname).
        machine_id: String,
    },
    /// Begin a challenge-response login for an existing username.
    AuthBegin { username: String },
    /// Finish login by returning the ed25519 signature over the server nonce.
    AuthFinish {
        username: String,
        /// base64 ed25519 signature over the challenge nonce.
        signature: String,
    },
    /// Upload one-time prekeys so peers can start Olm sessions while we're offline.
    PublishPrekeys { one_time_keys: Vec<OneTimeKey> },
    /// Fetch a peer's prekey bundle (consumes one of their one-time keys).
    FetchPrekeys { username: String },
    /// Request a server attestation. Run before registering / authenticating so
    /// the client can show a trust verdict first.
    AttestRequest { nonce: String },
    /// Announce the client build (sent right after connecting, pre-auth) so the
    /// server can enforce an official-client policy. Honest limit: a client can
    /// lie about its hash (no client TEE), so this is a deterrent, like the
    /// software attestation tier.
    ClientHello {
        /// Hex BLAKE3 of the client (core) build artifact.
        build_hash: String,
        client_version: String,
    },
    /// Request the server's public metadata (repo URL, name, ...). Pre-auth.
    GetServerInfo,
    /// Relay an end-to-end-encrypted message to one or more recipients.
    Send {
        /// Recipient usernames. For 1:1 this is a single name; for a group
        /// broadcast it is every member (the relay fans it out).
        to: Vec<String>,
        /// Logical kind: "msg", "group_invite", "group_msg", etc.
        msg_type: String,
        /// base64 opaque ciphertext. Server cannot read this.
        payload: String,
        /// Set for group traffic so clients can route to the right room.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_id: Option<String>,
        /// Client-side send timestamp (unix millis).
        client_ts: i64,
    },
    /// Request any messages queued while we were offline.
    Pull,
    /// Liveness probe.
    Ping,
}

/// Messages sent from the relay server to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMsg {
    /// Random nonce the client must sign to prove key ownership.
    Challenge { nonce: String },
    /// Login (or registration) succeeded.
    AuthOk { uuid: String, username: String },
    /// Result of `FetchPrekeys`: a peer's identity keys plus (if available) one
    /// consumed one-time key, enough to start an Olm session.
    PrekeyBundle {
        username: String,
        uuid: String,
        ed25519: String,
        curve25519: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        one_time_key_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        one_time_key: Option<String>,
    },
    /// Result of `AttestRequest`: the server attestation
    /// (`cherm_attest::Attestation` serialized as JSON).
    AttestResponse { attestation: serde_json::Value },
    /// Result of `GetServerInfo`: the server owner's public metadata so users can
    /// see what codebase the server claims to run. All operator-supplied.
    ServerInfo {
        name: String,
        repo_url: String,
        description: String,
        contact: String,
        version: String,
    },
    /// A relayed end-to-end-encrypted message addressed to this client.
    Deliver {
        from: String,
        to: Vec<String>,
        msg_type: String,
        payload: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_id: Option<String>,
        server_ts: i64,
        client_ts: i64,
    },
    /// Generic acknowledgement.
    Ok {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// An error occurred handling the previous request.
    Error { code: String, message: String },
    /// Liveness response.
    Pong,
    /// Server is about to stop for maintenance/update. Broadcast to every online
    /// client so they can render a *local* countdown to `deadline_unix_ms` (NOT
    /// 60 separate chat messages — this is UI state), enter a waiting-for-server
    /// state, and reconnect automatically once the server returns. `version` is
    /// the release being deployed, when known.
    Maintenance {
        reason: String,
        /// Unix-millis deadline after which the server stops accepting traffic.
        deadline_unix_ms: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
}

/// Stable error codes the server returns in [`ServerMsg::Error`].
pub mod errcode {
    pub const USERNAME_TAKEN: &str = "username_taken";
    pub const USERNAME_INVALID: &str = "username_invalid";
    pub const USERNAME_RESERVED: &str = "username_reserved";
    pub const UNOFFICIAL_CLIENT: &str = "unofficial_client";
    pub const KEY_ALREADY_REGISTERED: &str = "key_already_registered";
    pub const UNKNOWN_USER: &str = "unknown_user";
    pub const NO_PREKEYS: &str = "no_prekeys";
    pub const AUTH_FAILED: &str = "auth_failed";
    pub const NOT_AUTHENTICATED: &str = "not_authenticated";
    pub const ALREADY_AUTHENTICATED: &str = "already_authenticated";
    pub const BAD_REQUEST: &str = "bad_request";
    pub const INTERNAL: &str = "internal";
}

/// Write a single length-prefixed JSON frame.
pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let buf = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if buf.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let len = (buf.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Read a single length-prefixed JSON frame.
pub async fn read_msg<R, T>(r: &mut R) -> std::io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    // Read the body INCREMENTALLY (bounded by the declared length) instead of
    // allocating `len` bytes up front. A peer that sends a huge length prefix but
    // then stalls/dribbles otherwise pins up to MAX_FRAME (16 MiB) of zeroed heap
    // per connection before a single body byte arrives; with `take` + read_to_end
    // the buffer only grows as bytes actually arrive (and the caller's read
    // deadline tears down a stalled connection).
    let mut buf = Vec::new();
    let read = r.take(len as u64).read_to_end(&mut buf).await?;
    if read != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "frame body shorter than its length prefix",
        ));
    }
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rules() {
        assert!(valid_username("alice"));
        assert!(valid_username("Bob123"));
        assert!(valid_username("a"));
        assert!(valid_username("0123456789abcdef")); // 16 chars
        assert!(!valid_username("")); // empty
        assert!(!valid_username("0123456789abcdefg")); // 17 chars
        assert!(!valid_username("has space"));
        assert!(!valid_username("dash-no"));
        assert!(!valid_username("emoji😀"));
    }

    #[test]
    fn reserved_usernames() {
        for n in ["System", "system", "Server", "server", "SYSTEM", "SeRvEr"] {
            assert!(is_reserved_username(n), "{n} must be reserved");
            assert!(!is_registerable_username(n), "{n} must not be registerable");
        }
        assert!(!is_reserved_username("alice"));
        assert!(is_registerable_username("alice"));
        // valid charset but reserved:
        assert!(valid_username("system") && !is_registerable_username("system"));
    }

    #[test]
    fn access_modes() {
        assert!(access_mode::valid("open"));
        assert!(access_mode::valid("approval"));
        assert!(access_mode::valid("invite_only"));
        assert!(!access_mode::valid("public"));
        assert!(!access_mode::valid("Open")); // case-sensitive
        assert!(!access_mode::valid(""));
        assert_eq!(access_mode::ALL.len(), 3);
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        let msg = ClientMsg::AuthBegin {
            username: "alice".into(),
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &msg).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let got: ClientMsg = read_msg(&mut cursor).await.unwrap();
        match got {
            ClientMsg::AuthBegin { username } => assert_eq!(username, "alice"),
            _ => panic!("wrong variant"),
        }
    }
}
