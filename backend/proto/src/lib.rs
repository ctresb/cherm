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

/// Constraints on usernames (requirements 8 & 9).
pub const USERNAME_MAX: usize = 16;

/// Returns true if `name` is a valid username: 1..=16 chars, `[a-zA-Z0-9]` only.
pub fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= USERNAME_MAX
        && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Messages sent from a client to the relay server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMsg {
    /// Register a brand-new immutable identity. Fails if the username is
    /// taken or this key is already registered under another name.
    Register {
        username: String,
        /// base64 ed25519 public key (the identity / auth anchor).
        ed_pub: String,
        /// base64 x25519 public key (used by peers to encrypt to this user).
        dh_pub: String,
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
    /// Look up another user's public keys so we can encrypt to them.
    Lookup { username: String },
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
    /// Result of a `Lookup`.
    UserInfo {
        username: String,
        uuid: String,
        ed_pub: String,
        dh_pub: String,
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
}

/// Stable error codes the server returns in [`ServerMsg::Error`].
pub mod errcode {
    pub const USERNAME_TAKEN: &str = "username_taken";
    pub const USERNAME_INVALID: &str = "username_invalid";
    pub const KEY_ALREADY_REGISTERED: &str = "key_already_registered";
    pub const UNKNOWN_USER: &str = "unknown_user";
    pub const AUTH_FAILED: &str = "auth_failed";
    pub const NOT_AUTHENTICATED: &str = "not_authenticated";
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
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
