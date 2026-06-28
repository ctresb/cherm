//! cherm.chat client cryptography — the message layer (Olm + Megolm via the
//! audited [`vodozemac`] crate) plus at-rest vault-key derivation.
//!
//! We do NOT hand-roll a ratchet. DMs use Olm (a Signal-derived Double Ratchet:
//! forward secrecy + post-compromise security). Groups use Megolm (a sender-key
//! ratchet: forward secrecy, one-encrypt-to-many), with the group key shared to
//! each member over a pairwise Olm session. See PRIVACY.md.
//!
//! All key material lives only on the client; the relay sees opaque ciphertext.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle, MegolmMessage,
    SessionConfig as MegolmConfig, SessionKey,
};
use vodozemac::olm::{
    Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

const PICKLE_NONCE: usize = 24;

// ===========================================================================
// Device identity (vodozemac Account)
// ===========================================================================

/// A per-(user, server) device identity: the Ed25519 + Curve25519 identity keys
/// plus the one-time-key pool used to bootstrap Olm sessions.
pub struct Device {
    account: Account,
}

impl Device {
    /// Create a fresh random identity.
    pub fn generate() -> Self {
        Device {
            account: Account::new(),
        }
    }

    /// Base64 Ed25519 identity key — the immutable anchor + auth/signing key.
    pub fn ed25519_b64(&self) -> String {
        self.account.ed25519_key().to_base64()
    }

    /// Base64 Curve25519 identity key — used by peers to start Olm sessions.
    pub fn curve25519_b64(&self) -> String {
        self.account.curve25519_key().to_base64()
    }

    /// A human-comparable safety-number fingerprint of the Ed25519 identity key
    /// (groups of 5 digits), for out-of-band verification in the TUI.
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.account.ed25519_key().to_base64())
    }

    /// Sign a server challenge nonce with the Ed25519 identity key.
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        self.account.sign(msg).to_base64()
    }

    /// Generate `n` one-time keys and return them as `(key_id, curve25519_b64)`.
    /// Call [`Device::mark_published`] once they have been uploaded.
    pub fn generate_one_time_keys(&mut self, n: usize) -> Vec<(String, String)> {
        self.account.generate_one_time_keys(n);
        self.account
            .one_time_keys()
            .into_iter()
            .map(|(id, key)| (id.to_base64(), key.to_base64()))
            .collect()
    }

    /// Mark all currently-unpublished one-time keys as published.
    pub fn mark_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    /// Start an OUTBOUND Olm session to a peer, given their published bundle.
    pub fn start_session(&self, their_curve_b64: &str, their_otk_b64: &str) -> Result<OlmSession> {
        let id = Curve25519PublicKey::from_base64(their_curve_b64).context("peer curve key")?;
        let otk = Curve25519PublicKey::from_base64(their_otk_b64).context("peer one-time key")?;
        let session = self
            .account
            .create_outbound_session(SessionConfig::version_1(), id, otk)
            .map_err(|e| anyhow!("outbound session: {e}"))?;
        Ok(OlmSession { session })
    }

    /// Accept an INBOUND Olm session from a peer's prekey message
    /// (`olm_type == 0`). Returns the new session and the decrypted first message.
    pub fn create_inbound(
        &mut self,
        their_curve_b64: &str,
        olm_type: u8,
        olm_body: &[u8],
    ) -> Result<(OlmSession, Vec<u8>)> {
        let id = Curve25519PublicKey::from_base64(their_curve_b64).context("peer curve key")?;
        let msg = OlmMessage::from_parts(olm_type as usize, olm_body)
            .map_err(|e| anyhow!("olm message: {e}"))?;
        let pre = match msg {
            OlmMessage::PreKey(pre) => pre,
            OlmMessage::Normal(_) => {
                return Err(anyhow!("expected a prekey message to start a session"))
            }
        };
        let res = self
            .account
            .create_inbound_session(SessionConfig::version_1(), id, &pre)
            .map_err(|e| anyhow!("inbound session: {e}"))?;
        Ok((OlmSession { session: res.session }, res.plaintext))
    }

    /// Encrypt this account to an at-rest pickle blob.
    pub fn to_pickle_encrypted(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        encrypt_blob(key, &serde_json::to_vec(&self.account.pickle())?)
    }

    /// Restore an account from an at-rest pickle blob.
    pub fn from_pickle_encrypted(key: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let bytes = decrypt_blob(key, blob)?;
        let pickle: AccountPickle = serde_json::from_slice(&bytes)?;
        Ok(Device {
            account: Account::from(pickle),
        })
    }
}

/// Compute a safety-number fingerprint from a base64 Ed25519 key.
pub fn fingerprint_of(ed25519_b64: &str) -> String {
    let digest = blake3::hash(ed25519_b64.as_bytes());
    let bytes = digest.as_bytes();
    // 30 decimal digits in groups of 5 (six groups) — easy to read aloud.
    let mut digits = String::new();
    for (i, b) in bytes.iter().take(15).enumerate() {
        if i > 0 && i % 5 == 0 {
            digits.push(' ');
        }
        digits.push_str(&format!("{:02}", (*b as u16 * 100 / 256)));
    }
    digits
}

// ===========================================================================
// Olm 1:1 session
// ===========================================================================

/// A live Olm (Double Ratchet) session with one peer.
pub struct OlmSession {
    session: Session,
}

impl OlmSession {
    /// Stable session id.
    pub fn session_id(&self) -> String {
        self.session.session_id()
    }

    /// Encrypt plaintext. Returns `(olm_type, body)` — `olm_type` is 0 for a
    /// prekey message (until the peer replies) and 1 afterwards.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u8, Vec<u8>)> {
        let msg = self
            .session
            .encrypt(plaintext)
            .map_err(|e| anyhow!("olm encrypt: {e}"))?;
        let (t, body) = msg.to_parts();
        Ok((t as u8, body))
    }

    /// Decrypt an Olm message produced by the peer.
    pub fn decrypt(&mut self, olm_type: u8, body: &[u8]) -> Result<Vec<u8>> {
        let msg = OlmMessage::from_parts(olm_type as usize, body)
            .map_err(|e| anyhow!("olm message: {e}"))?;
        self.session
            .decrypt(&msg)
            .map_err(|e| anyhow!("olm decrypt: {e}"))
    }

    pub fn to_pickle_encrypted(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        encrypt_blob(key, &serde_json::to_vec(&self.session.pickle())?)
    }

    pub fn from_pickle_encrypted(key: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let bytes = decrypt_blob(key, blob)?;
        let pickle: SessionPickle = serde_json::from_slice(&bytes)?;
        Ok(OlmSession {
            session: Session::from(pickle),
        })
    }
}

// ===========================================================================
// Megolm group sessions
// ===========================================================================

/// An OUTBOUND Megolm session (what *we* send to a group with).
pub struct GroupSender {
    session: GroupSession,
}

impl GroupSender {
    pub fn new() -> Self {
        GroupSender {
            session: GroupSession::new(MegolmConfig::version_1()),
        }
    }

    pub fn session_id(&self) -> String {
        self.session.session_id()
    }

    /// The shareable session key (base64) to seal to each member over Olm.
    pub fn session_key_b64(&self) -> String {
        self.session.session_key().to_base64()
    }

    /// The current ratchet index (rotation/forward-secrecy bookkeeping).
    pub fn message_index(&self) -> u32 {
        self.session.message_index()
    }

    /// Encrypt a group message (returns the Megolm message bytes).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.session.encrypt(plaintext).to_bytes()
    }

    pub fn to_pickle_encrypted(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        encrypt_blob(key, &serde_json::to_vec(&self.session.pickle())?)
    }

    pub fn from_pickle_encrypted(key: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let bytes = decrypt_blob(key, blob)?;
        let pickle: GroupSessionPickle = serde_json::from_slice(&bytes)?;
        Ok(GroupSender {
            session: GroupSession::from(pickle),
        })
    }
}

impl Default for GroupSender {
    fn default() -> Self {
        Self::new()
    }
}

/// An INBOUND Megolm session (decrypts a particular sender's group messages).
pub struct GroupReceiver {
    session: InboundGroupSession,
}

impl GroupReceiver {
    /// Build from a base64 session key received (over Olm) from the sender.
    pub fn from_session_key_b64(session_key_b64: &str) -> Result<Self> {
        let key = SessionKey::from_base64(session_key_b64).context("megolm session key")?;
        Ok(GroupReceiver {
            session: InboundGroupSession::new(&key, MegolmConfig::version_1()),
        })
    }

    pub fn session_id(&self) -> String {
        self.session.session_id()
    }

    /// Decrypt a Megolm message. Returns `(plaintext, message_index)`.
    pub fn decrypt(&mut self, body: &[u8]) -> Result<(Vec<u8>, u32)> {
        let msg = MegolmMessage::from_bytes(body).map_err(|e| anyhow!("megolm message: {e}"))?;
        let out = self
            .session
            .decrypt(&msg)
            .map_err(|e| anyhow!("megolm decrypt: {e}"))?;
        Ok((out.plaintext, out.message_index))
    }

    pub fn to_pickle_encrypted(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        encrypt_blob(key, &serde_json::to_vec(&self.session.pickle())?)
    }

    pub fn from_pickle_encrypted(key: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let bytes = decrypt_blob(key, blob)?;
        let pickle: InboundGroupSessionPickle = serde_json::from_slice(&bytes)?;
        Ok(GroupReceiver {
            session: InboundGroupSession::from(pickle),
        })
    }
}

// ===========================================================================
// Vault keys (per-server at-rest encryption)
// ===========================================================================

/// Generate a fresh 32-byte master key (stored at `~/.cherm/master.key`, 0600).
pub fn gen_master_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// A stable server id (hex BLAKE3 of the server address) used as the vault
/// directory name.
pub fn server_id(addr: &str) -> String {
    hex::encode(&blake3::hash(addr.as_bytes()).as_bytes()[..16])
}

/// Derive a per-server 32-byte vault key from the master key (keyed BLAKE3).
pub fn derive_vault_key(master: &[u8; 32], server_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"cherm-vault\0");
    hasher.update(server_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// SQLCipher raw-key form (`x'<hex>'`) of a 32-byte vault key, for `PRAGMA key`.
pub fn vault_key_sqlcipher(key: &[u8; 32]) -> String {
    format!("x'{}'", hex::encode(key))
}

// ===========================================================================
// Pickle AEAD + base64 helpers
// ===========================================================================

fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("cipher: {e}"))?;
    let mut nonce = [0u8; PICKLE_NONCE];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    let mut out = Vec::with_capacity(PICKLE_NONCE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_blob(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < PICKLE_NONCE {
        return Err(anyhow!("blob too short"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("cipher: {e}"))?;
    cipher
        .decrypt(XNonce::from_slice(&blob[..PICKLE_NONCE]), &blob[PICKLE_NONCE..])
        .map_err(|e| anyhow!("decrypt (wrong key or tampered): {e}"))
}

/// Verify a base64 Ed25519 signature against a base64 Ed25519 public key.
pub fn verify_ed25519_b64(ed_pub_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (
        Ed25519PublicKey::from_base64(ed_pub_b64),
        Ed25519Signature::from_base64(sig_b64),
    ) else {
        return false;
    };
    pk.verify(msg, &sig).is_ok()
}

pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(B64.decode(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn olm_dm_roundtrip() {
        let alice = Device::generate();
        let mut bob = Device::generate();
        let otks = bob.generate_one_time_keys(1);
        bob.mark_published();
        let (_id, otk) = &otks[0];

        let mut a = alice.start_session(&bob.curve25519_b64(), otk).unwrap();
        let (t, body) = a.encrypt(b"hello bob").unwrap();
        assert_eq!(t, 0); // prekey message

        let (mut b, pt) = bob
            .create_inbound(&alice.curve25519_b64(), t, &body)
            .unwrap();
        assert_eq!(pt, b"hello bob");

        let (t2, body2) = b.encrypt(b"hi alice").unwrap();
        assert_eq!(a.decrypt(t2, &body2).unwrap(), b"hi alice");
    }

    #[test]
    fn megolm_group_roundtrip() {
        let mut sender = GroupSender::new();
        let key = sender.session_key_b64();
        let ct = sender.encrypt(b"hello group");
        let mut receiver = GroupReceiver::from_session_key_b64(&key).unwrap();
        let (pt, idx) = receiver.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello group");
        assert_eq!(idx, 0);
    }

    #[test]
    fn challenge_signature() {
        let d = Device::generate();
        let nonce = b"server-nonce";
        let sig = d.sign_b64(nonce);
        assert!(verify_ed25519_b64(&d.ed25519_b64(), nonce, &sig));
        assert!(!verify_ed25519_b64(&d.ed25519_b64(), b"other", &sig));
    }

    #[test]
    fn account_pickle_roundtrip() {
        let key = gen_master_key();
        let mut d = Device::generate();
        d.generate_one_time_keys(2);
        let blob = d.to_pickle_encrypted(&key).unwrap();
        let d2 = Device::from_pickle_encrypted(&key, &blob).unwrap();
        assert_eq!(d.ed25519_b64(), d2.ed25519_b64());
        // wrong key fails
        let bad = gen_master_key();
        assert!(Device::from_pickle_encrypted(&bad, &blob).is_err());
    }

    #[test]
    fn vault_key_is_deterministic_and_separated() {
        let m = gen_master_key();
        let id1 = server_id("relay.a:9000");
        let id2 = server_id("relay.b:9000");
        assert_ne!(id1, id2);
        assert_eq!(derive_vault_key(&m, &id1), derive_vault_key(&m, &id1));
        assert_ne!(derive_vault_key(&m, &id1), derive_vault_key(&m, &id2));
        assert!(vault_key_sqlcipher(&derive_vault_key(&m, &id1)).starts_with("x'"));
    }
}
