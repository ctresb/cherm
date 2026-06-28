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
use rand::{rngs::OsRng, Rng, RngCore};
use zeroize::Zeroizing;
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
    MegolmMessage, SessionConfig as MegolmConfig, SessionKey,
};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
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
        Ok((
            OlmSession {
                session: res.session,
            },
            res.plaintext,
        ))
    }

    /// Export the FULL identity (including the private keys) as a portable JSON
    /// string. This IS the secret — it is what lets you recover your username on
    /// a new machine, so back it up safely (the core writes it to a `0600` file).
    pub fn export_pickle_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.account.pickle())?)
    }

    /// Restore an identity from [`Device::export_pickle_json`] output.
    pub fn from_pickle_json(json: &str) -> Result<Self> {
        let pickle: AccountPickle = serde_json::from_str(json)?;
        Ok(Device {
            account: Account::from(pickle),
        })
    }

    /// Encrypt this account to an at-rest pickle blob.
    pub fn to_pickle_encrypted(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        encrypt_blob(key, &Zeroizing::new(serde_json::to_vec(&self.account.pickle())?))
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
        encrypt_blob(key, &Zeroizing::new(serde_json::to_vec(&self.session.pickle())?))
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
        encrypt_blob(key, &Zeroizing::new(serde_json::to_vec(&self.session.pickle())?))
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
        encrypt_blob(key, &Zeroizing::new(serde_json::to_vec(&self.session.pickle())?))
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

/// Write secret bytes (private keys, identity backups) to `path` with
/// owner-only permissions, created ATOMICALLY at mode 0600 — there is never a
/// window where the file exists world-readable. The parent directory is created
/// 0700 if missing. On unix it fails loudly if the restrictive mode cannot be
/// enforced; on non-unix it writes with the platform default (the user profile
/// directory is normally already owner-private).
pub fn write_secret_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // SYMLINK / TOCTOU HARDENING: a local attacker who can pre-create the key
        // path (or a permissive/symlinked file there) must not be able to redirect
        // our secret write to a file they control, nor have us follow a symlink to
        // a sensitive target and truncate it. Two layers:
        //   1. Reject an existing symlink up front (`symlink_metadata` does NOT
        //      follow links, so this sees the link itself).
        //   2. Open with `O_NOFOLLOW` so the kernel refuses to follow a symlink in
        //      the FINAL path component even under a race after the check.
        // The parent dir is created 0700 above; together this closes the
        // "pre-place a symlink at the secret path" attack.
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing to write secret to {}: path is a symlink (possible tampering)",
                    path.display()
                );
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(data)?;
        f.flush()?;
        // Normalize the mode (in case the file pre-existed with looser perms) via
        // the OPEN FILE DESCRIPTOR (fchmod), not a path-based set_permissions —
        // the latter re-resolves `path` and would follow a symlink swapped in after
        // our O_NOFOLLOW open. FAIL if owner-only can't be enforced rather than
        // silently leave a secret world-readable.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("enforcing 0600 on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

/// Generate a fresh 32-byte master key (stored at `~/.cherm/master.key`, 0600).
pub fn gen_master_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

// ===========================================================================
// Group invite/access keys
// ===========================================================================
//
// A group key is a short, stable, human-shareable handle for a group on a
// server (an "invite/group link"). It is NOT a secret token: access is gated by
// who the owner shares the Megolm session key with (see core::net), so knowing a
// group key alone never grants access to a banned/unapproved user. Uniqueness is
// enforced by the vault `groups.group_key` UNIQUE constraint plus collision
// retry; this module only mints + validates the character shape.

/// Charset for group keys: `A-Z`, `a-z`, `0-9` (62 symbols).
const GROUP_KEY_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Length of a group invite/access key.
pub const GROUP_KEY_LEN: usize = 8;

/// Generate a random alphanumeric code of length `tamanho` from the group-key
/// charset (`A-Z`, `a-z`, `0-9`). Uses the OS CSPRNG.
pub fn gerar_codigo(tamanho: usize) -> String {
    let mut rng = OsRng;
    (0..tamanho)
        .map(|_| {
            let idx = rng.gen_range(0..GROUP_KEY_CHARSET.len());
            GROUP_KEY_CHARSET[idx] as char
        })
        .collect()
}

/// Mint a fresh 8-char group key. Uniqueness across groups is the caller's job
/// (DB UNIQUE + retry); this just produces a syntactically valid candidate.
pub fn gen_group_key() -> String {
    gerar_codigo(GROUP_KEY_LEN)
}

/// True if `s` is a syntactically valid group key: exactly [`GROUP_KEY_LEN`]
/// chars, each in `[A-Za-z0-9]`.
pub fn valid_group_key(s: &str) -> bool {
    s.len() == GROUP_KEY_LEN && s.bytes().all(|b| b.is_ascii_alphanumeric())
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
/// Returned in a [`Zeroizing`] wrapper so the hex (which embeds the raw key) is
/// wiped on drop instead of lingering in freed heap.
pub fn vault_key_sqlcipher(key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(format!("x'{}'", hex::encode(key)))
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

fn decrypt_blob(key: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < PICKLE_NONCE {
        return Err(anyhow!("blob too short"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("cipher: {e}"))?;
    // The decrypted plaintext is a private-key pickle (device / Olm / Megolm
    // secrets). Wrap it so the buffer is wiped on drop instead of lingering in
    // freed heap (cold-boot / core-dump / swap exposure in the local-attacker model).
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&blob[..PICKLE_NONCE]),
            &blob[PICKLE_NONCE..],
        )
        .map_err(|e| anyhow!("decrypt (wrong key or tampered): {e}"))?;
    Ok(Zeroizing::new(plaintext))
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
    fn group_key_shape() {
        // Every minted key is exactly 8 chars and alphanumeric, over many tries.
        for _ in 0..2000 {
            let k = gen_group_key();
            assert_eq!(k.len(), GROUP_KEY_LEN, "key {k:?} must be 8 chars");
            assert!(valid_group_key(&k), "minted key {k:?} must validate");
            assert!(k.bytes().all(|b| b.is_ascii_alphanumeric()));
        }
        // Validation rejects the wrong length / charset.
        assert!(valid_group_key("Ab3xZ9q0"));
        assert!(!valid_group_key("short")); // 5 chars
        assert!(!valid_group_key("toolongkey")); // 10 chars
        assert!(!valid_group_key("abcdef!@")); // punctuation
        assert!(!valid_group_key("abcd efg")); // space
        assert!(!valid_group_key("")); // empty
    }

    #[test]
    fn group_keys_are_well_distributed() {
        use std::collections::HashSet;
        // 8-char base62 has 62^8 ≈ 2.18e14 values, so 5000 draws should collide
        // essentially never — a sanity check that the generator isn't degenerate.
        let mut seen = HashSet::new();
        for _ in 0..5000 {
            seen.insert(gen_group_key());
        }
        assert!(seen.len() > 4990, "generator produced too many collisions");
    }

    #[test]
    fn gerar_codigo_honours_length() {
        for n in [0usize, 1, 4, 8, 16, 32] {
            assert_eq!(gerar_codigo(n).chars().count(), n);
        }
    }

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
    fn identity_export_import_roundtrip() {
        // Exporting + re-importing an identity preserves the keypair, so a user
        // can recover their username on a fresh machine.
        let mut d = Device::generate();
        d.generate_one_time_keys(3);
        d.mark_published();
        let json = d.export_pickle_json().unwrap();
        let restored = Device::from_pickle_json(&json).unwrap();
        assert_eq!(d.ed25519_b64(), restored.ed25519_b64());
        assert_eq!(d.curve25519_b64(), restored.curve25519_b64());
        // The restored key signs identically (so server challenge-auth still works).
        let nonce = b"server-nonce";
        assert!(verify_ed25519_b64(
            &restored.ed25519_b64(),
            nonce,
            &restored.sign_b64(nonce)
        ));
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

    #[cfg(unix)]
    #[test]
    fn write_secret_file_refuses_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cherm-secret-test-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("attacker-target");
        std::fs::write(&target, b"victim").unwrap();
        let link = dir.join("instance.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // Writing the secret through a symlink must be refused, and the symlink's
        // target must remain untouched (not truncated / overwritten).
        let err = write_secret_file(&link, b"TOP-SECRET-KEY");
        assert!(err.is_err(), "must refuse to write through a symlink");
        assert_eq!(std::fs::read(&target).unwrap(), b"victim", "target untouched");

        // A normal (non-symlink) path still writes 0600.
        let real = dir.join("real.key");
        write_secret_file(&real, b"ok").unwrap();
        assert_eq!(std::fs::read(&real).unwrap(), b"ok");
        let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(test)]
    fn uuid_like() -> String {
        // Avoid pulling uuid into this crate's tests; a process+addr nonce suffices
        // for a unique temp dir name.
        let x = Box::new(0u8);
        format!("{:p}", &*x)
            .trim_start_matches("0x")
            .to_string()
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
