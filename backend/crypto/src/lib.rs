//! cherm.chat client-side cryptography.
//!
//! All key material lives only on the client. The relay server never receives
//! private keys and only ever forwards opaque ciphertext, so it cannot read
//! message content (requirements 11 & 12).
//!
//! Primitives:
//! - Identity & authentication: Ed25519 (an SSH-like keypair). The public key
//!   is the immutable identity anchor that binds one username to one person
//!   forever (requirements 6 & 7). Login is challenge-response: the server
//!   sends a random nonce, the client returns an Ed25519 signature.
//! - 1:1 encryption & key distribution: an anonymous "sealed box" — an
//!   ephemeral X25519 ECDH to the recipient's static key, HKDF-SHA256 to a
//!   symmetric key, then XChaCha20-Poly1305. Each message uses a fresh
//!   ephemeral key, giving per-message key separation.
//! - Group encryption: a random 32-byte group key shared once with each
//!   member via a sealed box, then XChaCha20-Poly1305 for every group message.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};

const HKDF_INFO: &[u8] = b"cherm-v1-seal";
const EPH_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// A long-lived identity: an Ed25519 signing key plus an X25519 key for ECDH.
pub struct Identity {
    signing: SigningKey,
    dh: StaticSecret,
}

/// On-disk serialization of an [`Identity`]. Both secrets are 32 raw bytes,
/// base64-encoded. Store this file with `0600` permissions.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    /// base64 Ed25519 seed (32 bytes).
    ed_seed: String,
    /// base64 X25519 secret scalar (32 bytes).
    dh_secret: String,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing = SigningKey::generate(&mut rng);
        let dh = StaticSecret::random_from_rng(&mut rng);
        Identity { signing, dh }
    }

    /// Ed25519 public key (32 bytes) — the identity anchor.
    pub fn ed_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// X25519 public key (32 bytes) — peers encrypt to this.
    pub fn dh_public(&self) -> [u8; 32] {
        XPublicKey::from(&self.dh).to_bytes()
    }

    /// Base64 of [`Identity::ed_public`].
    pub fn ed_public_b64(&self) -> String {
        B64.encode(self.ed_public())
    }

    /// Base64 of [`Identity::dh_public`].
    pub fn dh_public_b64(&self) -> String {
        B64.encode(self.dh_public())
    }

    /// Sign a message with the Ed25519 key, returning a 64-byte signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Sign and base64-encode in one step (used for challenge responses).
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.sign(msg))
    }

    /// Serialize to the on-disk JSON form.
    pub fn to_json(&self) -> Result<String> {
        let file = IdentityFile {
            ed_seed: B64.encode(self.signing.to_bytes()),
            dh_secret: B64.encode(self.dh.to_bytes()),
        };
        Ok(serde_json::to_string_pretty(&file)?)
    }

    /// Parse from the on-disk JSON form.
    pub fn from_json(s: &str) -> Result<Self> {
        let file: IdentityFile = serde_json::from_str(s).context("parsing identity file")?;
        let ed_seed = decode_array::<32>(&file.ed_seed).context("ed_seed")?;
        let dh_secret = decode_array::<32>(&file.dh_secret).context("dh_secret")?;
        Ok(Identity {
            signing: SigningKey::from_bytes(&ed_seed),
            dh: StaticSecret::from(dh_secret),
        })
    }

    /// Decrypt a sealed box that was sealed to this identity's X25519 key.
    pub fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>> {
        unseal(&self.dh, blob)
    }
}

/// Verify an Ed25519 signature given a raw 32-byte public key.
pub fn verify(ed_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(ed_pub) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify(msg, &signature).is_ok()
}

/// Verify using base64 inputs (convenience for the server).
pub fn verify_b64(ed_pub_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let (Ok(ed_pub), Ok(sig)) = (
        decode_array::<32>(ed_pub_b64),
        decode_array::<64>(sig_b64),
    ) else {
        return false;
    };
    verify(&ed_pub, msg, &sig)
}

/// Encrypt `plaintext` to a recipient's X25519 public key (sealed box).
///
/// Layout: `ephemeral_pub(32) || nonce(24) || ciphertext`.
pub fn seal(recipient_dh_pub: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
    let eph_pub = XPublicKey::from(&eph_secret);
    let recipient = XPublicKey::from(*recipient_dh_pub);
    let shared = eph_secret.diffie_hellman(&recipient);

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub.as_bytes());
    salt.extend_from_slice(recipient.as_bytes());
    let key = hkdf_key(shared.as_bytes(), &salt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("cipher init: {e}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("seal encrypt: {e}"))?;

    let mut out = Vec::with_capacity(EPH_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a sealed box with the recipient's X25519 static secret.
pub fn unseal(my_dh: &StaticSecret, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < EPH_LEN + NONCE_LEN {
        return Err(anyhow!("sealed blob too short"));
    }
    let eph_pub: [u8; 32] = blob[..EPH_LEN].try_into().unwrap();
    let nonce = &blob[EPH_LEN..EPH_LEN + NONCE_LEN];
    let ct = &blob[EPH_LEN + NONCE_LEN..];

    let eph = XPublicKey::from(eph_pub);
    let shared = my_dh.diffie_hellman(&eph);
    let me = XPublicKey::from(my_dh);

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&eph_pub);
    salt.extend_from_slice(me.as_bytes());
    let key = hkdf_key(shared.as_bytes(), &salt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("cipher init: {e}"))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|e| anyhow!("unseal decrypt (wrong key or tampered): {e}"))
}

/// Sealed-box helpers that work with base64 strings directly.
pub fn seal_b64(recipient_dh_pub_b64: &str, plaintext: &[u8]) -> Result<String> {
    let pk = decode_array::<32>(recipient_dh_pub_b64).context("recipient dh_pub")?;
    Ok(B64.encode(seal(&pk, plaintext)?))
}

/// Generate a random 32-byte symmetric group key.
pub fn gen_group_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt a group message. Layout: `nonce(24) || ciphertext`.
pub fn group_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("cipher init: {e}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("group encrypt: {e}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a group message produced by [`group_encrypt`].
pub fn group_decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(anyhow!("group blob too short"));
    }
    let nonce = &blob[..NONCE_LEN];
    let ct = &blob[NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("cipher init: {e}"))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|e| anyhow!("group decrypt (wrong key or tampered): {e}"))
}

/// Base64-encode helper.
pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

/// Base64-decode helper.
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(B64.decode(s)?)
}

fn hkdf_key(ikm: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| anyhow!("hkdf expand"))?;
    Ok(okm)
}

fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = B64.decode(s)?;
    let arr: [u8; N] = v
        .try_into()
        .map_err(|_| anyhow!("expected {N} bytes"))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrips_through_json() {
        let id = Identity::generate();
        let json = id.to_json().unwrap();
        let id2 = Identity::from_json(&json).unwrap();
        assert_eq!(id.ed_public(), id2.ed_public());
        assert_eq!(id.dh_public(), id2.dh_public());
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let msg = b"challenge-nonce";
        let sig = id.sign(msg);
        assert!(verify(&id.ed_public(), msg, &sig));
        assert!(!verify(&id.ed_public(), b"other", &sig));
        let other = Identity::generate();
        assert!(!verify(&other.ed_public(), msg, &sig));
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let plaintext = b"hello bob, this is private";
        let blob = seal(&bob.dh_public(), plaintext).unwrap();
        let got = bob.unseal(&blob).unwrap();
        assert_eq!(got, plaintext);
        // Alice cannot decrypt a box sealed to Bob.
        assert!(alice.unseal(&blob).is_err());
    }

    #[test]
    fn group_roundtrip() {
        let key = gen_group_key();
        let plaintext = b"hello everyone in the room";
        let blob = group_encrypt(&key, plaintext).unwrap();
        assert_eq!(group_decrypt(&key, &blob).unwrap(), plaintext);
        let wrong = gen_group_key();
        assert!(group_decrypt(&wrong, &blob).is_err());
    }
}
