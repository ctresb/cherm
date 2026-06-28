//! cherm.chat server attestation: a server proves *what code it runs* with one
//! of three tiers, and the client renders an honest verdict. See ATTESTATION.md.
//!
//! - **unsigned** → 🔴 nothing is proven.
//! - **software** → 🟡 a genuine official release hash, signed by the project
//!   key. Does NOT prove the server actually runs it (replayable) — a deterrent.
//! - **tee** → 🟢 a hardware (AWS Nitro) quote binding the official measurement
//!   and a fresh nonce. Unforgeable modulo trusting the TEE vendor.

pub mod nitro;
pub mod official;

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub use official::{Official, PUBLIC_CODEBASE_URL, SIGNATURES_URL};

/// The attestation strength a server advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Unsigned,
    Software,
    Tee,
}

/// The attestation message a server returns to a client's `AttestRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub tier: Tier,
    /// Echoed client nonce (base64, 32 bytes).
    pub nonce: String,
    pub server_unix_ms: i64,
    /// Hex BLAKE3 of the server's build artifact.
    pub build_hash: String,
    pub build_hash_alg: String,
    /// "x.y.z+gitsha".
    pub release_version: String,
    /// base64 8-byte id selecting which pinned release key signed.
    pub release_key_id: String,
    /// base64 Ed25519 signature over the release message (static, by the project).
    pub release_sig: String,
    /// base64 Ed25519 per-server instance public key.
    pub instance_pub: String,
    /// base64 Ed25519 signature over the instance message (liveness/anti-replay).
    pub instance_sig: String,
    /// base64 AWS Nitro COSE_Sign1 quote (present iff tier == tee).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_quote: Option<String>,
}

/// Verdict colour shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Green,
    Yellow,
    Red,
}

/// Outcome of verifying an [`Attestation`].
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub verdict: Verdict,
    pub tier: Tier,
    pub reason: String,
    pub build_hash: String,
    pub fingerprint: String,
}

// ===========================================================================
// Signed messages (stable domain-separated strings)
// ===========================================================================

fn release_msg(version: &str, build_hash: &str) -> Vec<u8> {
    format!("cherm-release\n{version}\n{build_hash}").into_bytes()
}

fn instance_msg(nonce_b64: &str, build_hash: &str, ts: i64) -> Vec<u8> {
    format!("cherm-instance\n{nonce_b64}\n{build_hash}\n{ts}").into_bytes()
}

// ===========================================================================
// Provider side (server)
// ===========================================================================

/// Hex BLAKE3 of the running executable — the server's build measurement.
/// Honest: a malicious operator can patch the binary to report any value; this
/// is a deterrent unless combined with a TEE quote.
pub fn build_hash() -> String {
    match std::env::current_exe().and_then(std::fs::read) {
        Ok(bytes) => hex::encode(blake3::hash(&bytes).as_bytes()),
        Err(_) => "unknown".to_string(),
    }
}

/// The project release key (signs build hashes at release time). In dev the
/// embedded key is used so local builds show the software tier.
pub struct ReleaseKey {
    signing: SigningKey,
}

impl ReleaseKey {
    pub fn dev() -> Self {
        Self::from_secret_b64(official::DEV_RELEASE_SECRET_B64).expect("valid dev key")
    }

    pub fn from_secret_b64(secret_b64: &str) -> Result<Self> {
        let bytes = decode32(secret_b64)?;
        Ok(ReleaseKey {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> String {
        B64.encode(&self.signing.verifying_key().to_bytes()[..8])
    }

    pub fn sign(&self, version: &str, build_hash: &str) -> String {
        B64.encode(self.signing.sign(&release_msg(version, build_hash)).to_bytes())
    }
}

/// A per-server instance key (proves liveness; bound to code only in the TEE
/// tier via the quote's user_data).
pub struct InstanceKey {
    signing: SigningKey,
}

impl InstanceKey {
    pub fn generate() -> Self {
        InstanceKey {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    pub fn from_secret_b64(secret_b64: &str) -> Result<Self> {
        Ok(InstanceKey {
            signing: SigningKey::from_bytes(&decode32(secret_b64)?),
        })
    }

    pub fn to_secret_b64(&self) -> String {
        B64.encode(self.signing.to_bytes())
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
    }

    /// Raw 32-byte public key (for binding into a TEE quote's user_data).
    pub fn public_raw(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, nonce_b64: &str, build_hash: &str, ts: i64) -> String {
        B64.encode(
            self.signing
                .sign(&instance_msg(nonce_b64, build_hash, ts))
                .to_bytes(),
        )
    }
}

/// Build a software-tier attestation answering `nonce_b64`.
pub fn build_software(
    nonce_b64: &str,
    version: &str,
    now_ms: i64,
    release: &ReleaseKey,
    instance: &InstanceKey,
) -> Attestation {
    let bh = build_hash();
    Attestation {
        tier: Tier::Software,
        nonce: nonce_b64.to_string(),
        server_unix_ms: now_ms,
        release_sig: release.sign(version, &bh),
        release_key_id: release.key_id(),
        instance_sig: instance.sign(nonce_b64, &bh, now_ms),
        instance_pub: instance.public_b64(),
        release_version: version.to_string(),
        build_hash_alg: "blake3".to_string(),
        build_hash: bh,
        tee_quote: None,
    }
}

/// Build an unsigned attestation (no integrity claim).
pub fn build_unsigned(nonce_b64: &str, version: &str, now_ms: i64, instance: &InstanceKey) -> Attestation {
    let bh = build_hash();
    Attestation {
        tier: Tier::Unsigned,
        nonce: nonce_b64.to_string(),
        server_unix_ms: now_ms,
        release_sig: String::new(),
        release_key_id: String::new(),
        instance_sig: instance.sign(nonce_b64, &bh, now_ms),
        instance_pub: instance.public_b64(),
        release_version: version.to_string(),
        build_hash_alg: "blake3".to_string(),
        build_hash: bh,
        tee_quote: None,
    }
}

// ===========================================================================
// Verifier side (client)
// ===========================================================================

/// Verify an attestation against the pinned official trust set.
pub fn verify(att: &Attestation, expected_nonce_b64: &str, now_ms: i64, off: &Official) -> VerifyResult {
    let fp = fingerprint_of(&att.instance_pub);
    let red = |reason: &str| VerifyResult {
        verdict: Verdict::Red,
        tier: att.tier,
        reason: reason.to_string(),
        build_hash: att.build_hash.clone(),
        fingerprint: fp.clone(),
    };

    if att.nonce != expected_nonce_b64 {
        return red("attestation nonce did not match (possible replay)");
    }

    match att.tier {
        Tier::Unsigned => red("server provided no signature — its code is unverified"),

        Tier::Software => {
            if !verify_release_sig(off, &att.release_key_id, &att.release_version, &att.build_hash, &att.release_sig) {
                return red("release signature is not from the official project key");
            }
            if let Some(expected) = &off.official_build_hash {
                if expected != &att.build_hash {
                    return red("build hash does not match the official public codebase");
                }
            }
            if !verify_instance_sig(&att.instance_pub, &att.nonce, &att.build_hash, att.server_unix_ms, &att.instance_sig) {
                return red("server instance signature is invalid");
            }
            VerifyResult {
                verdict: Verdict::Yellow,
                tier: att.tier,
                reason: "this server has only a software signature".to_string(),
                build_hash: att.build_hash.clone(),
                fingerprint: fp,
            }
        }

        Tier::Tee => {
            let Some(q) = &att.tee_quote else {
                return red("tee tier but no quote provided");
            };
            let (Ok(quote), Ok(nonce_bytes)) = (b64_decode(q), b64_decode(expected_nonce_b64)) else {
                return red("malformed tee quote or nonce");
            };
            let instance_raw = b64_decode(&att.instance_pub).unwrap_or_default();
            match nitro::verify(
                &quote,
                off.nitro_pcr0.as_deref(),
                &nonce_bytes,
                now_ms,
                &off.nitro_roots,
                Some(&instance_raw),
            ) {
                Ok(_claims) => VerifyResult {
                    verdict: Verdict::Green,
                    tier: att.tier,
                    reason: "hardware TEE attests the official build".to_string(),
                    build_hash: att.build_hash.clone(),
                    fingerprint: fp,
                },
                Err(e) => red(&format!("TEE quote verification failed: {e}")),
            }
        }
    }
}

fn verify_release_sig(off: &Official, key_id: &str, version: &str, build_hash: &str, sig_b64: &str) -> bool {
    let Some((_, pub_b64)) = off.release_pubkeys.iter().find(|(id, _)| id == key_id) else {
        return false;
    };
    verify_ed(pub_b64, &release_msg(version, build_hash), sig_b64)
}

fn verify_instance_sig(instance_pub_b64: &str, nonce_b64: &str, build_hash: &str, ts: i64, sig_b64: &str) -> bool {
    verify_ed(instance_pub_b64, &instance_msg(nonce_b64, build_hash, ts), sig_b64)
}

fn verify_ed(pub_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let (Ok(pk_bytes), Ok(sig_bytes)) = (decode32(pub_b64), b64_decode(sig_b64)) else {
        return false;
    };
    let (Ok(vk), Ok(sig)) = (VerifyingKey::from_bytes(&pk_bytes), Signature::from_slice(&sig_bytes)) else {
        return false;
    };
    vk.verify_strict(msg, &sig).is_ok()
}

// ===========================================================================
// Helpers
// ===========================================================================

/// A short readable fingerprint of a base64 key (hex groups of 4).
pub fn fingerprint_of(key_b64: &str) -> String {
    let digest = blake3::hash(key_b64.as_bytes());
    let hex = hex::encode(&digest.as_bytes()[..12]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(B64.decode(s)?)
}

fn decode32(b64: &str) -> Result<[u8; 32]> {
    let v = B64.decode(b64)?;
    v.try_into().map_err(|_| anyhow!("expected 32 bytes"))
}

/// Decode the first PEM block into DER bytes.
pub(crate) fn pem_first_der(pem: &str) -> Result<Vec<u8>> {
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    if b64.is_empty() {
        bail!("no PEM block found");
    }
    b64_decode(&b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::Decode;

    const NOW: i64 = 1_700_000_000_000;

    #[test]
    fn embedded_aws_root_loads() {
        let off = official::pinned();
        assert_eq!(off.nitro_roots.len(), 1, "AWS Nitro root must embed");
        assert!(x509_cert::Certificate::from_der(&off.nitro_roots[0]).is_ok());
    }

    #[test]
    fn software_tier_yields_yellow() {
        let release = ReleaseKey::dev();
        let instance = InstanceKey::generate();
        let nonce = b64_encode(b"0123456789abcdef0123456789abcdef");
        let att = build_software(&nonce, "0.1.0+test", NOW, &release, &instance);
        let off = official::pinned();
        let r = verify(&att, &nonce, NOW, &off);
        assert_eq!(r.verdict, Verdict::Yellow, "{}", r.reason);
    }

    #[test]
    fn unsigned_tier_yields_red() {
        let instance = InstanceKey::generate();
        let nonce = b64_encode(b"n");
        let att = build_unsigned(&nonce, "0.1.0", NOW, &instance);
        let off = official::pinned();
        assert_eq!(verify(&att, &nonce, NOW, &off).verdict, Verdict::Red);
    }

    #[test]
    fn wrong_release_key_yields_red() {
        let rogue = ReleaseKey::from_secret_b64(&b64_encode(&[7u8; 32])).unwrap();
        let instance = InstanceKey::generate();
        let nonce = b64_encode(b"n");
        let att = build_software(&nonce, "0.1.0", NOW, &rogue, &instance);
        let off = official::pinned();
        assert_eq!(verify(&att, &nonce, NOW, &off).verdict, Verdict::Red);
    }

    #[test]
    fn replayed_nonce_yields_red() {
        let release = ReleaseKey::dev();
        let instance = InstanceKey::generate();
        let att = build_software(&b64_encode(b"old-nonce"), "0.1.0", NOW, &release, &instance);
        let off = official::pinned();
        assert_eq!(verify(&att, &b64_encode(b"new-nonce"), NOW, &off).verdict, Verdict::Red);
    }

    #[test]
    fn build_hash_mismatch_yields_red() {
        let release = ReleaseKey::dev();
        let instance = InstanceKey::generate();
        let nonce = b64_encode(b"n");
        let att = build_software(&nonce, "0.1.0", NOW, &release, &instance);
        let mut off = official::pinned();
        off.official_build_hash = Some("deadbeef".to_string());
        assert_eq!(verify(&att, &nonce, NOW, &off).verdict, Verdict::Red);
    }
}
