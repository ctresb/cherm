//! Pinned "official" values the client trusts when judging a server.
//!
//! Dev defaults are baked in so a locally-built server shows the 🟡 software
//! tier out of the box. Production overrides via env: `CHERM_OFFICIAL_HASH`,
//! `CHERM_OFFICIAL_PCR0`, `CHERM_OFFICIAL_RELEASE_PUBS` (comma-separated base64
//! Ed25519 public keys).

use crate::{b64_decode, b64_encode};

/// Public links surfaced in the verdict UI.
pub const PUBLIC_CODEBASE_URL: &str = "https://github.com/cherm-chat/cherm";
pub const SIGNATURES_URL: &str = "https://cherm.chat/signatures";

/// DEV-ONLY release keypair. Production servers are signed by the real project
/// key; this exists only so local builds demonstrate the software tier.
pub const DEV_RELEASE_PUBLIC_B64: &str = "rP8FiokGtvgz/SsImR73QCYo8fL5tAbw333dA5tUNJ8=";
pub const DEV_RELEASE_SECRET_B64: &str = "IwAL8LHaDW6SOrgkBVl0FUUuYXsZgcGJJb4PLIf7Fss=";

/// The genuine AWS Nitro Enclaves Root-G1 (fingerprint-verified at vendoring
/// time: SHA-256 64:1A:03:...:5B).
const AWS_NITRO_ROOT_PEM: &str = include_str!("../roots/aws_nitro_root_g1.pem");

/// Everything the verifier needs to render a verdict.
pub struct Official {
    /// (key_id_b64, ed25519_public_b64) pairs trusted as project release keys.
    pub release_pubkeys: Vec<(String, String)>,
    /// If set, the build hash a server MUST present to be considered official.
    pub official_build_hash: Option<String>,
    /// If set, the Nitro PCR0 measurement of the official enclave image.
    pub nitro_pcr0: Option<String>,
    /// Trusted Nitro root certificates (DER).
    pub nitro_roots: Vec<Vec<u8>>,
}

/// Derive an 8-byte key id (base64) from a base64 Ed25519 public key.
pub fn key_id_of(pub_b64: &str) -> String {
    match b64_decode(pub_b64) {
        Ok(bytes) if bytes.len() >= 8 => b64_encode(&bytes[..8]),
        _ => String::new(),
    }
}

/// Build the pinned trust set (dev defaults + env overrides).
pub fn pinned() -> Official {
    let mut release_pubkeys = vec![(key_id_of(DEV_RELEASE_PUBLIC_B64), DEV_RELEASE_PUBLIC_B64.to_string())];
    if let Ok(extra) = std::env::var("CHERM_OFFICIAL_RELEASE_PUBS") {
        for p in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            release_pubkeys.push((key_id_of(p), p.to_string()));
        }
    }

    let official_build_hash = std::env::var("CHERM_OFFICIAL_HASH").ok().filter(|s| !s.is_empty());
    let nitro_pcr0 = std::env::var("CHERM_OFFICIAL_PCR0").ok().filter(|s| !s.is_empty());

    let mut nitro_roots = Vec::new();
    if let Ok(der) = crate::pem_first_der(AWS_NITRO_ROOT_PEM) {
        nitro_roots.push(der);
    }

    Official {
        release_pubkeys,
        official_build_hash,
        nitro_pcr0,
        nitro_roots,
    }
}
