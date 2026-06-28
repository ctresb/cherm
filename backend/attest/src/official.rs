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

/// DEV-ONLY release keypair. Its SECRET is committed in this repo, so it must
/// NEVER be a trust anchor in a release build — anyone could forge an "official"
/// release signature with it. [`pinned`] therefore trusts this public key ONLY
/// in debug builds (local demos). Production servers sign with the real project
/// key (secret kept offline); clients trust it via `CHERM_RELEASE_PUBS` baked in
/// at build time, or the `CHERM_OFFICIAL_RELEASE_PUBS` runtime override.
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

/// Add every comma-separated base64 key in `raw` to `list` (deduped by key id).
fn add_keys(raw: &str, list: &mut Vec<(String, String)>) {
    for p in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let id = key_id_of(p);
        if !id.is_empty() && !list.iter().any(|(eid, _)| eid == &id) {
            list.push((id, p.to_string()));
        }
    }
}

/// Build the pinned trust set.
///
/// SECURITY: the committed dev release key is trusted ONLY in debug builds. In a
/// release build the trust anchors come exclusively from the real project key(s)
/// — baked in at official-build time via `CHERM_RELEASE_PUBS` and/or supplied at
/// runtime via `CHERM_OFFICIAL_RELEASE_PUBS` — whose secrets are never shipped.
/// A release client with no configured key trusts no release key (servers then
/// show 🔴), which is the safe default.
pub fn pinned() -> Official {
    let mut release_pubkeys: Vec<(String, String)> = Vec::new();

    // Real project key(s) baked in when the official client is built.
    if let Some(baked) = option_env!("CHERM_RELEASE_PUBS") {
        add_keys(baked, &mut release_pubkeys);
    }
    // Runtime override / additional production keys.
    if let Ok(extra) = std::env::var("CHERM_OFFICIAL_RELEASE_PUBS") {
        add_keys(&extra, &mut release_pubkeys);
    }
    // Dev key: debug builds ONLY (its secret is public in the repo).
    if cfg!(debug_assertions) {
        add_keys(DEV_RELEASE_PUBLIC_B64, &mut release_pubkeys);
    }

    let official_build_hash = std::env::var("CHERM_OFFICIAL_HASH")
        .ok()
        .filter(|s| !s.is_empty());
    let nitro_pcr0 = std::env::var("CHERM_OFFICIAL_PCR0")
        .ok()
        .filter(|s| !s.is_empty());

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
