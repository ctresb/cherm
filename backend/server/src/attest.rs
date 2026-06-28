//! Server-side attestation state (ATTESTATION.md, PROTOCOL.md §3).
//!
//! The relay proves *what code it runs* so clients can render a trust verdict
//! BEFORE registering or authenticating. This module owns the long-lived signing
//! material and builds a fresh [`cherm_attest::Attestation`] for each
//! `AttestRequest`:
//!
//!   * a per-server [`InstanceKey`] persisted to disk (base64), generated on
//!     first run — it signs each `(nonce, build_hash, ts)` to prove liveness;
//!   * a [`ReleaseKey`] (the project release key, or `ReleaseKey::dev()`) that
//!     signs the build hash to yield the 🟡 software tier;
//!   * the advertised release `version`.
//!
//! With `--no-attest` we emit an unsigned (🔴) attestation instead. The TEE
//! (🟢) path is a deployment concern (a Nitro enclave) and is not built here.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use cherm_attest::{build_software, build_unsigned, Attestation, InstanceKey, ReleaseKey};

/// Immutable attestation configuration, cloned (as an `Arc`) into every
/// connection task. None of its state is mutated per request.
pub struct Attestor {
    instance: InstanceKey,
    release: ReleaseKey,
    version: String,
    no_attest: bool,
}

/// Shared handle to the [`Attestor`].
pub type Shared = Arc<Attestor>;

impl Attestor {
    /// Build the attestor: load/generate the instance key, pick the release key,
    /// and record the version + tier choice.
    pub fn new(
        instance_key_path: &Path,
        release_secret_b64: Option<&str>,
        version: String,
        no_attest: bool,
    ) -> Result<Self> {
        let instance = load_or_create_instance_key(instance_key_path)?;
        let release = match release_secret_b64 {
            Some(secret) => {
                ReleaseKey::from_secret_b64(secret).context("parsing --release-secret")?
            }
            // No release secret supplied. The committed dev key's SECRET is public
            // (anyone could forge an "official" software signature with it), so a
            // RELEASE build must NOT silently fall back to it — that ships a
            // server believing it serves a 🟡 software tier while every release
            // client correctly shows 🔴, a confusing and insecure misconfiguration.
            // Fail closed: require an explicit `--release-secret` or an explicit
            // `--no-attest` (which serves an honest unsigned 🔴). The dev key is
            // only an acceptable default in debug builds (local demos), where
            // clients also trust it via `cfg!(debug_assertions)`.
            None if !no_attest && !cfg!(debug_assertions) => {
                anyhow::bail!(
                    "refusing to start a release server without a release key: pass \
                     --release-secret <b64> to sign the software tier, or --no-attest \
                     to serve an honest unsigned attestation"
                );
            }
            None => ReleaseKey::dev(),
        };
        Ok(Attestor {
            instance,
            release,
            version,
            no_attest,
        })
    }

    /// The advertised release version (for logging).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// True if running in unsigned (no-attest) mode.
    pub fn no_attest(&self) -> bool {
        self.no_attest
    }

    /// Base64 instance public key (for logging the server's identity).
    pub fn instance_pub_b64(&self) -> String {
        self.instance.public_b64()
    }

    /// Build an attestation answering a client's base64 32-byte `nonce`.
    pub fn build(&self, nonce_b64: &str, now_ms: i64) -> Attestation {
        if self.no_attest {
            build_unsigned(nonce_b64, &self.version, now_ms, &self.instance)
        } else {
            build_software(
                nonce_b64,
                &self.version,
                now_ms,
                &self.release,
                &self.instance,
            )
        }
    }
}

/// Load the persisted instance key from `path`, or generate + save a fresh one
/// (base64 secret, `0600` on unix). The key must be stable across restarts so a
/// server keeps the same fingerprint clients have come to recognise.
fn load_or_create_instance_key(path: &Path) -> Result<InstanceKey> {
    if path.exists() {
        let b64 = std::fs::read_to_string(path)
            .with_context(|| format!("reading instance key {}", path.display()))?;
        let key = InstanceKey::from_secret_b64(b64.trim())
            .with_context(|| format!("parsing instance key {}", path.display()))?;
        Ok(key)
    } else {
        let key = InstanceKey::generate();
        // The instance key is the server's signing secret — write it atomically
        // owner-only (0600, parent 0700), failing loudly if it can't be enforced.
        cherm_crypto::write_secret_file(path, key.to_secret_b64().as_bytes())
            .with_context(|| format!("writing instance key {}", path.display()))?;
        Ok(key)
    }
}
