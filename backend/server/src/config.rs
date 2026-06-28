//! Operator-supplied server configuration (PROTOCOL.md §3).
//!
//! Loaded from a JSON file via `--config <path>`; everything is optional and
//! defaults to empty/permissive. It carries two kinds of public-facing policy:
//!
//!   * **public metadata** (name, repo URL, ...) returned by `GetServerInfo` so
//!     users can see what codebase the operator *claims* to run;
//!   * an **official-client policy**: whether to reject clients whose build hash
//!     is not on an allow-list. Honest limit — a client can lie about its hash
//!     (no client TEE), so this is a deterrent, not a guarantee.
//!
//! Nothing here is hardcoded into the binary; an operator who passes no config
//! gets empty metadata and accepts all clients.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Shared, immutable server configuration cloned into each connection task.
pub type Shared = Arc<ServerConfig>;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Public display name of this server.
    pub name: String,
    /// URL of the codebase this server claims to run (shown to users).
    pub repo_url: String,
    /// Free-text description.
    pub description: String,
    /// Operator contact (email / handle / url).
    pub contact: String,
    /// If true, only clients whose build hash is in `allowed_client_hashes` may
    /// register or log in.
    pub reject_unofficial_clients: bool,
    /// Allow-list of official client (core) build hashes.
    pub allowed_client_hashes: Vec<String>,
}

impl ServerConfig {
    /// Load from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parsing config {}", path.display()))
    }

    /// Apply the official-client policy to a connection's announced build hash.
    pub fn client_allowed(&self, client_build_hash: Option<&str>) -> bool {
        if !self.reject_unofficial_clients {
            return true;
        }
        match client_build_hash {
            Some(h) => self.allowed_client_hashes.iter().any(|a| a == h),
            None => false,
        }
    }
}
