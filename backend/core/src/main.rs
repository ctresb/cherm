//! cherm.chat client core (`cherm-core`) — v2, multi-server.
//!
//! This binary is the client engine spawned by the Go TUI. It owns ALL crypto,
//! networking, attestation and local history; the TUI is presentation-only
//! (PROTOCOL.md). It manages MANY servers — each with its own attested trust
//! verdict and its own encrypted vault — and routes chat commands to the active
//! server.
//!
//! - stdin : newline-delimited JSON commands from the TUI ([`ipc::Command`]).
//! - stdout: newline-delimited JSON events to the TUI (single writer task).
//! - stderr: structured logs via `tracing`.
//!
//! Global state lives in `~/.cherm`: the master key (`master.key`, mode 0600),
//! the server index (`servers.json`), and one encrypted vault per server under
//! `servers/<server_id>/vault.db`.

mod attest_client;
mod ipc;
mod net;
mod session;
mod vault;

use anyhow::{anyhow, Result};
use std::os::unix::fs::PermissionsExt;
use tracing_subscriber::EnvFilter;

/// Current unix time in milliseconds (the protocol's timestamp unit).
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr so they never pollute the stdout event stream.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_ansi(false)
        .init();

    // ~/.cherm
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow!("could not determine home directory"))?
        .join(".cherm");
    std::fs::create_dir_all(&home)?;

    // Master key (~/.cherm/master.key, 32 bytes, mode 0600).
    let master = load_or_create_master(&home.join("master.key"))?;

    // Server index (~/.cherm/servers.json).
    let index_path = home.join("servers.json");
    let index: session::ServerIndex = if index_path.exists() {
        match std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(i) => i,
            None => session::ServerIndex::default(),
        }
    } else {
        session::ServerIndex::default()
    };

    // Single stdout writer task + the cloneable emitter.
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(ipc::writer_task(event_rx));
    let events = ipc::Events::new(event_tx);

    let mut app = session::App::new(home, master, events, index);
    app.run().await?;
    Ok(())
}

/// Load the 32-byte master key, or generate + persist it (mode 0600) if absent.
fn load_or_create_master(path: &std::path::Path) -> Result<[u8; 32]> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        bytes
            .try_into()
            .map_err(|_| anyhow!("master.key has an unexpected size (expected 32 bytes)"))
    } else {
        let key = cherm_crypto::gen_master_key();
        std::fs::write(path, key)?;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
        Ok(key)
    }
}
