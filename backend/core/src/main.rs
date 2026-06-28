//! cherm.chat client core (`cherm-core`).
//!
//! This binary is the client engine spawned by the Go TUI. It owns ALL crypto,
//! networking and local history: the TUI is presentation-only (PROTOCOL.md).
//!
//! - stdin : newline-delimited JSON commands from the TUI ([`ipc::Command`]).
//! - stdout: newline-delimited JSON events to the TUI (single writer task).
//! - stderr: structured logs via `tracing`.
//!
//! Local state lives in `~/.cherm`: the identity (`identity.json`, mode 0600)
//! and the SQLite history (`cherm.db`).

mod db;
mod ipc;
mod net;
mod session;

use anyhow::{anyhow, Result};
use std::sync::Arc;
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

    // Ensure the local state directory exists: ~/.cherm
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow!("could not determine home directory"))?
        .join(".cherm");
    std::fs::create_dir_all(&home)?;

    // Open the local history database (creates + migrates schema if needed).
    let database = db::open_db(&home.join("cherm.db"))?;

    // Load the identity if it already exists; otherwise it is created on
    // `register`.
    let identity_path = home.join("identity.json");
    let identity = if identity_path.exists() {
        let json = std::fs::read_to_string(&identity_path)?;
        Some(Arc::new(cherm_crypto::Identity::from_json(&json)?))
    } else {
        None
    };

    // Spin up the single stdout writer task and the cloneable emitter.
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(ipc::writer_task(event_rx));
    let events = ipc::Events::new(event_tx);

    // Restore our username from meta (set during a previous register).
    let username = db::meta_get(&database, "username")?;

    // Announce readiness before processing any commands.
    let registered = identity.is_some() && username.is_some();
    events.emit(serde_json::json!({
        "event": "ready",
        "registered": registered,
        "username": username,
    }));

    let mut app = session::App::new(home, identity, database, events, username);
    app.run().await?;
    Ok(())
}
