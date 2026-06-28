//! cherm.chat relay server (`cherm-server`).
//!
//! A relay only forwards opaque ciphertext between users; it can never read
//! message content (requirements 11 & 12). Anyone can run one, which is what
//! makes the network federated (requirement 13). See PROTOCOL.md sections 2 & 3
//! for the wire format and storage schema this binary implements.
//!
//! Architecture:
//!   * A tokio multi-threaded runtime accepts TCP connections.
//!   * Shared state is two handles cloned into each connection task:
//!       - `Online`: username -> writer-channel map (presence + push routing),
//!         behind a tokio async mutex.
//!       - `Db`: a single SQLite connection behind a std mutex, locked only for
//!         brief synchronous SQL (rusqlite is not `Sync`).
//!   * Each connection is driven by `conn::handle` (see that module).

mod conn;
mod db;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::conn::{Db, Online};

/// Command-line configuration, parsed by hand (no clap dependency).
struct Config {
    addr: String,
    db: String,
}

impl Config {
    /// Parse `--addr <bind>` and `--db <path>`, falling back to defaults.
    fn from_args() -> Self {
        let mut addr = "0.0.0.0:9000".to_string();
        let mut db = "cherm-server.db".to_string();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--addr" => {
                    if let Some(v) = args.next() {
                        addr = v;
                    }
                }
                "--db" => {
                    if let Some(v) = args.next() {
                        db = v;
                    }
                }
                other => {
                    eprintln!("warning: ignoring unknown argument: {other}");
                }
            }
        }
        Config { addr, db }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr so stdout stays clean for any tooling.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = Config::from_args();

    // Open the database and build the shared state handles.
    let conn = db::open(&cfg.db).with_context(|| format!("opening database {}", cfg.db))?;
    let database: Db = Arc::new(Mutex::new(conn));
    let online: Online = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let listener = TcpListener::bind(&cfg.addr)
        .await
        .with_context(|| format!("binding {}", cfg.addr))?;
    info!(addr = %cfg.addr, db = %cfg.db, "cherm relay listening");

    // Accept loop: a single misbehaving connection must never take down the
    // server, so per-connection work runs in its own task and accept errors are
    // logged and skipped rather than propagated.
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let online = online.clone();
        let database = database.clone();
        tokio::spawn(async move {
            conn::handle(stream, peer, online, database).await;
        });
    }
}
