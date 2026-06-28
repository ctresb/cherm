//! cherm.chat relay server (`cherm-server`).
//!
//! A relay only forwards opaque ciphertext between users; it can never read
//! message content. Anyone can run one, which is what makes the network
//! federated — clients *attest* a server's code before trusting it (see
//! ATTESTATION.md). See PROTOCOL.md sections 2 & 3 for the wire format and
//! storage schema this binary implements.
//!
//! Architecture:
//!   * A tokio multi-threaded runtime accepts TCP connections.
//!   * Shared state is three handles cloned into each connection task:
//!       - `Online`: username -> writer-channel map (presence + push routing),
//!         behind a tokio async mutex.
//!       - `Db`: a single SQLite connection behind a std mutex, locked only for
//!         brief synchronous SQL (rusqlite is not `Sync`).
//!       - `attest::Shared`: the immutable attestation signer (instance key +
//!         release key + version), serving `AttestRequest` pre-auth.
//!   * Each connection is driven by `conn::handle` (see that module).

mod attest;
mod config;
mod conn;
mod db;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::conn::{Db, Online};

/// Default advertised release version when neither `--version` nor the
/// `CHERM_VERSION` environment variable is set.
const DEFAULT_VERSION: &str = "0.1.0+dev";

/// Command-line configuration, parsed by hand (no clap dependency).
struct Config {
    addr: String,
    db: String,
    no_attest: bool,
    release_secret: Option<String>,
    instance_key: Option<String>,
    version: Option<String>,
    config: Option<String>,
}

impl Config {
    /// Parse the relay flags, falling back to defaults.
    ///
    ///   `--addr <bind>` `--db <path>` `--no-attest`
    ///   `--release-secret <b64>` `--instance-key <path>` `--version <str>`
    fn from_args() -> Self {
        let mut addr = "0.0.0.0:9000".to_string();
        let mut db = "cherm-server.db".to_string();
        let mut no_attest = false;
        let mut release_secret = None;
        let mut instance_key = None;
        let mut version = None;
        let mut config = None;
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
                "--no-attest" => no_attest = true,
                "--release-secret" => release_secret = args.next(),
                "--instance-key" => instance_key = args.next(),
                "--version" => version = args.next(),
                "--config" => config = args.next(),
                other => {
                    eprintln!("warning: ignoring unknown argument: {other}");
                }
            }
        }
        Config {
            addr,
            db,
            no_attest,
            release_secret,
            instance_key,
            version,
            config,
        }
    }

    /// Resolve the instance-key path: `--instance-key` if given, else
    /// `<db_dir>/instance.key` (or `instance.key` in the cwd if the db path has
    /// no directory component).
    fn instance_key_path(&self) -> PathBuf {
        if let Some(p) = &self.instance_key {
            return PathBuf::from(p);
        }
        match std::path::Path::new(&self.db).parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join("instance.key"),
            _ => PathBuf::from("instance.key"),
        }
    }

    /// Resolve the advertised version: `--version`, else `$CHERM_VERSION`, else
    /// [`DEFAULT_VERSION`].
    fn resolve_version(&self) -> String {
        self.version
            .clone()
            .or_else(|| std::env::var("CHERM_VERSION").ok())
            .unwrap_or_else(|| DEFAULT_VERSION.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr so stdout stays clean for any tooling.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_args();

    // Build the attestation signer (loads or generates the instance key).
    let instance_key_path = cfg.instance_key_path();
    let version = cfg.resolve_version();
    let attestor = attest::Attestor::new(
        &instance_key_path,
        cfg.release_secret.as_deref(),
        version,
        cfg.no_attest,
    )
    .context("initializing attestation")?;
    info!(
        version = %attestor.version(),
        tier = if attestor.no_attest() { "unsigned" } else { "software" },
        instance_key = %instance_key_path.display(),
        instance_pub = %attestor.instance_pub_b64(),
        "attestation ready"
    );
    let attestor: attest::Shared = Arc::new(attestor);

    // Load operator config (public metadata + official-client policy), if given.
    let server_config = match &cfg.config {
        Some(path) => config::ServerConfig::load(std::path::Path::new(path))
            .with_context(|| format!("loading config {path}"))?,
        None => config::ServerConfig::default(),
    };
    info!(
        name = %server_config.name,
        repo_url = %server_config.repo_url,
        reject_unofficial = server_config.reject_unofficial_clients,
        "server config loaded"
    );
    let server_config: config::Shared = Arc::new(server_config);

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
        let attestor = attestor.clone();
        let server_config = server_config.clone();
        tokio::spawn(async move {
            conn::handle(stream, peer, online, database, attestor, server_config).await;
        });
    }
}
