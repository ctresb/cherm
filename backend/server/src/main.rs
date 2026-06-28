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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use cherm_proto::ServerMsg;
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::conn::{Db, Online};

/// Default advertised release version when neither `--version` nor the
/// `CHERM_VERSION` environment variable is set.
const DEFAULT_VERSION: &str = "0.1.0+dev";

/// Default maintenance-warning window (seconds) clients count down before a
/// graceful update stop (install_specification §12.3).
const DEFAULT_MAINTENANCE_WARNING: u64 = 60;

/// Hard ceiling on concurrently-served connections. Each connection owns a task,
/// a writer task, and a bounded channel; this caps total resource use and the
/// number of in-flight pre-auth handshakes a flood can open. Excess connections
/// are dropped immediately (the client may retry).
const MAX_CONNECTIONS: usize = 4096;

/// Max simultaneous connections from a single source IP. Stops one host from
/// monopolising the global pool (slowloris / connection-flood) while leaving room
/// for legitimate NAT'd clients.
const MAX_CONNECTIONS_PER_IP: usize = 64;

/// Shared per-IP live-connection counter. An RAII [`IpGuard`] increments on accept
/// and decrements on drop (connection end), so the map reflects only live links.
type IpCounts = std::sync::Arc<Mutex<HashMap<std::net::IpAddr, usize>>>;

/// RAII decrementer for the per-IP counter: dropping it (when the connection task
/// ends, however it ends) releases the IP's slot.
struct IpGuard {
    counts: IpCounts,
    ip: std::net::IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.counts.lock() {
            if let Some(n) = map.get_mut(&self.ip) {
                *n -= 1;
                if *n == 0 {
                    map.remove(&self.ip);
                }
            }
        }
    }
}

/// Admit a connection from `ip` if it is under the per-IP cap, returning a guard
/// that frees the slot on drop. Returns `None` (reject) when the cap is reached.
fn admit_ip(counts: &IpCounts, ip: std::net::IpAddr) -> Option<IpGuard> {
    let mut map = counts.lock().ok()?;
    let n = map.entry(ip).or_insert(0);
    if *n >= MAX_CONNECTIONS_PER_IP {
        // Don't leave a zero-or-capped entry we just created lingering.
        if *n == 0 {
            map.remove(&ip);
        }
        return None;
    }
    *n += 1;
    Some(IpGuard {
        counts: counts.clone(),
        ip,
    })
}

/// Command-line configuration, parsed by hand (no clap dependency).
struct Config {
    addr: String,
    db: String,
    no_attest: bool,
    release_secret: Option<String>,
    release_secret_file: Option<String>,
    instance_key: Option<String>,
    version: Option<String>,
    config: Option<String>,
    maintenance_warning: u64,
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
        let mut release_secret_file = None;
        let mut instance_key = None;
        let mut version = None;
        let mut config = None;
        let mut maintenance_warning = DEFAULT_MAINTENANCE_WARNING;
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
                "--release-secret-file" => release_secret_file = args.next(),
                "--instance-key" => instance_key = args.next(),
                "--version" => version = args.next(),
                "--config" => config = args.next(),
                "--maintenance-warning" => {
                    if let Some(v) = args.next().and_then(|s| s.parse().ok()) {
                        maintenance_warning = v;
                    }
                }
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
            release_secret_file,
            instance_key,
            version,
            config,
            maintenance_warning,
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

    /// Resolve the release signing secret, preferring `--release-secret-file`
    /// (read from a `0600` path) over `--release-secret`. The latter is exposed to
    /// any local process via `/proc/<pid>/cmdline` / `ps`, so passing the
    /// higher-value release key on argv is discouraged with a loud warning.
    fn resolve_release_secret(&self) -> Result<Option<String>> {
        if let Some(path) = &self.release_secret_file {
            let s = std::fs::read_to_string(path)
                .with_context(|| format!("reading --release-secret-file {path}"))?;
            return Ok(Some(s.trim().to_string()));
        }
        if self.release_secret.is_some() {
            warn!(
                "the release secret was passed on the command line; it is readable by other \
                 local processes via /proc/<pid>/cmdline. Prefer --release-secret-file <path>."
            );
        }
        Ok(self.release_secret.clone())
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
    let release_secret = cfg.resolve_release_secret()?;
    let attestor = attest::Attestor::new(
        &instance_key_path,
        release_secret.as_deref(),
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
    // Shared, per-target gate that bounds how fast any user's one-time keys can be
    // consumed across ALL connections (anti OTK-drain DoS).
    let fetch_gate = conn::new_fetch_gate();

    let listener = TcpListener::bind(&cfg.addr)
        .await
        .with_context(|| format!("binding {}", cfg.addr))?;

    // Startup banner (install_specification §11.4): clear enough for an operator
    // to confirm the server is running correctly. Logs go to stderr.
    let tier = if attestor.no_attest() {
        "unsigned"
    } else {
        "software"
    };
    info!(
        name = %server_config.name,
        version = %attestor.version(),
        public_address = %if server_config.public_address.is_empty() { cfg.addr.clone() } else { server_config.public_address.clone() },
        listening = %cfg.addr,
        db = %cfg.db,
        client_acceptance = %if server_config.reject_unofficial_clients { "official-only" } else { "all clients" },
        offline_queue = "encrypted, 72h max, delete-on-delivery/expiry",
        maintenance_warning_s = cfg.maintenance_warning,
        repo_url = %server_config.repo_url,
        tier,
        "cherm relay listening"
    );

    // Enforce the advertised offline-queue TTL: periodically delete outbox frames
    // older than 72h so an undelivered queue (e.g. for puppet accounts that never
    // log in) cannot pin disk indefinitely.
    spawn_outbox_pruner(database.clone());

    // `draining` flips true during a maintenance window so the accept loop stops
    // admitting NEW connections while existing ones finish (install_specification
    // §12.2 "stop accepting new connections").
    let draining = Arc::new(AtomicBool::new(false));
    spawn_maintenance_signal_handler(
        online.clone(),
        draining.clone(),
        attestor.version().to_string(),
        cfg.maintenance_warning,
    );

    // Global connection ceiling + per-IP cap: bound total resource use and stop a
    // single host from monopolising the pool (slowloris / connection flood).
    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let ip_counts: IpCounts = Arc::new(Mutex::new(HashMap::new()));

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
        // During a maintenance drain, refuse new connections (close immediately)
        // so no client joins mid-update; existing clients keep their session.
        if draining.load(Ordering::SeqCst) {
            drop(stream);
            continue;
        }
        // Global ceiling: drop (don't queue) when saturated. The permit is held for
        // the connection's lifetime and released when its task ends.
        let permit = match conn_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(%peer, "connection limit reached; dropping new connection");
                drop(stream);
                continue;
            }
        };
        // Per-IP cap: one host can't exhaust the global pool. The guard frees the
        // slot when the connection task ends.
        let ip_guard = match admit_ip(&ip_counts, peer.ip()) {
            Some(g) => g,
            None => {
                warn!(%peer, "per-IP connection limit reached; dropping");
                drop(stream);
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let online = online.clone();
        let database = database.clone();
        let attestor = attestor.clone();
        let server_config = server_config.clone();
        let fetch_gate = fetch_gate.clone();
        tokio::spawn(async move {
            // Hold the global permit + per-IP guard for the whole connection; both
            // release on drop when `handle` returns (however it returns).
            let _permit = permit;
            let _ip_guard = ip_guard;
            conn::handle(stream, peer, online, database, attestor, server_config, fetch_gate).await;
        });
    }
}

/// Install a SIGUSR1 handler that runs the graceful maintenance/update stop
/// (install_specification §12): broadcast a single `Maintenance` event with a
/// deadline to every online client (so each renders a LOCAL countdown — never 60
/// chat lines), stop accepting new connections, wait the warning window so
/// clients can finish and show the countdown, then exit cleanly. The supervisor
/// (Docker `restart` / systemd / `update-server.sh`) replaces the binary and
/// brings the server back; clients reconnect automatically.
///
/// On non-unix targets this is a no-op (the signal does not exist).
fn spawn_maintenance_signal_handler(
    online: Online,
    draining: Arc<AtomicBool>,
    version: String,
    warning_secs: u64,
) {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = match signal(SignalKind::user_defined1()) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to install SIGUSR1 handler; update broadcast disabled");
                return;
            }
        };
        while sig.recv().await.is_some() {
            if draining.swap(true, Ordering::SeqCst) {
                warn!("maintenance already in progress; ignoring repeat SIGUSR1");
                continue;
            }
            let deadline = now_millis() + (warning_secs as i64) * 1000;
            let notice = ServerMsg::Maintenance {
                reason: format!("Server will stop in {warning_secs}s for update."),
                deadline_unix_ms: deadline,
                version: Some(version.clone()),
            };
            // Broadcast to every online client through its writer channel.
            let count = {
                let guard = online.lock().await;
                for tx in guard.values() {
                    // Bounded channel: best-effort, non-blocking. We must NOT await a
                    // send while holding the global online lock; a non-reading client
                    // simply misses the notice (it is disconnected by the drain anyway).
                    let _ = tx.try_send(notice.clone());
                }
                guard.len()
            };
            info!(
                clients = count,
                warning_secs, "maintenance broadcast sent; draining, will exit for update"
            );
            // Give clients the warning window to show the countdown + prepare to
            // wait, then exit so the supervisor can swap the binary and restart.
            tokio::time::sleep(std::time::Duration::from_secs(warning_secs)).await;
            info!("maintenance window elapsed; exiting for update");
            std::process::exit(0);
        }
    });
    #[cfg(not(unix))]
    {
        let _ = (online, draining, version, warning_secs);
    }
}

/// Offline-queue retention (72h, matching the operator banner) and how often the
/// pruner runs.
const OUTBOX_TTL_MS: i64 = 72 * 3600 * 1000;
const OUTBOX_PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Spawn a background task that deletes outbox frames older than [`OUTBOX_TTL_MS`]
/// on a fixed interval. The DB lock is held only for the brief DELETE.
fn spawn_outbox_pruner(db: Db) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(OUTBOX_PRUNE_INTERVAL);
        loop {
            tick.tick().await;
            let cutoff = now_millis() - OUTBOX_TTL_MS;
            let removed = {
                let conn = db.lock().unwrap();
                db::prune_expired(&conn, cutoff)
            };
            match removed {
                Ok(n) if n > 0 => info!(rows = n, "pruned expired outbox frames"),
                Ok(_) => {}
                Err(e) => error!(error = %e, "outbox prune failed"),
            }
        }
    });
}

/// Current unix time in milliseconds (mirrors `conn::now_millis`).
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
