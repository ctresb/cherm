//! The client engine: multi-server application state plus one handler per IPC
//! command (PROTOCOL.md section 4).
//!
//! `App` owns the local master key, the event emitter, a `servers.json` index
//! and a map of per-server [`Server`]s (each holding its encrypted vault and,
//! when connected, a live [`ServerLink`] + reader). Chat commands act on the
//! **active** server. Commands arrive one at a time from stdin and are
//! dispatched sequentially in [`App::run`].

use anyhow::{anyhow, Result};
use cherm_crypto::Device;
use cherm_proto::{valid_username, ClientMsg, OneTimeKey, ServerMsg};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::task::JoinHandle;

use crate::ipc::{err_event, Command, Events};
use crate::net::{self, ServerLink};
use crate::plugins::{Manifest, Plugins};
use crate::vault::{self, Vault};
use crate::{attest_client, now_millis, update};

/// Number of one-time keys published per (re)connect.
const PREKEY_BATCH: usize = 20;

/// Advertised client version (sent in `ClientHello` for the official-client policy).
const CLIENT_VERSION: &str = "0.1.1";

// ===========================================================================
// Persisted server index (~/.cherm/servers.json)
// ===========================================================================

/// One known server: its address plus the last cached attestation verdict and
/// the username registered there (if any).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerRecord {
    pub addr: String,
    /// User-defined display label shown in the server list (so the user sees a
    /// friendly name, not `host:port`). Defaults to the host when unset.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

/// The list of known servers, persisted as `servers.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerIndex {
    #[serde(default)]
    pub servers: Vec<ServerRecord>,
}

impl ServerIndex {
    fn record_mut(&mut self, addr: &str) -> &mut ServerRecord {
        if let Some(i) = self.servers.iter().position(|s| s.addr == addr) {
            return &mut self.servers[i];
        }
        self.servers.push(ServerRecord {
            addr: addr.to_string(),
            ..Default::default()
        });
        self.servers.last_mut().expect("just pushed")
    }

    fn ensure(&mut self, addr: &str) {
        let _ = self.record_mut(addr);
    }

    fn set_attest(&mut self, addr: &str, verdict: &str, tier: &str) {
        let r = self.record_mut(addr);
        r.verdict = Some(verdict.to_string());
        r.tier = Some(tier.to_string());
    }

    fn set_username(&mut self, addr: &str, username: &str) {
        self.record_mut(addr).username = Some(username.to_string());
    }

    fn set_name(&mut self, addr: &str, name: &str) {
        if !name.is_empty() {
            self.record_mut(addr).name = Some(name.to_string());
        }
    }

    /// Ensure the official Cherm server is always present in the list (named so
    /// users connect without thinking about host:port). Idempotent; does not
    /// override an existing name a user may have set.
    pub fn seed_official(&mut self) {
        const OFFICIAL_ADDR: &str = "srv.cherm.chat:9000";
        const OFFICIAL_NAME: &str = "cherm.chat";
        let existed = self.servers.iter().any(|s| s.addr == OFFICIAL_ADDR);
        let r = self.record_mut(OFFICIAL_ADDR);
        if !existed || r.name.is_none() {
            r.name = Some(OFFICIAL_NAME.to_string());
        }
    }
}

// ===========================================================================
// Per-server runtime state
// ===========================================================================

/// One server's vault + (when connected) live link and reader task.
struct Server {
    vault: Vault,
    vault_key: [u8; 32],
    link: Option<ServerLink>,
    reader: Option<JoinHandle<()>>,
}

// ===========================================================================
// App
// ===========================================================================

pub struct App {
    home: PathBuf,
    master: [u8; 32],
    events: Events,
    index: ServerIndex,
    servers: HashMap<String, Server>,
    active: Option<String>,
    plugins: Plugins,
}

impl App {
    pub fn new(home: PathBuf, master: [u8; 32], events: Events, index: ServerIndex) -> Self {
        let plugins = Plugins::new(&home, events.clone());
        App {
            home,
            master,
            events,
            index,
            servers: HashMap::new(),
            active: None,
            plugins,
        }
    }

    // -- main loop ----------------------------------------------------------

    pub async fn run(&mut self) -> Result<()> {
        self.emit_ready();
        // Quietly attest all known servers so the list shows real verdicts
        // (green/yellow/red) instead of "unchecked", without hijacking the UI to
        // the verdict screen (that only happens on an explicit add/check).
        self.refresh_verdicts().await;

        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(line) = lines.next_line().await? {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Command>(line) {
                Ok(cmd) => {
                    self.prune_dead_links();
                    if let Err(e) = self.handle(cmd).await {
                        self.events.emit(err_event("internal", &e.to_string()));
                    }
                }
                Err(e) => {
                    self.events
                        .emit(err_event("bad_request", &format!("invalid command: {e}")));
                }
            }
        }
        self.events.shutdown().await;
        Ok(())
    }

    async fn handle(&mut self, cmd: Command) -> Result<()> {
        match cmd {
            Command::ListServers => {
                self.emit_servers();
                Ok(())
            }
            Command::CheckServer { server, name } => self.check_server(server, name).await,
            Command::Connect { server } => self.connect(server).await,
            Command::Register { server, username } => self.register(server, username).await,
            Command::SwitchServer { server } => self.switch_server(server).await,
            Command::RemoveServer { server } => self.remove_server(server),
            Command::ListChats => self.list_chats(),
            Command::History { chat, limit } => self.history(&chat, limit.unwrap_or(200)),
            Command::StartDm { username } => self.start_dm(username).await,
            Command::CreateGroup { name, members } => self.create_group(name, members).await,
            Command::Send { chat, text } => self.send(chat, text).await,
            Command::LeaveChat { chat } => self.leave_chat(chat).await,
            Command::Ping => self.ping().await,

            // ---- plugin store / plugins ------------------------------------
            Command::ListStore => self.plugins.list_store().await,
            Command::ListInstalled => self.plugins.list_installed(),
            Command::InstallPlugin { name } => self.plugins.install(&name).await,
            Command::RemovePlugin { name } => self.plugins.remove(&name),
            Command::CheckPluginUpdates => self.plugins.check_updates().await,
            Command::SubmitPlugin { manifest, package } => {
                match serde_json::from_value::<Manifest>(manifest) {
                    Ok(m) => self.plugins.submit(m, package).await,
                    Err(e) => {
                        self.events.emit(err_event(
                            "bad_submission",
                            &format!("invalid plugin manifest: {e}"),
                        ));
                        Ok(())
                    }
                }
            }

            // ---- updates ---------------------------------------------------
            Command::CheckClientUpdate => {
                update::check_client_update(CLIENT_VERSION, &self.events).await
            }

            // ---- identity backup / recovery --------------------------------
            Command::ExportIdentity => self.export_identity(),
            Command::ImportIdentity { path } => self.import_identity(path),

            Command::Quit => self.quit().await,
        }
    }

    // -- commands -----------------------------------------------------------

    /// Background attestation refresh: attest every known server (with a short
    /// timeout so an unreachable host never stalls startup) and cache the
    /// verdict/tier in the index, emitting a `servers` update so the list badges
    /// become accurate. Deliberately does NOT emit an `attest` event (which would
    /// pop the verdict screen) — this is a quiet badge refresh.
    async fn refresh_verdicts(&mut self) {
        let addrs: Vec<String> = self.index.servers.iter().map(|s| s.addr.clone()).collect();
        let mut changed = false;
        for addr in addrs {
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(6),
                attest_client::check_server(&addr),
            )
            .await;
            if let Ok(Ok(out)) = res {
                self.index.set_attest(
                    &addr,
                    attest_client::verdict_str(out.verdict),
                    attest_client::tier_str(out.tier),
                );
                changed = true;
            }
        }
        if changed {
            let _ = self.save_index();
            self.emit_servers();
        }
    }

    /// `check_server` -> attest a server pre-auth and cache its verdict.
    async fn check_server(&mut self, server: String, name: Option<String>) -> Result<()> {
        let server = normalize_addr(&server);
        self.index.ensure(&server);
        if let Some(n) = name {
            self.index.set_name(&server, n.trim());
        }
        match attest_client::check_server(&server).await {
            Ok(out) => {
                self.events.emit(json!({
                    "event": "attest",
                    "server": server,
                    "verdict": attest_client::verdict_str(out.verdict),
                    "tier": attest_client::tier_str(out.tier),
                    "reason": out.reason,
                    "build_hash": out.build_hash,
                    "fingerprint": out.fingerprint,
                    "public_codebase_url": cherm_attest::PUBLIC_CODEBASE_URL,
                    "signatures_url": cherm_attest::SIGNATURES_URL,
                    "server_name": out.server_name,
                    "repo_url": out.repo_url,
                    "description": out.description,
                }));
                self.index.set_attest(
                    &server,
                    attest_client::verdict_str(out.verdict),
                    attest_client::tier_str(out.tier),
                );
            }
            Err(e) => {
                self.events
                    .emit(err_event("check_failed", &e.to_string()));
            }
        }
        self.save_index()?;
        Ok(())
    }

    /// `register` -> create identity + vault on a server and go live.
    async fn register(&mut self, server: String, username: String) -> Result<()> {
        let server = normalize_addr(&server);
        if !valid_username(&username) {
            self.events.emit(err_event(
                cherm_proto::errcode::USERNAME_INVALID,
                "username must be 1-16 alphanumeric characters",
            ));
            return Ok(());
        }
        if cherm_proto::is_reserved_username(&username) {
            self.events.emit(err_event(
                cherm_proto::errcode::USERNAME_RESERVED,
                "that username is reserved for system use",
            ));
            return Ok(());
        }

        self.ensure_server(&server)?;
        let (vault, vk) = self.vault_of(&server);

        // Ensure a Device exists (generate + persist on first run).
        let device = match vault::load_account(&vault, &vk)? {
            Some(d) => d,
            None => {
                let d = Device::generate();
                vault::save_account(&vault, &vk, &d)?;
                d
            }
        };
        let ed = device.ed25519_b64();
        let curve = device.curve25519_b64();

        self.teardown_link(&server);
        let (read_half, link) = match net::open(&server).await {
            Ok(p) => p,
            Err(e) => {
                self.events.emit(err_event("connect_failed", &e.to_string()));
                return Ok(());
            }
        };
        // Start the reader BEFORE the handshake so `send_and_wait` can be
        // fulfilled by it (no Deliver can arrive before we are authenticated).
        let handle = net::spawn_reader(
            read_half,
            link.clone(),
            vault.clone(),
            vk,
            self.events.clone(),
            username.clone(),
            server.clone(),
        );

        // Announce our build so a server enforcing an official-client policy can
        // accept/reject us (the reply is just an Ok we consume here).
        let _ = net::send_and_wait(&link, client_hello()).await;

        let reply = net::send_and_wait(
            &link,
            ClientMsg::Register {
                username: username.clone(),
                ed25519: ed,
                curve25519: curve,
                machine_id: machine_id(),
            },
        )
        .await?;

        match reply {
            ServerMsg::AuthOk { uuid, username: uname } => {
                vault::meta_set(&vault, "username", &uname)?;
                vault::meta_set(&vault, "uuid", &uuid)?;
                vault::meta_set(&vault, "server", &server)?;
                vault::upsert_contact(
                    &vault,
                    &uname,
                    &uuid,
                    &device.ed25519_b64(),
                    &device.curve25519_b64(),
                )?;

                // Publish a fresh batch of one-time keys, then persist the
                // account (now holding the published OTK private halves).
                let mut device = device;
                let otks = device.generate_one_time_keys(PREKEY_BATCH);
                device.mark_published();
                vault::save_account(&vault, &vk, &device)?;
                let one_time_keys = to_otks(otks);

                // Auto-back-up the brand-new identity to a 0600 file so the
                // username can never be silently lost (recover with import).
                match self.backup_identity(&server, &uname, &uuid, &device) {
                    Ok(path) => self.events.emit(json!({
                        "event": "info",
                        "message": format!("identity backed up to {} (keep it safe)", path.display())
                    })),
                    Err(e) => tracing::warn!("identity backup failed: {e}"),
                }

                if let Some(s) = self.servers.get_mut(&server) {
                    s.link = Some(link.clone());
                    s.reader = Some(handle);
                }
                self.active = Some(server.clone());

                let _ = net::send_and_wait(&link, ClientMsg::PublishPrekeys { one_time_keys }).await;
                let _ = net::send(&link, ClientMsg::Pull);

                self.index.set_username(&server, &uname);
                self.save_index()?;

                self.events.emit(
                    json!({"event": "registered", "server": server, "username": uname, "uuid": uuid}),
                );
                self.events.emit(
                    json!({"event": "connected", "server": server, "username": uname, "active": true}),
                );
                self.events
                    .emit(vault::build_chats_event(&vault, &server)?);
                self.emit_servers();
            }
            ServerMsg::Error { code, message } => {
                handle.abort();
                self.events.emit(err_event(&code, &message));
            }
            other => {
                handle.abort();
                self.events
                    .emit(err_event("internal", &format!("unexpected register reply: {other:?}")));
            }
        }
        Ok(())
    }

    /// `connect` -> challenge-response auth with the stored identity, replenish
    /// prekeys, pull offline messages, and make active.
    async fn connect(&mut self, server: String) -> Result<()> {
        let server = normalize_addr(&server);
        self.ensure_server(&server)?;
        let (vault, vk) = self.vault_of(&server);

        let username = match vault::meta_get(&vault, "username")? {
            Some(u) => u,
            None => {
                self.events
                    .emit(json!({"event": "need_username", "server": server}));
                return Ok(());
            }
        };
        let device = match vault::load_account(&vault, &vk)? {
            Some(d) => d,
            None => {
                self.events
                    .emit(err_event("internal", "username present but no device in vault"));
                return Ok(());
            }
        };

        self.teardown_link(&server);
        let (read_half, link) = match net::open(&server).await {
            Ok(p) => p,
            Err(e) => {
                self.events.emit(err_event("connect_failed", &e.to_string()));
                return Ok(());
            }
        };
        let handle = net::spawn_reader(
            read_half,
            link.clone(),
            vault.clone(),
            vk,
            self.events.clone(),
            username.clone(),
            server.clone(),
        );

        // Announce our build (official-client policy) before authenticating.
        let _ = net::send_and_wait(&link, client_hello()).await;

        // AuthBegin -> Challenge -> sign(b64decode(nonce)) -> AuthFinish -> AuthOk.
        let nonce = match net::send_and_wait(&link, ClientMsg::AuthBegin { username: username.clone() }).await? {
            ServerMsg::Challenge { nonce } => nonce,
            ServerMsg::Error { code, message } => {
                handle.abort();
                self.events.emit(err_event(&code, &message));
                return Ok(());
            }
            other => {
                handle.abort();
                self.events
                    .emit(err_event("internal", &format!("unexpected challenge: {other:?}")));
                return Ok(());
            }
        };
        let nonce_bytes = match cherm_crypto::b64_decode(&nonce) {
            Ok(b) => b,
            Err(e) => {
                handle.abort();
                self.events
                    .emit(err_event("internal", &format!("bad challenge nonce: {e}")));
                return Ok(());
            }
        };
        let signature = device.sign_b64(&nonce_bytes);
        let (uuid, uname) = match net::send_and_wait(
            &link,
            ClientMsg::AuthFinish { username: username.clone(), signature },
        )
        .await?
        {
            ServerMsg::AuthOk { uuid, username } => (uuid, username),
            ServerMsg::Error { code, message } => {
                handle.abort();
                self.events.emit(err_event(&code, &message));
                return Ok(());
            }
            other => {
                handle.abort();
                self.events
                    .emit(err_event("internal", &format!("unexpected auth reply: {other:?}")));
                return Ok(());
            }
        };

        vault::meta_set(&vault, "uuid", &uuid)?;
        vault::meta_set(&vault, "server", &server)?;

        // Replenish one-time keys so peers can keep starting sessions.
        let mut device = device;
        let otks = device.generate_one_time_keys(PREKEY_BATCH);
        device.mark_published();
        vault::save_account(&vault, &vk, &device)?;
        let one_time_keys = to_otks(otks);

        if let Some(s) = self.servers.get_mut(&server) {
            s.link = Some(link.clone());
            s.reader = Some(handle);
        }
        self.active = Some(server.clone());

        let _ = net::send_and_wait(&link, ClientMsg::PublishPrekeys { one_time_keys }).await;
        let _ = net::send(&link, ClientMsg::Pull);

        self.index.set_username(&server, &uname);
        self.save_index()?;

        self.events.emit(
            json!({"event": "connected", "server": server, "username": uname, "active": true}),
        );
        self.events.emit(vault::build_chats_event(&vault, &server)?);
        self.emit_servers();
        Ok(())
    }

    /// `switch_server` -> make active and surface its chats (connecting if needed).
    async fn switch_server(&mut self, server: String) -> Result<()> {
        let server = normalize_addr(&server);
        self.ensure_server(&server)?;
        self.prune_dead_links();
        self.active = Some(server.clone());

        let has_link = self
            .servers
            .get(&server)
            .map(|s| s.link.is_some())
            .unwrap_or(false);
        let (vault, _vk) = self.vault_of(&server);

        if has_link {
            self.events.emit(vault::build_chats_event(&vault, &server)?);
            self.emit_servers();
        } else if vault::meta_get(&vault, "username")?.is_some() {
            self.connect(server).await?;
        } else {
            self.events
                .emit(json!({"event": "need_username", "server": server}));
            self.events.emit(vault::build_chats_event(&vault, &server)?);
            self.emit_servers();
        }
        Ok(())
    }

    /// `remove_server` -> forget a server entirely (after a UI confirm): drop any
    /// live link, remove it from the index, clear it if active, and delete its
    /// per-server vault directory. Destructive: the identity + history for that
    /// server are gone (the analog of leaving a chat, at server scope).
    fn remove_server(&mut self, server: String) -> Result<()> {
        let server = normalize_addr(&server);
        self.teardown_link(&server);
        self.servers.remove(&server);
        if self.active.as_deref() == Some(server.as_str()) {
            self.active = None;
        }
        self.index.servers.retain(|r| r.addr != server);
        self.save_index()?;
        // Delete the encrypted vault for this server (identity + history).
        let id = cherm_crypto::server_id(&server);
        let dir = self.home.join("servers").join(&id);
        let _ = std::fs::remove_dir_all(&dir);
        self.events
            .emit(json!({"event": "info", "message": format!("removed server {server}")}));
        self.emit_servers();
        Ok(())
    }

    /// Write the identity for a `(server, username)` to a `0600` backup file so
    /// the username can be recovered later (the file holds the PRIVATE key).
    fn backup_identity(
        &self,
        server: &str,
        username: &str,
        uuid: &str,
        device: &Device,
    ) -> Result<std::path::PathBuf> {
        let id = cherm_crypto::server_id(server);
        let path = self
            .home
            .join("identity-backups")
            .join(format!("{id}_{username}.chermkey"));
        let blob = json!({
            "cherm_identity": 1,
            "server": server,
            "username": username,
            "uuid": uuid,
            "ed25519": device.ed25519_b64(),
            "account": device.export_pickle_json()?,
        });
        // The backup holds the PRIVATE key — write it atomically owner-only (the
        // helper creates identity-backups/ 0700 and the file 0600, failing loudly
        // if that cannot be enforced).
        cherm_crypto::write_secret_file(&path, &serde_json::to_vec_pretty(&blob)?)?;
        Ok(path)
    }

    /// `export_identity` -> back up the active server's identity to a file and
    /// tell the user where it is.
    fn export_identity(&mut self) -> Result<()> {
        let (server, vault, vk) = match self.active_vault() {
            Some(x) => x,
            None => {
                self.events.emit(err_event("not_connected", "no active server"));
                return Ok(());
            }
        };
        let username = match vault::meta_get(&vault, "username")? {
            Some(u) => u,
            None => {
                self.events.emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };
        let uuid = vault::meta_get(&vault, "uuid")?.unwrap_or_default();
        let device = match vault::load_account(&vault, &vk)? {
            Some(d) => d,
            None => {
                self.events.emit(err_event("internal", "no identity in vault"));
                return Ok(());
            }
        };
        match self.backup_identity(&server, &username, &uuid, &device) {
            Ok(path) => self.events.emit(json!({
                "event": "info",
                "message": format!("identity '{username}' exported to {} — keep it safe; it is your private key", path.display())
            })),
            Err(e) => self.events.emit(err_event("export_failed", &e.to_string())),
        }
        Ok(())
    }

    /// `import_identity` -> restore an identity from a backup file so the user can
    /// log back in as that username (then they `connect` to authenticate).
    fn import_identity(&mut self, path: String) -> Result<()> {
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) => {
                self.events
                    .emit(err_event("import_failed", &format!("cannot read {path}: {e}")));
                return Ok(());
            }
        };
        let v: Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.events
                    .emit(err_event("import_failed", &format!("invalid identity file: {e}")));
                return Ok(());
            }
        };
        let server = normalize_addr(v["server"].as_str().unwrap_or(""));
        let username = v["username"].as_str().unwrap_or("").to_string();
        let account = v["account"].as_str().unwrap_or("");
        if server.is_empty() || username.is_empty() || account.is_empty() {
            self.events
                .emit(err_event("import_failed", "incomplete identity file"));
            return Ok(());
        }
        let device = match Device::from_pickle_json(account) {
            Ok(d) => d,
            Err(e) => {
                self.events
                    .emit(err_event("import_failed", &format!("bad identity key: {e}")));
                return Ok(());
            }
        };
        self.ensure_server(&server)?;
        let (vault, vk) = self.vault_of(&server);
        vault::save_account(&vault, &vk, &device)?;
        vault::meta_set(&vault, "username", &username)?;
        vault::meta_set(&vault, "server", &server)?;
        let uuid = v["uuid"].as_str().unwrap_or("");
        if !uuid.is_empty() {
            vault::meta_set(&vault, "uuid", uuid)?;
        }
        vault::upsert_contact(
            &vault,
            &username,
            uuid,
            &device.ed25519_b64(),
            &device.curve25519_b64(),
        )?;
        self.index.set_username(&server, &username);
        self.save_index()?;
        self.events.emit(json!({
            "event": "info",
            "message": format!("identity '{username}' imported on {server} — select it and Connect to log in")
        }));
        self.emit_servers();
        Ok(())
    }

    /// `start_dm` -> ensure an Olm session to the peer and a DM chat.
    async fn start_dm(&mut self, username: String) -> Result<()> {
        let (server, vault, vk) = match self.active_vault() {
            Some(x) => x,
            None => {
                self.events.emit(err_event("not_connected", "no active server"));
                return Ok(());
            }
        };
        let me = match vault::meta_get(&vault, "username")? {
            Some(m) => m,
            None => {
                self.events.emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };
        if username == me {
            self.events
                .emit(err_event("self_dm", "you can't start a chat with yourself"));
            return Ok(());
        }
        let link = match self.active_link() {
            Some(l) => l,
            None => {
                self.events.emit(err_event("not_connected", "not connected"));
                return Ok(());
            }
        };

        // Establish an outbound Olm session if we don't already have one.
        if vault::load_olm(&vault, &vk, &username)?.is_none() {
            match net::send_and_wait(&link, ClientMsg::FetchPrekeys { username: username.clone() })
                .await?
            {
                ServerMsg::PrekeyBundle {
                    username: u,
                    uuid,
                    ed25519,
                    curve25519,
                    one_time_key,
                    ..
                } => {
                    let otk = match one_time_key {
                        Some(k) => k,
                        None => {
                            self.events.emit(err_event(
                                cherm_proto::errcode::NO_PREKEYS,
                                &format!("{u} has no one-time keys available"),
                            ));
                            return Ok(());
                        }
                    };
                    let device = vault::load_account(&vault, &vk)?
                        .ok_or_else(|| anyhow!("no device identity"))?;
                    let session = device.start_session(&curve25519, &otk)?;
                    vault::save_olm(&vault, &vk, &username, &session)?;
                    vault::upsert_contact(&vault, &u, &uuid, &ed25519, &curve25519)?;
                }
                ServerMsg::Error { code, message } => {
                    self.events.emit(err_event(&code, &message));
                    return Ok(());
                }
                other => {
                    self.events
                        .emit(err_event("internal", &format!("unexpected prekey reply: {other:?}")));
                    return Ok(());
                }
            }
        }

        vault::upsert_chat(&vault, &username, "dm", &username)?;
        vault::add_member(&vault, &username, &me)?;
        vault::add_member(&vault, &username, &username)?;

        if let Some(ed) = vault::get_contact_ed(&vault, &username)? {
            self.events.emit(json!({
                "event": "fingerprint", "username": username,
                "fingerprint": cherm_crypto::fingerprint_of(&ed)
            }));
        }
        self.events.emit(vault::build_chats_event(&vault, &server)?);
        self.emit_history(&vault, &username, 200)?;
        // Auto-open the new DM so the user lands in the conversation directly.
        self.events
            .emit(json!({"event": "open_chat", "chat": username}));
        Ok(())
    }

    /// `create_group` -> mint a Megolm session, create the room, and share the
    /// session key to each member over their pairwise Olm channel.
    async fn create_group(&mut self, name: String, members: Vec<String>) -> Result<()> {
        let (server, vault, vk) = match self.active_vault() {
            Some(x) => x,
            None => {
                self.events.emit(err_event("not_connected", "no active server"));
                return Ok(());
            }
        };
        let me = match vault::meta_get(&vault, "username")? {
            Some(m) => m,
            None => {
                self.events.emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };
        let link = match self.active_link() {
            Some(l) => l,
            None => {
                self.events.emit(err_event("not_connected", "not connected"));
                return Ok(());
            }
        };

        let sender = cherm_crypto::GroupSender::new();
        let group_id = uuid::Uuid::new_v4().to_string();
        vault::save_group_out(&vault, &vk, &group_id, &sender)?;

        // Roster = {self} + members (deduped).
        let mut roster = vec![me.clone()];
        for m in &members {
            if m != &me && !roster.contains(m) {
                roster.push(m.clone());
            }
        }
        vault::upsert_chat(&vault, &group_id, "group", &name)?;
        for m in &roster {
            vault::add_member(&vault, &group_id, m)?;
        }

        self.distribute_group_key(&vault, &vk, &link, &me, &group_id, &name, &roster, &sender)
            .await?;

        self.events.emit(vault::build_chats_event(&vault, &server)?);
        // Auto-open the new group so the creator lands in it directly.
        self.events
            .emit(json!({"event": "open_chat", "chat": group_id}));
        Ok(())
    }

    /// Share a Megolm outbound session key with every other member over their
    /// pairwise Olm session. Megolm is per-sender, so each member that wants to
    /// speak in a group mints its own [`GroupSender`] and distributes it here
    /// (called by `create_group` and lazily by `send` for non-creators).
    #[allow(clippy::too_many_arguments)]
    async fn distribute_group_key(
        &self,
        vault: &Vault,
        vk: &[u8; 32],
        link: &ServerLink,
        me: &str,
        group_id: &str,
        name: &str,
        roster: &[String],
        sender: &cherm_crypto::GroupSender,
    ) -> Result<()> {
        let device = vault::load_account(vault, vk)?
            .ok_or_else(|| anyhow!("no device identity"))?;
        let sender_curve = device.curve25519_b64();
        let session_key = sender.session_key_b64();
        let now = now_millis();

        for member in roster {
            if member == me {
                continue;
            }
            // Ensure an Olm session to this member.
            let mut session = match vault::load_olm(vault, vk, member)? {
                Some(s) => s,
                None => match net::send_and_wait(
                    link,
                    ClientMsg::FetchPrekeys { username: member.clone() },
                )
                .await?
                {
                    ServerMsg::PrekeyBundle {
                        username: u,
                        uuid,
                        ed25519,
                        curve25519,
                        one_time_key: Some(otk),
                        ..
                    } => {
                        vault::upsert_contact(vault, &u, &uuid, &ed25519, &curve25519)?;
                        device.start_session(&curve25519, &otk)?
                    }
                    ServerMsg::PrekeyBundle { .. } => {
                        self.events.emit(err_event(
                            cherm_proto::errcode::NO_PREKEYS,
                            &format!("{member} has no one-time keys; skipped"),
                        ));
                        continue;
                    }
                    ServerMsg::Error { code, message } => {
                        self.events.emit(err_event(&code, &message));
                        continue;
                    }
                    other => {
                        self.events.emit(err_event(
                            "internal",
                            &format!("unexpected prekey reply: {other:?}"),
                        ));
                        continue;
                    }
                },
            };

            let share = json!({
                "group_id": group_id,
                "name": name,
                "session_key": session_key.clone(),
                "sender_curve": sender_curve.clone(),
                "members": roster,
            });
            let plaintext = serde_json::to_vec(&share)?;
            let (t, body) = session.encrypt(&plaintext)?;
            vault::save_olm(vault, vk, member, &session)?;

            net::send(
                link,
                ClientMsg::Send {
                    to: vec![member.clone()],
                    msg_type: "olm_group_key".to_string(),
                    payload: net::encode_olm(t, &body),
                    group_id: Some(group_id.to_string()),
                    client_ts: now,
                },
            )?;
        }
        Ok(())
    }

    /// `send` -> encrypt for the chat, relay it, store our plaintext, and echo.
    async fn send(&mut self, chat: String, text: String) -> Result<()> {
        let (_server, vault, vk) = match self.active_vault() {
            Some(x) => x,
            None => {
                self.events.emit(err_event("not_connected", "no active server"));
                return Ok(());
            }
        };
        let me = match vault::meta_get(&vault, "username")? {
            Some(m) => m,
            None => {
                self.events.emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };
        let (kind, title) = match vault::get_chat(&vault, &chat)? {
            Some(c) => c,
            None => {
                self.events
                    .emit(err_event("no_such_chat", &format!("unknown chat {chat}")));
                return Ok(());
            }
        };
        let link = match self.active_link() {
            Some(l) => l,
            None => {
                self.events.emit(err_event("not_connected", "not connected"));
                return Ok(());
            }
        };

        let now = now_millis();
        match kind.as_str() {
            "dm" => {
                let peer = chat.clone();
                let mut session = match vault::load_olm(&vault, &vk, &peer)? {
                    Some(s) => s,
                    None => {
                        self.events
                            .emit(err_event("no_session", "no Olm session; start_dm first"));
                        return Ok(());
                    }
                };
                let (t, body) = session.encrypt(text.as_bytes())?;
                vault::save_olm(&vault, &vk, &peer, &session)?;
                net::send(
                    &link,
                    ClientMsg::Send {
                        to: vec![peer],
                        msg_type: "olm".to_string(),
                        payload: net::encode_olm(t, &body),
                        group_id: None,
                        client_ts: now,
                    },
                )?;
            }
            "group" => {
                let mut sender = match vault::load_group_out(&vault, &vk, &chat)? {
                    Some(s) => s,
                    None => {
                        // Megolm is per-sender: lazily mint our own outbound
                        // session and share it with the group before sending.
                        let roster = vault::get_members(&vault, &chat)?;
                        let s = cherm_crypto::GroupSender::new();
                        vault::save_group_out(&vault, &vk, &chat, &s)?;
                        self.distribute_group_key(&vault, &vk, &link, &me, &chat, &title, &roster, &s)
                            .await?;
                        s
                    }
                };
                let bytes = sender.encrypt(text.as_bytes());
                vault::save_group_out(&vault, &vk, &chat, &sender)?;
                let recipients: Vec<String> = vault::get_members(&vault, &chat)?
                    .into_iter()
                    .filter(|m| *m != me)
                    .collect();
                net::send(
                    &link,
                    ClientMsg::Send {
                        to: recipients,
                        msg_type: "megolm".to_string(),
                        payload: cherm_crypto::b64_encode(&bytes),
                        group_id: Some(chat.clone()),
                        client_ts: now,
                    },
                )?;
            }
            other => {
                self.events
                    .emit(err_event("bad_request", &format!("unknown chat kind {other}")));
                return Ok(());
            }
        }

        vault::insert_message(&vault, &chat, &me, &text, now, 1)?;
        self.events.emit(json!({
            "event": "message", "chat": chat, "from": me,
            "text": text, "ts": now, "outgoing": true, "color": null
        }));
        Ok(())
    }

    /// `leave_chat` -> leave a DM or group: notify the other side with a system
    /// message, then delete the chat (and its sessions) from the local vault.
    async fn leave_chat(&mut self, chat: String) -> Result<()> {
        let (server, vault, vk) = match self.active_vault() {
            Some(x) => x,
            None => {
                self.events.emit(err_event("not_connected", "no active server"));
                return Ok(());
            }
        };
        let me = match vault::meta_get(&vault, "username")? {
            Some(m) => m,
            None => {
                self.events.emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };
        let (kind, title) = match vault::get_chat(&vault, &chat)? {
            Some(c) => c,
            None => {
                self.events
                    .emit(err_event("no_such_chat", &format!("unknown chat {chat}")));
                return Ok(());
            }
        };
        let link = self.active_link();
        let now = now_millis();

        match kind.as_str() {
            "dm" => {
                // Notify the peer (best-effort) over the existing Olm session.
                if let Some(link) = &link {
                    if let Some(mut session) = vault::load_olm(&vault, &vk, &chat)? {
                        let (t, body) = session.encrypt(b"left")?;
                        vault::save_olm(&vault, &vk, &chat, &session)?;
                        let _ = net::send(
                            link,
                            ClientMsg::Send {
                                to: vec![chat.clone()],
                                msg_type: "olm_system".to_string(),
                                payload: net::encode_olm(t, &body),
                                group_id: None,
                                client_ts: now,
                            },
                        );
                    }
                }
            }
            "group" => {
                if let Some(link) = &link {
                    let members = vault::get_members(&vault, &chat)?;
                    // Need an outbound Megolm session to broadcast the notice;
                    // mint + distribute one if we never spoke in this group.
                    let mut sender = match vault::load_group_out(&vault, &vk, &chat)? {
                        Some(s) => s,
                        None => {
                            let s = cherm_crypto::GroupSender::new();
                            vault::save_group_out(&vault, &vk, &chat, &s)?;
                            self.distribute_group_key(&vault, &vk, link, &me, &chat, &title, &members, &s)
                                .await?;
                            s
                        }
                    };
                    let bytes = sender.encrypt(b"left");
                    vault::save_group_out(&vault, &vk, &chat, &sender)?;
                    let recipients: Vec<String> =
                        members.into_iter().filter(|m| *m != me).collect();
                    let _ = net::send(
                        link,
                        ClientMsg::Send {
                            to: recipients,
                            msg_type: "megolm_system".to_string(),
                            payload: cherm_crypto::b64_encode(&bytes),
                            group_id: Some(chat.clone()),
                            client_ts: now,
                        },
                    );
                }
            }
            other => {
                self.events
                    .emit(err_event("bad_request", &format!("unknown chat kind {other}")));
                return Ok(());
            }
        }

        // Remove the chat and all its local state.
        vault::delete_chat(&vault, &chat)?;
        let notified = if link.is_some() { "" } else { " (offline — peers not notified)" };
        self.events.emit(vault::build_chats_event(&vault, &server)?);
        self.events
            .emit(json!({"event": "info", "message": format!("left {chat}{notified}")}));
        Ok(())
    }

    /// `ping` -> measure round-trip latency to the active server.
    async fn ping(&mut self) -> Result<()> {
        let server = match self.active.clone() {
            Some(s) => s,
            None => {
                self.events.emit(err_event("not_connected", "no active server"));
                return Ok(());
            }
        };
        let link = match self.active_link() {
            Some(l) => l,
            None => {
                self.events.emit(err_event("not_connected", "not connected"));
                return Ok(());
            }
        };
        let start = std::time::Instant::now();
        let reply = net::send_and_wait(&link, ClientMsg::Ping).await?;
        let rtt = start.elapsed().as_millis() as i64;
        match reply {
            ServerMsg::Pong => {
                self.events
                    .emit(json!({"event": "pong", "rtt_ms": rtt, "server": server}));
            }
            other => {
                self.events
                    .emit(err_event("internal", &format!("unexpected ping reply: {other:?}")));
            }
        }
        Ok(())
    }

    /// `list_chats` -> emit the active server's chat set.
    fn list_chats(&self) -> Result<()> {
        match self.active_vault() {
            Some((server, vault, _)) => {
                self.events.emit(vault::build_chats_event(&vault, &server)?);
            }
            None => self.events.emit(err_event("not_connected", "no active server")),
        }
        Ok(())
    }

    /// `history` -> emit a chat's recent messages from the active vault.
    fn history(&self, chat: &str, limit: i64) -> Result<()> {
        match self.active_vault() {
            Some((_server, vault, _)) => self.emit_history(&vault, chat, limit),
            None => {
                self.events.emit(err_event("not_connected", "no active server"));
                Ok(())
            }
        }
    }

    /// `quit` -> flush queued events, then exit.
    async fn quit(&mut self) -> Result<()> {
        self.events.shutdown().await;
        std::process::exit(0);
    }

    // -- helpers ------------------------------------------------------------

    /// Emit the initial `ready` event (the server list + master-key presence),
    /// then surface any active theme/widgets so the TUI applies them immediately.
    fn emit_ready(&self) {
        self.events.emit(json!({
            "event": "ready",
            "servers": self.servers_value(),
            "has_master": true,
            "client_version": CLIENT_VERSION,
        }));
        self.plugins.emit_active();
    }

    /// Emit the `servers` event.
    fn emit_servers(&self) {
        self.events
            .emit(json!({"event": "servers", "servers": self.servers_value()}));
    }

    /// Build the per-server descriptors for `ready`/`servers`.
    fn servers_value(&self) -> Vec<Value> {
        self.index
            .servers
            .iter()
            .map(|r| {
                json!({
                    "id": cherm_crypto::server_id(&r.addr),
                    "addr": r.addr,
                    "name": r.name.clone().unwrap_or_else(|| host_of(&r.addr)),
                    "tier": r.tier.clone(),
                    "verdict": r.verdict.clone(),
                    "username": r.username.clone(),
                    "active": self.active.as_deref() == Some(r.addr.as_str()),
                })
            })
            .collect()
    }

    fn emit_history(&self, vault: &Vault, chat: &str, limit: i64) -> Result<()> {
        let messages: Vec<Value> = vault::get_messages(vault, chat, limit)?
            .into_iter()
            .map(|(sender, body, ts, outgoing)| {
                json!({"from": sender, "text": body, "ts": ts, "outgoing": outgoing != 0, "system": sender == "System"})
            })
            .collect();
        self.events
            .emit(json!({"event": "history", "chat": chat, "messages": messages}));
        Ok(())
    }

    /// Ensure a [`Server`] (vault opened, dir created, index recorded) exists.
    fn ensure_server(&mut self, addr: &str) -> Result<()> {
        if !self.servers.contains_key(addr) {
            let id = cherm_crypto::server_id(addr);
            let vault_key = cherm_crypto::derive_vault_key(&self.master, &id);
            let dir = self.home.join("servers").join(&id);
            std::fs::create_dir_all(&dir)?;
            let conn = vault::open_vault(&dir.join("vault.db"), &vault_key)?;
            self.servers.insert(
                addr.to_string(),
                Server {
                    vault: std::sync::Arc::new(std::sync::Mutex::new(conn)),
                    vault_key,
                    link: None,
                    reader: None,
                },
            );
            self.index.ensure(addr);
            self.save_index()?;
        }
        Ok(())
    }

    /// Cloned `(vault, vault_key)` for a server that has been `ensure_server`d.
    fn vault_of(&self, addr: &str) -> (Vault, [u8; 32]) {
        let s = self.servers.get(addr).expect("server must be ensured");
        (s.vault.clone(), s.vault_key)
    }

    /// `(active_addr, vault, vault_key)` for the active server, if any.
    fn active_vault(&self) -> Option<(String, Vault, [u8; 32])> {
        let addr = self.active.clone()?;
        let s = self.servers.get(&addr)?;
        Some((addr, s.vault.clone(), s.vault_key))
    }

    /// A clone of the active server's live link, if connected.
    fn active_link(&self) -> Option<ServerLink> {
        let addr = self.active.as_ref()?;
        self.servers.get(addr)?.link.clone()
    }

    /// Drop any connection whose reader task has finished (server disconnected).
    fn prune_dead_links(&mut self) {
        for s in self.servers.values_mut() {
            let dead = s.reader.as_ref().map(|h| h.is_finished()).unwrap_or(false);
            if dead {
                s.reader = None;
                s.link = None;
            }
        }
    }

    /// Tear down a server's live connection (abort the reader, drop the link).
    fn teardown_link(&mut self, addr: &str) {
        if let Some(s) = self.servers.get_mut(addr) {
            if let Some(h) = s.reader.take() {
                h.abort();
            }
            s.link = None;
        }
    }

    /// Persist the server index to `~/.cherm/servers.json`.
    fn save_index(&self) -> Result<()> {
        let path = self.home.join("servers.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&self.index)?)?;
        Ok(())
    }
}

/// Build a `ClientHello` announcing this client's build hash + version, so a
/// server enforcing an official-client policy can accept or reject us.
fn client_hello() -> ClientMsg {
    ClientMsg::ClientHello {
        build_hash: cherm_attest::build_hash(),
        client_version: CLIENT_VERSION.to_string(),
    }
}

/// Map vodozemac one-time keys into the wire `OneTimeKey` shape.
fn to_otks(otks: Vec<(String, String)>) -> Vec<OneTimeKey> {
    otks.into_iter()
        .map(|(key_id, curve25519)| OneTimeKey { key_id, curve25519 })
        .collect()
}

/// The host portion of a `host:port` (everything before the last `:`), used as
/// a fallback display name when no user-defined name is set.
fn host_of(addr: &str) -> String {
    match addr.rsplit_once(':') {
        Some((host, _)) if !host.is_empty() => host.to_string(),
        _ => addr.to_string(),
    }
}

/// Normalize a user-typed server address into a connectable `host:port`.
///
/// The Cherm transport is raw TCP, not HTTP, so a pasted URL like
/// `https://srv.cherm.chat` (or a bare `srv.cherm.chat` with no port) must become
/// `srv.cherm.chat:9000`. This strips any scheme + path and appends the default
/// port 9000 when none is present, so `TcpStream::connect` always gets a valid
/// `host:port`. Idempotent. IPv6 literals (already containing `:`) are left as-is.
pub fn normalize_addr(s: &str) -> String {
    let mut s = s.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s = &s[..i];
    }
    let s = s.trim();
    if !s.is_empty() && !s.contains(':') {
        format!("{s}:9000")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_addr;

    #[test]
    fn normalizes_user_input() {
        assert_eq!(normalize_addr("srv.cherm.chat"), "srv.cherm.chat:9000");
        assert_eq!(normalize_addr("https://srv.cherm.chat"), "srv.cherm.chat:9000");
        assert_eq!(normalize_addr("http://srv.cherm.chat/"), "srv.cherm.chat:9000");
        assert_eq!(normalize_addr("https://srv.cherm.chat:9000"), "srv.cherm.chat:9000");
        assert_eq!(normalize_addr("srv.cherm.chat:9000"), "srv.cherm.chat:9000");
        assert_eq!(normalize_addr(" 127.0.0.1:4000 "), "127.0.0.1:4000");
        assert_eq!(normalize_addr("srv.cherm.chat:9000/path?x"), "srv.cherm.chat:9000");
        // idempotent
        assert_eq!(normalize_addr(&normalize_addr("https://srv.cherm.chat")), "srv.cherm.chat:9000");
    }
}

/// Best-effort device fingerprint (the machine's hostname).
fn machine_id() -> String {
    hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}
