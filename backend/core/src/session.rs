//! The client engine: application state plus one handler per IPC command.
//!
//! `App` owns the shared identity, the local database handle, the event emitter
//! and (when connected) the live [`ServerLink`] + reader task. Commands arrive
//! one at a time from stdin and are dispatched sequentially in [`App::run`], so
//! there is only ever a single outstanding control request to the server — the
//! invariant the single-slot oneshot in `net` relies on.

use anyhow::{anyhow, Result};
use cherm_crypto::Identity;
use cherm_proto::{valid_username, ClientMsg, ServerMsg};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::task::JoinHandle;

use crate::db::{self, Db};
use crate::ipc::{err_event, Command, Events};
use crate::net::{self, GroupInvite, ServerLink};
use crate::now_millis;

/// Result of resolving a peer's X25519 public key.
enum Resolved {
    /// We have their base64 dh_pub.
    Found(String),
    /// The server returned an error (e.g. `unknown_user`).
    Err(String, String),
}

/// All client state.
pub struct App {
    /// `~/.cherm` directory.
    home: PathBuf,
    /// Our long-lived identity, present once registered (or generated).
    identity: Option<Arc<Identity>>,
    /// Local SQLite handle.
    db: Db,
    /// Event emitter to the TUI (single serialized writer).
    events: Events,
    /// Our username, set from `meta` once registered.
    username: Option<String>,
    /// Live server connection, when connected.
    link: Option<ServerLink>,
    /// Handle to the reader task for the live connection (so we can abort it).
    reader: Option<JoinHandle<()>>,
}

impl App {
    pub fn new(
        home: PathBuf,
        identity: Option<Arc<Identity>>,
        db: Db,
        events: Events,
        username: Option<String>,
    ) -> Self {
        App {
            home,
            identity,
            db,
            events,
            username,
            link: None,
            reader: None,
        }
    }

    /// Our username, cloned (for the `ready`/`status` events).
    pub fn username(&self) -> Option<String> {
        self.username.clone()
    }

    /// "registered" = an identity exists AND a username is stored in `meta`.
    pub fn registered(&self) -> bool {
        self.identity.is_some() && self.username.is_some()
    }

    // -- main loop ----------------------------------------------------------

    /// Read newline-delimited commands from stdin until EOF, dispatching each.
    pub async fn run(&mut self) -> Result<()> {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(line) = lines.next_line().await? {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Command>(line) {
                Ok(cmd) => {
                    if let Err(e) = self.handle(cmd).await {
                        // Unexpected internal failures surface as an error event
                        // rather than killing the engine.
                        self.events.emit(err_event("internal", &e.to_string()));
                    }
                }
                Err(e) => {
                    self.events
                        .emit(err_event("bad_request", &format!("invalid command: {e}")));
                }
            }
        }
        // stdin closed: flush and let the process exit cleanly.
        self.events.shutdown().await;
        Ok(())
    }

    async fn handle(&mut self, cmd: Command) -> Result<()> {
        // If the reader task has exited (the server dropped the connection),
        // clear the now-dead link so commands report `not_connected` and
        // `status` reflects reality instead of using a stale, broken link.
        self.prune_dead_link();
        match cmd {
            Command::Status => self.status(),
            Command::Register { username, server } => self.register(username, server).await,
            Command::Connect { server } => self.connect(server).await,
            Command::ListChats => self.emit_chats(),
            Command::StartDm { username } => self.start_dm(username).await,
            Command::CreateGroup { name, members } => self.create_group(name, members).await,
            Command::History { chat, limit } => self.emit_history(&chat, limit.unwrap_or(200)),
            Command::Send { chat, text } => self.send(chat, text).await,
            Command::Ping => self.ping().await,
            Command::Quit => self.quit().await,
        }
    }

    // -- commands -----------------------------------------------------------

    /// `status` -> emit current connection/registration state.
    fn status(&self) -> Result<()> {
        self.events.emit(json!({
            "event": "status",
            "connected": self.link.is_some(),
            "registered": self.registered(),
            "username": self.username(),
        }));
        Ok(())
    }

    /// `register` -> create identity (if needed), connect, register on the
    /// server, persist identity, and start the live session.
    async fn register(&mut self, username: String, server: String) -> Result<()> {
        if !valid_username(&username) {
            self.events.emit(err_event(
                cherm_proto::errcode::USERNAME_INVALID,
                "username must be 1-16 alphanumeric characters",
            ));
            return Ok(());
        }

        // Ensure we have an identity, generating + persisting one on first run.
        let id = match self.identity.clone() {
            Some(id) => id,
            None => {
                let id = Identity::generate();
                self.save_identity(&id)?;
                let id = Arc::new(id);
                self.identity = Some(id.clone());
                id
            }
        };

        // Replace any prior connection.
        self.teardown_link();
        let (read_half, link) = match net::open(&server).await {
            Ok(pair) => pair,
            Err(e) => {
                self.events
                    .emit(err_event("connect_failed", &e.to_string()));
                return Ok(());
            }
        };
        // Start the reader BEFORE the handshake so `send_and_wait` can be
        // fulfilled by it. (It only forwards control frames to the oneshot;
        // no Deliver can arrive until we are authenticated.)
        let handle = net::spawn_reader(
            read_half,
            net::ReaderCtx {
                identity: id.clone(),
                db: self.db.clone(),
                events: self.events.clone(),
                pending: link.pending.clone(),
                me: username.clone(),
            },
        );

        let machine_id = machine_id();
        let reply = net::send_and_wait(
            &link,
            ClientMsg::Register {
                username: username.clone(),
                ed_pub: id.ed_public_b64(),
                dh_pub: id.dh_public_b64(),
                machine_id,
            },
        )
        .await?;

        match reply {
            ServerMsg::AuthOk { uuid, username: uname } => {
                db::meta_set(&self.db, "username", &uname)?;
                db::meta_set(&self.db, "uuid", &uuid)?;
                db::meta_set(&self.db, "server", &server)?;
                // Record ourselves as a contact so group rosters resolve.
                db::upsert_contact(&self.db, &uname, &uuid, &id.ed_public_b64(), &id.dh_public_b64())?;

                self.username = Some(uname.clone());
                self.link = Some(link);
                self.reader = Some(handle);

                self.events
                    .emit(json!({"event": "registered", "username": uname, "uuid": uuid}));
                self.events
                    .emit(json!({"event": "connected", "username": uname, "uuid": uuid}));
                self.emit_chats()?;
            }
            ServerMsg::Error { code, message } => {
                handle.abort();
                self.events.emit(err_event(&code, &message));
            }
            other => {
                handle.abort();
                self.events.emit(err_event(
                    "internal",
                    &format!("unexpected register reply: {other:?}"),
                ));
            }
        }
        Ok(())
    }

    /// `connect` -> authenticate with the stored identity, then pull offline
    /// messages.
    async fn connect(&mut self, server: String) -> Result<()> {
        let id = match self.identity.clone() {
            Some(id) => id,
            None => {
                self.events
                    .emit(err_event("not_registered", "no local identity; register first"));
                return Ok(());
            }
        };
        let username = match self.username.clone() {
            Some(u) => u,
            None => {
                self.events
                    .emit(err_event("not_registered", "no username; register first"));
                return Ok(());
            }
        };

        self.teardown_link();
        let (read_half, link) = match net::open(&server).await {
            Ok(pair) => pair,
            Err(e) => {
                self.events
                    .emit(err_event("connect_failed", &e.to_string()));
                return Ok(());
            }
        };
        let handle = net::spawn_reader(
            read_half,
            net::ReaderCtx {
                identity: id.clone(),
                db: self.db.clone(),
                events: self.events.clone(),
                pending: link.pending.clone(),
                me: username.clone(),
            },
        );

        // Challenge-response: AuthBegin -> Challenge -> AuthFinish -> AuthOk.
        let challenge = net::send_and_wait(&link, ClientMsg::AuthBegin { username: username.clone() }).await?;
        let nonce = match challenge {
            ServerMsg::Challenge { nonce } => nonce,
            ServerMsg::Error { code, message } => {
                handle.abort();
                self.events.emit(err_event(&code, &message));
                return Ok(());
            }
            other => {
                handle.abort();
                self.events
                    .emit(err_event("internal", &format!("unexpected challenge reply: {other:?}")));
                return Ok(());
            }
        };

        // Sign the RAW decoded nonce bytes (PROTOCOL.md section 1). A malformed
        // nonce must not bubble up and leak the spawned reader task.
        let nonce_bytes = match cherm_crypto::b64_decode(&nonce) {
            Ok(b) => b,
            Err(e) => {
                handle.abort();
                self.events
                    .emit(err_event("internal", &format!("bad challenge nonce: {e}")));
                return Ok(());
            }
        };
        let signature = id.sign_b64(&nonce_bytes);
        let authok = net::send_and_wait(
            &link,
            ClientMsg::AuthFinish {
                username: username.clone(),
                signature,
            },
        )
        .await?;
        let (uuid, uname) = match authok {
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

        db::meta_set(&self.db, "server", &server)?;
        db::meta_set(&self.db, "uuid", &uuid)?;
        self.username = Some(uname.clone());
        self.link = Some(link.clone());
        self.reader = Some(handle);

        // Ask for anything queued while we were offline (arrives as Delivers).
        net::send(&link, ClientMsg::Pull)?;

        self.events
            .emit(json!({"event": "connected", "username": uname, "uuid": uuid}));
        self.emit_chats()?;
        Ok(())
    }

    /// `start_dm` -> resolve the peer's keys if needed and ensure a DM chat.
    async fn start_dm(&mut self, username: String) -> Result<()> {
        let me = match self.username.clone() {
            Some(u) => u,
            None => {
                self.events
                    .emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };

        // A user cannot open a chat with themselves.
        if username == me {
            self.events.emit(err_event(
                "self_dm",
                "you can't start a chat with yourself",
            ));
            return Ok(());
        }

        // Resolve keys (Lookup) only if we don't already know them.
        if db::get_contact_dh(&self.db, &username)?.is_none() {
            let link = match self.link.clone() {
                Some(l) => l,
                None => {
                    self.events
                        .emit(err_event("not_connected", "not connected to a server"));
                    return Ok(());
                }
            };
            match self.resolve_dh(&link, &username).await? {
                Resolved::Found(_) => {}
                Resolved::Err(code, message) => {
                    self.events.emit(err_event(&code, &message));
                    return Ok(());
                }
            }
        }

        db::upsert_chat(&self.db, &username, "dm", &username, None)?;
        db::add_member(&self.db, &username, &me)?;
        db::add_member(&self.db, &username, &username)?;

        self.emit_chats()?;
        self.emit_history(&username, 200)?;
        Ok(())
    }

    /// `create_group` -> mint a group key, create the local room, and seal an
    /// invite (key + roster) to each other member.
    async fn create_group(&mut self, name: String, members: Vec<String>) -> Result<()> {
        let me = match self.username.clone() {
            Some(u) => u,
            None => {
                self.events
                    .emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };
        let link = match self.link.clone() {
            Some(l) => l,
            None => {
                self.events
                    .emit(err_event("not_connected", "not connected to a server"));
                return Ok(());
            }
        };

        let key = cherm_crypto::gen_group_key();
        let key_b64 = cherm_crypto::b64_encode(&key);
        let group_id = uuid::Uuid::new_v4().to_string();

        // Resolve each (other) member's dh_pub and build the full roster.
        let mut roster = vec![me.clone()];
        let mut member_keys: Vec<(String, String)> = Vec::new();
        for member in &members {
            if member == &me {
                continue;
            }
            match self.resolve_dh(&link, member).await? {
                Resolved::Found(dh) => {
                    if !roster.contains(member) {
                        roster.push(member.clone());
                    }
                    member_keys.push((member.clone(), dh));
                }
                Resolved::Err(code, message) => {
                    self.events.emit(err_event(&code, &message));
                    return Ok(());
                }
            }
        }

        // Create the local room.
        db::upsert_chat(&self.db, &group_id, "group", &name, Some(key_b64.clone()))?;
        for member in &roster {
            db::add_member(&self.db, &group_id, member)?;
        }

        // Seal the invite to every other member individually.
        let invite = GroupInvite {
            group_id: group_id.clone(),
            name: name.clone(),
            key: key_b64,
            members: roster,
        };
        let invite_json = serde_json::to_vec(&invite)?;
        let now = now_millis();
        for (member, dh) in &member_keys {
            let payload = cherm_crypto::seal_b64(dh, &invite_json)?;
            net::send(
                &link,
                ClientMsg::Send {
                    to: vec![member.clone()],
                    msg_type: "group_invite".to_string(),
                    payload,
                    group_id: Some(group_id.clone()),
                    client_ts: now,
                },
            )?;
        }

        self.emit_chats()?;
        Ok(())
    }

    /// `send` -> encrypt for the chat, relay it, store our plaintext, and echo
    /// the outgoing message back to the TUI.
    async fn send(&mut self, chat: String, text: String) -> Result<()> {
        let me = match self.username.clone() {
            Some(u) => u,
            None => {
                self.events
                    .emit(err_event("not_registered", "register first"));
                return Ok(());
            }
        };
        let (kind, group_key) = match db::get_chat(&self.db, &chat)? {
            Some(c) => c,
            None => {
                self.events
                    .emit(err_event("no_such_chat", &format!("unknown chat {chat}")));
                return Ok(());
            }
        };
        let link = match self.link.clone() {
            Some(l) => l,
            None => {
                self.events
                    .emit(err_event("not_connected", "not connected to a server"));
                return Ok(());
            }
        };

        let now = now_millis();
        match kind.as_str() {
            "dm" => {
                // The DM chat id is the peer's username.
                let peer = chat.clone();
                let dh = match self.resolve_dh(&link, &peer).await? {
                    Resolved::Found(dh) => dh,
                    Resolved::Err(code, message) => {
                        self.events.emit(err_event(&code, &message));
                        return Ok(());
                    }
                };
                let payload = cherm_crypto::seal_b64(&dh, text.as_bytes())?;
                net::send(
                    &link,
                    ClientMsg::Send {
                        to: vec![peer],
                        msg_type: "msg".to_string(),
                        payload,
                        group_id: None,
                        client_ts: now,
                    },
                )?;
            }
            "group" => {
                let group_key =
                    group_key.ok_or_else(|| anyhow!("group chat {chat} has no key"))?;
                let key = net::group_key_from_b64(&group_key)?;
                let blob = cherm_crypto::group_encrypt(&key, text.as_bytes())?;
                let payload = cherm_crypto::b64_encode(&blob);
                // Fan out to every member except ourselves.
                let recipients: Vec<String> = db::get_members(&self.db, &chat)?
                    .into_iter()
                    .filter(|m| *m != me)
                    .collect();
                net::send(
                    &link,
                    ClientMsg::Send {
                        to: recipients,
                        msg_type: "group_msg".to_string(),
                        payload,
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

        // Persist our own plaintext and echo it locally.
        db::insert_message(&self.db, &chat, &me, &text, now, 1)?;
        self.events.emit(json!({
            "event": "message", "chat": chat, "from": me,
            "text": text, "ts": now, "outgoing": true, "color": null
        }));
        Ok(())
    }

    /// `ping` -> measure round-trip latency to the server and report it.
    async fn ping(&mut self) -> Result<()> {
        let link = match self.link.clone() {
            Some(l) => l,
            None => {
                self.events
                    .emit(err_event("not_connected", "not connected to a server"));
                return Ok(());
            }
        };
        let server = db::meta_get(&self.db, "server")?.unwrap_or_default();
        let start = std::time::Instant::now();
        let reply = net::send_and_wait(&link, ClientMsg::Ping).await?;
        let rtt = start.elapsed().as_millis() as i64;
        match reply {
            ServerMsg::Pong => {
                self.events.emit(json!({
                    "event": "pong", "rtt_ms": rtt, "server": server
                }));
            }
            other => {
                self.events.emit(err_event(
                    "internal",
                    &format!("unexpected ping reply: {other:?}"),
                ));
            }
        }
        Ok(())
    }

    /// `quit` -> flush all queued events, then exit the process.
    async fn quit(&mut self) -> Result<()> {
        self.events.shutdown().await;
        std::process::exit(0);
    }

    // -- helpers ------------------------------------------------------------

    /// Emit the current chat set so the TUI sidebar updates.
    fn emit_chats(&self) -> Result<()> {
        self.events.emit(db::build_chats_event(&self.db)?);
        Ok(())
    }

    /// Emit the last `limit` messages of a chat in chronological order.
    fn emit_history(&self, chat: &str, limit: i64) -> Result<()> {
        let rows = db::get_messages(&self.db, chat, limit)?;
        let messages: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|(sender, body, ts, outgoing)| {
                json!({"from": sender, "text": body, "ts": ts, "outgoing": outgoing != 0})
            })
            .collect();
        self.events
            .emit(json!({"event": "history", "chat": chat, "messages": messages}));
        Ok(())
    }

    /// Return a peer's base64 dh_pub, looking it up on the server (and caching
    /// the result as a contact) when we don't already have it.
    async fn resolve_dh(&self, link: &ServerLink, username: &str) -> Result<Resolved> {
        if let Some(dh) = db::get_contact_dh(&self.db, username)? {
            return Ok(Resolved::Found(dh));
        }
        let reply = net::send_and_wait(link, ClientMsg::Lookup { username: username.to_string() }).await?;
        match reply {
            ServerMsg::UserInfo { username: u, uuid, ed_pub, dh_pub } => {
                db::upsert_contact(&self.db, &u, &uuid, &ed_pub, &dh_pub)?;
                Ok(Resolved::Found(dh_pub))
            }
            ServerMsg::Error { code, message } => Ok(Resolved::Err(code, message)),
            other => Ok(Resolved::Err(
                "internal".to_string(),
                format!("unexpected lookup reply: {other:?}"),
            )),
        }
    }

    /// Drop a connection that has already died. The reader task finishes only
    /// when the socket is closed (read error) or it was aborted, so once it is
    /// finished the link is unusable: clear it so later commands don't try to
    /// send over a broken connection. The reader already emitted `disconnected`.
    fn prune_dead_link(&mut self) {
        let dead = self.reader.as_ref().map(|h| h.is_finished()).unwrap_or(false);
        if dead {
            self.teardown_link();
        }
    }

    /// Tear down the live connection: abort the reader and drop the link (which
    /// closes the writer task).
    fn teardown_link(&mut self) {
        if let Some(handle) = self.reader.take() {
            handle.abort();
        }
        self.link = None;
    }

    /// Path to the on-disk identity file.
    fn identity_path(&self) -> PathBuf {
        self.home.join("identity.json")
    }

    /// Persist an identity to `identity.json` with `0600` permissions.
    fn save_identity(&self, id: &Identity) -> Result<()> {
        let path = self.identity_path();
        std::fs::write(&path, id.to_json()?)?;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
        Ok(())
    }
}

/// Best-effort device fingerprint (the machine's hostname).
fn machine_id() -> String {
    hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}
