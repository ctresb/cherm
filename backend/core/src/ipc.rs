//! IPC bridge between the Go TUI and this core (PROTOCOL.md section 4) — v2,
//! multi-server.
//!
//! - commands arrive on our **stdin** (one JSON object per line),
//! - events go out on our **stdout** (one JSON object per line),
//! - logs go to **stderr** (handled by `tracing`).
//!
//! CRITICAL: every stdout write is funneled through a single mpsc channel into
//! one writer task ([`writer_task`]). That guarantees event lines can never
//! interleave even when multiple tasks (command handlers + each server's
//! processor) emit concurrently.

use serde::Deserialize;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

/// Commands received from the TUI on stdin. The `cmd` field is the tag.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// `{"cmd":"list_servers"}`
    ListServers,
    /// `{"cmd":"check_server","server":"host:port","name":"cherm.chat"}`
    CheckServer {
        server: String,
        #[serde(default)]
        name: Option<String>,
    },
    /// `{"cmd":"connect","server":"host:port"}`
    Connect { server: String },
    /// `{"cmd":"register","server":"host:port","username":"alice"}`
    Register { server: String, username: String },
    /// `{"cmd":"switch_server","server":"host:port"}`
    SwitchServer { server: String },
    /// `{"cmd":"remove_server","server":"host:port"}` — forget a server: drop its
    /// connection, remove it from the index, and delete its local vault (after a
    /// UI confirm — this is destructive: identity + history for that server go).
    RemoveServer { server: String },
    /// `{"cmd":"list_chats"}`
    ListChats,
    /// `{"cmd":"history","chat":"bob","limit":200}`
    History {
        chat: String,
        #[serde(default)]
        limit: Option<i64>,
    },
    /// `{"cmd":"start_dm","username":"bob"}`
    StartDm { username: String },
    /// `{"cmd":"create_group","name":"devs","members":["bob","carol"]}`
    CreateGroup { name: String, members: Vec<String> },
    /// `{"cmd":"send","chat":"bob","text":"hi"}`
    Send { chat: String, text: String },
    /// `{"cmd":"leave_chat","chat":"bob"}` — leave a DM or group (after confirm).
    LeaveChat { chat: String },
    /// `{"cmd":"ping"}`
    Ping,

    // ---- plugin store / plugins (architecture_specification §6, §7) --------
    /// `{"cmd":"list_store"}` — fetch the official plugin store index.
    ListStore,
    /// `{"cmd":"list_installed"}` — list locally-installed plugins.
    ListInstalled,
    /// `{"cmd":"install_plugin","name":"pastel-theme"}`
    InstallPlugin { name: String },
    /// `{"cmd":"remove_plugin","name":"pastel-theme"}`
    RemovePlugin { name: String },
    /// `{"cmd":"check_plugin_updates"}`
    CheckPluginUpdates,
    /// `{"cmd":"submit_plugin","manifest":{...},"package":{...}}` — submit a
    /// plugin to the official store (lands as community_unaudited).
    SubmitPlugin {
        manifest: Value,
        #[serde(default)]
        package: Value,
    },

    // ---- updates (install_specification §8) --------------------------------
    /// `{"cmd":"check_client_update"}` — check cherm.chat for a newer client.
    CheckClientUpdate,

    // ---- identity backup / recovery ---------------------------------------
    /// `{"cmd":"export_identity"}` — write the active server's identity to a
    /// `0600` backup file so the username can be recovered later.
    ExportIdentity,
    /// `{"cmd":"import_identity","path":"/path/to/file.chermkey"}` — restore an
    /// identity from a backup so you can log back in as that username.
    ImportIdentity { path: String },

    /// `{"cmd":"quit"}`
    Quit,
}

/// Items handed to the single stdout writer task.
pub enum Out {
    /// A serialized event line to write.
    Line(Value),
    /// Flush everything and shut the writer down, then signal completion.
    Shutdown(oneshot::Sender<()>),
}

/// Cloneable handle used everywhere to emit events to the TUI. All clones feed
/// the same underlying channel, preserving global ordering.
#[derive(Clone)]
pub struct Events {
    tx: mpsc::UnboundedSender<Out>,
}

impl Events {
    pub fn new(tx: mpsc::UnboundedSender<Out>) -> Self {
        Events { tx }
    }

    /// Queue one event line. Best-effort: if the writer is gone we drop silently.
    pub fn emit(&self, value: Value) {
        let _ = self.tx.send(Out::Line(value));
    }

    /// Flush all queued lines, then stop the writer. Resolves once flushed.
    pub async fn shutdown(&self) {
        let (done_tx, done_rx) = oneshot::channel();
        if self.tx.send(Out::Shutdown(done_tx)).is_ok() {
            let _ = done_rx.await;
        }
    }
}

/// Build a standard `error` event value.
pub fn err_event(code: &str, message: &str) -> Value {
    serde_json::json!({"event": "error", "code": code, "message": message})
}

/// The single stdout writer task. Drains the channel in order, one JSON object
/// per line, flushing after each so the TUI sees events promptly.
pub async fn writer_task(mut rx: mpsc::UnboundedReceiver<Out>) {
    let mut out = tokio::io::stdout();
    while let Some(item) = rx.recv().await {
        match item {
            Out::Line(value) => match serde_json::to_string(&value) {
                Ok(mut line) => {
                    line.push('\n');
                    if out.write_all(line.as_bytes()).await.is_err() {
                        break;
                    }
                    let _ = out.flush().await;
                }
                Err(e) => tracing::error!("failed to serialize event: {e}"),
            },
            Out::Shutdown(done) => {
                let _ = out.flush().await;
                let _ = done.send(());
                break;
            }
        }
    }
}
