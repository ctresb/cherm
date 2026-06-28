//! Server connection: framing, the writer/reader tasks, and the
//! single-outstanding control-response channel.
//!
//! Wire protocol (PROTOCOL.md section 2) is length-prefixed JSON via
//! `cherm_proto::{read_msg, write_msg}`. We split a `TcpStream` into halves:
//!
//! - The **write half** is owned by a dedicated task fed by an
//!   `mpsc<ClientMsg>` ([`ServerLink::tx`]). Anyone can send by cloning the
//!   sender.
//! - The **read half** is owned by the reader task ([`spawn_reader`]). It reads
//!   `ServerMsg` frames forever. `Deliver` frames are end-to-end-encrypted
//!   payloads addressed to us, so they go to [`process_incoming`]. Everything
//!   else (`Challenge`, `AuthOk`, `UserInfo`, `Ok`, `Error`, `Pong`) is a
//!   control response and fulfills the single pending oneshot.
//!
//! Because the TUI feeds us commands sequentially, there is at most ONE
//! in-flight control request at a time, so a single shared
//! `Option<oneshot::Sender<ServerMsg>>` slot is sufficient.

use anyhow::{anyhow, Result};
use cherm_crypto::Identity;
use cherm_proto::{read_msg, write_msg, ClientMsg, ServerMsg};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::db::{self, Db};
use crate::ipc::Events;

/// The slot holding the single outstanding control-response sender.
pub type Pending = Arc<AsyncMutex<Option<oneshot::Sender<ServerMsg>>>>;

/// Handle to a live server connection. Cheaply cloneable (a channel sender and
/// an `Arc`), so command handlers can grab a copy without borrowing `App`.
#[derive(Clone)]
pub struct ServerLink {
    /// Send a `ClientMsg` to the server (consumed by the writer task).
    pub tx: mpsc::UnboundedSender<ClientMsg>,
    /// The single-outstanding control-response slot.
    pub pending: Pending,
}

/// The on-the-wire JSON wrapped inside a sealed `group_invite` payload. It
/// carries the group key and roster so the recipient can join the room.
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupInvite {
    pub group_id: String,
    pub name: String,
    /// base64 of the 32-byte group key.
    pub key: String,
    /// Full member roster (including the creator).
    pub members: Vec<String>,
}

/// Connect to `addr`, split the stream, and spawn the writer task. Returns the
/// read half (for the caller to hand to [`spawn_reader`]) plus a [`ServerLink`].
pub async fn open(addr: &str) -> Result<(OwnedReadHalf, ServerLink)> {
    let stream = TcpStream::connect(addr).await?;
    let (read_half, mut write_half) = stream.into_split();

    // Writer task: drain ClientMsgs and frame them onto the socket.
    let (tx, mut rx) = mpsc::unbounded_channel::<ClientMsg>();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_msg(&mut write_half, &msg).await {
                tracing::warn!("server writer ended: {e}");
                break;
            }
        }
        tracing::debug!("server writer task exiting");
    });

    let pending: Pending = Arc::new(AsyncMutex::new(None));
    Ok((read_half, ServerLink { tx, pending }))
}

/// Send a `ClientMsg` and await the single control response. Installs the
/// oneshot BEFORE sending so the reader can never beat us to it.
pub async fn send_and_wait(link: &ServerLink, msg: ClientMsg) -> Result<ServerMsg> {
    let (otx, orx) = oneshot::channel();
    {
        let mut slot = link.pending.lock().await;
        *slot = Some(otx);
    }
    link.tx
        .send(msg)
        .map_err(|_| anyhow!("server connection closed"))?;
    orx.await
        .map_err(|_| anyhow!("server closed before replying"))
}

/// Fire-and-forget send (used for `Send` and `Pull`, whose results arrive as
/// `Deliver` frames rather than a single control response).
pub fn send(link: &ServerLink, msg: ClientMsg) -> Result<()> {
    link.tx
        .send(msg)
        .map_err(|_| anyhow!("server connection closed"))?;
    Ok(())
}

/// Everything the reader task needs to decrypt and persist incoming traffic.
pub struct ReaderCtx {
    pub identity: Arc<Identity>,
    pub db: Db,
    pub events: Events,
    pub pending: Pending,
    /// Our own username (used to record ourselves as a DM member).
    pub me: String,
}

/// Spawn the reader loop. Returns its `JoinHandle` so the caller can `.abort()`
/// it if the connection is being torn down or auth fails.
pub fn spawn_reader(mut read_half: OwnedReadHalf, ctx: ReaderCtx) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let msg: ServerMsg = match read_msg(&mut read_half).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::info!("server reader closed: {e}");
                    // Wake any in-flight control request: its reply will never
                    // arrive now, so drop the parked oneshot sender to make the
                    // awaiting `send_and_wait` resolve with an error instead of
                    // hanging forever (which would freeze the command loop).
                    if let Some(tx) = ctx.pending.lock().await.take() {
                        drop(tx);
                    }
                    ctx.events
                        .emit(json!({"event": "disconnected", "reason": e.to_string()}));
                    break;
                }
            };

            match msg {
                ServerMsg::Deliver {
                    from,
                    msg_type,
                    payload,
                    group_id,
                    client_ts,
                    ..
                } => {
                    if let Err(e) = process_incoming(
                        &ctx,
                        &from,
                        &msg_type,
                        &payload,
                        group_id.as_deref(),
                        client_ts,
                    ) {
                        // Never crash the loop on a bad/undecryptable frame.
                        tracing::warn!("incoming delivery failed: {e}");
                        ctx.events
                            .emit(json!({"event": "error", "code": "decrypt_failed", "message": e.to_string()}));
                    }
                }
                // Any non-Deliver frame is a control response: fulfill the
                // pending oneshot installed by `send_and_wait`.
                other => {
                    let mut slot = ctx.pending.lock().await;
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(other);
                    } else {
                        tracing::warn!("unsolicited control message: {:?}", other);
                    }
                }
            }
        }
    })
}

/// Decrypt, persist, and surface a single delivered frame. Returns an error on
/// any decryption/parse failure; the caller logs + emits and keeps going.
fn process_incoming(
    ctx: &ReaderCtx,
    from: &str,
    msg_type: &str,
    payload: &str,
    group_id: Option<&str>,
    client_ts: i64,
) -> Result<()> {
    match msg_type {
        // 1:1 sealed box addressed to us.
        "msg" => {
            let plaintext = ctx.identity.unseal(&cherm_crypto::b64_decode(payload)?)?;
            let text = String::from_utf8(plaintext)?;

            // Lazily materialize a DM chat keyed by the sender's username.
            let new_chat = !db::chat_exists(&ctx.db, from)?;
            db::upsert_chat(&ctx.db, from, "dm", from, None)?;
            db::add_member(&ctx.db, from, &ctx.me)?;
            db::add_member(&ctx.db, from, from)?;
            db::insert_message(&ctx.db, from, from, &text, client_ts, 0)?;

            if new_chat {
                // The chat set changed: refresh the sidebar.
                ctx.events.emit(db::build_chats_event(&ctx.db)?);
            }
            ctx.events.emit(json!({
                "event": "message", "chat": from, "from": from,
                "text": text, "ts": client_ts, "outgoing": false, "color": null
            }));
        }

        // A group key + roster, sealed to our X25519 key.
        "group_invite" => {
            let raw = ctx.identity.unseal(&cherm_crypto::b64_decode(payload)?)?;
            let invite: GroupInvite = serde_json::from_slice(&raw)?;

            db::upsert_chat(
                &ctx.db,
                &invite.group_id,
                "group",
                &invite.name,
                Some(invite.key.clone()),
            )?;
            for member in &invite.members {
                db::add_member(&ctx.db, &invite.group_id, member)?;
            }

            ctx.events.emit(db::build_chats_event(&ctx.db)?);
            ctx.events.emit(
                json!({"event": "info", "message": format!("added to group {}", invite.name)}),
            );
        }

        // A symmetric group message; decrypt with the stored group key.
        "group_msg" => {
            let gid = group_id.ok_or_else(|| anyhow!("group_msg missing group_id"))?;
            let (_kind, group_key) = db::get_chat(&ctx.db, gid)?
                .ok_or_else(|| anyhow!("group_msg for unknown group {gid}"))?;
            let group_key = group_key.ok_or_else(|| anyhow!("group {gid} has no key"))?;
            let key = group_key_from_b64(&group_key)?;

            let blob = cherm_crypto::b64_decode(payload)?;
            let text = String::from_utf8(cherm_crypto::group_decrypt(&key, &blob)?)?;

            db::insert_message(&ctx.db, gid, from, &text, client_ts, 0)?;
            ctx.events.emit(json!({
                "event": "message", "chat": gid, "from": from,
                "text": text, "ts": client_ts, "outgoing": false, "color": null
            }));
        }

        other => tracing::warn!("ignoring unknown msg_type {other:?} from {from}"),
    }
    Ok(())
}

/// Decode a base64 group key into the fixed 32-byte array the crypto API wants.
pub fn group_key_from_b64(s: &str) -> Result<[u8; 32]> {
    let bytes = cherm_crypto::b64_decode(s)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("group key must be exactly 32 bytes"))
}
