//! Per-server connection: framing, the writer/reader/processor tasks, and the
//! single-outstanding control-response channel (PROTOCOL.md section 2).
//!
//! Each server connection splits one `TcpStream` into halves:
//!
//! - The **write half** is owned by a dedicated task fed by an
//!   `mpsc<ClientMsg>` ([`ServerLink::tx`]); anyone can send by cloning it.
//! - The **read half** is owned by the **reader task** ([`spawn_reader`]). It
//!   reads `ServerMsg` frames forever. `Deliver` frames are forwarded to a
//!   single **processor task**; every other frame (`Challenge`, `AuthOk`,
//!   `PrekeyBundle`, `Ok`, `Error`, `Pong`, ...) is a control response and
//!   fulfills the one pending [`oneshot`].
//!
//! Why a separate processor task? Decrypting an incoming Olm message from a
//! brand-new peer may require a `FetchPrekeys` round-trip — i.e. it must
//! `send_and_wait`. If the reader did that itself it would deadlock (it is the
//! only thing that reads + routes the reply). So the reader hands Delivers to a
//! single serialized processor that can freely `send_and_wait`; the reader keeps
//! pumping the socket and routes the reply. One processor ⇒ messages are
//! processed in order and Olm/Megolm ratchets never race.
//!
//! `send_and_wait` serializes requesters with [`ServerLink::control`] so there
//! is only ever ONE outstanding control request (command handlers AND the
//! processor share it). On disconnect the reader drains the pending oneshot so a
//! parked `send_and_wait` resolves with an error instead of hanging.

use anyhow::{anyhow, Result};
use cherm_proto::{read_msg, write_msg, ClientMsg, ServerMsg};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::ipc::Events;
use crate::vault::{self, Vault};

/// The slot holding the single outstanding control-response sender.
pub type Pending = Arc<AsyncMutex<Option<oneshot::Sender<ServerMsg>>>>;

/// Handle to a live server connection. Cheaply cloneable so command handlers and
/// the processor can grab a copy without borrowing `App`.
#[derive(Clone)]
pub struct ServerLink {
    /// Send a `ClientMsg` to the server (consumed by the writer task).
    pub tx: mpsc::UnboundedSender<ClientMsg>,
    /// The single-outstanding control-response slot.
    pub pending: Pending,
    /// Serializes requesters so only one control request is in flight at a time.
    pub control: Arc<AsyncMutex<()>>,
}

/// Connect to `addr`, split the stream, and spawn the writer task. Returns the
/// read half (for [`spawn_reader`]) plus a [`ServerLink`].
pub async fn open(addr: &str) -> Result<(OwnedReadHalf, ServerLink)> {
    let stream = TcpStream::connect(addr).await?;
    let (read_half, mut write_half) = stream.into_split();

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

    Ok((
        read_half,
        ServerLink {
            tx,
            pending: Arc::new(AsyncMutex::new(None)),
            control: Arc::new(AsyncMutex::new(())),
        },
    ))
}

/// Send a `ClientMsg` and await the single control response. Holds the control
/// lock so concurrent requesters (command handlers + the processor) serialize,
/// and installs the oneshot BEFORE sending so the reader can never beat us.
pub async fn send_and_wait(link: &ServerLink, msg: ClientMsg) -> Result<ServerMsg> {
    let _guard = link.control.lock().await;
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
        .map_err(|_| anyhow!("server connection closed"))
}

/// A delivered ciphertext frame, forwarded reader → processor.
struct Incoming {
    from: String,
    msg_type: String,
    payload: String,
    group_id: Option<String>,
    client_ts: i64,
}

/// Everything the processor needs to decrypt, persist and surface traffic.
#[derive(Clone)]
struct ProcCtx {
    vault: Vault,
    vault_key: [u8; 32],
    link: ServerLink,
    events: Events,
    /// Our own username (recorded as a DM member).
    me: String,
    /// This server's address (for `server`-tagged events).
    addr: String,
}

/// Spawn the processor + reader for one connection. Returns the reader's
/// `JoinHandle` so the caller can `.abort()` it (dropping the reader closes the
/// processor channel, which ends the processor too).
#[allow(clippy::too_many_arguments)]
pub fn spawn_reader(
    mut read_half: OwnedReadHalf,
    link: ServerLink,
    vault: Vault,
    vault_key: [u8; 32],
    events: Events,
    me: String,
    addr: String,
) -> JoinHandle<()> {
    let pending = link.pending.clone();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Incoming>();

    let ctx = ProcCtx {
        vault,
        vault_key,
        link,
        events: events.clone(),
        me,
        addr: addr.clone(),
    };
    tokio::spawn(processor_loop(in_rx, ctx));

    tokio::spawn(async move {
        loop {
            // Read the frame as untyped JSON FIRST. `read_msg` consumes exactly
            // the framed bytes regardless of shape, so a well-framed JSON frame
            // that does not match `ServerMsg` (unknown variant / missing field)
            // leaves the stream IN SYNC and we can recover from it. Only a true
            // I/O error, EOF, oversized frame or non-JSON body is fatal for this
            // connection.
            let value: serde_json::Value = match read_msg(&mut read_half).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::info!("server reader closed: {e}");
                    // Wake any parked control request so `send_and_wait` resolves
                    // with an error instead of hanging the command loop.
                    if let Some(tx) = pending.lock().await.take() {
                        drop(tx);
                    }
                    events.emit(json!({"event": "disconnected", "server": addr, "reason": e.to_string()}));
                    break;
                }
            };
            // A single malformed/unknown frame must NEVER tear down (or crash)
            // the reader: the stream is still in sync, so log it and keep going.
            let msg: ServerMsg = match serde_json::from_value(value) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("ignoring malformed/unknown server frame: {e}");
                    continue;
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
                    // Hand off to the serialized processor; never block the reader.
                    let _ = in_tx.send(Incoming {
                        from,
                        msg_type,
                        payload,
                        group_id,
                        client_ts,
                    });
                }
                // Server-pushed maintenance/update notice — UNSOLICITED, so it
                // must NOT consume the pending control oneshot. Surface it as a
                // `maintenance` event; the TUI renders a LOCAL countdown to the
                // deadline (not 60 chat lines), then enters waiting-for-server.
                ServerMsg::Maintenance {
                    reason,
                    deadline_unix_ms,
                    version,
                } => {
                    events.emit(json!({
                        "event": "maintenance",
                        "server": addr,
                        "reason": reason,
                        "deadline_ms": deadline_unix_ms,
                        "version": version,
                    }));
                }
                other => {
                    let mut slot = pending.lock().await;
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(other);
                    } else {
                        tracing::warn!("unsolicited control message: {other:?}");
                    }
                }
            }
        }
        // `in_tx` drops here → the processor's channel closes → processor ends.
    })
}

/// The single processor task: drains delivered frames in order. Each is decrypted
/// and persisted; a bad/undecryptable frame is logged + surfaced but never
/// crashes the loop.
async fn processor_loop(mut rx: mpsc::UnboundedReceiver<Incoming>, ctx: ProcCtx) {
    while let Some(inc) = rx.recv().await {
        if let Err(e) = process_one(&ctx, &inc).await {
            tracing::warn!("incoming delivery failed: {e}");
            ctx.events
                .emit(json!({"event": "error", "code": "decrypt_failed", "message": e.to_string()}));
        }
    }
    tracing::debug!("processor task exiting");
}

/// The on-the-wire JSON inside an `olm_group_key` payload: a Megolm session key
/// shared over the pairwise Olm channel.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GroupKeyShare {
    group_id: String,
    name: String,
    session_key: String,
    sender_curve: String,
    members: Vec<String>,
}

async fn process_one(ctx: &ProcCtx, inc: &Incoming) -> Result<()> {
    match inc.msg_type.as_str() {
        // An Olm DM (plaintext is the message text).
        "olm" => {
            let plaintext = obtain_olm_plaintext(ctx, &inc.from, &inc.payload).await?;
            deliver_dm_text(ctx, &inc.from, &plaintext, inc.client_ts)?;
        }
        // An Olm message whose plaintext is a Megolm group-key share JSON.
        "olm_group_key" => {
            let plaintext = obtain_olm_plaintext(ctx, &inc.from, &inc.payload).await?;
            handle_group_key_share(ctx, &inc.from, &plaintext)?;
        }
        // A Megolm group message.
        "megolm" => {
            let gid = inc
                .group_id
                .as_deref()
                .ok_or_else(|| anyhow!("megolm frame missing group_id"))?;
            process_megolm(ctx, &inc.from, gid, &inc.payload, inc.client_ts)?;
        }
        // A DM "left the chat" notice over Olm. We still decrypt (to advance the
        // ratchet) but IGNORE the plaintext and render the notice from the
        // relay-asserted `from`, so the leaver's name can't be spoofed.
        "olm_system" => {
            let _ = obtain_olm_plaintext(ctx, &inc.from, &inc.payload).await?;
            deliver_system(ctx, &inc.from, &inc.from, inc.client_ts)?;
        }
        // A group "left the chat" notice over Megolm.
        "megolm_system" => {
            let gid = inc
                .group_id
                .as_deref()
                .ok_or_else(|| anyhow!("megolm_system missing group_id"))?;
            process_megolm_system(ctx, &inc.from, gid, &inc.payload, inc.client_ts)?;
        }
        other => tracing::warn!("ignoring unknown msg_type {other:?} from {}", inc.from),
    }
    Ok(())
}

/// Decrypt an Olm payload `"<olm_type>.<base64 body>"` from `from`, establishing
/// an inbound session (and, if needed, fetching the peer's curve key) the first
/// time. Re-persists the mutated session (and account on first contact).
async fn obtain_olm_plaintext(ctx: &ProcCtx, from: &str, payload: &str) -> Result<Vec<u8>> {
    let (olm_type, body) = parse_olm(payload)?;

    // Existing session: try to decrypt + re-persist (the ratchet advanced).
    if let Some(mut session) = vault::load_olm(&ctx.vault, &ctx.vault_key, from)? {
        match session.decrypt(olm_type, &body) {
            Ok(plaintext) => {
                vault::save_olm(&ctx.vault, &ctx.vault_key, from, &session)?;
                return Ok(plaintext);
            }
            Err(e) => {
                // A normal (type 1) message that fails to decrypt is a real
                // error. But a PREKEY (type 0) message may be the peer starting a
                // brand-new session (e.g. after one side left and re-contacted,
                // or Olm "glare") that our stored session cannot decrypt — fall
                // through and establish a fresh inbound session instead.
                if olm_type != 0 {
                    return Err(e);
                }
                tracing::info!("prekey for a new session from {from}; re-establishing");
            }
        }
    }

    // No usable session: we need the sender's curve25519 to accept the prekey msg.
    let curve = match vault::get_contact_curve(&ctx.vault, from)? {
        Some(c) => c,
        None => {
            // Fetch the bundle. Safe here: we're the processor, not the reader,
            // so the reader still routes this reply to us — no deadlock.
            match send_and_wait(&ctx.link, ClientMsg::FetchPrekeys { username: from.to_string() })
                .await?
            {
                ServerMsg::PrekeyBundle {
                    username,
                    uuid,
                    ed25519,
                    curve25519,
                    ..
                } => {
                    vault::upsert_contact(&ctx.vault, &username, &uuid, &ed25519, &curve25519)?;
                    curve25519
                }
                ServerMsg::Error { code, message } => return Err(anyhow!("{code}: {message}")),
                other => return Err(anyhow!("unexpected prekey reply: {other:?}")),
            }
        }
    };

    // Accept the inbound prekey message: consumes one of our one-time keys, so
    // both the new session AND the mutated account must be persisted.
    let mut device = vault::load_account(&ctx.vault, &ctx.vault_key)?
        .ok_or_else(|| anyhow!("no device identity in vault"))?;
    let (session, plaintext) = device.create_inbound(&curve, olm_type, &body)?;
    vault::save_account(&ctx.vault, &ctx.vault_key, &device)?;
    vault::save_olm(&ctx.vault, &ctx.vault_key, from, &session)?;
    Ok(plaintext)
}

/// Materialize a DM chat for an incoming text and surface it.
fn deliver_dm_text(ctx: &ProcCtx, from: &str, plaintext: &[u8], client_ts: i64) -> Result<()> {
    let text = String::from_utf8(plaintext.to_vec())?;

    let new_chat = !vault::chat_exists(&ctx.vault, from)?;
    vault::upsert_chat(&ctx.vault, from, "dm", from)?;
    vault::add_member(&ctx.vault, from, &ctx.me)?;
    vault::add_member(&ctx.vault, from, from)?;
    vault::insert_message(&ctx.vault, from, from, &text, client_ts, 0)?;

    if new_chat {
        ctx.events
            .emit(vault::build_chats_event(&ctx.vault, &ctx.addr)?);
    }
    ctx.events.emit(json!({
        "event": "message", "chat": from, "from": from,
        "text": text, "ts": client_ts, "outgoing": false, "color": null
    }));
    if let Some(ed) = vault::get_contact_ed(&ctx.vault, from)? {
        ctx.events.emit(json!({
            "event": "fingerprint", "username": from,
            "fingerprint": cherm_crypto::fingerprint_of(&ed)
        }));
    }
    Ok(())
}

/// Accept a Megolm group-key share received over Olm: store the inbound session
/// and materialize the group chat.
fn handle_group_key_share(ctx: &ProcCtx, from: &str, plaintext: &[u8]) -> Result<()> {
    let share: GroupKeyShare = serde_json::from_slice(plaintext)?;
    let receiver = cherm_crypto::GroupReceiver::from_session_key_b64(&share.session_key)?;
    vault::save_group_in(&ctx.vault, &ctx.vault_key, &share.group_id, from, &receiver)?;

    vault::upsert_chat(&ctx.vault, &share.group_id, "group", &share.name)?;
    for m in &share.members {
        vault::add_member(&ctx.vault, &share.group_id, m)?;
    }

    ctx.events
        .emit(vault::build_chats_event(&ctx.vault, &ctx.addr)?);
    ctx.events
        .emit(json!({"event": "info", "message": format!("added to group {}", share.name)}));
    Ok(())
}

/// Decrypt a Megolm group message with the inbound session for `(group_id, from)`.
fn process_megolm(
    ctx: &ProcCtx,
    from: &str,
    group_id: &str,
    payload: &str,
    client_ts: i64,
) -> Result<()> {
    let mut receiver = match vault::load_group_in(&ctx.vault, &ctx.vault_key, group_id, from)? {
        Some(r) => r,
        None => {
            // We have not received the key share yet; surface and keep going.
            ctx.events.emit(json!({
                "event": "error", "code": "decrypt_pending",
                "message": format!("no inbound session for group {group_id} from {from} yet")
            }));
            return Ok(());
        }
    };

    let body = cherm_crypto::b64_decode(payload)?;
    let (plaintext, _idx) = receiver.decrypt(&body)?;
    vault::save_group_in(&ctx.vault, &ctx.vault_key, group_id, from, &receiver)?;

    let text = String::from_utf8(plaintext)?;
    vault::insert_message(&ctx.vault, group_id, from, &text, client_ts, 0)?;
    ctx.events.emit(json!({
        "event": "message", "chat": group_id, "from": from,
        "text": text, "ts": client_ts, "outgoing": false, "color": null
    }));
    Ok(())
}

/// A group "left" notice over Megolm: decrypt (to advance the ratchet), drop
/// the leaver from the local roster, and surface a system message. The leaver's
/// name comes from the relay-asserted `from`, not the (ignored) plaintext.
fn process_megolm_system(
    ctx: &ProcCtx,
    from: &str,
    group_id: &str,
    payload: &str,
    client_ts: i64,
) -> Result<()> {
    let mut receiver = match vault::load_group_in(&ctx.vault, &ctx.vault_key, group_id, from)? {
        Some(r) => r,
        None => {
            ctx.events.emit(json!({
                "event": "error", "code": "decrypt_pending",
                "message": format!("no inbound session for group {group_id} from {from} yet")
            }));
            return Ok(());
        }
    };
    let body = cherm_crypto::b64_decode(payload)?;
    let _ = receiver.decrypt(&body)?; // advance ratchet; plaintext ignored
    vault::save_group_in(&ctx.vault, &ctx.vault_key, group_id, from, &receiver)?;

    vault::remove_member(&ctx.vault, group_id, from)?;
    deliver_system(ctx, group_id, from, client_ts)?;
    Ok(())
}

/// Record + surface a "✣ System" message attributing a leave to `leaver`. Stored
/// under the reserved "System" sender so it can never be confused with a user.
fn deliver_system(ctx: &ProcCtx, chat: &str, leaver: &str, client_ts: i64) -> Result<()> {
    let text = format!("{leaver} left the chat.");
    vault::insert_message(&ctx.vault, chat, "System", &text, client_ts, 0)?;
    ctx.events.emit(json!({
        "event": "message", "chat": chat, "from": "System",
        "text": text, "ts": client_ts, "outgoing": false, "system": true, "color": null
    }));
    Ok(())
}

/// Split an Olm payload `"<olm_type>.<base64 body>"` into `(olm_type, body)`.
pub fn parse_olm(payload: &str) -> Result<(u8, Vec<u8>)> {
    let (t_str, b_str) = payload
        .split_once('.')
        .ok_or_else(|| anyhow!("malformed olm payload (expected <type>.<b64>)"))?;
    let olm_type: u8 = t_str
        .parse()
        .map_err(|_| anyhow!("invalid olm type prefix"))?;
    let body = cherm_crypto::b64_decode(b_str)?;
    Ok((olm_type, body))
}

/// Encode an Olm `(olm_type, body)` into the wire payload `"<type>.<b64>"`.
pub fn encode_olm(olm_type: u8, body: &[u8]) -> String {
    format!("{}.{}", olm_type, cherm_crypto::b64_encode(body))
}
