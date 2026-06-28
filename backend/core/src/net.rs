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
use cherm_crypto::{GroupSender, OlmSession};
use cherm_proto::{access_mode, errcode, msgtype, read_msg, write_msg, ClientMsg, ServerMsg, MAX_PAYLOAD};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::ipc::{err_event, Events};
use crate::vault::{self, Vault};

/// Bound on the reader→processor delivery queue. Generously above any honest
/// login/Pull backlog (the server's per-recipient outbox cap is 10k, but those are
/// processed quickly); reaching it means the relay is flooding, so we disconnect.
const IN_QUEUE: usize = 2048;

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

/// Max time to wait for a control reply before giving up. A malicious/dead relay
/// that accepts a request but never answers must not park `send_and_wait` (and the
/// control lock it holds) forever — that would wedge every other command handler.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    // Bounded wait: a silent relay must not hold the control lock indefinitely.
    match tokio::time::timeout(REQUEST_TIMEOUT, orx).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(_)) => Err(anyhow!("server closed before replying")),
        Err(_) => {
            // Timed out — clear the single pending slot so a late reply can't be
            // mis-routed to the NEXT requester (the design has no request IDs).
            *link.pending.lock().await = None;
            Err(anyhow!("server timed out (no reply within {REQUEST_TIMEOUT:?})"))
        }
    }
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
    // BOUNDED so a malicious relay can't make us buffer unbounded `Deliver` frames
    // in memory faster than the single processor drains them. Sized well above any
    // honest login/Pull backlog (the server flushes the whole outbox on login). We
    // must NEVER block the reader on a full queue (the reader also routes the
    // control replies the processor's `send_and_wait` is waiting for — blocking
    // would deadlock), so on overflow we DISCONNECT instead.
    let (in_tx, in_rx) = mpsc::channel::<Incoming>(IN_QUEUE);

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
                    events.emit(
                        json!({"event": "disconnected", "server": addr, "reason": e.to_string()}),
                    );
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
                    // A relay must not exceed the per-message ciphertext cap; an
                    // oversized payload is malformed/abusive, so drop just that frame
                    // (keep serving) rather than buffering up to MAX_FRAME of it.
                    if payload.len() > MAX_PAYLOAD {
                        tracing::warn!("dropping oversized Deliver payload from {from}");
                        continue;
                    }
                    // Hand off to the serialized processor WITHOUT blocking the reader.
                    // On overflow the relay is flooding faster than we can decrypt:
                    // disconnect (bounded memory) rather than block (deadlock) or
                    // silently grow the heap.
                    match in_tx.try_send(Incoming {
                        from,
                        msg_type,
                        payload,
                        group_id,
                        client_ts,
                    }) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!("incoming delivery queue full; disconnecting (relay flood?)");
                            if let Some(tx) = pending.lock().await.take() {
                                drop(tx);
                            }
                            events.emit(json!({
                                "event": "disconnected", "server": addr,
                                "reason": "incoming queue overflow"
                            }));
                            break;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                    }
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
async fn processor_loop(mut rx: mpsc::Receiver<Incoming>, ctx: ProcCtx) {
    while let Some(inc) = rx.recv().await {
        if let Err(e) = process_one(&ctx, &inc).await {
            tracing::warn!("incoming delivery failed: {e}");
            ctx.events.emit(
                json!({"event": "error", "code": "decrypt_failed", "message": e.to_string()}),
            );
        }
    }
    tracing::debug!("processor task exiting");
}

/// The on-the-wire JSON inside an `olm_group_key` payload: a Megolm session key
/// shared over the pairwise Olm channel, plus the group's access metadata so the
/// joining member's vault mirrors the owner's view (owner, mode, invite key).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GroupKeyShare {
    group_id: String,
    name: String,
    session_key: String,
    sender_curve: String,
    members: Vec<String>,
    /// Group owner's username (authority); absent in pre-feature shares.
    #[serde(default)]
    owner: String,
    /// Access mode (open|approval|invite_only); defaults to open if absent.
    #[serde(default)]
    access_mode: String,
    /// The group's 8-char invite/access key; absent in pre-feature shares.
    #[serde(default)]
    group_key: String,
}

/// A moderation/membership event the owner broadcasts (Megolm) to the group.
#[derive(Debug, Deserialize)]
struct GroupEvent {
    /// One of: joined, removed, banned, suspended, access.
    kind: String,
    /// The user the event is about (empty for `access`).
    #[serde(default)]
    who: String,
    /// New access mode (only for `kind == "access"`).
    #[serde(default)]
    mode: Option<String>,
    /// Suspension deadline in unix-millis (only for `kind == "suspended"`), so
    /// members can mirror the suspension and reject the target's key shares until
    /// it expires.
    #[serde(default)]
    until: Option<i64>,
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
        // A DM "left the chat" notice over Olm. We decrypt (advancing the ratchet)
        // and require the AUTHENTICATED `b"left"` sentinel before rendering the
        // notice: `msg_type` is relay-asserted, so without this a relay could
        // relabel a normal DM message as `olm_system` to forge a "left" line.
        "olm_system" => {
            let plaintext = obtain_olm_plaintext(ctx, &inc.from, &inc.payload).await?;
            if plaintext == b"left" {
                deliver_system(ctx, &inc.from, &inc.from, inc.client_ts)?;
            } else {
                tracing::warn!(
                    "ignoring olm_system from {}: plaintext is not the leave sentinel",
                    inc.from
                );
            }
        }
        // A group "left the chat" notice over Megolm.
        "megolm_system" => {
            let gid = inc
                .group_id
                .as_deref()
                .ok_or_else(|| anyhow!("megolm_system missing group_id"))?;
            process_megolm_system(ctx, &inc.from, gid, &inc.payload, inc.client_ts)?;
        }
        // A join request from a prospective member (Olm). Owner-side: validate the
        // group key + ban/suspend state and admit / queue / deny per access mode.
        "group_join" => {
            let plaintext = obtain_olm_plaintext(ctx, &inc.from, &inc.payload).await?;
            handle_join_request(ctx, &inc.from, &plaintext, inc.client_ts).await?;
        }
        // The owner's reply denying our join request (Olm).
        "group_join_denied" => {
            let plaintext = obtain_olm_plaintext(ctx, &inc.from, &inc.payload).await?;
            handle_join_denied(ctx, &inc.from, &plaintext)?;
        }
        // A moderation/membership event broadcast by the owner (Megolm).
        "group_event" => {
            let gid = inc
                .group_id
                .as_deref()
                .ok_or_else(|| anyhow!("group_event missing group_id"))?;
            process_group_event(ctx, &inc.from, gid, &inc.payload, inc.client_ts)?;
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
            match send_and_wait(
                &ctx.link,
                ClientMsg::FetchPrekeys {
                    username: from.to_string(),
                },
            )
            .await?
            {
                ServerMsg::PrekeyBundle {
                    username,
                    uuid,
                    ed25519,
                    curve25519,
                    ..
                } => {
                    if !accept_identity(
                        &ctx.vault,
                        &ctx.events,
                        &username,
                        &uuid,
                        &ed25519,
                        &curve25519,
                    )? {
                        return Err(anyhow!(
                            "identity key for {username} changed; refusing to accept message"
                        ));
                    }
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
    // Refuse a key share from someone we've recorded as banned or currently
    // suspended in this group, so a moderated user cannot re-inject themselves by
    // pushing a fresh Megolm session. (Bans/suspensions are mirrored locally from
    // the owner's broadcast events.)
    if vault::is_banned(&ctx.vault, &share.group_id, from)? {
        tracing::warn!("dropping group key share from banned sender {from}");
        return Ok(());
    }
    if vault::is_suspended(&ctx.vault, &share.group_id, from, crate::now_millis())? {
        tracing::warn!("dropping group key share from suspended sender {from}");
        return Ok(());
    }

    let is_new = !vault::chat_exists(&ctx.vault, &share.group_id)?;
    let existing_meta = vault::get_group_meta(&ctx.vault, &share.group_id)?;
    let sender_is_member = !is_new && vault::is_member(&ctx.vault, &share.group_id, from)?;
    let claimed_owner = !share.owner.is_empty() && share.owner == from;
    let owner_share = match (is_new, existing_meta.as_ref()) {
        (true, None) => claimed_owner,
        (false, Some(meta)) if !meta.owner.is_empty() => meta.owner == from,
        // Existing legacy/backfilled groups with no owner are not allowed to learn
        // authority from a random key share; that would let any sender become the
        // local owner and rewrite roster/access metadata.
        _ => false,
    };

    // A non-owner member may share only their own sender session. They must not be
    // allowed to rewrite roster/owner/mode/key metadata; otherwise a malicious or
    // removed user could add outsiders or make later spoofed group_event messages
    // pass the owner check.
    if is_new && !owner_share {
        tracing::warn!(
            "dropping group key share for new group {group_id} from non-owner {from}",
            group_id = share.group_id
        );
        return Ok(());
    }
    if !is_new && !owner_share && !sender_is_member {
        tracing::warn!(
            "dropping group key share for {group_id} from non-member {from}",
            group_id = share.group_id
        );
        return Ok(());
    }

    let receiver = cherm_crypto::GroupReceiver::from_session_key_b64(&share.session_key)?;
    vault::save_group_in(&ctx.vault, &ctx.vault_key, &share.group_id, from, &receiver)?;
    if owner_share {
        vault::upsert_chat(&ctx.vault, &share.group_id, "group", &share.name)?;
    } else if is_new {
        // Defensive belt: new non-owner shares returned above, but avoid any
        // metadata write if that invariant changes later.
        return Ok(());
    }

    if owner_share {
        for m in &share.members {
            vault::add_member(&ctx.vault, &share.group_id, m)?;
        }

        // Mirror the owner's group metadata (owner/mode/invite key) so this member
        // can display the mode and so group_event spoof-checks have the recorded
        // owner. Only when the share actually carried a key (pre-feature shares
        // omit it).
        if cherm_crypto::valid_group_key(&share.group_key) {
            let mode = if access_mode::valid(&share.access_mode) {
                share.access_mode.as_str()
            } else {
                access_mode::OPEN
            };
            vault::upsert_group_meta(&ctx.vault, &share.group_id, &share.group_key, mode, from)?;
        }
    }

    ctx.events
        .emit(vault::build_chats_event(&ctx.vault, &ctx.addr)?);
    // Only announce on first add; re-shares (e.g. when a new member joins and the
    // owner refreshes the roster) must not spam existing members.
    if is_new {
        ctx.events
            .emit(json!({"event": "info", "message": format!("added to group {}", share.name)}));
    }
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
    let (plaintext, idx) = receiver.decrypt(&body)?;
    // Replay guard: a relay can re-deliver a recorded Megolm frame; Megolm decrypts
    // it again happily. Drop anything at-or-below the highest index we've applied
    // for this sender session so a duplicate message is never re-inserted.
    if !vault::megolm_accept(&ctx.vault, group_id, from, &receiver.session_id(), idx)? {
        tracing::warn!("dropping replayed megolm message (idx {idx}) for {group_id} from {from}");
        return Ok(());
    }
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
    let (plaintext, idx) = receiver.decrypt(&body)?;
    // AUTHENTICATED content gate. `msg_type`/`from`/`group_id` on a Deliver are
    // relay-asserted and NOT covered by Megolm authentication — only the ciphertext
    // is. Without this check a relay could relabel a normal `megolm` message as
    // `megolm_system` and have every recipient drop the sender from the roster
    // (a forged removal / silent partition). A genuine leave decrypts to the
    // `b"left"` sentinel the sender encrypted, which the relay cannot forge.
    if plaintext != b"left" {
        tracing::warn!(
            "ignoring megolm_system from {from} for {group_id}: plaintext is not the leave sentinel"
        );
        return Ok(());
    }
    // Replay guard: don't let a replayed "left" notice re-fire (and re-remove the
    // sender from the roster) on every re-delivery.
    if !vault::megolm_accept(&ctx.vault, group_id, from, &receiver.session_id(), idx)? {
        tracing::warn!("dropping replayed megolm_system (idx {idx}) for {group_id} from {from}");
        return Ok(());
    }
    vault::save_group_in(&ctx.vault, &ctx.vault_key, group_id, from, &receiver)?;

    vault::remove_member(&ctx.vault, group_id, from)?;
    deliver_system(ctx, group_id, from, client_ts)?;
    Ok(())
}

/// Record + surface a "✣ System" message attributing a leave to `leaver`.
fn deliver_system(ctx: &ProcCtx, chat: &str, leaver: &str, client_ts: i64) -> Result<()> {
    emit_system(
        &ctx.events,
        &ctx.vault,
        chat,
        &format!("{leaver} left the chat."),
        client_ts,
    )
}

/// Record a `✣ System` line in a chat and surface it. Stored under the reserved
/// "System" sender so it can never be confused with a user. Shared by the
/// processor (incoming events) and the command engine (owner-side actions).
pub fn emit_system(events: &Events, vault: &Vault, chat: &str, text: &str, ts: i64) -> Result<()> {
    vault::insert_message(vault, chat, "System", text, ts, 0)?;
    events.emit(json!({
        "event": "message", "chat": chat, "from": "System",
        "text": text, "ts": ts, "outgoing": false, "system": true, "color": null
    }));
    Ok(())
}

/// Human text for a group moderation/membership event (matches the system-message
/// examples in the spec). Returns `None` for kinds with no rendered line. Shared
/// by the owner (local emit) and members (on decrypt) so wording lives once.
pub fn group_event_text(kind: &str, who: &str, extra: &str) -> Option<String> {
    Some(match kind {
        "requested" => format!("{who} requested to join the group."),
        "joined" => format!("{who} joined the group."),
        "removed" => format!("{who} was removed from the group."),
        "banned" => format!("{who} was banned from the group."),
        "suspended" => format!("{who} was suspended from the group."),
        "access" => format!("group access mode set to {extra}."),
        _ => return None,
    })
}

/// True if `s` is a well-formed base64 32-byte public key. An empty/garbage key
/// must never be pinned: pinning `""` would let a relay later "re-pin" to a real
/// attacker key (the TOFU check treats an empty pinned key as first contact).
fn valid_pubkey_b64(s: &str) -> bool {
    !s.is_empty()
        && cherm_crypto::b64_decode(s)
            .map(|b| b.len() == 32)
            .unwrap_or(false)
}

/// Validate a server-supplied identity bundle against our pinned record (TOFU)
/// and pin/refresh it. On a key-substitution conflict — or a malformed/empty key
/// — surface a loud security warning and return `false` so the caller refuses to
/// establish a session; a malicious/compromised relay must not be able to swap
/// (or blank out) a peer's identity key.
pub fn accept_identity(
    vault: &Vault,
    events: &Events,
    username: &str,
    uuid: &str,
    ed25519: &str,
    curve25519: &str,
) -> Result<bool> {
    if !valid_pubkey_b64(ed25519) || !valid_pubkey_b64(curve25519) {
        events.emit(json!({
            "event": "error",
            "code": "identity_invalid",
            "message": format!("malformed identity bundle for {username} — refusing")
        }));
        return Ok(false);
    }
    match vault::check_identity(vault, username, ed25519)? {
        vault::IdentityCheck::Conflict => {
            events.emit(json!({
                "event": "error",
                "code": "identity_changed",
                "message": format!(
                    "SECURITY: identity key for {username} changed — refusing (possible relay key substitution). If they truly reset their account, leave/remove the chat to re-pin."
                )
            }));
            Ok(false)
        }
        _ => {
            vault::upsert_contact(vault, username, uuid, ed25519, curve25519)?;
            Ok(true)
        }
    }
}

/// Ensure we hold an Olm session to `peer`, establishing one via a prekey fetch
/// if needed. Returns `None` (after surfacing an error) when the peer has no
/// one-time keys available, so callers can skip them gracefully.
async fn ensure_olm(
    vault: &Vault,
    vk: &[u8; 32],
    link: &ServerLink,
    events: &Events,
    peer: &str,
) -> Result<Option<OlmSession>> {
    if let Some(s) = vault::load_olm(vault, vk, peer)? {
        return Ok(Some(s));
    }
    let device = vault::load_account(vault, vk)?.ok_or_else(|| anyhow!("no device identity"))?;
    match send_and_wait(
        link,
        ClientMsg::FetchPrekeys {
            username: peer.to_string(),
        },
    )
    .await?
    {
        ServerMsg::PrekeyBundle {
            username,
            uuid,
            ed25519,
            curve25519,
            one_time_key: Some(otk),
            ..
        } => {
            if !accept_identity(vault, events, &username, &uuid, &ed25519, &curve25519)? {
                return Ok(None);
            }
            Ok(Some(device.start_session(&curve25519, &otk)?))
        }
        ServerMsg::PrekeyBundle { .. } => {
            events.emit(err_event(
                errcode::NO_PREKEYS,
                &format!("{peer} has no one-time keys; skipped"),
            ));
            Ok(None)
        }
        ServerMsg::Error { code, message } => {
            events.emit(err_event(&code, &message));
            Ok(None)
        }
        other => {
            events.emit(err_event(
                "internal",
                &format!("unexpected prekey reply: {other:?}"),
            ));
            Ok(None)
        }
    }
}

/// Share our outbound Megolm session key with `recipients` over their pairwise
/// Olm sessions. The share embeds the FULL current roster (read from the vault)
/// plus the group's access metadata, so every recipient mirrors the owner's view.
/// Used both when creating/refreshing a group and when admitting a single member.
#[allow(clippy::too_many_arguments)]
pub async fn distribute_group_key(
    vault: &Vault,
    vk: &[u8; 32],
    link: &ServerLink,
    events: &Events,
    me: &str,
    group_id: &str,
    name: &str,
    recipients: &[String],
    sender: &GroupSender,
) -> Result<()> {
    let device = vault::load_account(vault, vk)?.ok_or_else(|| anyhow!("no device identity"))?;
    let sender_curve = device.curve25519_b64();
    let session_key = sender.session_key_b64();
    let members = vault::get_members(vault, group_id)?;
    let meta = vault::get_group_meta(vault, group_id)?;
    let owner = meta.as_ref().map(|m| m.owner.clone()).unwrap_or_default();
    let mode = meta
        .as_ref()
        .map(|m| m.access_mode.clone())
        .unwrap_or_else(|| access_mode::OPEN.to_string());
    let group_key = meta
        .as_ref()
        .map(|m| m.group_key.clone())
        .unwrap_or_default();
    let now = crate::now_millis();

    for member in recipients {
        if member == me {
            continue;
        }
        let mut session = match ensure_olm(vault, vk, link, events, member).await? {
            Some(s) => s,
            None => continue,
        };
        let share = json!({
            "group_id": group_id,
            "name": name,
            "session_key": session_key,
            "sender_curve": sender_curve,
            "members": members,
            "owner": owner,
            "access_mode": mode,
            "group_key": group_key,
        });
        let plaintext = serde_json::to_vec(&share)?;
        let (t, body) = session.encrypt(&plaintext)?;
        vault::save_olm(vault, vk, member, &session)?;
        send(
            link,
            ClientMsg::Send {
                to: vec![member.clone()],
                msg_type: msgtype::OLM_GROUP_KEY.to_string(),
                payload: encode_olm(t, &body),
                group_id: Some(group_id.to_string()),
                client_ts: now,
            },
        )?;
    }
    Ok(())
}

/// Broadcast a moderation/membership `event` JSON to the group over Megolm. Mints
/// + distributes an outbound session first if we never spoke in this group.
#[allow(clippy::too_many_arguments)]
pub async fn broadcast_group_event(
    vault: &Vault,
    vk: &[u8; 32],
    link: &ServerLink,
    events: &Events,
    me: &str,
    group_id: &str,
    name: &str,
    event: &Value,
) -> Result<()> {
    let roster = vault::get_members(vault, group_id)?;
    let mut sender = match vault::load_group_out(vault, vk, group_id)? {
        Some(s) => s,
        None => {
            let s = GroupSender::new();
            vault::save_group_out(vault, vk, group_id, &s)?;
            distribute_group_key(vault, vk, link, events, me, group_id, name, &roster, &s).await?;
            s
        }
    };
    let bytes = sender.encrypt(&serde_json::to_vec(event)?);
    vault::save_group_out(vault, vk, group_id, &sender)?;
    let recipients: Vec<String> = roster.into_iter().filter(|m| m != me).collect();
    if !recipients.is_empty() {
        send(
            link,
            ClientMsg::Send {
                to: recipients,
                msg_type: msgtype::GROUP_EVENT.to_string(),
                payload: cherm_crypto::b64_encode(&bytes),
                group_id: Some(group_id.to_string()),
                client_ts: crate::now_millis(),
            },
        )?;
    }
    Ok(())
}

/// JSON a prospective member sends to the owner to request access.
#[derive(Debug, Deserialize)]
struct JoinRequest {
    group_id: String,
    group_key: String,
}

/// Owner-side handling of an incoming `group_join`: validate the key + ban/suspend
/// state, then admit (open), queue for approval, or deny (invite-only / bad key /
/// banned / suspended). Silently ignores requests for groups we don't own.
async fn handle_join_request(ctx: &ProcCtx, from: &str, plaintext: &[u8], now: i64) -> Result<()> {
    let req: JoinRequest = serde_json::from_slice(plaintext)?;
    // We are only the authority for a group whose recorded owner is us.
    let meta = match vault::get_group_meta(&ctx.vault, &req.group_id)? {
        Some(m) if !m.owner.is_empty() && m.owner == ctx.me => m,
        _ => {
            tracing::info!("join request for a group we don't own; ignoring");
            return Ok(());
        }
    };

    let key_ok = cherm_crypto::valid_group_key(&req.group_key) && req.group_key == meta.group_key;
    let banned = vault::is_banned(&ctx.vault, &req.group_id, from)?;
    let suspended = vault::is_suspended(&ctx.vault, &req.group_id, from, now)?;
    // Already a member (e.g. re-requesting after a reinstall) → re-share the key.
    let member = vault::is_member(&ctx.vault, &req.group_id, from)?;

    match decide_join(&meta.access_mode, key_ok, banned, suspended, member) {
        JoinDecision::Admit => {
            admit_member(
                &ctx.vault,
                &ctx.vault_key,
                &ctx.link,
                &ctx.events,
                &ctx.me,
                &ctx.addr,
                &meta.group_id,
                from,
                now,
            )
            .await
        }
        JoinDecision::Queue => {
            vault::add_join_request(&ctx.vault, &req.group_id, from, now)?;
            if let Some(text) = group_event_text("requested", from, "") {
                emit_system(&ctx.events, &ctx.vault, &req.group_id, &text, now)?;
            }
            ctx.events.emit(json!({
                "event": "info",
                "message": format!("{from} requested to join — /accept {from} (in that group) to admit")
            }));
            Ok(())
        }
        JoinDecision::Deny(reason) => deny_join(ctx, from, &req.group_id, reason).await,
    }
}

/// The owner's verdict on an incoming join request.
#[derive(Debug, PartialEq, Eq)]
pub enum JoinDecision {
    /// Add the requester immediately (open mode, or an existing member re-syncing).
    Admit,
    /// Hold for owner approval (approval mode).
    Queue,
    /// Refuse, with a user-facing reason.
    Deny(&'static str),
}

/// Decide how to handle a join request from the group's access metadata and the
/// requester's standing. Pure (no I/O) so the full decision matrix is unit-tested:
///
/// * a bad/mismatched key, a ban, or an active suspension is always refused —
///   the invite key never bypasses these (acceptance criteria);
/// * an existing member is re-admitted (key re-sync) regardless of mode;
/// * otherwise: open → admit, approval → queue, invite-only → refuse.
pub fn decide_join(
    access_mode: &str,
    key_ok: bool,
    banned: bool,
    suspended: bool,
    member: bool,
) -> JoinDecision {
    if !key_ok {
        return JoinDecision::Deny("invalid group key");
    }
    if banned {
        return JoinDecision::Deny("you are banned from this group");
    }
    if suspended {
        return JoinDecision::Deny("you are suspended from this group");
    }
    if member {
        return JoinDecision::Admit;
    }
    match access_mode {
        access_mode::OPEN => JoinDecision::Admit,
        access_mode::APPROVAL => JoinDecision::Queue,
        access_mode::INVITE_ONLY => {
            JoinDecision::Deny("this group is invite-only; ask the owner for an invite")
        }
        _ => JoinDecision::Deny("this group is not accepting joins"),
    }
}

/// Add `who` to the group, hand them the Megolm key, and tell everyone they
/// joined. Owner-side; used by open-mode joins, `/accept` and `/invite`.
#[allow(clippy::too_many_arguments)]
pub async fn admit_member(
    vault: &Vault,
    vk: &[u8; 32],
    link: &ServerLink,
    events: &Events,
    me: &str,
    addr: &str,
    group_id: &str,
    who: &str,
    now: i64,
) -> Result<()> {
    let name = vault::get_chat(vault, group_id)?
        .map(|(_, t)| t)
        .unwrap_or_default();

    vault::add_member(vault, group_id, who)?;
    vault::remove_join_request(vault, group_id, who)?;

    // Hand the new member our outbound key (minting one if we never spoke here).
    let sender = match vault::load_group_out(vault, vk, group_id)? {
        Some(s) => s,
        None => {
            let s = GroupSender::new();
            vault::save_group_out(vault, vk, group_id, &s)?;
            s
        }
    };
    distribute_group_key(
        vault,
        vk,
        link,
        events,
        me,
        group_id,
        &name,
        &[who.to_string()],
        &sender,
    )
    .await?;

    // Tell existing members so they add `who` to their rosters + see the line.
    broadcast_group_event(
        vault,
        vk,
        link,
        events,
        me,
        group_id,
        &name,
        &json!({"kind": "joined", "who": who}),
    )
    .await?;

    if let Some(text) = group_event_text("joined", who, "") {
        emit_system(events, vault, group_id, &text, now)?;
    }
    events.emit(vault::build_chats_event(vault, addr)?);
    Ok(())
}

/// Send an Olm-encrypted JSON control message to `to` (best-effort; skips if the
/// peer is unreachable / has no prekeys). Used both by the processor (denials)
/// and the command engine (join requests).
#[allow(clippy::too_many_arguments)]
pub async fn send_olm_control(
    vault: &Vault,
    vk: &[u8; 32],
    link: &ServerLink,
    events: &Events,
    to: &str,
    msg_type: &str,
    group_id: &str,
    value: &Value,
) -> Result<()> {
    let mut session = match ensure_olm(vault, vk, link, events, to).await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let plaintext = serde_json::to_vec(value)?;
    let (t, body) = session.encrypt(&plaintext)?;
    vault::save_olm(vault, vk, to, &session)?;
    send(
        link,
        ClientMsg::Send {
            to: vec![to.to_string()],
            msg_type: msg_type.to_string(),
            payload: encode_olm(t, &body),
            group_id: Some(group_id.to_string()),
            client_ts: crate::now_millis(),
        },
    )
}

/// Tell a prospective member their join was refused, with a reason.
async fn deny_join(ctx: &ProcCtx, to: &str, group_id: &str, reason: &str) -> Result<()> {
    let value = json!({"group_id": group_id, "reason": reason});
    send_olm_control(
        &ctx.vault,
        &ctx.vault_key,
        &ctx.link,
        &ctx.events,
        to,
        msgtype::GROUP_JOIN_DENIED,
        group_id,
        &value,
    )
    .await
}

/// JSON the owner sends back when refusing a join.
#[derive(Debug, Deserialize)]
struct JoinDenied {
    #[allow(dead_code)]
    group_id: String,
    reason: String,
}

/// Surface a join refusal to the user who tried to join.
fn handle_join_denied(ctx: &ProcCtx, from: &str, plaintext: &[u8]) -> Result<()> {
    let d: JoinDenied = serde_json::from_slice(plaintext)?;
    ctx.events.emit(json!({
        "event": "info",
        "message": format!("could not join group (from {from}): {}", d.reason)
    }));
    Ok(())
}

/// Member-side handling of a broadcast `group_event`. Only events from the group's
/// recorded owner are honoured (anti-spoof). Updates the local roster, renders the
/// system line, and — if WE were removed/banned — drops the group locally.
fn process_group_event(
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
    let (plaintext, idx) = receiver.decrypt(&body)?;
    // Replay guard (most important here): without it a relay could re-deliver an
    // OLD owner moderation event and re-apply it — re-add a removed user, roll the
    // access mode back, or delete a victim's group via a stale "you were removed".
    // Megolm authenticates the event but does not reject replays; rejecting any
    // index at-or-below the highest already applied for this owner session closes
    // that. (Owner re-key starts a new session_id, so legitimate new events still
    // pass.)
    if !vault::megolm_accept(&ctx.vault, group_id, from, &receiver.session_id(), idx)? {
        tracing::warn!("dropping replayed group_event (idx {idx}) for {group_id} from {from}");
        return Ok(());
    }
    vault::save_group_in(&ctx.vault, &ctx.vault_key, group_id, from, &receiver)?;

    // Only the recorded owner may issue moderation events (the Megolm `from` is
    // relay-asserted, and we stored `owner` from the key-share).
    let owner_ok = vault::get_group_meta(&ctx.vault, group_id)?
        .map(|m| !m.owner.is_empty() && m.owner == from)
        .unwrap_or(false);
    if !owner_ok {
        tracing::warn!("ignoring group_event from non-owner {from} for {group_id}");
        return Ok(());
    }

    let ev: GroupEvent = serde_json::from_slice(&plaintext)?;
    match ev.kind.as_str() {
        "joined" => {
            // A (re)admitted user — clear any stale local ban/suspension so their
            // fresh key share is accepted again.
            vault::unban_user(&ctx.vault, group_id, &ev.who)?;
            vault::clear_suspension(&ctx.vault, group_id, &ev.who)?;
            vault::add_member(&ctx.vault, group_id, &ev.who)?;
        }
        "removed" | "banned" | "suspended" => {
            if ev.who == ctx.me {
                if ev.kind == "suspended" {
                    // Suspension keeps our local history but we lose the live key
                    // (owner re-keyed); just inform the user.
                    ctx.events.emit(json!({
                        "event": "info",
                        "message": "you were suspended from a group"
                    }));
                } else {
                    // Removed/banned: tear the group down locally and stop (the
                    // chat is gone, so no system line follows).
                    vault::delete_chat(&ctx.vault, group_id)?;
                    ctx.events
                        .emit(vault::build_chats_event(&ctx.vault, &ctx.addr)?);
                    ctx.events.emit(json!({
                        "event": "info",
                        "message": format!("you were {} from a group", ev.kind)
                    }));
                    return Ok(());
                }
            } else {
                // Drop the target from our roster AND forget their inbound session
                // so their future messages stop rendering. Mirror the ban/suspension
                // locally so the target cannot re-inject themselves via a fresh key
                // share (checked in handle_group_key_share).
                vault::remove_member(&ctx.vault, group_id, &ev.who)?;
                vault::delete_group_in(&ctx.vault, group_id, &ev.who)?;
                match ev.kind.as_str() {
                    "banned" => vault::ban_user(&ctx.vault, group_id, &ev.who, client_ts)?,
                    "suspended" => {
                        if let Some(until) = ev.until {
                            vault::suspend_user(&ctx.vault, group_id, &ev.who, until)?;
                        }
                    }
                    _ => {}
                }
            }
        }
        "access" => {
            if let Some(mode) = ev.mode.as_deref() {
                if access_mode::valid(mode) {
                    vault::set_access_mode(&ctx.vault, group_id, mode)?;
                }
            }
        }
        _ => {}
    }

    if let Some(text) = group_event_text(&ev.kind, &ev.who, ev.mode.as_deref().unwrap_or("")) {
        emit_system(&ctx.events, &ctx.vault, group_id, &text, client_ts)?;
    }
    ctx.events
        .emit(vault::build_chats_event(&ctx.vault, &ctx.addr)?);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_key_validation() {
        // A real 32-byte base64 key is accepted; empty/short/garbage are refused
        // (refusing empty closes the "pin empty then re-pin to attacker" bypass).
        let good = cherm_crypto::b64_encode(&[3u8; 32]);
        assert!(valid_pubkey_b64(&good));
        assert!(!valid_pubkey_b64(""));
        assert!(!valid_pubkey_b64(&cherm_crypto::b64_encode(&[1u8; 16]))); // 16 bytes
        assert!(!valid_pubkey_b64("not base64!!"));
    }

    // The join-decision matrix is the heart of group access control; cover every
    // combination that maps to an acceptance criterion.
    #[test]
    fn open_admits_with_valid_key() {
        assert_eq!(
            decide_join(access_mode::OPEN, true, false, false, false),
            JoinDecision::Admit
        );
    }

    #[test]
    fn approval_queues_with_valid_key() {
        assert_eq!(
            decide_join(access_mode::APPROVAL, true, false, false, false),
            JoinDecision::Queue
        );
    }

    #[test]
    fn invite_only_refuses_even_with_valid_key() {
        match decide_join(access_mode::INVITE_ONLY, true, false, false, false) {
            JoinDecision::Deny(r) => assert!(r.contains("invite-only")),
            other => panic!("invite_only must deny, got {other:?}"),
        }
    }

    #[test]
    fn bad_key_is_refused_in_every_mode() {
        for m in access_mode::ALL {
            assert!(matches!(
                decide_join(m, false, false, false, false),
                JoinDecision::Deny(_)
            ));
        }
    }

    #[test]
    fn ban_overrides_valid_key_and_mode() {
        // Even an open group with a valid key must refuse a banned user.
        for m in access_mode::ALL {
            match decide_join(m, true, true, false, false) {
                JoinDecision::Deny(r) => assert!(r.contains("banned")),
                other => panic!("banned must deny in {m}, got {other:?}"),
            }
        }
    }

    #[test]
    fn suspension_overrides_valid_key_and_mode() {
        for m in access_mode::ALL {
            match decide_join(m, true, false, true, false) {
                JoinDecision::Deny(r) => assert!(r.contains("suspended")),
                other => panic!("suspended must deny in {m}, got {other:?}"),
            }
        }
    }

    #[test]
    fn ban_takes_precedence_over_suspension_message() {
        // Both flags set → banned wins (more severe), still a Deny.
        match decide_join(access_mode::OPEN, true, true, true, false) {
            JoinDecision::Deny(r) => assert!(r.contains("banned")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn existing_member_resyncs_regardless_of_mode() {
        for m in access_mode::ALL {
            assert_eq!(
                decide_join(m, true, false, false, true),
                JoinDecision::Admit,
                "member re-sync should admit in {m}"
            );
        }
        // ...but a banned member is still refused.
        assert!(matches!(
            decide_join(access_mode::OPEN, true, true, false, true),
            JoinDecision::Deny(_)
        ));
    }

    // The system-message wording must match the spec examples exactly.
    #[test]
    fn group_event_text_matches_spec() {
        assert_eq!(
            group_event_text("requested", "alice", "").unwrap(),
            "alice requested to join the group."
        );
        assert_eq!(
            group_event_text("joined", "alice", "").unwrap(),
            "alice joined the group."
        );
        assert_eq!(
            group_event_text("removed", "bob", "").unwrap(),
            "bob was removed from the group."
        );
        assert_eq!(
            group_event_text("banned", "bob", "").unwrap(),
            "bob was banned from the group."
        );
        assert_eq!(
            group_event_text("suspended", "bob", "").unwrap(),
            "bob was suspended from the group."
        );
        assert_eq!(
            group_event_text("access", "", "approval").unwrap(),
            "group access mode set to approval."
        );
        assert!(group_event_text("nonsense", "x", "").is_none());
    }
}
