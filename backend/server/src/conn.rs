//! Per-connection handling for the cherm relay.
//!
//! THE CORE INVARIANT — "the relay cannot read messages":
//! Everything in this module operates on opaque, already-encrypted bytes. When
//! a client sends a `Send`, its `payload` is base64 ciphertext produced on the
//! client with keys the server never possesses (Olm / Megolm, see
//! `cherm_crypto`). This module only ever:
//!   * routes that ciphertext to the named recipients (online -> push, offline
//!     -> outbox), copying `payload` verbatim into a `Deliver` frame,
//!   * stores/hands out PUBLIC prekeys and PUBLIC directory records, and
//!   * verifies *signatures* over a random nonce for authentication.
//! It never decrypts, re-encrypts, or inspects `payload`. The relay therefore
//! learns routing metadata (who talks to whom, and when) but never content.
//!
//! Concurrency model for one TCP connection:
//!   * The stream is split (`tokio::io::split`) into a read half and a write
//!     half.
//!   * A dedicated *writer task* drains an `mpsc::UnboundedSender<ServerMsg>`
//!     and serializes each frame with `cherm_proto::write_msg`. ALL outbound
//!     frames — direct replies AND relayed `Deliver`s pushed by *other*
//!     connections — flow through this one channel, so writes never interleave
//!     and ordering is preserved.
//!   * The *reader loop* (this task) reads `ClientMsg`s and dispatches them.
//!   * When the user authenticates, a clone of its sender is published in the
//!     shared online map so other connections can push `Deliver`s to it.

use std::collections::HashMap;
use std::sync::Arc;

use rand::RngCore;
use rusqlite::Connection;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use cherm_proto::{
    errcode, is_reserved_username, read_msg, valid_username, write_msg, ClientMsg, ServerMsg,
};

use crate::attest;
use crate::config;
use crate::db;

/// Map of currently-online username -> a channel to that connection's writer
/// task. Guarded by a tokio (async) mutex because it is touched from `.await`
/// points across many connection tasks.
pub type Online = Arc<tokio::sync::Mutex<HashMap<String, mpsc::UnboundedSender<ServerMsg>>>>;

/// The single shared SQLite connection. A `std` mutex (NOT tokio's): it is held
/// only for the brief, synchronous duration of each SQL statement and never
/// across an `.await`, because `rusqlite::Connection` is not `Sync`.
pub type Db = Arc<std::sync::Mutex<Connection>>;

/// Build an `Error` reply frame.
fn err(code: &str, message: &str) -> ServerMsg {
    ServerMsg::Error {
        code: code.to_string(),
        message: message.to_string(),
    }
}

/// Current unix time in milliseconds (the protocol's timestamp unit).
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Reasons a registration can fail.
enum RegErr {
    Taken,
    KeyExists,
    Db(rusqlite::Error),
}

/// Check uniqueness and insert a new identity, all under the caller's DB lock.
/// Returns the freshly minted uuid on success.
fn register_user(
    conn: &Connection,
    username: &str,
    ed25519: &str,
    curve25519: &str,
    machine_id: &str,
) -> Result<String, RegErr> {
    if db::username_exists(conn, username).map_err(RegErr::Db)? {
        return Err(RegErr::Taken);
    }
    if db::key_exists(conn, ed25519).map_err(RegErr::Db)? {
        return Err(RegErr::KeyExists);
    }
    let uuid = uuid::Uuid::new_v4().to_string();
    db::insert_user(conn, &uuid, username, ed25519, curve25519, machine_id, now_millis())
        .map_err(RegErr::Db)?;
    Ok(uuid)
}

/// Serialize a `Deliver` frame and append it to a recipient's outbox.
///
/// `deliver` already carries only opaque ciphertext, so the stored row is
/// unreadable to the relay.
fn enqueue_frame(db: &Db, recipient: &str, deliver: &ServerMsg, ts: i64) {
    let frame = match serde_json::to_string(deliver) {
        Ok(f) => f,
        Err(e) => {
            error!(error = %e, "failed to serialize Deliver frame for outbox");
            return;
        }
    };
    // Brief, synchronous critical section — no `.await` while the lock is held.
    let conn = db.lock().unwrap();
    if let Err(e) = db::enqueue(&conn, recipient, &frame, ts) {
        error!(error = %e, recipient, "failed to enqueue offline message");
    }
}

/// Flush a user's outbox to its live connection: read the queued frames, send
/// each one, then delete exactly those rows.
///
/// The DB lock is held only for the two SQL phases (read, then delete) and is
/// dropped before the channel sends, per the "never hold the lock across work"
/// rule. The sends themselves are non-blocking `mpsc` pushes.
fn flush_outbox(db: &Db, tx: &mpsc::UnboundedSender<ServerMsg>, username: &str) {
    // Phase 1: read queued frames under the lock.
    let rows = {
        let conn = db.lock().unwrap();
        match db::pending_frames(&conn, username) {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, username, "failed to read outbox");
                return;
            }
        }
    };
    if rows.is_empty() {
        return;
    }

    // Phase 2: send each frame WITHOUT holding the lock. Only rows we actually
    // hand off (or rows that can never be delivered) are marked for deletion, so
    // a dead writer does not cause silent message loss.
    let mut delivered = Vec::with_capacity(rows.len());
    for (id, frame) in rows {
        match serde_json::from_str::<ServerMsg>(&frame) {
            Ok(msg) => {
                // The writer task owns the receiver; a failed send means the
                // connection is gone. Stop and leave this row (and the rest) in
                // the outbox so they flush on the next login / Pull.
                if tx.send(msg).is_err() {
                    break;
                }
                delivered.push(id);
            }
            // A corrupt frame can never be delivered; still mark it for deletion
            // so it does not poison the queue forever.
            Err(e) => {
                warn!(error = %e, id, "dropping unparseable outbox frame");
                delivered.push(id);
            }
        }
    }
    if delivered.is_empty() {
        return;
    }

    // Phase 3: delete exactly the rows we handled, under the lock.
    let conn = db.lock().unwrap();
    if let Err(e) = db::delete_frames(&conn, &delivered) {
        error!(error = %e, username, "failed to delete flushed outbox rows");
    }
}

/// Handle one accepted TCP connection from start to finish.
pub async fn handle(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    online: Online,
    db: Db,
    attestor: attest::Shared,
    config: config::Shared,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);

    // The single outbound channel for this connection (see module docs).
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();

    // Writer task: drains the channel and frames each message onto the socket.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_msg(&mut writer, &msg).await {
                debug!(error = %e, "writer task stopping: socket write failed");
                break;
            }
        }
    });

    // Per-connection authentication state.
    let mut authed: Option<String> = None; // Some(username) once logged in.
    let mut pending_nonce: Option<Vec<u8>> = None; // raw 32-byte challenge nonce.
    // The client's announced build hash (from ClientHello), used for the
    // official-client policy. A client can lie about this, so it is a deterrent.
    let mut client_build_hash: Option<String> = None;

    loop {
        // Read the next frame as untyped JSON first. `read_msg` consumes exactly
        // the framed bytes regardless of shape, so a well-formed-JSON-but-
        // unknown/invalid command leaves the stream in sync and we can recover.
        // A true I/O error, EOF, oversized frame or non-JSON body is fatal for
        // this connection only (it never takes down the server).
        let value: serde_json::Value = match read_msg(&mut reader).await {
            Ok(v) => v,
            Err(e) => {
                debug!(%peer, error = %e, "connection closed / read error");
                break;
            }
        };
        // A single bad or unknown command must not kill the connection: report a
        // bad_request and keep serving instead of disconnecting.
        let msg: ClientMsg = match serde_json::from_value(value) {
            Ok(m) => m,
            Err(e) => {
                warn!(%peer, error = %e, "ignoring malformed or unknown client message");
                let _ = tx.send(err(errcode::BAD_REQUEST, "malformed or unknown message"));
                continue;
            }
        };

        match msg {
            // ---- Attestation: prove what code we run (runs pre-auth) --------
            ClientMsg::AttestRequest { nonce } => {
                let att = attestor.build(&nonce, now_millis());
                match serde_json::to_value(&att) {
                    Ok(attestation) => {
                        let _ = tx.send(ServerMsg::AttestResponse { attestation });
                        debug!(%peer, "served attestation");
                    }
                    Err(e) => {
                        error!(error = %e, "failed to serialize attestation");
                        let _ = tx.send(err(errcode::INTERNAL, "internal server error"));
                    }
                }
            }

            // ---- Client announces its build (official-client policy) --------
            ClientMsg::ClientHello {
                build_hash,
                client_version,
            } => {
                client_build_hash = Some(build_hash.clone());
                debug!(%peer, client_version, "client hello");
                let _ = tx.send(ServerMsg::Ok { detail: None });
            }

            // ---- Public server metadata (operator-supplied, pre-auth) -------
            ClientMsg::GetServerInfo => {
                let _ = tx.send(ServerMsg::ServerInfo {
                    name: config.name.clone(),
                    repo_url: config.repo_url.clone(),
                    description: config.description.clone(),
                    contact: config.contact.clone(),
                    version: attestor.version().to_string(),
                });
            }

            // ---- Registration: create a brand-new immutable identity --------
            ClientMsg::Register {
                username,
                ed25519,
                curve25519,
                machine_id,
            } => {
                // Official-client policy: reject builds the operator doesn't trust.
                if !config.client_allowed(client_build_hash.as_deref()) {
                    let _ = tx.send(err(
                        errcode::UNOFFICIAL_CLIENT,
                        "this server only accepts the official client",
                    ));
                    continue;
                }
                // Reserved system/server identities can never be registered.
                if is_reserved_username(&username) {
                    let _ = tx.send(err(
                        errcode::USERNAME_RESERVED,
                        "that username is reserved for system use",
                    ));
                    continue;
                }
                if !valid_username(&username) {
                    let _ = tx.send(err(
                        errcode::USERNAME_INVALID,
                        "username must be 1-16 chars of [a-zA-Z0-9]",
                    ));
                    continue;
                }
                let result = {
                    let conn = db.lock().unwrap();
                    register_user(&conn, &username, &ed25519, &curve25519, &machine_id)
                };
                match result {
                    Ok(uuid) => {
                        // Registration auto-authenticates this connection.
                        authed = Some(username.clone());
                        online.lock().await.insert(username.clone(), tx.clone());
                        // AuthOk first, then flush — matches the documented login
                        // sequence. A just-claimed username can already have an
                        // outbox if a peer sent to it before it existed.
                        let _ = tx.send(ServerMsg::AuthOk {
                            uuid,
                            username: username.clone(),
                        });
                        flush_outbox(&db, &tx, &username);
                        info!(user = %username, "registered and authenticated");
                    }
                    Err(RegErr::Taken) => {
                        let _ = tx.send(err(errcode::USERNAME_TAKEN, "username already taken"));
                    }
                    Err(RegErr::KeyExists) => {
                        let _ = tx.send(err(
                            errcode::KEY_ALREADY_REGISTERED,
                            "this key is already registered",
                        ));
                    }
                    Err(RegErr::Db(e)) => {
                        error!(error = %e, "database error during registration");
                        let _ = tx.send(err(errcode::INTERNAL, "internal server error"));
                    }
                }
            }

            // ---- Login step 1: hand out a random challenge nonce ------------
            ClientMsg::AuthBegin { username } => {
                let mut nonce = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                pending_nonce = Some(nonce.to_vec());
                let _ = tx.send(ServerMsg::Challenge {
                    nonce: cherm_crypto::b64_encode(&nonce),
                });
                debug!(user = %username, "issued auth challenge");
            }

            // ---- Login step 2: verify the signature over the raw nonce ------
            ClientMsg::AuthFinish {
                username,
                signature,
            } => {
                // Official-client policy also gates login, not just registration.
                if !config.client_allowed(client_build_hash.as_deref()) {
                    let _ = tx.send(err(
                        errcode::UNOFFICIAL_CLIENT,
                        "this server only accepts the official client",
                    ));
                    continue;
                }
                let nonce = match pending_nonce.take() {
                    Some(n) => n,
                    None => {
                        let _ = tx.send(err(errcode::AUTH_FAILED, "no challenge in progress"));
                        continue;
                    }
                };
                let record = {
                    let conn = db.lock().unwrap();
                    db::lookup_user(&conn, &username)
                };
                match record {
                    Ok(Some(rec)) => {
                        // The signature is over the RAW decoded nonce bytes,
                        // verified against the stored Ed25519 public key.
                        if cherm_crypto::verify_ed25519_b64(&rec.ed25519, &nonce, &signature) {
                            authed = Some(username.clone());
                            online.lock().await.insert(username.clone(), tx.clone());
                            let _ = tx.send(ServerMsg::AuthOk {
                                uuid: rec.uuid,
                                username: username.clone(),
                            });
                            // Deliver anything queued while the user was offline.
                            flush_outbox(&db, &tx, &username);
                            info!(user = %username, "authenticated");
                        } else {
                            let _ = tx
                                .send(err(errcode::AUTH_FAILED, "signature verification failed"));
                        }
                    }
                    Ok(None) => {
                        let _ = tx.send(err(errcode::UNKNOWN_USER, "no such user"));
                    }
                    Err(e) => {
                        error!(error = %e, "database error during AuthFinish");
                        let _ = tx.send(err(errcode::INTERNAL, "internal server error"));
                    }
                }
            }

            // ---- Publish one-time prekeys (requires auth) ------------------
            ClientMsg::PublishPrekeys { one_time_keys } => {
                let user = match &authed {
                    Some(u) => u.clone(),
                    None => {
                        let _ = tx
                            .send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                        continue;
                    }
                };
                let result = {
                    let conn = db.lock().unwrap();
                    let mut res = Ok(());
                    for k in &one_time_keys {
                        if let Err(e) = db::insert_prekey(&conn, &user, &k.key_id, &k.curve25519) {
                            res = Err(e);
                            break;
                        }
                    }
                    res
                };
                match result {
                    Ok(()) => {
                        debug!(user = %user, count = one_time_keys.len(), "published prekeys");
                        let _ = tx.send(ServerMsg::Ok { detail: None });
                    }
                    Err(e) => {
                        error!(error = %e, "database error during PublishPrekeys");
                        let _ = tx.send(err(errcode::INTERNAL, "internal server error"));
                    }
                }
            }

            // ---- Fetch a peer's prekey bundle (consumes one OTK) ----------
            ClientMsg::FetchPrekeys { username } => {
                // A fetch CONSUMES one of the target's one-time keys, so it is a
                // state-mutating, resource-consuming operation and must require
                // auth — exactly like PublishPrekeys / Send / Pull. Without this
                // gate an anonymous peer could repeatedly drain any user's OTK
                // pool (a DoS that also forces peers into the no-OTK fallback,
                // weakening session-bootstrap forward secrecy). The documented
                // DM-setup sequence always fetches after AuthOk, so this never
                // breaks a legitimate client.
                if authed.is_none() {
                    let _ = tx.send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                    continue;
                }
                let outcome = {
                    let conn = db.lock().unwrap();
                    db::fetch_bundle(&conn, &username)
                };
                match outcome {
                    Ok(Some((rec, otk))) => {
                        let (one_time_key_id, one_time_key) = match otk {
                            Some((id, key)) => (Some(id), Some(key)),
                            None => (None, None),
                        };
                        let _ = tx.send(ServerMsg::PrekeyBundle {
                            username: rec.username,
                            uuid: rec.uuid,
                            ed25519: rec.ed25519,
                            curve25519: rec.curve25519,
                            one_time_key_id,
                            one_time_key,
                        });
                    }
                    Ok(None) => {
                        let _ = tx.send(err(errcode::UNKNOWN_USER, "no such user"));
                    }
                    Err(e) => {
                        error!(error = %e, "database error during FetchPrekeys");
                        let _ = tx.send(err(errcode::INTERNAL, "internal server error"));
                    }
                }
            }

            // ---- Relay: fan ciphertext out to every recipient -------------
            ClientMsg::Send {
                to,
                msg_type,
                payload,
                group_id,
                client_ts,
            } => {
                let from = match &authed {
                    Some(u) => u.clone(),
                    None => {
                        let _ = tx
                            .send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                        continue;
                    }
                };
                let server_ts = now_millis();
                for recipient in &to {
                    // Never echo a message back to its sender. For a group the
                    // `to` list is every member, which includes the author; the
                    // author already has the plaintext locally, so delivering it
                    // back would duplicate it. Harmless for 1:1 where `to` is
                    // just the peer.
                    if recipient == &from {
                        continue;
                    }
                    // `payload` is copied verbatim — the relay never reads it.
                    let deliver = ServerMsg::Deliver {
                        from: from.clone(),
                        to: to.clone(),
                        msg_type: msg_type.clone(),
                        payload: payload.clone(),
                        group_id: group_id.clone(),
                        server_ts,
                        client_ts,
                    };
                    // Snapshot the recipient's sender (clone) under the lock,
                    // then release it before doing any send.
                    let online_tx = {
                        let guard = online.lock().await;
                        guard.get(recipient).cloned()
                    };
                    match online_tx {
                        Some(rtx) => {
                            // Online: push immediately. If the recipient's writer
                            // died between the lookup and now, fall back to the
                            // outbox so the message is not lost.
                            if rtx.send(deliver.clone()).is_err() {
                                enqueue_frame(&db, recipient, &deliver, server_ts);
                            }
                        }
                        None => {
                            // Offline: queue for their next login / Pull.
                            enqueue_frame(&db, recipient, &deliver, server_ts);
                        }
                    }
                }
                let _ = tx.send(ServerMsg::Ok { detail: None });
            }

            // ---- Pull: deliver queued offline messages on demand ----------
            ClientMsg::Pull => match &authed {
                Some(u) => flush_outbox(&db, &tx, u),
                None => {
                    let _ = tx.send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                }
            },

            // ---- Liveness -------------------------------------------------
            ClientMsg::Ping => {
                let _ = tx.send(ServerMsg::Pong);
            }
        }
    }

    // Cleanup: drop our presence so other connections stop routing to us, and
    // let the writer task finish once its channel is closed. A read error or
    // disconnect must never bring down the whole server.
    if let Some(u) = authed.take() {
        // Only remove our own presence. If the same user re-logged in on a newer
        // connection, the map now holds *that* connection's sender; removing it
        // here would wrongly mark the live connection offline and silently route
        // its messages to the outbox. Compare channel identity before removing.
        let mut guard = online.lock().await;
        if guard
            .get(&u)
            .map(|existing| existing.same_channel(&tx))
            .unwrap_or(false)
        {
            guard.remove(&u);
        }
        drop(guard);
        info!(user = %u, "went offline");
    }
    drop(tx); // closes the channel -> writer task exits its recv loop.
    let _ = writer_task.await;
}
