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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

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

/// Map of currently-online username -> a BOUNDED channel to that connection's
/// writer task. Guarded by a tokio (async) mutex because it is touched from
/// `.await` points across many connection tasks. The channel is bounded so a
/// slow/non-reading recipient cannot make the server buffer unbounded `Deliver`
/// frames in memory: once it is full, senders fall back to the (capped) outbox.
pub type Online = Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<ServerMsg>>>>;

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

/// Max frames we will queue for a single offline recipient before dropping new
/// ones. Bounds the storage a malicious sender can force into one user's outbox.
const MAX_OUTBOX_PER_RECIPIENT: i64 = 10_000;

/// Max TOTAL bytes of queued frames for a single offline recipient. The row cap
/// alone doesn't bound disk (each frame carries ciphertext up to `MAX_PAYLOAD`),
/// so this byte budget is the real per-recipient storage limit.
const MAX_OUTBOX_BYTES_PER_RECIPIENT: i64 = 64 * 1024 * 1024;

/// Capacity of each connection's bounded outbound channel. Generous enough that a
/// healthy client's replies + backlog flush never stall, small enough that a
/// stuck (non-reading) client can only pin `OUTBOUND_CAP * MAX_PAYLOAD` of memory
/// before new deliveries spill to its (capped) outbox instead of growing the heap.
const OUTBOUND_CAP: usize = 512;

/// Max time the writer task will wait on a single socket write before giving up
/// and tearing the connection down. Stops a stalled-reader client from pinning
/// its outbound channel (and thus its memory) indefinitely.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long an UNAUTHENTICATED connection may sit without sending a full frame
/// before we drop it. Bounds slowloris / idle-hold of pre-auth resources.
const PREAUTH_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Idle window for an AUTHENTICATED connection (a live-but-quiet client sends a
/// periodic `Ping` well inside this). Frees the FD/task of a vanished client.
const AUTHED_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Max length of the informational `machine_id` stored at registration. It is a
/// device fingerprint (e.g. a hostname), never huge; bounding it stops a single
/// `Register` from persisting a multi-megabyte row.
const MAX_MACHINE_ID_LEN: usize = 256;

/// Max one-time prekeys accepted in a single `PublishPrekeys` frame.
const MAX_PREKEY_BATCH: usize = 200;

/// Max UNUSED one-time prekeys a user may stockpile on the server. Peers consume
/// these to start Olm sessions; a few hundred is plenty for a healthy client and
/// bounds how much an authenticated user can grow the prekeys table.
const MAX_UNUSED_PREKEYS: i64 = 500;

/// Max length of a prekey `key_id` string (a short base64 id in practice).
const MAX_KEY_ID_LEN: usize = 64;

/// A simple token-bucket rate limiter (per connection). `tokens` refill at `rate`
/// per second up to `burst`; each allowed action costs one token. Used to bound
/// abusive request rates (e.g. draining a peer's one-time keys, or send-spam)
/// without affecting a legitimate client, whose bursts stay well under `burst`.
pub struct RateLimiter {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(rate: f64, burst: f64) -> Self {
        RateLimiter {
            tokens: burst,
            rate,
            burst,
            last: Instant::now(),
        }
    }

    /// Refill based on elapsed time and consume one token. Returns false (deny)
    /// when the bucket is empty.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-TARGET rate gate for FetchPrekeys, SHARED across all connections. Keyed by
/// the fetched (victim) username so the total rate at which ANY user's one-time
/// keys can be consumed is bounded — no matter how many connections or throwaway
/// accounts an attacker cycles through (a per-connection limiter resets on
/// reconnect and can be bypassed). Because legitimate group setup fetches DISTINCT
/// members (one per target), it never trips this gate.
pub type FetchGate = Arc<std::sync::Mutex<HashMap<String, RateLimiter>>>;

/// Construct an empty fetch gate (one per server).
pub fn new_fetch_gate() -> FetchGate {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

/// Per-target OTK fetch limits + the map-size cap (idle buckets are pruned when
/// exceeded so the map can't grow without bound).
const FETCH_RATE: f64 = 4.0; // 4/s sustained per victim
const FETCH_BURST: f64 = 30.0; // burst 30
const FETCH_GATE_CAP: usize = 50_000;

/// Consume one token from `target`'s bucket (creating it on first use). Prunes
/// idle (full) buckets when the map grows past the cap.
fn fetch_allowed(gate: &FetchGate, target: &str) -> bool {
    let mut map = gate.lock().unwrap();
    if map.len() > FETCH_GATE_CAP {
        // A bucket at full capacity is idle; dropping it is equivalent to never
        // having seen the target (a fresh bucket also starts full).
        map.retain(|_, rl| rl.tokens < rl.burst);
    }
    map.entry(target.to_string())
        .or_insert_with(|| RateLimiter::new(FETCH_RATE, FETCH_BURST))
        .allow()
}

/// True if `s` is a well-formed base64 32-byte public key (Ed25519 / Curve25519).
/// Rejects empty / garbage identity material at registration so it never enters
/// the directory and can't poison a peer's trust-on-first-use pinning.
fn valid_pubkey_b64(s: &str) -> bool {
    !s.is_empty() && matches!(cherm_crypto::b64_decode(s), Ok(b) if b.len() == 32)
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
    db::insert_user(
        conn,
        &uuid,
        username,
        ed25519,
        curve25519,
        machine_id,
        now_millis(),
    )
    .map_err(RegErr::Db)?;
    Ok(uuid)
}

/// Append a PRE-SERIALIZED `Deliver` frame to a recipient's outbox. The frame is
/// identical for every recipient of a `Send`, so the caller serializes it once and
/// reuses the `&str` across recipients (O(N), not O(N^2)).
///
/// The frame carries only opaque ciphertext, so the stored row is unreadable to
/// the relay.
fn enqueue_frame_str(db: &Db, recipient: &str, frame: &str, ts: i64) -> bool {
    // Brief, synchronous critical section — no `.await` while the lock is held.
    // The cap check lives inside this same critical section to avoid races where
    // concurrent senders all observe room and then all insert.
    let conn = db.lock().unwrap();
    match db::enqueue_if_under_cap(
        &conn,
        recipient,
        frame,
        ts,
        MAX_OUTBOX_PER_RECIPIENT,
        MAX_OUTBOX_BYTES_PER_RECIPIENT,
    ) {
        Ok(true) => true,
        Ok(false) => {
            warn!(recipient, "outbox full (rows or bytes); dropping frame");
            false
        }
        Err(e) => {
            error!(error = %e, recipient, "failed to enqueue offline message");
            false
        }
    }
}

/// Flush a user's outbox to its live connection: read the queued frames, send
/// each one, then delete exactly those rows.
///
/// The DB lock is held only for the two SQL phases (read, then delete) and is
/// dropped before the channel sends, per the "never hold the lock across work"
/// rule. The sends themselves are non-blocking `mpsc` pushes.
async fn flush_outbox(db: &Db, tx: &mpsc::Sender<ServerMsg>, username: &str) {
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
    //
    // We use the bounded channel's async `send` here (backpressure): this is the
    // connection's OWN task draining ITS OWN backlog, so awaiting paces the flush
    // to the writer/socket instead of buffering the whole queue in memory. A
    // stalled client unblocks when the writer's WRITE_TIMEOUT closes the channel,
    // leaving the remaining rows in the outbox for the next login / Pull.
    let mut delivered = Vec::with_capacity(rows.len());
    for (id, frame) in rows {
        match serde_json::from_str::<ServerMsg>(&frame) {
            Ok(msg) => {
                // The writer task owns the receiver; a failed send means the
                // connection is gone. Stop and leave this row (and the rest) in
                // the outbox so they flush on the next login / Pull.
                if tx.send(msg).await.is_err() {
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
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    online: Online,
    db: Db,
    attestor: attest::Shared,
    config: config::Shared,
    fetch_gate: FetchGate,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);

    // The single, BOUNDED outbound channel for this connection (see module docs).
    // Bounded so a slow/non-reading client cannot make us buffer unbounded frames.
    let (tx, mut rx) = mpsc::channel::<ServerMsg>(OUTBOUND_CAP);

    // Writer task: drains the channel and frames each message onto the socket.
    // Each write has a deadline; a stalled socket tears the connection down rather
    // than letting the outbound channel (and its memory) stay pinned forever.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match tokio::time::timeout(WRITE_TIMEOUT, write_msg(&mut writer, &msg)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    debug!(error = %e, "writer task stopping: socket write failed");
                    break;
                }
                Err(_) => {
                    debug!("writer task stopping: socket write timed out (stalled reader)");
                    break;
                }
            }
        }
    });

    // Per-connection authentication state.
    let mut authed: Option<String> = None; // Some(username) once logged in.
    let mut pending_nonce: Option<Vec<u8>> = None; // raw 32-byte challenge nonce.
                                                   // The client's announced build hash (from ClientHello), used for the
                                                   // official-client policy. A client can lie about this, so it is a deterrent.
    let mut client_build_hash: Option<String> = None;
    // FetchPrekeys is gated by the SHARED per-target `fetch_gate` (bounds OTK drain
    // of any victim across all connections). Send is throttled per-connection to
    // curb spam / outbox flooding. Legitimate clients never hit either (DM setup is
    // a handful of fetches across distinct targets; chat is human-paced).
    let mut send_limiter = RateLimiter::new(20.0, 60.0); // ~20/s, burst 60
                                                         // Publishing prekeys is infrequent for a healthy client (a small top-up now
                                                         // and then), so a tight bucket curbs an authenticated client trying to grow
                                                         // the prekeys table.
    let mut prekey_limiter = RateLimiter::new(1.0, 10.0); // ~1/s, burst 10
                                                          // Every PRE-AUTH request (attestation, hello, server-info, the auth handshake)
                                                          // is metered so an unauthenticated peer cannot flood cheap-but-nonzero work
                                                          // (signing, exe-hash, account creation) or hold the connection busy. A real
                                                          // client sends only a handful before authenticating.
    let mut preauth_limiter = RateLimiter::new(10.0, 30.0); // ~10/s, burst 30

    loop {
        // Read the next frame with a DEADLINE. Without one, a connection that opens
        // the socket and then stalls (slowloris) parks this task forever holding an
        // FD + task + its pre-allocated read buffer. Unauthenticated connections get
        // a short deadline (just long enough for the handshake); once authenticated,
        // a longer idle window tolerates a quiet-but-live client (which sends Ping).
        let read_deadline = if authed.is_some() {
            AUTHED_IDLE_TIMEOUT
        } else {
            PREAUTH_READ_TIMEOUT
        };
        let read = tokio::time::timeout(read_deadline, read_msg(&mut reader));
        let value: serde_json::Value = match read.await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                debug!(%peer, error = %e, "connection closed / read error");
                break;
            }
            Err(_) => {
                debug!(%peer, "connection idle past deadline; closing");
                break;
            }
        };
        // A single bad or unknown command must not kill the connection: report a
        // bad_request and keep serving instead of disconnecting.
        let msg: ClientMsg = match serde_json::from_value(value) {
            Ok(m) => m,
            Err(e) => {
                warn!(%peer, error = %e, "ignoring malformed or unknown client message");
                let _ = tx.try_send(err(errcode::BAD_REQUEST, "malformed or unknown message"));
                continue;
            }
        };

        // Meter every pre-auth request. Authenticated traffic is governed by the
        // per-action limiters (send / prekey / fetch) below; this caps the work an
        // UNauthenticated peer can force (attestation signing, account creation,
        // signature verification) so the handshake surface can't be flooded.
        if authed.is_none() && !preauth_limiter.allow() {
            warn!(%peer, "rate-limited pre-auth request");
            let _ = tx.try_send(err("rate_limited", "too many requests; slow down"));
            continue;
        }

        match msg {
            // ---- Attestation: prove what code we run (runs pre-auth) --------
            ClientMsg::AttestRequest { nonce } => {
                let att = attestor.build(&nonce, now_millis());
                match serde_json::to_value(&att) {
                    Ok(attestation) => {
                        let _ = tx.try_send(ServerMsg::AttestResponse { attestation });
                        debug!(%peer, "served attestation");
                    }
                    Err(e) => {
                        error!(error = %e, "failed to serialize attestation");
                        let _ = tx.try_send(err(errcode::INTERNAL, "internal server error"));
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
                let _ = tx.try_send(ServerMsg::Ok { detail: None });
            }

            // ---- Public server metadata (operator-supplied, pre-auth) -------
            ClientMsg::GetServerInfo => {
                let _ = tx.try_send(ServerMsg::ServerInfo {
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
                // One connection == one identity. Re-registering after we're already
                // authenticated would leak a second `online` mapping (and keep a
                // sender clone alive so the writer task never exits), so refuse it.
                if authed.is_some() {
                    let _ = tx.try_send(err(
                        errcode::ALREADY_AUTHENTICATED,
                        "this connection is already authenticated",
                    ));
                    continue;
                }
                // Official-client policy: reject builds the operator doesn't trust.
                if !config.client_allowed(client_build_hash.as_deref()) {
                    let _ = tx.try_send(err(
                        errcode::UNOFFICIAL_CLIENT,
                        "this server only accepts the official client",
                    ));
                    continue;
                }
                // Bound the informational device fingerprint so a single Register
                // can't persist a multi-megabyte row.
                if machine_id.len() > MAX_MACHINE_ID_LEN {
                    let _ = tx.try_send(err(errcode::BAD_REQUEST, "machine_id too long"));
                    continue;
                }
                // Reserved system/server identities can never be registered.
                if is_reserved_username(&username) {
                    let _ = tx.try_send(err(
                        errcode::USERNAME_RESERVED,
                        "that username is reserved for system use",
                    ));
                    continue;
                }
                if !valid_username(&username) {
                    let _ = tx.try_send(err(
                        errcode::USERNAME_INVALID,
                        "username must be 1-16 chars of [a-zA-Z0-9]",
                    ));
                    continue;
                }
                // Reject malformed/empty identity keys so junk identity material
                // never enters the directory (an empty ed25519 could later be used
                // to poison a peer's trust-on-first-use pinning).
                if !valid_pubkey_b64(&ed25519) || !valid_pubkey_b64(&curve25519) {
                    let _ = tx.try_send(err(
                        errcode::BAD_REQUEST,
                        "ed25519/curve25519 must be base64 32-byte public keys",
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
                        let _ = tx.try_send(ServerMsg::AuthOk {
                            uuid,
                            username: username.clone(),
                        });
                        flush_outbox(&db, &tx, &username).await;
                        info!(user = %username, "registered and authenticated");
                    }
                    Err(RegErr::Taken) => {
                        let _ = tx.try_send(err(errcode::USERNAME_TAKEN, "username already taken"));
                    }
                    Err(RegErr::KeyExists) => {
                        let _ = tx.try_send(err(
                            errcode::KEY_ALREADY_REGISTERED,
                            "this key is already registered",
                        ));
                    }
                    Err(RegErr::Db(e)) => {
                        error!(error = %e, "database error during registration");
                        let _ = tx.try_send(err(errcode::INTERNAL, "internal server error"));
                    }
                }
            }

            // ---- Login step 1: hand out a random challenge nonce ------------
            ClientMsg::AuthBegin { username } => {
                let mut nonce = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                pending_nonce = Some(nonce.to_vec());
                let _ = tx.try_send(ServerMsg::Challenge {
                    nonce: cherm_crypto::b64_encode(&nonce),
                });
                debug!(user = %username, "issued auth challenge");
            }

            // ---- Login step 2: verify the signature over the raw nonce ------
            ClientMsg::AuthFinish {
                username,
                signature,
            } => {
                // One connection == one identity (see Register). Refuse a second
                // login on a connection that is already authenticated.
                if authed.is_some() {
                    let _ = tx.try_send(err(
                        errcode::ALREADY_AUTHENTICATED,
                        "this connection is already authenticated",
                    ));
                    continue;
                }
                // Official-client policy also gates login, not just registration.
                if !config.client_allowed(client_build_hash.as_deref()) {
                    let _ = tx.try_send(err(
                        errcode::UNOFFICIAL_CLIENT,
                        "this server only accepts the official client",
                    ));
                    continue;
                }
                let nonce = match pending_nonce.take() {
                    Some(n) => n,
                    None => {
                        let _ = tx.try_send(err(errcode::AUTH_FAILED, "no challenge in progress"));
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
                            let _ = tx.try_send(ServerMsg::AuthOk {
                                uuid: rec.uuid,
                                username: username.clone(),
                            });
                            // Deliver anything queued while the user was offline.
                            flush_outbox(&db, &tx, &username).await;
                            info!(user = %username, "authenticated");
                        } else {
                            let _ =
                                tx.try_send(err(errcode::AUTH_FAILED, "signature verification failed"));
                        }
                    }
                    Ok(None) => {
                        let _ = tx.try_send(err(errcode::UNKNOWN_USER, "no such user"));
                    }
                    Err(e) => {
                        error!(error = %e, "database error during AuthFinish");
                        let _ = tx.try_send(err(errcode::INTERNAL, "internal server error"));
                    }
                }
            }

            // ---- Publish one-time prekeys (requires auth) ------------------
            ClientMsg::PublishPrekeys { one_time_keys } => {
                let user = match &authed {
                    Some(u) => u.clone(),
                    None => {
                        let _ =
                            tx.try_send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                        continue;
                    }
                };
                // Rate-limit (publishing is infrequent for a real client).
                if !prekey_limiter.allow() {
                    let _ = tx.try_send(err("rate_limited", "publishing prekeys too fast; slow down"));
                    continue;
                }
                // Bound the batch size so one frame can't carry a huge array.
                if one_time_keys.len() > MAX_PREKEY_BATCH {
                    let _ = tx.try_send(err(errcode::BAD_REQUEST, "too many prekeys in one batch"));
                    continue;
                }
                // Validate every key BEFORE any DB write: a short non-empty id and a
                // well-formed 32-byte base64 Curve25519 public key. Junk keys must
                // never enter the table (they'd also poison fetched bundles).
                if one_time_keys.iter().any(|k| {
                    k.key_id.is_empty()
                        || k.key_id.len() > MAX_KEY_ID_LEN
                        || !valid_pubkey_b64(&k.curve25519)
                }) {
                    let _ = tx.try_send(err(
                        errcode::BAD_REQUEST,
                        "each prekey needs a short key_id and a base64 32-byte curve25519 key",
                    ));
                    continue;
                }
                // Enforce the per-user UNUSED cap atomically under the DB lock, then
                // insert (idempotent on (username,key_id)). The count + insert share
                // one critical section so concurrent publishes can't race past the cap.
                enum PubResult {
                    Ok,
                    OverCap,
                    Db(rusqlite::Error),
                }
                let result = {
                    let conn = db.lock().unwrap();
                    match db::count_unused_prekeys(&conn, &user) {
                        Ok(existing) if existing + one_time_keys.len() as i64 > MAX_UNUSED_PREKEYS => {
                            PubResult::OverCap
                        }
                        Ok(_) => {
                            let mut res = PubResult::Ok;
                            for k in &one_time_keys {
                                if let Err(e) =
                                    db::insert_prekey(&conn, &user, &k.key_id, &k.curve25519)
                                {
                                    res = PubResult::Db(e);
                                    break;
                                }
                            }
                            res
                        }
                        Err(e) => PubResult::Db(e),
                    }
                };
                match result {
                    PubResult::Ok => {
                        debug!(user = %user, count = one_time_keys.len(), "published prekeys");
                        let _ = tx.try_send(ServerMsg::Ok { detail: None });
                    }
                    PubResult::OverCap => {
                        let _ = tx.try_send(err(
                            "prekeys_full",
                            "you already have the maximum number of unused prekeys stored",
                        ));
                    }
                    PubResult::Db(e) => {
                        error!(error = %e, "database error during PublishPrekeys");
                        let _ = tx.try_send(err(errcode::INTERNAL, "internal server error"));
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
                    let _ = tx.try_send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                    continue;
                }
                // Throttle per TARGET across all connections: each fetch consumes a
                // one-time key, so an unbounded rate (even via reconnecting or many
                // accounts) would let a peer drain a victim's OTK pool.
                if !fetch_allowed(&fetch_gate, &username) {
                    warn!(%peer, target = %username, "rate-limited FetchPrekeys");
                    let _ = tx.try_send(err("rate_limited", "too many prekey fetches for that user; slow down"));
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
                        let _ = tx.try_send(ServerMsg::PrekeyBundle {
                            username: rec.username,
                            uuid: rec.uuid,
                            ed25519: rec.ed25519,
                            curve25519: rec.curve25519,
                            one_time_key_id,
                            one_time_key,
                        });
                    }
                    Ok(None) => {
                        let _ = tx.try_send(err(errcode::UNKNOWN_USER, "no such user"));
                    }
                    Err(e) => {
                        error!(error = %e, "database error during FetchPrekeys");
                        let _ = tx.try_send(err(errcode::INTERNAL, "internal server error"));
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
                        let _ =
                            tx.try_send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                        continue;
                    }
                };
                // Throttle send to curb spam / outbox flooding.
                if !send_limiter.allow() {
                    warn!(%peer, "rate-limited Send");
                    let _ = tx.try_send(err("rate_limited", "sending too fast; slow down"));
                    continue;
                }
                // Bound the ciphertext size: every legitimate Olm/Megolm payload is
                // far below this, and capping it removes a per-message amplification
                // vector (forcing a recipient to buffer near-`MAX_FRAME` blobs).
                if payload.len() > cherm_proto::MAX_PAYLOAD {
                    let _ = tx.try_send(err(errcode::BAD_REQUEST, "payload too large"));
                    continue;
                }
                // Bound the fan-out: one rate-limited Send must not address an
                // unbounded recipient list (the existence check + enqueue per
                // recipient is the work an attacker would amplify).
                if to.len() > cherm_proto::MAX_RECIPIENTS {
                    let _ = tx.try_send(err(errcode::BAD_REQUEST, "too many recipients"));
                    continue;
                }
                let server_ts = now_millis();
                // Build the Deliver ONCE: it is identical for every recipient (the
                // recipient is the outbox row key, not a frame field), so serialize
                // the offline frame a single time and reuse it — O(N), not O(N^2).
                let deliver = ServerMsg::Deliver {
                    from: from.clone(),
                    to: to.clone(),
                    msg_type: msg_type.clone(),
                    payload: payload.clone(),
                    group_id: group_id.clone(),
                    server_ts,
                    client_ts,
                };
                let offline_frame = match serde_json::to_string(&deliver) {
                    Ok(f) => f,
                    Err(e) => {
                        error!(error = %e, "failed to serialize Deliver frame");
                        let _ = tx.try_send(err(errcode::INTERNAL, "internal server error"));
                        continue;
                    }
                };
                let mut delivered_any = false;
                let mut had_unknown = false;
                // Dedup recipients (and drop the author): listing a user N times must
                // not cost N enqueues / pushes.
                let mut seen = HashSet::new();
                for recipient in to.iter().filter(|r| seen.insert((*r).clone())) {
                    // Never echo a message back to its sender (the author already has
                    // the plaintext locally; for a 1:1 chat `to` is just the peer).
                    if recipient == &from {
                        continue;
                    }
                    // Snapshot the recipient's sender (clone) under the lock, and
                    // while we hold it, confirm the recipient actually exists. We
                    // must NEVER enqueue for a non-existent username: that row could
                    // never be drained (the user can't log in), so it is permanent
                    // junk an attacker can use to exhaust storage.
                    let (online_tx, exists) = {
                        let guard_online = online.lock().await;
                        let rtx = guard_online.get(recipient).cloned();
                        let conn = db.lock().unwrap();
                        let exists = db::username_exists(&conn, recipient).unwrap_or(false);
                        (rtx, exists)
                    };
                    if !exists {
                        had_unknown = true;
                        continue;
                    }
                    match online_tx {
                        Some(rtx) => {
                            // Online: push immediately, NON-BLOCKING. If the
                            // recipient's bounded channel is full (slow / non-reading
                            // client) or its writer died, fall back to the capped
                            // outbox so we neither block this sender on the recipient's
                            // slowness nor buffer unbounded frames in memory for it.
                            match rtx.try_send(deliver.clone()) {
                                Ok(()) => delivered_any = true,
                                Err(_) => {
                                    delivered_any |=
                                        enqueue_frame_str(&db, recipient, &offline_frame, server_ts);
                                }
                            }
                        }
                        None => {
                            // Offline: queue for their next login / Pull, unless
                            // their outbox is already at the per-recipient cap.
                            delivered_any |=
                                enqueue_frame_str(&db, recipient, &offline_frame, server_ts);
                        }
                    }
                }
                // If we routed to nobody and at least one target was an unknown
                // user, tell the sender — don't silently accept junk.
                if !delivered_any && had_unknown {
                    let _ = tx.try_send(err(errcode::UNKNOWN_USER, "no such recipient"));
                } else {
                    let _ = tx.try_send(ServerMsg::Ok { detail: None });
                }
            }

            // ---- Pull: deliver queued offline messages on demand ----------
            ClientMsg::Pull => match &authed {
                Some(u) => flush_outbox(&db, &tx, u).await,
                None => {
                    let _ = tx.try_send(err(errcode::NOT_AUTHENTICATED, "register or log in first"));
                }
            },

            // ---- Liveness -------------------------------------------------
            ClientMsg::Ping => {
                let _ = tx.try_send(ServerMsg::Pong);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_validation_rejects_malformed() {
        assert!(valid_pubkey_b64(&cherm_crypto::b64_encode(&[5u8; 32])));
        assert!(!valid_pubkey_b64("")); // empty
        assert!(!valid_pubkey_b64(&cherm_crypto::b64_encode(&[5u8; 31]))); // wrong len
        assert!(!valid_pubkey_b64("@@@not-base64@@@"));
    }

    #[test]
    fn fetch_gate_throttles_one_target_but_not_distinct_targets() {
        let gate = new_fetch_gate();

        // A single victim can be fetched at most `burst` times before throttling,
        // bounding OTK drain of that user (shared across connections).
        let mut allowed = 0;
        for _ in 0..((FETCH_BURST as usize) + 20) {
            if fetch_allowed(&gate, "victim") {
                allowed += 1;
            }
        }
        assert_eq!(allowed, FETCH_BURST as usize, "one target is capped at the burst");

        // Fetching MANY DISTINCT targets (e.g. setting up a large group) is never
        // throttled — each target has its own bucket. This is the regression guard.
        for i in 0..500 {
            assert!(
                fetch_allowed(&gate, &format!("member{i}")),
                "distinct targets must not be throttled (group setup)"
            );
        }
    }
}
