//! Per-server encrypted vault (`~/.cherm/servers/<server_id>/vault.db`).
//!
//! Each server gets its OWN [SQLCipher] database (PROTOCOL.md section 5 /
//! PRIVACY.md). The connection is opened then IMMEDIATELY keyed with the
//! per-server vault key (`PRAGMA key`) before any other SQL runs, so nothing
//! readable — not even metadata — ever hits disk.
//!
//! The vodozemac `Account` and every Olm/Megolm session live here as
//! **encrypted pickles** (the pickle helpers AEAD-encrypt with the same vault
//! key; inside SQLCipher this is defense-in-depth). Ratchets mutate on every
//! encrypt/decrypt, so callers RE-PERSIST after each operation. The vault is the
//! single source of truth: helpers load owned objects, the caller operates, then
//! persists — no live session is held across an `.await`.
//!
//! CONCURRENCY: a `rusqlite::Connection` is `Send` but not `Sync`, so it is
//! wrapped in `Arc<std::sync::Mutex<Connection>>`. Every helper is synchronous:
//! it locks, does its work, and releases the lock before returning. None of
//! these functions are `async`, so the guard is NEVER held across an `.await`.

use anyhow::Result;
use cherm_crypto::{Device, GroupReceiver, GroupSender, OlmSession};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Shared, thread-safe handle to one server's encrypted vault.
pub type Vault = Arc<Mutex<Connection>>;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS contacts(
    username   TEXT PRIMARY KEY,
    uuid       TEXT,
    ed25519    TEXT,
    curve25519 TEXT
);
CREATE TABLE IF NOT EXISTS olm_sessions(
    peer   TEXT PRIMARY KEY,
    pickle BLOB
);
CREATE TABLE IF NOT EXISTS chats(
    id         TEXT PRIMARY KEY,
    kind       TEXT,
    title      TEXT,
    created_ts INTEGER
);
CREATE TABLE IF NOT EXISTS chat_members(
    chat_id  TEXT,
    username TEXT
);
CREATE TABLE IF NOT EXISTS group_out(
    group_id TEXT PRIMARY KEY,
    pickle   BLOB
);
CREATE TABLE IF NOT EXISTS group_in(
    group_id TEXT,
    sender   TEXT,
    pickle   BLOB,
    PRIMARY KEY(group_id, sender)
);
CREATE TABLE IF NOT EXISTS messages(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id  TEXT,
    sender   TEXT,
    body     TEXT,
    ts       INTEGER,
    outgoing INTEGER,
    -- LOCAL receipt time (unix millis), stamped by us at insert. `ts` is the
    -- sender's client_ts which, for an inbound message, rides OUTSIDE the
    -- Olm/Megolm ciphertext and is therefore relay-controllable — a relay could
    -- set it far-future/past to pin or bury a message in the sorted view. Ordering
    -- uses this trusted column instead; `ts` is kept only as a display label.
    recv_ts  INTEGER NOT NULL DEFAULT 0
);
-- Group access-control metadata (one row per group chat). `group_key` is the
-- 8-char invite/access handle; UNIQUE makes duplicate keys impossible at the DB
-- level (the application also retries on collision). `owner` is the creator's
-- username — the authority that gates Megolm key distribution. `access_mode` is
-- one of open|approval|invite_only.
CREATE TABLE IF NOT EXISTS groups(
    group_id    TEXT PRIMARY KEY,
    group_key   TEXT NOT NULL UNIQUE,
    access_mode TEXT NOT NULL DEFAULT 'open',
    owner       TEXT NOT NULL DEFAULT ''
);
-- Belt-and-suspenders explicit unique index (the column UNIQUE already creates
-- one; this documents the invariant and survives schema edits).
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_group_key ON groups(group_key);
-- Users banned from a group: permanently blocked from (re)joining via any link.
CREATE TABLE IF NOT EXISTS group_bans(
    group_id TEXT NOT NULL,
    username TEXT NOT NULL,
    ts       INTEGER NOT NULL,
    PRIMARY KEY(group_id, username)
);
-- Users temporarily suspended from a group. The suspension is active while
-- `now < until_ts` (unix millis); after it expires the row no longer blocks.
CREATE TABLE IF NOT EXISTS group_suspensions(
    group_id TEXT NOT NULL,
    username TEXT NOT NULL,
    until_ts INTEGER NOT NULL,
    PRIMARY KEY(group_id, username)
);
-- Pending join requests awaiting owner approval (approval-mode groups).
CREATE TABLE IF NOT EXISTS group_join_requests(
    group_id TEXT NOT NULL,
    username TEXT NOT NULL,
    ts       INTEGER NOT NULL,
    PRIMARY KEY(group_id, username)
);
-- Megolm REPLAY guard. Megolm authenticates a message but does NOT, by itself,
-- reject a re-delivered (replayed) ciphertext — vodozemac will happily decrypt the
-- same frame twice. A malicious/compromised relay can record a valid `Deliver`
-- and re-send it later to duplicate a message or, worse, re-apply an old owner
-- moderation event (re-add a removed user, roll back the access mode, or delete a
-- victim's group via a stale "removed you"). We therefore record the highest
-- Megolm `message_index` we have APPLIED per inbound sender session and reject
-- anything at-or-below it. Keyed by `session_id` so a legitimate owner re-key (a
-- brand-new session that restarts the index at 0) is unaffected, and so an
-- owner re-install (new session) is never falsely rejected. Frames arrive in
-- order (outbox is drained id-ASC, online pushes are sequential), so a fresh
-- message always has a strictly greater index — no legitimate message is dropped.
CREATE TABLE IF NOT EXISTS megolm_seen(
    group_id   TEXT NOT NULL,
    sender     TEXT NOT NULL,
    session_id TEXT NOT NULL,
    max_index  INTEGER NOT NULL,
    PRIMARY KEY(group_id, sender, session_id)
);
"#;

/// Open (or create) the SQLCipher vault at `path`, key it with `vault_key`
/// IMMEDIATELY (before any SQL), then ensure the schema exists.
pub fn open_vault(path: &Path, vault_key: &[u8; 32]) -> Result<Connection> {
    let conn = Connection::open(path)?;
    // Key the database FIRST — every subsequent statement is encrypted/decrypted
    // with this raw key. On an existing vault a wrong key makes the first SQL
    // statement fail (which is the desired tamper/wrong-master behaviour).
    let key = cherm_crypto::vault_key_sqlcipher(vault_key);
    conn.pragma_update(None, "key", key.as_str())?;
    conn.execute_batch(SCHEMA)?;
    migrate_recv_ts(&conn)?;
    backfill_group_keys(&conn)?;
    Ok(conn)
}

/// Add the `recv_ts` column to an OLDER `messages` table (created before trusted
/// ordering existed) and backfill it from `ts` so existing history keeps its
/// order. On a fresh vault the column is already in the schema, so the `ALTER`
/// fails with "duplicate column" and is harmless. Idempotent.
fn migrate_recv_ts(conn: &Connection) -> Result<()> {
    // Ignore the duplicate-column error on vaults that already have it.
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN recv_ts INTEGER NOT NULL DEFAULT 0", []);
    // Backfill: rows inserted before this column existed sort by their old `ts`.
    conn.execute("UPDATE messages SET recv_ts = ts WHERE recv_ts = 0", [])?;
    Ok(())
}

/// Migration/backfill: every pre-existing group chat that lacks a `groups` row
/// (created before group access control existed) gets a freshly-minted unique
/// 8-char key, `access_mode = 'open'` and an empty `owner` (the real owner is
/// unknown for legacy groups, so moderation stays disabled there — fail-safe).
/// New groups always create their `groups` row up front, so this is a one-time
/// catch-up for upgraded vaults. Idempotent.
fn backfill_group_keys(conn: &Connection) -> Result<()> {
    let ids: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT c.id FROM chats c
             LEFT JOIN groups g ON g.group_id = c.id
             WHERE c.kind = 'group' AND g.group_id IS NULL",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for id in ids {
        insert_group_with_retry(conn, &id, "open", "")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// meta(key, value) — username, uuid, server addr, account_pickle (base64)
// ---------------------------------------------------------------------------

pub fn meta_get(v: &Vault, key: &str) -> Result<Option<String>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let value = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
            r.get::<_, String>(0)
        })
        .optional()?;
    Ok(value)
}

pub fn meta_set(v: &Vault, key: &str, value: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// account (vodozemac Device) — stored as a base64 encrypted pickle in meta
// ---------------------------------------------------------------------------

pub fn save_account(v: &Vault, vk: &[u8; 32], device: &Device) -> Result<()> {
    let blob = device.to_pickle_encrypted(vk)?;
    meta_set(v, "account_pickle", &cherm_crypto::b64_encode(&blob))
}

pub fn load_account(v: &Vault, vk: &[u8; 32]) -> Result<Option<Device>> {
    match meta_get(v, "account_pickle")? {
        Some(s) => {
            let blob = cherm_crypto::b64_decode(&s)?;
            Ok(Some(Device::from_pickle_encrypted(vk, &blob)?))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// contacts(username, uuid, ed25519, curve25519)
// ---------------------------------------------------------------------------

/// Result of comparing an incoming identity key against what we've pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCheck {
    /// We have never seen this username — safe to pin (TOFU first contact).
    FirstContact,
    /// The incoming Ed25519 matches the one we pinned earlier.
    Match,
    /// The incoming Ed25519 DIFFERS from the pinned one — a key substitution
    /// (possible MITM by the relay). Callers MUST refuse to use the new key.
    Conflict,
}

/// Compare a peer's server-supplied Ed25519 identity key against the one we have
/// pinned (trust-on-first-use). The Ed25519 key is the immutable identity anchor;
/// a change for a known username means the relay tried to substitute keys.
pub fn check_identity(v: &Vault, username: &str, ed25519: &str) -> Result<IdentityCheck> {
    match get_contact_ed(v, username)? {
        None => Ok(IdentityCheck::FirstContact),
        Some(e) if e.is_empty() => Ok(IdentityCheck::FirstContact),
        Some(e) if e == ed25519 => Ok(IdentityCheck::Match),
        Some(_) => Ok(IdentityCheck::Conflict),
    }
}

/// Insert or update a contact's public directory record.
///
/// SECURITY (TOFU pinning): the Ed25519 identity key is pinned on first contact
/// and NEVER overwritten with a different value — a malicious/compromised relay
/// must not be able to substitute a peer's identity. The Curve25519 key is only
/// refreshed while the Ed25519 still matches (so legit curve rotation works but a
/// substituted bundle can't poison the session key). Callers that consume a
/// server bundle should additionally gate on [`check_identity`] and abort on a
/// [`IdentityCheck::Conflict`] before establishing a session.
pub fn upsert_contact(
    v: &Vault,
    username: &str,
    uuid: &str,
    ed25519: &str,
    curve25519: &str,
) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO contacts(username, uuid, ed25519, curve25519) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(username) DO UPDATE SET
            uuid = excluded.uuid,
            ed25519 = CASE
                WHEN contacts.ed25519 IS NULL OR contacts.ed25519 = ''
                    THEN excluded.ed25519
                ELSE contacts.ed25519
            END,
            curve25519 = CASE
                WHEN contacts.ed25519 IS NULL OR contacts.ed25519 = ''
                     OR contacts.ed25519 = excluded.ed25519
                    THEN excluded.curve25519
                ELSE contacts.curve25519
            END",
        params![username, uuid, ed25519, curve25519],
    )?;
    Ok(())
}

pub fn get_contact_curve(v: &Vault, username: &str) -> Result<Option<String>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let curve = conn
        .query_row(
            "SELECT curve25519 FROM contacts WHERE username = ?1",
            params![username],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    Ok(curve)
}

pub fn get_contact_ed(v: &Vault, username: &str) -> Result<Option<String>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let ed = conn
        .query_row(
            "SELECT ed25519 FROM contacts WHERE username = ?1",
            params![username],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    Ok(ed)
}

// ---------------------------------------------------------------------------
// olm_sessions(peer, pickle)
// ---------------------------------------------------------------------------

pub fn save_olm(v: &Vault, vk: &[u8; 32], peer: &str, session: &OlmSession) -> Result<()> {
    let blob = session.to_pickle_encrypted(vk)?;
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO olm_sessions(peer, pickle) VALUES(?1, ?2)
         ON CONFLICT(peer) DO UPDATE SET pickle = excluded.pickle",
        params![peer, blob],
    )?;
    Ok(())
}

pub fn load_olm(v: &Vault, vk: &[u8; 32], peer: &str) -> Result<Option<OlmSession>> {
    let blob: Option<Vec<u8>> = {
        let conn = v.lock().expect("vault mutex poisoned");
        conn.query_row(
            "SELECT pickle FROM olm_sessions WHERE peer = ?1",
            params![peer],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
    };
    match blob {
        Some(b) => Ok(Some(OlmSession::from_pickle_encrypted(vk, &b)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// group_out(group_id, pickle) — our outbound Megolm session
// ---------------------------------------------------------------------------

pub fn save_group_out(v: &Vault, vk: &[u8; 32], group_id: &str, s: &GroupSender) -> Result<()> {
    let blob = s.to_pickle_encrypted(vk)?;
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO group_out(group_id, pickle) VALUES(?1, ?2)
         ON CONFLICT(group_id) DO UPDATE SET pickle = excluded.pickle",
        params![group_id, blob],
    )?;
    Ok(())
}

pub fn load_group_out(v: &Vault, vk: &[u8; 32], group_id: &str) -> Result<Option<GroupSender>> {
    let blob: Option<Vec<u8>> = {
        let conn = v.lock().expect("vault mutex poisoned");
        conn.query_row(
            "SELECT pickle FROM group_out WHERE group_id = ?1",
            params![group_id],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
    };
    match blob {
        Some(b) => Ok(Some(GroupSender::from_pickle_encrypted(vk, &b)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// group_in(group_id, sender, pickle) — inbound Megolm sessions
// ---------------------------------------------------------------------------

pub fn save_group_in(
    v: &Vault,
    vk: &[u8; 32],
    group_id: &str,
    sender: &str,
    r: &GroupReceiver,
) -> Result<()> {
    let blob = r.to_pickle_encrypted(vk)?;
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO group_in(group_id, sender, pickle) VALUES(?1, ?2, ?3)
         ON CONFLICT(group_id, sender) DO UPDATE SET pickle = excluded.pickle",
        params![group_id, sender, blob],
    )?;
    Ok(())
}

/// Forget one sender's inbound Megolm session for a group. Used by moderation:
/// after a user is removed/banned/suspended, members drop their session so the
/// target's *future* messages no longer decrypt (best-effort participation cut —
/// Megolm can't retroactively revoke already-delivered messages).
pub fn delete_group_in(v: &Vault, group_id: &str, sender: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "DELETE FROM group_in WHERE group_id = ?1 AND sender = ?2",
        params![group_id, sender],
    )?;
    Ok(())
}

pub fn load_group_in(
    v: &Vault,
    vk: &[u8; 32],
    group_id: &str,
    sender: &str,
) -> Result<Option<GroupReceiver>> {
    let blob: Option<Vec<u8>> = {
        let conn = v.lock().expect("vault mutex poisoned");
        conn.query_row(
            "SELECT pickle FROM group_in WHERE group_id = ?1 AND sender = ?2",
            params![group_id, sender],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
    };
    match blob {
        Some(b) => Ok(Some(GroupReceiver::from_pickle_encrypted(vk, &b)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// megolm_seen(group_id, sender, session_id, max_index) — replay guard
// ---------------------------------------------------------------------------

/// Replay check for an inbound Megolm frame. Returns `true` if `index` is FRESH
/// (strictly greater than the highest index already applied for this exact
/// `(group_id, sender, session_id)`), recording it as the new high-water mark in
/// the same critical section. Returns `false` if `index` was already seen — i.e.
/// the frame is a replay/duplicate and the caller MUST drop it before applying any
/// side effect (storing the message, mutating the roster, deleting the group, ...).
///
/// Atomic: the read + conditional write happen under one lock so two concurrent
/// deliveries of the same frame cannot both be judged fresh. (Inbound frames for
/// one connection are processed by a single serialized processor task anyway, but
/// the lock keeps this correct regardless.)
pub fn megolm_accept(
    v: &Vault,
    group_id: &str,
    sender: &str,
    session_id: &str,
    index: u32,
) -> Result<bool> {
    let conn = v.lock().expect("vault mutex poisoned");
    let prev: Option<i64> = conn
        .query_row(
            "SELECT max_index FROM megolm_seen
             WHERE group_id = ?1 AND sender = ?2 AND session_id = ?3",
            params![group_id, sender, session_id],
            |r| r.get(0),
        )
        .optional()?;
    let idx = index as i64;
    if let Some(max) = prev {
        if idx <= max {
            return Ok(false); // replay / duplicate
        }
    }
    conn.execute(
        "INSERT INTO megolm_seen(group_id, sender, session_id, max_index) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(group_id, sender, session_id) DO UPDATE SET max_index = excluded.max_index",
        params![group_id, sender, session_id, idx],
    )?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// chats(id, kind, title, created_ts)
// ---------------------------------------------------------------------------

pub fn upsert_chat(v: &Vault, id: &str, kind: &str, title: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    let now = crate::now_millis();
    conn.execute(
        "INSERT INTO chats(id, kind, title, created_ts) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, title = excluded.title",
        params![id, kind, title, now],
    )?;
    Ok(())
}

pub fn chat_exists(v: &Vault, id: &str) -> Result<bool> {
    let conn = v.lock().expect("vault mutex poisoned");
    let exists = conn
        .query_row("SELECT 1 FROM chats WHERE id = ?1", params![id], |_| Ok(()))
        .optional()?
        .is_some();
    Ok(exists)
}

/// Fetch `(kind, title)` for a chat, or `None` if it doesn't exist.
pub fn get_chat(v: &Vault, id: &str) -> Result<Option<(String, String)>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let row = conn
        .query_row(
            "SELECT kind, title FROM chats WHERE id = ?1",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?;
    Ok(row)
}

/// List chats as `(id, kind, title, last_ts)`, most-recent first.
pub fn list_chats(v: &Vault) -> Result<Vec<(String, String, String, i64)>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT c.id, c.kind, c.title,
                COALESCE((SELECT MAX(m.ts) FROM messages m WHERE m.chat_id = c.id), 0) AS last_ts
         FROM chats c
         ORDER BY last_ts DESC, c.title ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Build the `chats` event for this server's vault.
pub fn build_chats_event(v: &Vault, server: &str) -> Result<Value> {
    let chats: Vec<Value> = list_chats(v)?
        .into_iter()
        .map(|(id, kind, title, last_ts)| {
            json!({"id": id, "kind": kind, "title": title, "last_ts": last_ts})
        })
        .collect();
    Ok(json!({"event": "chats", "server": server, "chats": chats}))
}

// ---------------------------------------------------------------------------
// chat_members(chat_id, username)
// ---------------------------------------------------------------------------

pub fn add_member(v: &Vault, chat_id: &str, username: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    let exists = conn
        .query_row(
            "SELECT 1 FROM chat_members WHERE chat_id = ?1 AND username = ?2",
            params![chat_id, username],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        conn.execute(
            "INSERT INTO chat_members(chat_id, username) VALUES(?1, ?2)",
            params![chat_id, username],
        )?;
    }
    Ok(())
}

/// Remove one member from a chat's roster (used when someone leaves a group).
pub fn remove_member(v: &Vault, chat_id: &str, username: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "DELETE FROM chat_members WHERE chat_id = ?1 AND username = ?2",
        params![chat_id, username],
    )?;
    Ok(())
}

/// Delete a chat and ALL of its local state when the user leaves it: the chat
/// row, its roster, its messages, and any crypto sessions tied to it (the DM's
/// Olm session keyed by the peer == chat_id, and the group's in/out Megolm
/// sessions keyed by the group id == chat_id).
pub fn delete_chat(v: &Vault, chat_id: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute("DELETE FROM chats WHERE id = ?1", params![chat_id])?;
    conn.execute(
        "DELETE FROM chat_members WHERE chat_id = ?1",
        params![chat_id],
    )?;
    conn.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
    conn.execute("DELETE FROM olm_sessions WHERE peer = ?1", params![chat_id])?;
    conn.execute(
        "DELETE FROM group_out WHERE group_id = ?1",
        params![chat_id],
    )?;
    conn.execute("DELETE FROM group_in WHERE group_id = ?1", params![chat_id])?;
    conn.execute("DELETE FROM groups WHERE group_id = ?1", params![chat_id])?;
    conn.execute(
        "DELETE FROM group_bans WHERE group_id = ?1",
        params![chat_id],
    )?;
    conn.execute(
        "DELETE FROM group_suspensions WHERE group_id = ?1",
        params![chat_id],
    )?;
    conn.execute(
        "DELETE FROM group_join_requests WHERE group_id = ?1",
        params![chat_id],
    )?;
    conn.execute(
        "DELETE FROM megolm_seen WHERE group_id = ?1",
        params![chat_id],
    )?;
    Ok(())
}

pub fn get_members(v: &Vault, chat_id: &str) -> Result<Vec<String>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let mut stmt = conn.prepare("SELECT username FROM chat_members WHERE chat_id = ?1")?;
    let rows = stmt.query_map(params![chat_id], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// True if `username` is already on a chat's roster.
pub fn is_member(v: &Vault, chat_id: &str, username: &str) -> Result<bool> {
    let conn = v.lock().expect("vault mutex poisoned");
    let exists = conn
        .query_row(
            "SELECT 1 FROM chat_members WHERE chat_id = ?1 AND username = ?2",
            params![chat_id, username],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

// ---------------------------------------------------------------------------
// groups(group_id, group_key, access_mode, owner) — group access metadata
// ---------------------------------------------------------------------------

/// Group access-control metadata (one row per group chat).
#[derive(Debug, Clone)]
pub struct GroupMeta {
    pub group_id: String,
    pub group_key: String,
    pub access_mode: String,
    /// Creator's username — the authority that gates Megolm key distribution. An
    /// empty string means "unknown" (legacy/backfilled group), which disables
    /// owner-only moderation for that group (fail-safe).
    pub owner: String,
}

/// Result of attempting to insert a `groups` row with one candidate key.
enum KeyInsert {
    /// A new row was inserted with the candidate key.
    Inserted,
    /// `UNIQUE(group_key)` collision — caller should retry with another key.
    KeyTaken,
    /// The `group_id` already had a row (left untouched).
    GroupExists,
}

fn group_meta_from_row(r: &rusqlite::Row) -> rusqlite::Result<GroupMeta> {
    Ok(GroupMeta {
        group_id: r.get(0)?,
        group_key: r.get(1)?,
        access_mode: r.get(2)?,
        owner: r.get(3)?,
    })
}

fn get_group_meta_conn(conn: &Connection, group_id: &str) -> Result<Option<GroupMeta>> {
    let row = conn
        .query_row(
            "SELECT group_id, group_key, access_mode, owner FROM groups WHERE group_id = ?1",
            params![group_id],
            group_meta_from_row,
        )
        .optional()?;
    Ok(row)
}

/// Try to insert a group row with a *specific* key. Only the `group_id` conflict
/// is swallowed (`DO NOTHING`); a `UNIQUE(group_key)` collision surfaces as a
/// constraint violation so the caller can retry with a fresh key.
fn try_insert_group(
    conn: &Connection,
    group_id: &str,
    key: &str,
    mode: &str,
    owner: &str,
) -> Result<KeyInsert> {
    match conn.execute(
        "INSERT INTO groups(group_id, group_key, access_mode, owner) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(group_id) DO NOTHING",
        params![group_id, key, mode, owner],
    ) {
        Ok(0) => Ok(KeyInsert::GroupExists),
        Ok(_) => Ok(KeyInsert::Inserted),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Ok(KeyInsert::KeyTaken)
        }
        Err(e) => Err(e.into()),
    }
}

/// Mint a unique key and insert the `groups` row, retrying on the (vanishingly
/// rare) `UNIQUE(group_key)` collision. The DB constraint is the source of truth;
/// this loop just turns a collision into a fresh key. `gen` supplies candidates
/// (injected so tests can force a collision). Returns the key actually used, or
/// the existing key if the group already had a row.
fn create_group_row<F: FnMut() -> String>(
    conn: &Connection,
    group_id: &str,
    mode: &str,
    owner: &str,
    mut gen: F,
) -> Result<String> {
    for _ in 0..64 {
        let key = gen();
        match try_insert_group(conn, group_id, &key, mode, owner)? {
            KeyInsert::Inserted => return Ok(key),
            KeyInsert::GroupExists => {
                return get_group_meta_conn(conn, group_id)?
                    .map(|m| m.group_key)
                    .ok_or_else(|| anyhow::anyhow!("group row missing after conflict"));
            }
            KeyInsert::KeyTaken => continue,
        }
    }
    Err(anyhow::anyhow!(
        "could not mint a unique group key after 64 tries"
    ))
}

fn insert_group_with_retry(
    conn: &Connection,
    group_id: &str,
    mode: &str,
    owner: &str,
) -> Result<String> {
    create_group_row(conn, group_id, mode, owner, cherm_crypto::gen_group_key)
}

/// Create the `groups` row for a new group, minting a unique 8-char key. Returns
/// the minted key (or the existing key if the group already had a row).
pub fn create_group_meta(v: &Vault, group_id: &str, mode: &str, owner: &str) -> Result<String> {
    let conn = v.lock().expect("vault mutex poisoned");
    insert_group_with_retry(&conn, group_id, mode, owner)
}

/// Like [`create_group_meta`] but with an injected key generator, so the
/// collision-retry path can be exercised deterministically in tests.
#[cfg_attr(not(test), allow(dead_code))]
pub fn create_group_meta_with<F: FnMut() -> String>(
    v: &Vault,
    group_id: &str,
    mode: &str,
    owner: &str,
    gen: F,
) -> Result<String> {
    let conn = v.lock().expect("vault mutex poisoned");
    create_group_row(&conn, group_id, mode, owner, gen)
}

/// Record/overwrite group metadata learned from a key-share (member side).
///
/// A `UNIQUE(group_key)` collision (the incoming key already belongs to a
/// *different* group in this vault — astronomically unlikely with random base62
/// keys, but a malicious/buggy peer could craft it) is swallowed: we keep the
/// existing metadata and the group still works (the crypto session is stored
/// separately), rather than failing the whole key-share with a misleading error.
pub fn upsert_group_meta(
    v: &Vault,
    group_id: &str,
    key: &str,
    mode: &str,
    owner: &str,
) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    match conn.execute(
        "INSERT INTO groups(group_id, group_key, access_mode, owner) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(group_id) DO UPDATE SET
            group_key = excluded.group_key,
            access_mode = excluded.access_mode,
            owner = excluded.owner",
        params![group_id, key, mode, owner],
    ) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            tracing::warn!(
                "group key collision storing metadata for {group_id}; keeping existing row"
            );
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Fetch a group's access metadata, or `None` if it has no `groups` row.
pub fn get_group_meta(v: &Vault, group_id: &str) -> Result<Option<GroupMeta>> {
    let conn = v.lock().expect("vault mutex poisoned");
    get_group_meta_conn(&conn, group_id)
}

/// Look up a group by its invite/access key. Handy for invite-link resolution
/// and exercised in tests; not yet wired into a command path.
#[cfg_attr(not(test), allow(dead_code))]
pub fn get_group_by_key(v: &Vault, key: &str) -> Result<Option<GroupMeta>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let row = conn
        .query_row(
            "SELECT group_id, group_key, access_mode, owner FROM groups WHERE group_key = ?1",
            params![key],
            group_meta_from_row,
        )
        .optional()?;
    Ok(row)
}

/// Change a group's access mode (owner side).
pub fn set_access_mode(v: &Vault, group_id: &str, mode: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "UPDATE groups SET access_mode = ?2 WHERE group_id = ?1",
        params![group_id, mode],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// group_bans / group_suspensions / group_join_requests
// ---------------------------------------------------------------------------

/// Ban a user from a group (blocks all future joins). Idempotent.
pub fn ban_user(v: &Vault, group_id: &str, username: &str, ts: i64) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO group_bans(group_id, username, ts) VALUES(?1, ?2, ?3)
         ON CONFLICT(group_id, username) DO UPDATE SET ts = excluded.ts",
        params![group_id, username, ts],
    )?;
    Ok(())
}

/// Lift a ban (owner side).
pub fn unban_user(v: &Vault, group_id: &str, username: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "DELETE FROM group_bans WHERE group_id = ?1 AND username = ?2",
        params![group_id, username],
    )?;
    Ok(())
}

/// True if `username` is banned from the group.
pub fn is_banned(v: &Vault, group_id: &str, username: &str) -> Result<bool> {
    let conn = v.lock().expect("vault mutex poisoned");
    let exists = conn
        .query_row(
            "SELECT 1 FROM group_bans WHERE group_id = ?1 AND username = ?2",
            params![group_id, username],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

/// All banned usernames for a group.
pub fn list_bans(v: &Vault, group_id: &str) -> Result<Vec<String>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let mut stmt =
        conn.prepare("SELECT username FROM group_bans WHERE group_id = ?1 ORDER BY username")?;
    let rows = stmt.query_map(params![group_id], |r| r.get::<_, String>(0))?;
    rows.collect::<rusqlite::Result<_>>().map_err(Into::into)
}

/// Suspend a user until `until_ts` (unix millis). Idempotent (replaces any
/// existing suspension for that user).
pub fn suspend_user(v: &Vault, group_id: &str, username: &str, until_ts: i64) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO group_suspensions(group_id, username, until_ts) VALUES(?1, ?2, ?3)
         ON CONFLICT(group_id, username) DO UPDATE SET until_ts = excluded.until_ts",
        params![group_id, username, until_ts],
    )?;
    Ok(())
}

/// Clear a user's suspension early (owner side).
pub fn clear_suspension(v: &Vault, group_id: &str, username: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "DELETE FROM group_suspensions WHERE group_id = ?1 AND username = ?2",
        params![group_id, username],
    )?;
    Ok(())
}

/// The `until_ts` of a user's suspension, if any row exists (even if expired).
pub fn suspended_until(v: &Vault, group_id: &str, username: &str) -> Result<Option<i64>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let until = conn
        .query_row(
            "SELECT until_ts FROM group_suspensions WHERE group_id = ?1 AND username = ?2",
            params![group_id, username],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    Ok(until)
}

/// True if `username` is currently suspended from the group (`now < until_ts`).
/// Expired suspensions are pruned opportunistically so they stop blocking.
pub fn is_suspended(v: &Vault, group_id: &str, username: &str, now: i64) -> Result<bool> {
    match suspended_until(v, group_id, username)? {
        Some(until) if until > now => Ok(true),
        Some(_) => {
            // Expired — clean it up so it no longer applies, then report unblocked.
            clear_suspension(v, group_id, username)?;
            Ok(false)
        }
        None => Ok(false),
    }
}

/// Record a pending join request awaiting owner approval. Idempotent.
pub fn add_join_request(v: &Vault, group_id: &str, username: &str, ts: i64) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO group_join_requests(group_id, username, ts) VALUES(?1, ?2, ?3)
         ON CONFLICT(group_id, username) DO UPDATE SET ts = excluded.ts",
        params![group_id, username, ts],
    )?;
    Ok(())
}

/// True if `username` has a pending join request for the group.
pub fn has_join_request(v: &Vault, group_id: &str, username: &str) -> Result<bool> {
    let conn = v.lock().expect("vault mutex poisoned");
    let exists = conn
        .query_row(
            "SELECT 1 FROM group_join_requests WHERE group_id = ?1 AND username = ?2",
            params![group_id, username],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

/// Remove a pending join request (after accept/decline).
pub fn remove_join_request(v: &Vault, group_id: &str, username: &str) -> Result<()> {
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "DELETE FROM group_join_requests WHERE group_id = ?1 AND username = ?2",
        params![group_id, username],
    )?;
    Ok(())
}

/// All usernames with a pending join request for a group.
pub fn list_join_requests(v: &Vault, group_id: &str) -> Result<Vec<String>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let mut stmt = conn
        .prepare("SELECT username FROM group_join_requests WHERE group_id = ?1 ORDER BY ts ASC")?;
    let rows = stmt.query_map(params![group_id], |r| r.get::<_, String>(0))?;
    rows.collect::<rusqlite::Result<_>>().map_err(Into::into)
}

// ---------------------------------------------------------------------------
// messages(id, chat_id, sender, body, ts, outgoing)
// ---------------------------------------------------------------------------

pub fn insert_message(
    v: &Vault,
    chat_id: &str,
    sender: &str,
    body: &str,
    ts: i64,
    outgoing: i64,
) -> Result<()> {
    let recv_ts = crate::now_millis();
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO messages(chat_id, sender, body, ts, outgoing, recv_ts)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![chat_id, sender, body, ts, outgoing, recv_ts],
    )?;
    Ok(())
}

/// Last `limit` messages of a chat as `(sender, body, ts, outgoing)`, oldest-first.
pub fn get_messages(
    v: &Vault,
    chat_id: &str,
    limit: i64,
) -> Result<Vec<(String, String, i64, i64)>> {
    let conn = v.lock().expect("vault mutex poisoned");
    // Order by the TRUSTED local receipt time (not the relay-controllable `ts`), so
    // a malicious relay can't reorder/hide messages by stamping client_ts. `ts` is
    // still returned as the display label.
    let mut stmt = conn.prepare(
        "SELECT sender, body, ts, outgoing FROM messages
         WHERE chat_id = ?1
         ORDER BY recv_ts DESC, id DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![chat_id, limit], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    out.reverse();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use std::sync::{Arc, Mutex};

    const KEY: [u8; 32] = [7u8; 32];

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cherm-vault-test-{}.db", uuid::Uuid::new_v4()))
    }

    fn temp_vault() -> Vault {
        let conn = open_vault(&temp_path(), &KEY).expect("open vault");
        Arc::new(Mutex::new(conn))
    }

    #[test]
    fn create_group_meta_mints_valid_unique_key() {
        let v = temp_vault();
        let k = create_group_meta(&v, "g1", "open", "alice").unwrap();
        assert!(
            cherm_crypto::valid_group_key(&k),
            "minted key must be valid"
        );

        let meta = get_group_meta(&v, "g1").unwrap().expect("row exists");
        assert_eq!(meta.group_key, k);
        assert_eq!(meta.access_mode, "open");
        assert_eq!(meta.owner, "alice");

        // Lookup-by-key round-trips and is idempotent for the same group.
        assert_eq!(get_group_by_key(&v, &k).unwrap().unwrap().group_id, "g1");
        assert_eq!(create_group_meta(&v, "g1", "open", "alice").unwrap(), k);
    }

    #[test]
    fn collision_retry_picks_a_fresh_key() {
        let v = temp_vault();
        // Group A claims a fixed key.
        let k1 = create_group_meta_with(&v, "gA", "open", "a", || "AAAAAAAA".to_string()).unwrap();
        assert_eq!(k1, "AAAAAAAA");

        // Group B's generator first yields the taken key (collision), then a fresh
        // one — the retry loop must skip the dup and land on the second.
        let candidates = ["AAAAAAAA".to_string(), "CCCCCCCC".to_string()];
        let mut i = 0;
        let k2 = create_group_meta_with(&v, "gB", "open", "b", || {
            let k = candidates[i].clone();
            i += 1;
            k
        })
        .unwrap();
        assert_eq!(k2, "CCCCCCCC");
        assert_ne!(k1, k2);
        assert_eq!(
            get_group_by_key(&v, "AAAAAAAA").unwrap().unwrap().group_id,
            "gA"
        );
        assert_eq!(
            get_group_by_key(&v, "CCCCCCCC").unwrap().unwrap().group_id,
            "gB"
        );
    }

    #[test]
    fn db_enforces_key_uniqueness() {
        let v = temp_vault();
        create_group_meta(&v, "g1", "open", "o").unwrap();
        let key = get_group_meta(&v, "g1").unwrap().unwrap().group_key;
        // A raw insert of a second group reusing the same key must be rejected by
        // the UNIQUE constraint — not just the app-level retry.
        let conn = v.lock().unwrap();
        let res = conn.execute(
            "INSERT INTO groups(group_id, group_key, access_mode, owner) VALUES('g2', ?1, 'open', 'o')",
            params![key],
        );
        assert!(res.is_err(), "duplicate group_key must violate UNIQUE");
    }

    #[test]
    fn backfill_keys_existing_groups_on_open() {
        let path = temp_path();
        {
            // Simulate a legacy vault: a group chat with NO `groups` row.
            let conn = open_vault(&path, &KEY).unwrap();
            conn.execute(
                "INSERT INTO chats(id, kind, title, created_ts) VALUES('legacy', 'group', 'Old', 0)",
                [],
            )
            .unwrap();
            // (connection dropped here → closed)
        }
        // Reopening runs the backfill migration.
        let v = Arc::new(Mutex::new(open_vault(&path, &KEY).unwrap()));
        let meta = get_group_meta(&v, "legacy")
            .unwrap()
            .expect("backfilled row");
        assert!(cherm_crypto::valid_group_key(&meta.group_key));
        assert_eq!(meta.access_mode, "open");
        assert_eq!(meta.owner, "", "legacy owner is unknown (fail-safe)");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn access_mode_can_change() {
        let v = temp_vault();
        create_group_meta(&v, "g", "open", "o").unwrap();
        set_access_mode(&v, "g", "approval").unwrap();
        assert_eq!(
            get_group_meta(&v, "g").unwrap().unwrap().access_mode,
            "approval"
        );
        set_access_mode(&v, "g", "invite_only").unwrap();
        assert_eq!(
            get_group_meta(&v, "g").unwrap().unwrap().access_mode,
            "invite_only"
        );
    }

    #[test]
    fn bans_block_and_lift() {
        let v = temp_vault();
        assert!(!is_banned(&v, "g", "mallory").unwrap());
        ban_user(&v, "g", "mallory", 100).unwrap();
        assert!(is_banned(&v, "g", "mallory").unwrap());
        assert_eq!(list_bans(&v, "g").unwrap(), vec!["mallory".to_string()]);
        // Idempotent re-ban does not duplicate.
        ban_user(&v, "g", "mallory", 200).unwrap();
        assert_eq!(list_bans(&v, "g").unwrap().len(), 1);
        unban_user(&v, "g", "mallory").unwrap();
        assert!(!is_banned(&v, "g", "mallory").unwrap());
    }

    #[test]
    fn suspensions_expire() {
        let v = temp_vault();
        let now = 1_000_000i64;
        // Active suspension (future deadline) blocks.
        suspend_user(&v, "g", "eve", now + 10_000).unwrap();
        assert!(is_suspended(&v, "g", "eve", now).unwrap());
        // After the deadline it no longer applies AND is pruned.
        assert!(!is_suspended(&v, "g", "eve", now + 20_000).unwrap());
        assert_eq!(suspended_until(&v, "g", "eve").unwrap(), None);
        // Early clear also works.
        suspend_user(&v, "g", "eve", now + 10_000).unwrap();
        clear_suspension(&v, "g", "eve").unwrap();
        assert!(!is_suspended(&v, "g", "eve", now).unwrap());
    }

    #[test]
    fn join_requests_queue() {
        let v = temp_vault();
        assert!(!has_join_request(&v, "g", "carol").unwrap());
        add_join_request(&v, "g", "carol", 1).unwrap();
        add_join_request(&v, "g", "dave", 2).unwrap();
        assert!(has_join_request(&v, "g", "carol").unwrap());
        assert_eq!(
            list_join_requests(&v, "g").unwrap(),
            vec!["carol".to_string(), "dave".to_string()]
        );
        remove_join_request(&v, "g", "carol").unwrap();
        assert!(!has_join_request(&v, "g", "carol").unwrap());
        assert_eq!(
            list_join_requests(&v, "g").unwrap(),
            vec!["dave".to_string()]
        );
    }

    #[test]
    fn contact_identity_is_pinned_tofu() {
        let v = temp_vault();
        // First contact pins the identity.
        assert_eq!(
            check_identity(&v, "bob", "ED_BOB").unwrap(),
            IdentityCheck::FirstContact
        );
        upsert_contact(&v, "bob", "uuid1", "ED_BOB", "CURVE_BOB").unwrap();
        assert_eq!(
            check_identity(&v, "bob", "ED_BOB").unwrap(),
            IdentityCheck::Match
        );

        // A substituted Ed25519 for the same username is a Conflict...
        assert_eq!(
            check_identity(&v, "bob", "ED_ATTACKER").unwrap(),
            IdentityCheck::Conflict
        );
        // ...and upsert must NOT overwrite the pinned ed OR its curve key.
        upsert_contact(&v, "bob", "uuid2", "ED_ATTACKER", "CURVE_ATTACKER").unwrap();
        assert_eq!(
            get_contact_ed(&v, "bob").unwrap().as_deref(),
            Some("ED_BOB")
        );
        assert_eq!(
            get_contact_curve(&v, "bob").unwrap().as_deref(),
            Some("CURVE_BOB")
        );

        // A legit curve refresh under the SAME ed is allowed.
        upsert_contact(&v, "bob", "uuid1", "ED_BOB", "CURVE_BOB2").unwrap();
        assert_eq!(
            get_contact_curve(&v, "bob").unwrap().as_deref(),
            Some("CURVE_BOB2")
        );
        assert_eq!(
            get_contact_ed(&v, "bob").unwrap().as_deref(),
            Some("ED_BOB")
        );
    }

    #[test]
    fn upsert_group_meta_tolerates_key_collision() {
        // Two different groups must not be able to claim the same key — but the
        // member-side upsert degrades gracefully instead of erroring the share.
        let v = temp_vault();
        upsert_group_meta(&v, "gA", "DUPDUPDU", "open", "alice").unwrap();
        // gB tries to reuse gA's key: upsert must NOT error, and gA keeps the key.
        upsert_group_meta(&v, "gB", "DUPDUPDU", "open", "bob").unwrap();
        assert_eq!(
            get_group_by_key(&v, "DUPDUPDU").unwrap().unwrap().group_id,
            "gA"
        );
        // A normal (non-colliding) update still works.
        upsert_group_meta(&v, "gA", "DUPDUPDU", "approval", "alice").unwrap();
        assert_eq!(
            get_group_meta(&v, "gA").unwrap().unwrap().access_mode,
            "approval"
        );
    }

    #[test]
    fn megolm_replay_guard_rejects_duplicates() {
        let v = temp_vault();
        // First message at index 0 is fresh.
        assert!(megolm_accept(&v, "g", "bob", "sess1", 0).unwrap());
        // Replaying index 0 (same frame re-delivered) is rejected.
        assert!(!megolm_accept(&v, "g", "bob", "sess1", 0).unwrap());
        // Next in-order indexes are fresh...
        assert!(megolm_accept(&v, "g", "bob", "sess1", 1).unwrap());
        assert!(megolm_accept(&v, "g", "bob", "sess1", 2).unwrap());
        // ...and any index at-or-below the high-water mark is a replay.
        assert!(!megolm_accept(&v, "g", "bob", "sess1", 1).unwrap());
        assert!(!megolm_accept(&v, "g", "bob", "sess1", 2).unwrap());

        // A DIFFERENT sender is tracked independently.
        assert!(megolm_accept(&v, "g", "carol", "sessX", 0).unwrap());
        // A DIFFERENT session (owner re-key / re-install) restarts at 0 cleanly —
        // no false rejection even though "bob" already reached index 2 on sess1.
        assert!(megolm_accept(&v, "g", "bob", "sess2", 0).unwrap());
        assert!(megolm_accept(&v, "g", "bob", "sess2", 1).unwrap());
        // A different group is independent too.
        assert!(megolm_accept(&v, "g2", "bob", "sess1", 0).unwrap());

        // Cleanup on delete.
        upsert_chat(&v, "g", "group", "G").unwrap();
        delete_chat(&v, "g").unwrap();
        // After delete the high-water mark is gone, so index 0 is fresh again.
        assert!(megolm_accept(&v, "g", "bob", "sess1", 0).unwrap());
    }

    #[test]
    fn delete_group_in_removes_one_sender() {
        let v = temp_vault();
        let s = cherm_crypto::GroupSender::new();
        let r = cherm_crypto::GroupReceiver::from_session_key_b64(&s.session_key_b64()).unwrap();
        save_group_in(&v, &KEY, "g", "bob", &r).unwrap();
        assert!(load_group_in(&v, &KEY, "g", "bob").unwrap().is_some());
        delete_group_in(&v, "g", "bob").unwrap();
        assert!(load_group_in(&v, &KEY, "g", "bob").unwrap().is_none());
    }

    #[test]
    fn delete_chat_purges_group_state() {
        let v = temp_vault();
        upsert_chat(&v, "g", "group", "G").unwrap();
        add_member(&v, "g", "alice").unwrap();
        create_group_meta(&v, "g", "open", "alice").unwrap();
        ban_user(&v, "g", "mallory", 1).unwrap();
        suspend_user(&v, "g", "eve", 999_999_999_999).unwrap();
        add_join_request(&v, "g", "carol", 1).unwrap();

        delete_chat(&v, "g").unwrap();
        assert!(get_group_meta(&v, "g").unwrap().is_none());
        assert!(!is_banned(&v, "g", "mallory").unwrap());
        assert_eq!(suspended_until(&v, "g", "eve").unwrap(), None);
        assert!(!has_join_request(&v, "g", "carol").unwrap());
        assert!(get_members(&v, "g").unwrap().is_empty());
    }
}
