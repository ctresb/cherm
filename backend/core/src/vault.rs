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
    outgoing INTEGER
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
    conn.pragma_update(None, "key", &key)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
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
            uuid = excluded.uuid, ed25519 = excluded.ed25519, curve25519 = excluded.curve25519",
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
    conn.execute("DELETE FROM chat_members WHERE chat_id = ?1", params![chat_id])?;
    conn.execute("DELETE FROM messages WHERE chat_id = ?1", params![chat_id])?;
    conn.execute("DELETE FROM olm_sessions WHERE peer = ?1", params![chat_id])?;
    conn.execute("DELETE FROM group_out WHERE group_id = ?1", params![chat_id])?;
    conn.execute("DELETE FROM group_in WHERE group_id = ?1", params![chat_id])?;
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
    let conn = v.lock().expect("vault mutex poisoned");
    conn.execute(
        "INSERT INTO messages(chat_id, sender, body, ts, outgoing) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![chat_id, sender, body, ts, outgoing],
    )?;
    Ok(())
}

/// Last `limit` messages of a chat as `(sender, body, ts, outgoing)`, oldest-first.
pub fn get_messages(v: &Vault, chat_id: &str, limit: i64) -> Result<Vec<(String, String, i64, i64)>> {
    let conn = v.lock().expect("vault mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT sender, body, ts, outgoing FROM messages
         WHERE chat_id = ?1
         ORDER BY ts DESC, id DESC
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
