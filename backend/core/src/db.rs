//! Local client storage (`~/.cherm/cherm.db`).
//!
//! This is the on-disk history that lives ONLY on the user's machine
//! (requirement 10). The core stores the plaintext it sent/received so the
//! user keeps a readable log; the relay server never sees any of this.
//!
//! The schema is exactly the one defined in `PROTOCOL.md` section 5.
//!
//! IMPORTANT concurrency rule: a `rusqlite::Connection` is `Send` but not
//! `Sync`, so it is wrapped in `Arc<std::sync::Mutex<Connection>>`. Every
//! helper here locks the mutex, does its synchronous work, and releases the
//! lock before returning. Because none of these functions are `async`, the
//! guard is NEVER held across an `.await` — the calling code only does network
//! I/O between (not during) these synchronous calls.

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Shared, thread-safe handle to the local SQLite database.
pub type Db = Arc<Mutex<Connection>>;

/// Open (or create) the local database at `path` and ensure the schema exists.
pub fn open_db(path: &Path) -> Result<Db> {
    let conn = Connection::open(path)?;
    // The exact schema from PROTOCOL.md section 5. `IF NOT EXISTS` makes this
    // idempotent so we can run it on every startup.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta(
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS contacts(
            username TEXT PRIMARY KEY,
            uuid     TEXT,
            ed_pub   TEXT,
            dh_pub   TEXT
        );
        CREATE TABLE IF NOT EXISTS chats(
            id         TEXT PRIMARY KEY,
            kind       TEXT,
            title      TEXT,
            group_key  TEXT,
            created_ts INTEGER
        );
        CREATE TABLE IF NOT EXISTS chat_members(
            chat_id  TEXT,
            username TEXT
        );
        CREATE TABLE IF NOT EXISTS messages(
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id  TEXT,
            sender   TEXT,
            body     TEXT,
            ts       INTEGER,
            outgoing INTEGER
        );
        "#,
    )?;
    Ok(Arc::new(Mutex::new(conn)))
}

// ---------------------------------------------------------------------------
// meta(key, value) — username, uuid, server addr, ...
// ---------------------------------------------------------------------------

/// Read a single `meta` value by key. Returns `None` if the key is absent.
pub fn meta_get(db: &Db, key: &str) -> Result<Option<String>> {
    let conn = db.lock().expect("db mutex poisoned");
    let value = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(value)
}

/// Insert or update a `meta` key/value pair.
pub fn meta_set(db: &Db, key: &str, value: &str) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// contacts(username, uuid, ed_pub, dh_pub)
// ---------------------------------------------------------------------------

/// Insert or update a contact's directory entry (public keys).
pub fn upsert_contact(
    db: &Db,
    username: &str,
    uuid: &str,
    ed_pub: &str,
    dh_pub: &str,
) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "INSERT INTO contacts(username, uuid, ed_pub, dh_pub) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(username) DO UPDATE SET
            uuid = excluded.uuid, ed_pub = excluded.ed_pub, dh_pub = excluded.dh_pub",
        params![username, uuid, ed_pub, dh_pub],
    )?;
    Ok(())
}

/// Fetch a contact's X25519 public key (base64), if we already know them.
pub fn get_contact_dh(db: &Db, username: &str) -> Result<Option<String>> {
    let conn = db.lock().expect("db mutex poisoned");
    let dh = conn
        .query_row(
            "SELECT dh_pub FROM contacts WHERE username = ?1",
            params![username],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    Ok(dh)
}

// ---------------------------------------------------------------------------
// chats(id, kind, title, group_key, created_ts)
// ---------------------------------------------------------------------------

/// Create a chat if absent, otherwise update its kind/title. A non-null
/// `group_key` is preserved via COALESCE so re-ensuring a DM (which passes a
/// NULL key) never wipes an existing group's key. `created_ts` is only set on
/// the initial insert.
pub fn upsert_chat(
    db: &Db,
    id: &str,
    kind: &str,
    title: &str,
    group_key: Option<String>,
) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    let now = crate::now_millis();
    conn.execute(
        "INSERT INTO chats(id, kind, title, group_key, created_ts) VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET
            kind = excluded.kind,
            title = excluded.title,
            group_key = COALESCE(excluded.group_key, chats.group_key)",
        params![id, kind, title, group_key, now],
    )?;
    Ok(())
}

/// Returns `true` if a chat row with this id exists.
pub fn chat_exists(db: &Db, id: &str) -> Result<bool> {
    let conn = db.lock().expect("db mutex poisoned");
    let exists = conn
        .query_row("SELECT 1 FROM chats WHERE id = ?1", params![id], |_| Ok(()))
        .optional()?
        .is_some();
    Ok(exists)
}

/// Fetch `(kind, group_key)` for a chat, or `None` if it doesn't exist.
pub fn get_chat(db: &Db, id: &str) -> Result<Option<(String, Option<String>)>> {
    let conn = db.lock().expect("db mutex poisoned");
    let row = conn
        .query_row(
            "SELECT kind, group_key FROM chats WHERE id = ?1",
            params![id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()?;
    Ok(row)
}

/// List all chats as `(id, kind, title, last_ts)`, ordered most-recent first.
/// `last_ts` is the newest message timestamp in that chat, or 0 if empty.
pub fn list_chats(db: &Db) -> Result<Vec<(String, String, String, i64)>> {
    let conn = db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare(
        "SELECT c.id, c.kind, c.title,
                COALESCE((SELECT MAX(m.ts) FROM messages m WHERE m.chat_id = c.id), 0) AS last_ts
         FROM chats c
         ORDER BY last_ts DESC, c.title ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Build the `chats` event payload directly from the database. Shared by the
/// command handlers and the incoming-message reader so the sidebar always
/// reflects the current chat set.
pub fn build_chats_event(db: &Db) -> Result<serde_json::Value> {
    let rows = list_chats(db)?;
    let chats: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, kind, title, last_ts)| {
            serde_json::json!({"id": id, "kind": kind, "title": title, "last_ts": last_ts})
        })
        .collect();
    Ok(serde_json::json!({"event": "chats", "chats": chats}))
}

// ---------------------------------------------------------------------------
// chat_members(chat_id, username)
// ---------------------------------------------------------------------------

/// Add a member to a chat, idempotently (no duplicate rows).
pub fn add_member(db: &Db, chat_id: &str, username: &str) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
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

/// List the usernames that belong to a chat.
pub fn get_members(db: &Db, chat_id: &str) -> Result<Vec<String>> {
    let conn = db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare("SELECT username FROM chat_members WHERE chat_id = ?1")?;
    let rows = stmt.query_map(params![chat_id], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// messages(id, chat_id, sender, body, ts, outgoing)
// ---------------------------------------------------------------------------

/// Append a plaintext message to the local log.
pub fn insert_message(
    db: &Db,
    chat_id: &str,
    sender: &str,
    body: &str,
    ts: i64,
    outgoing: i64,
) -> Result<()> {
    let conn = db.lock().expect("db mutex poisoned");
    conn.execute(
        "INSERT INTO messages(chat_id, sender, body, ts, outgoing) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![chat_id, sender, body, ts, outgoing],
    )?;
    Ok(())
}

/// Return the last `limit` messages for a chat as `(sender, body, ts, outgoing)`,
/// ordered oldest-first so the TUI can render them top-to-bottom.
pub fn get_messages(
    db: &Db,
    chat_id: &str,
    limit: i64,
) -> Result<Vec<(String, String, i64, i64)>> {
    let conn = db.lock().expect("db mutex poisoned");
    // Take the newest `limit` rows, then reverse to ascending order.
    let mut stmt = conn.prepare(
        "SELECT sender, body, ts, outgoing FROM messages
         WHERE chat_id = ?1
         ORDER BY ts DESC, id DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![chat_id, limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    out.reverse();
    Ok(out)
}
