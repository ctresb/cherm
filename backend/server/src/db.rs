//! SQLite-backed storage for the cherm relay.
//!
//! The relay is *only* a forwarder. To honour requirements 11 & 12 (the relay
//! can never read message content) it persists exactly two things, and neither
//! contains plaintext or any private key material:
//!
//!   * `users`  — the public identity directory: `username -> (uuid, ed_pub,
//!                dh_pub, machine_id)`. The Ed25519 public key (`ed_pub`) is the
//!                immutable identity anchor used to verify auth challenges; the
//!                X25519 public key (`dh_pub`) is what *peers* use to encrypt to
//!                this user. These are PUBLIC keys only — the relay never sees a
//!                private key.
//!   * `outbox` — an ephemeral queue of already-encrypted `Deliver` frames for
//!                recipients who were offline when a message was relayed. The
//!                `frame` column is the verbatim JSON of a `ServerMsg::Deliver`
//!                whose `payload` is opaque base64 ciphertext. The relay stores
//!                the bytes and forwards them later; it cannot decrypt them.
//!
//! Every helper here is *synchronous* and takes `&Connection`. Callers lock the
//! `std::sync::Mutex<Connection>` only for the duration of the SQL and NEVER
//! across an `.await`, which is required because `rusqlite::Connection` is not
//! `Sync`.

use rusqlite::{Connection, OptionalExtension};

/// A public identity record returned by [`lookup_user`].
///
/// Note the absence of any secret: only public keys live in the directory.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub uuid: String,
    pub username: String,
    pub ed_pub: String,
    pub dh_pub: String,
}

/// Open (or create) the database file and ensure the schema exists.
pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    init_schema(&conn)?;
    Ok(conn)
}

/// Create the `users` and `outbox` tables if they do not already exist.
///
/// The schema is verbatim from PROTOCOL.md section 3 — do not drift from it, it
/// is part of the federation contract.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users(
            uuid       TEXT PRIMARY KEY,
            username   TEXT UNIQUE NOT NULL,
            ed_pub     TEXT UNIQUE NOT NULL,
            dh_pub     TEXT NOT NULL,
            machine_id TEXT NOT NULL,
            is_premium INTEGER NOT NULL DEFAULT 0,
            created_ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS outbox(
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            frame     TEXT NOT NULL,
            ts        INTEGER NOT NULL
        );
        ",
    )
}

/// True if a row with this username already exists (requirement 7: usernames
/// are immutable and unique).
pub fn username_exists(conn: &Connection, username: &str) -> rusqlite::Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM users WHERE username = ?1",
        [username],
        |row| row.get(0),
    )?;
    Ok(n > 0)
}

/// True if this Ed25519 public key is already registered under some username.
/// One key == one person, so a key may never be reused for a second account.
pub fn key_exists(conn: &Connection, ed_pub: &str) -> rusqlite::Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM users WHERE ed_pub = ?1",
        [ed_pub],
        |row| row.get(0),
    )?;
    Ok(n > 0)
}

/// Insert a brand-new identity. `is_premium` is always 0 for now (requirement
/// 17). Callers must check uniqueness first; the UNIQUE constraints are the
/// last line of defence.
#[allow(clippy::too_many_arguments)]
pub fn insert_user(
    conn: &Connection,
    uuid: &str,
    username: &str,
    ed_pub: &str,
    dh_pub: &str,
    machine_id: &str,
    created_ts: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO users(uuid, username, ed_pub, dh_pub, machine_id, is_premium, created_ts)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        rusqlite::params![uuid, username, ed_pub, dh_pub, machine_id, created_ts],
    )?;
    Ok(())
}

/// Fetch a user's public directory entry, or `None` if unknown.
pub fn lookup_user(conn: &Connection, username: &str) -> rusqlite::Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT uuid, username, ed_pub, dh_pub FROM users WHERE username = ?1",
        [username],
        |row| {
            Ok(UserRecord {
                uuid: row.get(0)?,
                username: row.get(1)?,
                ed_pub: row.get(2)?,
                dh_pub: row.get(3)?,
            })
        },
    )
    .optional()
}

/// Append an opaque (already-encrypted) `Deliver` frame to a recipient's queue.
pub fn enqueue(conn: &Connection, recipient: &str, frame: &str, ts: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO outbox(recipient, frame, ts) VALUES (?1, ?2, ?3)",
        rusqlite::params![recipient, frame, ts],
    )?;
    Ok(())
}

/// Return all queued `(id, frame)` rows for a recipient, oldest first.
///
/// We return the ids alongside the frames so the caller can delete *exactly*
/// the rows it delivered (deleting `WHERE recipient = ?` could drop messages
/// that arrived in between, since the send happens without the DB lock held).
pub fn pending_frames(conn: &Connection, recipient: &str) -> rusqlite::Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare("SELECT id, frame FROM outbox WHERE recipient = ?1 ORDER BY id")?;
    let rows = stmt.query_map([recipient], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

/// Delete the given outbox rows by id (the ones we just delivered).
pub fn delete_frames(conn: &Connection, ids: &[i64]) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("DELETE FROM outbox WHERE id = ?1")?;
    for id in ids {
        stmt.execute([id])?;
    }
    Ok(())
}
