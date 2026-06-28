//! SQLite-backed storage for the cherm relay (v2 schema, PROTOCOL.md §3).
//!
//! The relay is *only* a forwarder. To honour the privacy contract (the relay
//! can never read message content) it persists exactly three things, none of
//! which contains plaintext or any private key material:
//!
//!   * `users`   — the public identity directory: `uuid -> (username, ed25519,
//!                 curve25519, machine_id, is_premium, created_ts)`. The Ed25519
//!                 key is the immutable identity anchor used to verify auth
//!                 challenges; the Curve25519 key is what peers use to start Olm
//!                 sessions. These are PUBLIC keys only.
//!   * `prekeys` — uploaded one-time Curve25519 prekeys (public) so peers can
//!                 bootstrap an Olm session while their target is offline. Each
//!                 row is handed out at most once (`used` flips to 1 on fetch).
//!   * `outbox`  — an ephemeral queue of already-encrypted `Deliver` frames for
//!                 recipients who were offline when a message was relayed. The
//!                 `frame` column is the verbatim JSON of a `ServerMsg::Deliver`
//!                 whose `payload` is opaque base64 ciphertext.
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
    pub ed25519: String,
    pub curve25519: String,
}

/// Open (or create) the database file and ensure the schema exists.
pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    init_schema(&conn)?;
    Ok(conn)
}

/// Create the `users`, `prekeys` and `outbox` tables if they do not exist.
///
/// The schema is verbatim from PROTOCOL.md section 3 — do not drift from it, it
/// is part of the federation contract.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users(
            uuid       TEXT PRIMARY KEY,
            username   TEXT UNIQUE NOT NULL,
            ed25519    TEXT UNIQUE NOT NULL,
            curve25519 TEXT NOT NULL,
            machine_id TEXT NOT NULL,
            is_premium INTEGER NOT NULL DEFAULT 0,
            created_ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS prekeys(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            key_id     TEXT NOT NULL,
            curve25519 TEXT NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0
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

/// True if a row with this username already exists (usernames are immutable and
/// unique).
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
pub fn key_exists(conn: &Connection, ed25519: &str) -> rusqlite::Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM users WHERE ed25519 = ?1",
        [ed25519],
        |row| row.get(0),
    )?;
    Ok(n > 0)
}

/// Insert a brand-new identity. `is_premium` is always 0 for now. Callers must
/// check uniqueness first; the UNIQUE constraints are the last line of defence.
pub fn insert_user(
    conn: &Connection,
    uuid: &str,
    username: &str,
    ed25519: &str,
    curve25519: &str,
    machine_id: &str,
    created_ts: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO users(uuid, username, ed25519, curve25519, machine_id, is_premium, created_ts)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        rusqlite::params![uuid, username, ed25519, curve25519, machine_id, created_ts],
    )?;
    Ok(())
}

/// Fetch a user's public directory entry, or `None` if unknown.
pub fn lookup_user(conn: &Connection, username: &str) -> rusqlite::Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT uuid, username, ed25519, curve25519 FROM users WHERE username = ?1",
        [username],
        |row| {
            Ok(UserRecord {
                uuid: row.get(0)?,
                username: row.get(1)?,
                ed25519: row.get(2)?,
                curve25519: row.get(3)?,
            })
        },
    )
    .optional()
}

/// Store one uploaded one-time prekey (public) as an unused row.
pub fn insert_prekey(
    conn: &Connection,
    username: &str,
    key_id: &str,
    curve25519: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO prekeys(username, key_id, curve25519, used) VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![username, key_id, curve25519],
    )?;
    Ok(())
}

/// Atomically claim one unused prekey for `username`, marking it used.
///
/// Returns `(key_id, curve25519)` for the consumed key, or `None` if the user
/// has no unused prekeys left. The select + update run on the single locked
/// connection, so the hand-out is delete-on-handout with no double-spend.
pub fn take_prekey(
    conn: &Connection,
    username: &str,
) -> rusqlite::Result<Option<(String, String)>> {
    let row = conn
        .query_row(
            "SELECT id, key_id, curve25519 FROM prekeys
             WHERE username = ?1 AND used = 0 ORDER BY id LIMIT 1",
            [username],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some((id, key_id, curve25519)) => {
            conn.execute("UPDATE prekeys SET used = 1 WHERE id = ?1", [id])?;
            Ok(Some((key_id, curve25519)))
        }
        None => Ok(None),
    }
}

/// Fetch a peer's bundle: their public directory record plus (if available) one
/// freshly-consumed one-time key. `Ok(None)` means the user is unknown.
pub fn fetch_bundle(
    conn: &Connection,
    username: &str,
) -> rusqlite::Result<Option<(UserRecord, Option<(String, String)>)>> {
    let rec = match lookup_user(conn, username)? {
        Some(r) => r,
        None => return Ok(None),
    };
    let otk = take_prekey(conn, username)?;
    Ok(Some((rec, otk)))
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
