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
        -- Index the per-recipient lookups (count/sum/flush/quota) so they stay
        -- O(log n) instead of full table scans an attacker could amplify.
        CREATE INDEX IF NOT EXISTS idx_outbox_recipient ON outbox(recipient);
        -- Collapse any pre-existing duplicate (username, key_id) rows (possible on
        -- an older DB created before the uniqueness rule) BEFORE adding the unique
        -- index, keeping the earliest row, so the index creation can't fail on
        -- legacy data. No-op on a fresh database.
        DELETE FROM prekeys
         WHERE id NOT IN (SELECT MIN(id) FROM prekeys GROUP BY username, key_id);
        -- One row per published one-time prekey. The UNIQUE(username, key_id)
        -- constraint makes re-publishing the same key a no-op (idempotent upload)
        -- and stops an authenticated client from inflating the table with
        -- duplicate ids. The (username, used) index makes the per-user unused-key
        -- count + the claim-one-key fetch cheap.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_prekeys_user_keyid ON prekeys(username, key_id);
        CREATE INDEX IF NOT EXISTS idx_prekeys_user_used ON prekeys(username, used);
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

/// Store one uploaded one-time prekey (public) as an unused row. Idempotent:
/// re-publishing the same `(username, key_id)` is a no-op (the UNIQUE index makes
/// duplicates impossible), so a client retrying an upload can't grow the table.
pub fn insert_prekey(
    conn: &Connection,
    username: &str,
    key_id: &str,
    curve25519: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO prekeys(username, key_id, curve25519, used) VALUES (?1, ?2, ?3, 0)
         ON CONFLICT(username, key_id) DO NOTHING",
        rusqlite::params![username, key_id, curve25519],
    )?;
    Ok(())
}

/// Number of UNUSED one-time prekeys currently stored for a user. Used to cap how
/// many an authenticated client may stockpile, bounding prekey-table growth.
pub fn count_unused_prekeys(conn: &Connection, username: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM prekeys WHERE username = ?1 AND used = 0",
        [username],
        |row| row.get(0),
    )
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

/// Number of queued frames currently sitting in a recipient's outbox. Used to
/// cap per-recipient storage so a malicious sender can't exhaust disk by flooding
/// an offline user's queue.
pub fn outbox_count(conn: &Connection, recipient: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM outbox WHERE recipient = ?1",
        [recipient],
        |row| row.get(0),
    )
}

/// Total bytes of queued frames for a recipient. The row count alone does not
/// bound disk: each frame can carry a large ciphertext, so a byte budget is the
/// real per-recipient storage cap (PROTOCOL.md offline-queue contract).
pub fn outbox_bytes(conn: &Connection, recipient: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COALESCE(SUM(length(frame)), 0) FROM outbox WHERE recipient = ?1",
        [recipient],
        |row| row.get(0),
    )
}

/// Append an opaque (already-encrypted) `Deliver` frame to a recipient's queue.
pub fn enqueue(conn: &Connection, recipient: &str, frame: &str, ts: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO outbox(recipient, frame, ts) VALUES (?1, ?2, ?3)",
        rusqlite::params![recipient, frame, ts],
    )?;
    Ok(())
}

/// Append an outbox frame only if the recipient is still under BOTH the row cap
/// and the byte cap.
///
/// The checks and the insert run under the caller's single DB mutex critical
/// section, so concurrent connections cannot all observe the same totals and
/// bypass the caps with a check-then-insert race. Returning `false` means the
/// recipient's queue is full (by rows or bytes) and the frame was dropped.
pub fn enqueue_if_under_cap(
    conn: &Connection,
    recipient: &str,
    frame: &str,
    ts: i64,
    cap_rows: i64,
    cap_bytes: i64,
) -> rusqlite::Result<bool> {
    if outbox_count(conn, recipient)? >= cap_rows {
        return Ok(false);
    }
    // Bound total bytes too: one near-`MAX_PAYLOAD` frame must not let a handful of
    // rows exhaust disk, and the byte budget is what actually caps storage.
    if outbox_bytes(conn, recipient)? + frame.len() as i64 > cap_bytes {
        return Ok(false);
    }
    enqueue(conn, recipient, frame, ts)?;
    Ok(true)
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

/// Delete outbox frames older than `cutoff_ms` (unix millis). Enforces the
/// advertised offline-queue TTL ("72h max") so an undelivered queue cannot pin
/// disk forever, and reaps rows for puppet recipients that never log in. Returns
/// the number of rows removed.
pub fn prune_expired(conn: &Connection, cutoff_ms: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM outbox WHERE ts < ?1", [cutoff_ms])
}

/// Delete the given outbox rows by id (the ones we just delivered).
pub fn delete_frames(conn: &Connection, ids: &[i64]) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("DELETE FROM outbox WHERE id = ?1")?;
    for id in ids {
        stmt.execute([id])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn outbox_enforces_row_and_byte_caps() {
        let conn = db();
        // Row cap: with a tiny cap, the 3rd frame is rejected.
        assert!(enqueue_if_under_cap(&conn, "bob", "aa", 1, 2, 1_000_000).unwrap());
        assert!(enqueue_if_under_cap(&conn, "bob", "bb", 2, 2, 1_000_000).unwrap());
        assert!(!enqueue_if_under_cap(&conn, "bob", "cc", 3, 2, 1_000_000).unwrap());
        assert_eq!(outbox_count(&conn, "bob").unwrap(), 2);

        // Byte cap: a frame that would push total bytes over the budget is rejected
        // even when the row cap has room. "alice" budget = 5 bytes.
        assert!(enqueue_if_under_cap(&conn, "alice", "abc", 1, 100, 5).unwrap()); // 3 bytes
        assert!(!enqueue_if_under_cap(&conn, "alice", "xyz", 2, 100, 5).unwrap()); // +3 > 5
        assert_eq!(outbox_bytes(&conn, "alice").unwrap(), 3);
    }

    #[test]
    fn prune_expired_removes_old_frames() {
        let conn = db();
        enqueue(&conn, "bob", "old", 100).unwrap();
        enqueue(&conn, "bob", "new", 10_000).unwrap();
        // Cutoff at 5000 removes only the ts=100 row.
        assert_eq!(prune_expired(&conn, 5_000).unwrap(), 1);
        assert_eq!(outbox_count(&conn, "bob").unwrap(), 1);
    }

    #[test]
    fn prekeys_unique_and_capped() {
        let conn = db();
        // Idempotent: re-publishing the same (user, key_id) does not duplicate.
        insert_prekey(&conn, "bob", "k1", "CURVE1").unwrap();
        insert_prekey(&conn, "bob", "k1", "CURVE1").unwrap();
        assert_eq!(count_unused_prekeys(&conn, "bob").unwrap(), 1);
        // Distinct ids accumulate; consuming one drops the unused count.
        insert_prekey(&conn, "bob", "k2", "CURVE2").unwrap();
        assert_eq!(count_unused_prekeys(&conn, "bob").unwrap(), 2);
        let taken = take_prekey(&conn, "bob").unwrap();
        assert!(taken.is_some());
        assert_eq!(count_unused_prekeys(&conn, "bob").unwrap(), 1);
    }
}
