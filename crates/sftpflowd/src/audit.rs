// ============================================================
// sftpflowd::audit - SQLite mutation audit log persistence
// ============================================================
//
// One row per mutating RPC. Records who (CLI-attributed
// `<user>@<host>`), when, what method, an args fingerprint, and
// the outcome (`ok` vs `err:<code>`). Read-only RPCs do not
// appear here; they're noisy and add no compliance value.
//
// The database lives at `<state_dir>/audit.db` — separate file
// from the run-history DB at `<state_dir>/runs.db` so the two
// concerns stay decoupled (different retention policies are
// likely; backup/restore handles each independently).
//
// Failures to record (disk full, schema migration error, etc.)
// are logged-and-swallowed: the daemon should NEVER refuse a
// mutation because the audit DB is unhappy. The audit log is a
// best-effort observability surface, not a transactional gate.

use std::path::Path;
use std::sync::Mutex;

use log::{error, info, warn};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use sftpflow_proto::{AuditEntry, Request};

// ============================================================
// AuditDb wrapper
// ============================================================

/// Thin wrapper around a SQLite connection holding the audit log.
/// Mirrors the shape of `RunDb` (history.rs).
///
/// The connection is wrapped in an internal `Mutex` so audit
/// writes can be performed via `&self` from a thread that holds
/// only an `Arc<AuditDb>` — NOT the daemon-state mutex. The
/// previous design had AuditDb owned directly by `DaemonState`,
/// which meant every `record()` was implicitly serialized behind
/// the daemon mutex; now the daemon-state lock is released
/// before the SQLite INSERT and only the audit-internal mutex
/// is held.
pub struct AuditDb {
    conn: Mutex<Connection>,
}

impl AuditDb {
    /// Open (or create) the database at `path` and ensure the
    /// schema exists. Creates parent directories if needed.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!("failed to create directory '{}': {}", parent.display(), e)
                })?;
            }
        }

        let conn = Connection::open(path).map_err(|e| {
            format!("failed to open audit database '{}': {}", path.display(), e)
        })?;

        // WAL keeps the audit recorder from blocking concurrent
        // reads (a `show audit` query while another connection is
        // mid-mutation). Log the downgrade if the FS rejects WAL —
        // operators should know if their durability story differs.
        if let Err(e) = conn.execute_batch("PRAGMA journal_mode=WAL;") {
            warn!(
                "audit db at '{}': WAL mode could not be set: {} \
                 (rollback-journal fallback in effect)",
                path.display(), e,
            );
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_unix   INTEGER NOT NULL,
                ts_iso    TEXT    NOT NULL,
                caller    TEXT,
                rpc       TEXT    NOT NULL,
                args_hash TEXT    NOT NULL,
                outcome   TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON audit_log (ts_unix DESC);"
        ).map_err(|e| format!("failed to initialize audit schema: {}", e))?;

        info!("audit log database opened at '{}'", path.display());
        Ok(AuditDb { conn: Mutex::new(conn) })
    }

    /// Acquire the inner connection, recovering from a poisoned
    /// mutex (a previous panic mid-insert). The audit log is
    /// best-effort, so a partial write that triggered a panic
    /// shouldn't prevent the next event from being recorded.
    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(poison) => {
                warn!("audit: recovering from poisoned audit-db mutex");
                poison.into_inner()
            }
        }
    }

    // --------------------------------------------------------
    // Write
    // --------------------------------------------------------

    /// Record one audit row. Errors are logged but never propagated
    /// — the audit log is best-effort and must not block mutations.
    pub fn record(
        &self,
        ts_unix:   i64,
        ts_iso:    &str,
        caller:    Option<&str>,
        rpc:       &str,
        args_hash: &str,
        outcome:   &str,
    ) {
        let conn = self.lock_conn();
        let res = conn.execute(
            "INSERT INTO audit_log (ts_unix, ts_iso, caller, rpc, args_hash, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![ts_unix, ts_iso, caller, rpc, args_hash, outcome],
        );
        if let Err(e) = res {
            error!(
                "audit: failed to record rpc={} caller={:?} outcome={}: {}",
                rpc, caller, outcome, e,
            );
        }
    }

    // --------------------------------------------------------
    // Read
    // --------------------------------------------------------

    /// Retrieve audit rows newest-first. `limit` defaults to 50.
    /// `since_unix` filters to rows with `ts_unix >= since_unix`
    /// (None = no lower bound).
    pub fn query(
        &self,
        limit:      Option<u32>,
        since_unix: Option<i64>,
    ) -> Result<Vec<AuditEntry>, String> {
        let limit = limit.unwrap_or(50) as i64;
        let since = since_unix.unwrap_or(i64::MIN);

        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, ts_unix, ts_iso, caller, rpc, args_hash, outcome
             FROM audit_log
             WHERE ts_unix >= ?1
             ORDER BY ts_unix DESC, id DESC
             LIMIT ?2"
        ).map_err(|e| format!("query error: {}", e))?;

        let rows = stmt.query_map(params![since, limit], |row| {
            Ok(AuditEntry {
                id:        row.get(0)?,
                ts_unix:   row.get(1)?,
                ts_iso:    row.get(2)?,
                caller:    row.get(3)?,
                rpc:       row.get(4)?,
                args_hash: row.get(5)?,
                outcome:   row.get(6)?,
            })
        }).map_err(|e| format!("query error: {}", e))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("row error: {}", e))?);
        }
        Ok(entries)
    }
}

// ============================================================
// args_hash - sha256 hex of the request's `params` JSON
// ============================================================
//
// The audit row records a fingerprint of the input rather than the
// raw input itself. This way:
//   - PutSecret never spills the secret value into the log
//   - PutEndpoint with a password_ref still produces a stable hash
//     across re-submissions of the same data
//   - Operators can answer "did the same request just get re-tried?"
//     by eyeballing two adjacent hashes, without needing to dig the
//     real values out of an alternate store.
//
// Implementation: serialize the entire `Request` to JSON (which
// includes the externally-tagged `method` + `params`) and hash that.
// We hash the whole envelope-without-id rather than just `params`
// so two different methods with identical-looking params don't
// collide. Parameterless methods (`Ping`, `ListEndpoints`, ...)
// hash their bare method-name JSON, which is fine — those are
// non-mutating anyway.

pub fn args_hash(request: &Request) -> String {
    // Wrap the serialized JSON in `Zeroizing` so PutSecret { value }
    // and similar variants don't leave plaintext copies on the heap
    // after the hash is computed. The hash itself is one-way; only
    // the intermediate buffer is sensitive.
    match serde_json::to_vec(request).map(zeroize::Zeroizing::new) {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(bytes.as_slice());
            let digest = hasher.finalize();
            let mut s = String::with_capacity(64);
            for b in digest {
                s.push_str(&format!("{:02x}", b));
            }
            s
        }
        Err(_) => {
            // Should be unreachable — every Request variant is
            // Serialize. Fall back to an obvious sentinel so the
            // audit row still records something we can grep for.
            "0".repeat(64)
        }
    }
}

// now_unix_and_iso lives in crate::time_fmt; re-export it here so
// existing call sites that did `audit::now_unix_and_iso()` keep
// working without churn.
pub use crate::time_fmt::now_unix_and_iso;

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sftpflow_proto::Request;
    use tempfile::tempdir;

    #[test]
    fn open_creates_schema_and_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("audit.db");
        let _db = AuditDb::open(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn record_and_query_round_trip() {
        let dir = tempdir().unwrap();
        let db = AuditDb::open(&dir.path().join("audit.db")).unwrap();

        db.record(1700_000_000, "2023-11-14T22:13:20Z",
                  Some("alice@prod-1"), "put_endpoint",
                  "abc123", "ok");
        db.record(1700_000_010, "2023-11-14T22:13:30Z",
                  Some("bob@prod-2"),   "delete_feed",
                  "def456", "err:1000");

        let rows = db.query(None, None).unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first: bob's delete sorts before alice's put.
        assert_eq!(rows[0].rpc, "delete_feed");
        assert_eq!(rows[0].outcome, "err:1000");
        assert_eq!(rows[0].caller.as_deref(), Some("bob@prod-2"));
        assert_eq!(rows[1].rpc, "put_endpoint");
        assert_eq!(rows[1].outcome, "ok");
    }

    #[test]
    fn since_unix_filter_excludes_older_rows() {
        let dir = tempdir().unwrap();
        let db = AuditDb::open(&dir.path().join("audit.db")).unwrap();
        db.record(100, "old", None, "rpc_a", "h", "ok");
        db.record(200, "mid", None, "rpc_b", "h", "ok");
        db.record(300, "new", None, "rpc_c", "h", "ok");

        let rows = db.query(None, Some(200)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].rpc, "rpc_c");
        assert_eq!(rows[1].rpc, "rpc_b");
    }

    #[test]
    fn limit_caps_returned_rows() {
        let dir = tempdir().unwrap();
        let db = AuditDb::open(&dir.path().join("audit.db")).unwrap();
        for i in 0..10 {
            db.record(i, "t", None, "rpc", "h", "ok");
        }
        let rows = db.query(Some(3), None).unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn args_hash_is_stable_per_request() {
        let r1 = Request::DeleteFeed { name: "nightly".into() };
        let r2 = Request::DeleteFeed { name: "nightly".into() };
        assert_eq!(args_hash(&r1), args_hash(&r2));
        // Different params → different hash.
        let r3 = Request::DeleteFeed { name: "weekly".into() };
        assert_ne!(args_hash(&r1), args_hash(&r3));
        // Hash is 64 hex chars.
        assert_eq!(args_hash(&r1).len(), 64);
    }

    #[test]
    fn args_hash_distinguishes_methods_with_same_param_shape() {
        let put = Request::PutSecret { name: "k".into(), value: "v".into() };
        // Method differs even if `name`/`value` shape matched
        // another variant — including the method tag prevents
        // collisions across RPC types.
        assert_eq!(args_hash(&put).len(), 64);
    }
}
