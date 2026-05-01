// ============================================================
// sftpflowd::history - SQLite run history persistence
// ============================================================
//
// Stores a record for every feed execution (RunFeedNow) so the
// CLI can display run history via `show runs <feed>`.
//
// Schema: a single `runs` table with auto-increment rowid.
// The database file defaults to `/var/lib/sftpflow/runs.db` on
// Linux and `%APPDATA%/sftpflow/runs.db` on Windows, overridable
// with `--db <path>`.

use std::path::Path;
use std::time::Duration;

use log::{error, info, warn};
use rusqlite::{Connection, params};

use sftpflow_proto::{RunHistoryEntry, RunResult, RunStatus};

// ============================================================
// RunDb wrapper
// ============================================================

/// Thin wrapper around a SQLite connection for run history.
pub struct RunDb {
    conn: Connection,
}

impl RunDb {
    /// Open (or create) the database at `path` and ensure the
    /// schema exists. Creates parent directories if needed.
    pub fn open(path: &Path) -> Result<Self, String> {
        // Ensure the parent directory exists.
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!("failed to create directory '{}': {}", parent.display(), e)
                })?;
            }
        }

        let conn = Connection::open(path).map_err(|e| {
            format!("failed to open runs database '{}': {}", path.display(), e)
        })?;

        // Enable WAL mode for better concurrency (multiple readers
        // while one writer records a run). SQLite silently downgrades
        // to rollback-journal mode when WAL isn't supported (read-only
        // FS, network mounts that block shared-memory mapping); log
        // the downgrade so operators don't assume durability semantics
        // they don't have.
        if let Err(e) = conn.execute_batch("PRAGMA journal_mode=WAL;") {
            warn!(
                "run history at '{}': WAL mode could not be set: {} \
                 (concurrent reads while writing may block)",
                path.display(), e,
            );
        }

        // Create the runs table if it doesn't exist yet.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS runs (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                feed              TEXT    NOT NULL,
                started_at        TEXT    NOT NULL,
                started_unix      INTEGER NOT NULL DEFAULT 0,
                duration_secs     REAL    NOT NULL,
                status            TEXT    NOT NULL,
                files_transferred INTEGER NOT NULL DEFAULT 0,
                message           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_runs_feed_unix
                ON runs (feed, started_unix DESC);"
        ).map_err(|e| format!("failed to initialize runs schema: {}", e))?;

        // Migration: older databases don't have `started_unix`.
        // Add it as nullable with a 0 default so existing rows
        // sort to the bottom of the recency window. New writes
        // populate the column from a real wall-clock value.
        // Errors here are swallowed because the column-already-
        // exists case returns a "duplicate column name" error
        // every time the daemon starts.
        let _ = conn.execute_batch(
            "ALTER TABLE runs ADD COLUMN started_unix INTEGER NOT NULL DEFAULT 0;"
        );
        // Build the new index even when ALTER above no-op'd, so
        // an upgraded daemon picks up the unix-ordered index.
        let _ = conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_runs_feed_unix
                ON runs (feed, started_unix DESC);"
        );

        info!("run history database opened at '{}'", path.display());
        Ok(RunDb { conn })
    }

    // --------------------------------------------------------
    // Write
    // --------------------------------------------------------

    /// Record a completed feed run. `started_unix` should match
    /// `started_at`'s wall-clock instant (both captured at the
    /// same time by the caller); we store both so the ISO column
    /// stays human-readable while the unix column gives a
    /// type-correct sort order.
    pub fn record_run(
        &self,
        feed_name:    &str,
        started_at:   &str,
        started_unix: i64,
        duration:     Duration,
        result:       &RunResult,
    ) {
        let status_str = match result.status {
            RunStatus::Success  => "success",
            RunStatus::Noaction => "noaction",
            RunStatus::Failed   => "failed",
        };

        let res = self.conn.execute(
            "INSERT INTO runs (feed, started_at, started_unix, duration_secs, status, files_transferred, message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                feed_name,
                started_at,
                started_unix,
                duration.as_secs_f64(),
                status_str,
                result.files_transferred as i64,
                result.message,
            ],
        );

        match res {
            Ok(_) => info!(
                "recorded run for '{}': status={}, files={}, duration={:.1}s",
                feed_name, status_str, result.files_transferred, duration.as_secs_f64()
            ),
            Err(e) => error!(
                "failed to record run for '{}': {}", feed_name, e
            ),
        }
    }

    // --------------------------------------------------------
    // Read
    // --------------------------------------------------------

    /// Retrieve the most recent runs for a feed, newest first.
    /// `limit` defaults to 25 if None.
    pub fn get_runs(
        &self,
        feed_name: &str,
        limit: Option<u32>,
    ) -> Result<Vec<RunHistoryEntry>, String> {
        let limit = limit.unwrap_or(25) as i64;

        // Order by the unix timestamp column so the sort is
        // type-correct; older rows that predate the migration
        // have started_unix=0 and tiebreak on rowid descending,
        // which keeps newest-inserted at the top within that
        // legacy bucket.
        let mut stmt = self.conn.prepare(
            "SELECT id, feed, started_at, duration_secs, status, files_transferred, message
             FROM runs
             WHERE feed = ?1
             ORDER BY started_unix DESC, id DESC
             LIMIT ?2"
        ).map_err(|e| format!("query error: {}", e))?;

        let rows = stmt.query_map(params![feed_name, limit], |row| {
            let status_str: String = row.get(4)?;
            let status = match status_str.as_str() {
                "success"  => RunStatus::Success,
                "noaction" => RunStatus::Noaction,
                _          => RunStatus::Failed,
            };

            Ok(RunHistoryEntry {
                id:                row.get(0)?,
                feed:              row.get(1)?,
                started_at:        row.get(2)?,
                duration_secs:     row.get(3)?,
                status,
                files_transferred: row.get::<_, i64>(5)? as usize,
                message:           row.get(6)?,
            })
        }).map_err(|e| format!("query error: {}", e))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("row error: {}", e))?);
        }

        Ok(entries)
    }
}
