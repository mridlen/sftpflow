// ============================================================
// sftpflow-proto - JSON-RPC message types (CLI <-> daemon)
// ============================================================
//
// Wire format: NDJSON — one JSON object per line, terminated with '\n'.
// Request envelopes carry a monotonic `id`; the daemon echoes the same
// `id` back in the matching ResponseEnvelope so the CLI can correlate.
//
// This crate intentionally has no I/O or socket code beyond the trivial
// `framing` helpers — anything heavier belongs in the daemon or CLI.

use serde::{Deserialize, Serialize};

use sftpflow_core::{Endpoint, Feed, PgpKey};

// ============================================================
// Requests - sent from CLI to daemon
// ============================================================

/// Every operation the CLI can ask the daemon to perform.
///
/// Wire form (externally tagged via "method" / "params"):
///
///   {"method": "ping"}
///   {"method": "get_feed", "params": {"name": "nightly-backup"}}
///   {"method": "put_feed", "params": {"name": "x", "feed": { ... }}}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    // ---- liveness / introspection ----
    Ping,
    GetServerInfo,

    // ---- endpoints ----
    ListEndpoints,
    GetEndpoint    { name: String },
    PutEndpoint    { name: String, endpoint: Endpoint },
    DeleteEndpoint { name: String },
    RenameEndpoint { from: String, to: String },

    // ---- PGP keys ----
    ListKeys,
    GetKey    { name: String },
    PutKey    { name: String, key: PgpKey },
    DeleteKey { name: String },
    RenameKey { from: String, to: String },

    // ---- feeds ----
    ListFeeds,
    GetFeed    { name: String },
    PutFeed    { name: String, feed: Feed },
    DeleteFeed { name: String },
    RenameFeed { from: String, to: String },

    /// Kick off a feed immediately, outside its cron schedule.
    RunFeedNow { name: String },

    /// Trigger a full reconciliation of feed schedules ↔ dkron jobs.
    SyncSchedules,

    /// Retrieve run history for a feed (most recent first).
    GetRunHistory { feed: String, limit: Option<u32> },

    // ---- sealed credential store ----
    /// Insert or replace a sealed secret by name. The value is sent
    /// over the RPC channel and re-sealed on the daemon side.
    PutSecret    { name: String, value: String },
    /// Remove a sealed secret by name. Not-found is not an error.
    DeleteSecret { name: String },
    /// List the names of every sealed secret. Values are never returned
    /// from the daemon — there is intentionally no `GetSecret`.
    ListSecrets,
}

// ============================================================
// Responses - sent from daemon to CLI
// ============================================================

/// Successful result payloads. One variant per response shape; the
/// CLI knows which shape to expect based on the Request it sent.
///
/// Wire form (externally tagged via "kind" / "value"):
///
///   {"kind": "pong"}
///   {"kind": "names", "value": ["alpha", "beta"]}
///   {"kind": "feed", "value": { ... }}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Response {
    /// Reply to Ping.
    Pong,
    /// Reply to GetServerInfo.
    ServerInfo(ServerInfo),
    /// Name-only listing (endpoints, keys).
    Names(Vec<String>),
    /// Reply to GetEndpoint. None => not found.
    Endpoint(Option<Endpoint>),
    /// Reply to GetKey. None => not found.
    Key(Option<PgpKey>),
    /// Reply to GetFeed. None => not found.
    Feed(Option<Feed>),
    /// Summaries suitable for `show feeds` list view.
    FeedSummaries(Vec<FeedSummary>),
    /// Generic acknowledgement for Put/Delete/Rename.
    Ok,
    /// Reply to RunFeedNow.
    RunResult(RunResult),
    /// Reply to SyncSchedules.
    SyncReport(SyncReport),
    /// Reply to GetRunHistory.
    RunHistory(Vec<RunHistoryEntry>),
}

/// Server identity and version, returned by GetServerInfo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerInfo {
    /// sftpflowd version string (e.g. "0.1.1").
    pub version: String,
    /// Hostname the daemon is running on.
    pub hostname: String,
    /// Seconds since the daemon started.
    pub uptime_seconds: u64,
}

/// One row of the feed listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedSummary {
    pub name: String,
    pub enabled: bool,
    pub sources: usize,
    pub destinations: usize,
    pub schedules: usize,
}

/// Outcome of a RunFeedNow invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunResult {
    pub feed: String,
    pub status: RunStatus,
    pub files_transferred: usize,
    /// Optional human-readable message (failure reason, etc).
    pub message: Option<String>,
}

/// Terminal status of a feed execution. Matches the TriggerCondition
/// variants so nextstep evaluation can consume it directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Feed ran and transferred at least one file.
    Success,
    /// Feed ran but no files matched / needed transfer.
    Noaction,
    /// Feed encountered an error.
    Failed,
}

/// Outcome of a SyncSchedules reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncReport {
    /// Number of dkron jobs created.
    pub created: usize,
    /// Number of dkron jobs updated (schedule or enabled state changed).
    pub updated: usize,
    /// Number of orphan dkron jobs deleted (no matching feed).
    pub deleted: usize,
    /// Non-fatal errors encountered during sync.
    pub errors: Vec<String>,
}

/// A single run history entry, returned by GetRunHistory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunHistoryEntry {
    /// Auto-incremented row id.
    pub id: i64,
    /// Feed name at the time of execution.
    pub feed: String,
    /// ISO 8601 UTC timestamp when the run started.
    pub started_at: String,
    /// Wall-clock duration of the run in seconds.
    pub duration_secs: f64,
    /// Terminal status (success / noaction / failed).
    pub status: RunStatus,
    /// Number of files transferred.
    pub files_transferred: usize,
    /// Optional human-readable message (failure reason, etc).
    pub message: Option<String>,
}

// ============================================================
// Errors
// ============================================================

/// Error payload carried by a failed ResponseEnvelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtoError {
    pub code: i32,
    pub message: String,
}

/// Error code constants. The -326xx range mirrors JSON-RPC 2.0 for
/// protocol-level errors; the 1xxx range is sftpflow-specific.
pub mod error_code {
    // ---- JSON-RPC 2.0 reserved range ----
    pub const PARSE_ERROR:      i32 = -32700;
    pub const INVALID_REQUEST:  i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS:   i32 = -32602;
    pub const INTERNAL_ERROR:   i32 = -32603;

    // ---- sftpflow application errors ----
    pub const NOT_FOUND:        i32 = 1000;
    pub const ALREADY_EXISTS:   i32 = 1001;
    pub const CONFIG_ERROR:     i32 = 1002;
    pub const REFERENCE_IN_USE: i32 = 1003;
}

// ============================================================
// Envelopes - wire-level correlation
// ============================================================

/// A request as it appears on the wire, with a correlation id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub request: Request,
}

/// A response as it appears on the wire. Exactly one of
/// `result` or `error` is present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub outcome: ResponseOutcome,
}

/// The body of a ResponseEnvelope: either a successful Response or
/// an error. Serialized untagged so the JSON shape is the familiar
/// `{"id": N, "result": ...}` or `{"id": N, "error": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ResponseOutcome {
    Success { result: Response },
    Failure { error: ProtoError },
}

impl ResponseEnvelope {
    /// Convenience: build a success envelope.
    pub fn success(id: u64, result: Response) -> Self {
        ResponseEnvelope {
            id,
            outcome: ResponseOutcome::Success { result },
        }
    }

    /// Convenience: build an error envelope.
    pub fn failure(id: u64, code: i32, message: impl Into<String>) -> Self {
        ResponseEnvelope {
            id,
            outcome: ResponseOutcome::Failure {
                error: ProtoError { code, message: message.into() },
            },
        }
    }
}

// ============================================================
// NDJSON framing helpers
// ============================================================
//
// These are deliberately tiny. Anything needing async, timeouts,
// or cancellation belongs in the daemon / CLI, not the proto crate.

pub mod framing {
    use std::io::{BufRead, Write};

    use serde::{de::DeserializeOwned, Serialize};

    /// Serialize `value` as one JSON line and write it to `w`.
    pub fn write_line<W, T>(w: &mut W, value: &T) -> std::io::Result<()>
    where
        W: Write,
        T: Serialize,
    {
        let mut line = serde_json::to_string(value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        w.write_all(line.as_bytes())?;
        w.flush()
    }

    /// Read one JSON line from `r` and deserialize into `T`.
    /// Returns `Ok(None)` on clean EOF.
    pub fn read_line<R, T>(r: &mut R) -> std::io::Result<Option<T>>
    where
        R: BufRead,
        T: DeserializeOwned,
    {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r');
        if trimmed.is_empty() {
            return Ok(None);
        }
        let value = serde_json::from_str(trimmed)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(value))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ---- request round-trips ----

    #[test]
    fn ping_request_serializes_predictably() {
        let env = RequestEnvelope {
            id: 1,
            request: Request::Ping,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""method":"ping""#));
        assert!(json.contains(r#""id":1"#));

        let parsed: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn get_feed_request_carries_params() {
        let env = RequestEnvelope {
            id: 42,
            request: Request::GetFeed { name: "nightly".to_string() },
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""method":"get_feed""#));
        assert!(json.contains(r#""name":"nightly""#));

        let parsed: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    // ---- response round-trips ----

    #[test]
    fn success_response_round_trips() {
        let env = ResponseEnvelope::success(
            1,
            Response::Names(vec!["alpha".into(), "beta".into()]),
        );
        let json = serde_json::to_string(&env).unwrap();
        let parsed: ResponseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn error_response_round_trips() {
        let env = ResponseEnvelope::failure(
            7,
            error_code::NOT_FOUND,
            "feed 'missing' not found",
        );
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""code":1000"#));

        let parsed: ResponseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    // ---- framing round-trip over a buffer ----

    #[test]
    fn ndjson_framing_round_trips_multiple_messages() {
        let mut buf: Vec<u8> = Vec::new();

        let req1 = RequestEnvelope { id: 1, request: Request::Ping };
        let req2 = RequestEnvelope {
            id: 2,
            request: Request::GetEndpoint { name: "prod-sftp".into() },
        };

        framing::write_line(&mut buf, &req1).unwrap();
        framing::write_line(&mut buf, &req2).unwrap();

        // The framed stream should contain exactly two newline-terminated
        // lines, regardless of the internal JSON structure.
        let text = std::str::from_utf8(&buf).unwrap();
        assert_eq!(text.lines().count(), 2);

        let mut cursor = Cursor::new(buf);
        let got1: Option<RequestEnvelope> = framing::read_line(&mut cursor).unwrap();
        let got2: Option<RequestEnvelope> = framing::read_line(&mut cursor).unwrap();
        let got3: Option<RequestEnvelope> = framing::read_line(&mut cursor).unwrap();

        assert_eq!(got1, Some(req1));
        assert_eq!(got2, Some(req2));
        assert_eq!(got3, None); // clean EOF
    }
}
