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

    // ---- cluster (M12+) ----
    /// Snapshot of cluster membership, leader, and self ID. Read-only;
    /// any node can answer.
    ClusterStatus,
    /// Mint a new join token. Only the bootstrap node holds the
    /// token-HMAC secret in M12; other nodes return CONFIG_ERROR.
    /// `ttl_seconds` is the requested validity window; the daemon
    /// caps it at its configured max (1 hour by default). `None`
    /// uses the daemon default.
    ClusterMintToken { ttl_seconds: Option<u32> },
    /// Remove a node from the cluster's voter set. Leader-only.
    /// The CLI must double-confirm before sending.
    ClusterRemoveNode { node_id: u64 },
    /// Self-removal: the receiving node steps itself out of the
    /// cluster. Sent to the node the operator wants to leave (not
    /// to the leader) — the leaver decides whether to call
    /// `change_membership` locally (if it is the leader) or to
    /// forward a `ClusterRemoveNode` for its own id to the current
    /// leader. The CLI double-confirms before sending.
    ClusterLeave,
    /// Fetch this node's copy of the cluster CA certificate (PEM).
    /// Read-only; any cluster member can serve it. Used by the
    /// CLI's `cluster join` command to ship the CA to a new host
    /// without an out-of-band scp.
    ClusterGetCa,
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
    /// Reply to ClusterStatus. Read-only snapshot used by the
    /// CLI's `cluster status` command.
    ClusterStatus(ClusterStatus),
    /// Reply to ClusterMintToken. Wraps the opaque token string
    /// so the CLI can surface its expiry alongside it.
    ClusterToken(ClusterToken),
    /// Reply to ClusterGetCa. PEM-encoded cluster CA cert.
    ClusterCaCert(String),
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

/// Snapshot of a Raft cluster's membership and current leader.
/// Returned by ClusterStatus. The CLI uses this to render a colored
/// table; daemon-side it's a thin projection of openraft metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterStatus {
    /// UUID minted at `sftpflowd init`. Identifies the cluster.
    pub cluster_id: String,
    /// Node ID of the daemon answering the request — lets the CLI
    /// mark the responding node distinctly in the output.
    pub self_id: u64,
    /// Node ID of the current leader, from the responder's view.
    /// `None` during an in-progress election.
    pub leader_id: Option<u64>,
    /// All members openraft knows about (voters + learners). Order
    /// is by node_id ascending so output is deterministic.
    pub members: Vec<ClusterMemberInfo>,
    /// Wall-clock seconds since the responder's daemon started.
    /// Defaulted on older daemons that don't populate this field.
    #[serde(default)]
    pub responder_uptime_secs: u64,
    /// Responder's local last-log index (leader: tip of the cluster
    /// log; follower: this node's tip). `None` if the responder has
    /// no log yet.
    #[serde(default)]
    pub responder_last_log_index: Option<u64>,
    /// Responder's local last-applied index (state-machine tip).
    /// Always populated when a state machine has applied at least
    /// one entry; otherwise `None`.
    #[serde(default)]
    pub responder_last_applied_index: Option<u64>,
    /// True if the responding node is itself the leader. When false,
    /// per-member matched/lag fields below are unavailable (only the
    /// leader sees replication progress).
    #[serde(default)]
    pub responder_is_leader: bool,
}

/// One row of cluster status output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterMemberInfo {
    pub node_id: u64,
    pub advertise_addr: String,
    /// Operator-supplied label from `--label` at init/join time.
    pub label: Option<String>,
    /// True if this node was a voter at the last applied membership
    /// change. False means this is a learner (non-voting replica).
    pub is_voter: bool,
    /// Highest log index the leader has seen this peer acknowledge
    /// (openraft replication-metrics matched index). Only populated
    /// when the responder is the leader; `None` otherwise. For the
    /// leader's own row this mirrors leader's last_log_index.
    #[serde(default)]
    pub matched_log_index: Option<u64>,
    /// `leader.last_log_index - matched_log_index`, saturating at 0.
    /// Same availability rule as `matched_log_index`. The CLI surfaces
    /// large values as the "this peer is falling behind" signal.
    #[serde(default)]
    pub lag: Option<u64>,
}

/// Outcome of a ClusterMintToken request. The token string itself
/// is opaque to the CLI; `expires_at_unix` is informational so the
/// operator knows how long they have to redeem it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterToken {
    pub token: String,
    pub expires_at_unix: i64,
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
    /// This node is not the Raft leader; the requested mutating
    /// RPC must be sent to whoever is. The error message includes
    /// the leader's advertise address when available so the CLI
    /// (or a human) can retry against the right node. M12 is
    /// fail-loud; M13 will turn this into automatic forwarding.
    pub const NOT_LEADER:       i32 = 1004;
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
