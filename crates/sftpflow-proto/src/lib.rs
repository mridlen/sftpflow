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
    /// Hot backup: the receiving node tars its own state (cluster
    /// certs, raft sled DB, vacuumed runs.db, sealed secrets,
    /// config.yaml) into `out_path` on the *server's* filesystem.
    /// Not in `is_mutating()` — every node can back up its own
    /// state regardless of leader status. Operator scps the file
    /// back from the server in v1; future versions may stream it
    /// inline. The path must be absolute server-side.
    ClusterBackup { out_path: String },

    /// Read-only: fetch the most recent rows from this node's
    /// audit log. The audit log records one row per successful (or
    /// failed) mutating RPC: timestamp, caller (the CLI-attributed
    /// `<user>@<host>`), method name, sha256 hash of the params,
    /// and outcome (`ok` or `err:<code>`). Useful for "who changed
    /// what when" investigations.
    ///
    /// `limit` defaults to 50 if `None`. `since_unix` filters to
    /// rows with `ts_unix >= since_unix` so an operator can scope
    /// to a window without paginating.
    GetAuditLog { limit: Option<u32>, since_unix: Option<i64> },
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
    /// Reply to ClusterBackup. Carries the resulting archive's
    /// server-side path, size, sha256, and source-node identifiers
    /// so the operator can verify the file post-scp.
    BackupReport(BackupReport),
    /// Reply to GetAuditLog. Newest-first ordering by `ts_unix`.
    AuditLog(Vec<AuditEntry>),
    /// Reply to a request that was sent with `dry_run=true` on the
    /// envelope. Carries a structured preview of what *would* happen
    /// (summary line, side-effect list, warnings) without any state
    /// being mutated. Only a fixed allowlist of mutating RPCs honors
    /// the dry-run flag — the rest reply with INVALID_PARAMS so the
    /// CLI never silently lets a real mutation through under a
    /// preview-shaped command.
    DryRunReport(DryRunReport),
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

/// Outcome of a `ClusterBackup` RPC. The archive itself is written
/// server-side at `archive_path`; this struct just gives the CLI
/// enough metadata to print a summary and verify a scp'd copy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupReport {
    /// Absolute path on the server's filesystem where the archive
    /// was written. The operator scps this back themselves in v1.
    pub archive_path: String,
    /// Compressed (.tar.gz) size in bytes.
    pub archive_size: u64,
    /// Lowercase hex sha256 of the archive bytes. Lets the operator
    /// verify their scp'd copy matches what the daemon produced.
    pub archive_sha256: String,
    /// Number of source files included (excludes manifest.json).
    pub file_count: usize,
    /// Source node's cluster UUID, when it is a cluster member.
    pub cluster_id: Option<String>,
    /// Source node's u64 ID, when present.
    pub node_id: Option<u64>,
}

// ============================================================
// DryRunReport - preview payload for `--dry-run` previews
// ============================================================
//
// A daemon-side "what would happen if I ran this for real" answer.
// Returned by every mutating RPC handler that supports dry-run mode
// (delete/rename of endpoints/keys/feeds, delete_secret, and
// cluster_remove_node). The CLI renders the three lists below as
// plain text under the destructive command's confirm flow.
//
// The shape is intentionally generic — `summary` is the headline
// (e.g. "would delete feed 'nightly'"), `effects` enumerates the
// concrete state changes that would land (reference rewrites,
// orphaned references, voter set deltas), and `warnings` flags
// anything the operator should look at twice (a removed endpoint
// still being referenced by N feeds, a quorum that drops to a
// single voter, etc.).
//
// Empty `effects` / `warnings` are valid and just mean "nothing
// notable" — a delete with zero references produces an effects
// list of one entry ("would remove `<thing>` from the registry")
// and no warnings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DryRunReport {
    /// One-line summary of the action that would have been taken.
    /// Always populated.
    pub summary: String,
    /// Bullet-list of concrete side-effects the real run would have.
    /// Cross-reference rewrites, dkron job deletions, voter set
    /// transitions, etc. Order is render order.
    pub effects: Vec<String>,
    /// Operator-facing warnings — orphaned references, quorum
    /// implications, in-use secret removals, etc. Empty when nothing
    /// is unusual.
    pub warnings: Vec<String>,
}

/// One row of the cluster mutation audit log, returned by GetAuditLog.
///
/// Audit rows are append-only. The daemon records one entry per
/// mutating RPC (handler success or failure both produce a row);
/// read-only RPCs do not appear here. `args_hash` is the sha256 of
/// the serialized `params` JSON — sensitive values (PutSecret etc.)
/// stay sealed but the hash still gives a consistent fingerprint
/// for "did the operator submit the same input twice?" questions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    /// Auto-incremented row id.
    pub id: i64,
    /// Unix epoch seconds when the RPC dispatched.
    pub ts_unix: i64,
    /// ISO 8601 UTC timestamp matching `ts_unix`. Cached at write
    /// time so the CLI doesn't reformat on every render.
    pub ts_iso: String,
    /// CLI-attributed `<user>@<host>` (or system user for socket
    /// dev mode). `None` for envelopes the CLI didn't stamp — older
    /// daemons forwarding in mid-cluster, or hand-crafted requests.
    pub caller: Option<String>,
    /// Method name from `Request`, snake_case (e.g. "put_endpoint").
    pub rpc: String,
    /// Lowercase hex sha256 (64 chars) of the request's `params`
    /// JSON. Empty string for parameterless mutations.
    pub args_hash: String,
    /// `"ok"` for handler success; `"err:<code>"` (e.g. `"err:1004"`
    /// for NOT_LEADER) for failures. Operators can filter on prefix.
    pub outcome: String,
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
///
/// `caller` is informational metadata stamped by the CLI for the
/// audit log: typically `"<ssh-user>@<host>"` (SSH transport) or
/// `"<system-user>@local"` (socket dev mode). The daemon does NOT
/// authenticate this string — SSH already authenticated the user
/// at the transport layer; `caller` just records what the CLI was
/// told to call them. `#[serde(default)]` keeps older CLIs (which
/// don't set this field) compatible.
///
/// `dry_run` asks the daemon to compute the effect of a mutating
/// RPC without applying it. Only an allowlist of mutating RPCs
/// (delete/rename of endpoints/keys/feeds, delete_secret,
/// cluster_remove_node) honors the flag — anything else returns
/// INVALID_PARAMS so the CLI can never silently let a real
/// mutation slip through under a preview-shaped command. The
/// audit row records dry-runs with an outcome of `"dry-run:ok"` /
/// `"dry-run:err:<code>"` so they're trivially filterable. Same
/// `#[serde(default, skip_serializing_if)]` shape as `caller` so
/// older daemons (which never read the flag) keep working.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestEnvelope {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    #[serde(flatten)]
    pub request: Request,
}

/// `skip_serializing_if` predicate for the `dry_run` envelope flag.
/// Free function (rather than a closure) so serde's macro can take
/// it by path — matches the existing `Option::is_none` pattern.
fn is_false(b: &bool) -> bool { !*b }

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
            caller: None,
            dry_run: false,
            request: Request::Ping,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""method":"ping""#));
        assert!(json.contains(r#""id":1"#));
        // No caller stamped → field omitted from the wire form.
        assert!(!json.contains(r#""caller""#));
        // dry_run defaults to false → field omitted too.
        assert!(!json.contains(r#""dry_run""#));

        let parsed: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn caller_round_trips_when_set() {
        let env = RequestEnvelope {
            id: 7,
            caller: Some("alice@prod-1".into()),
            dry_run: false,
            request: Request::DeleteFeed { name: "nightly".into() },
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""caller":"alice@prod-1""#));

        let parsed: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn dry_run_round_trips_when_set() {
        let env = RequestEnvelope {
            id: 99,
            caller: None,
            dry_run: true,
            request: Request::DeleteFeed { name: "nightly".into() },
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""dry_run":true"#));

        let parsed: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
        assert!(parsed.dry_run);
    }

    #[test]
    fn legacy_envelope_without_caller_still_parses() {
        // Older CLIs predate the `caller` and `dry_run` fields. Their
        // envelopes must still deserialize cleanly via #[serde(default)].
        let json = r#"{"id":3,"method":"ping"}"#;
        let parsed: RequestEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.id, 3);
        assert_eq!(parsed.caller, None);
        assert!(!parsed.dry_run);
    }

    #[test]
    fn get_feed_request_carries_params() {
        let env = RequestEnvelope {
            id: 42,
            caller: None,
            dry_run: false,
            request: Request::GetFeed { name: "nightly".to_string() },
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""method":"get_feed""#));
        assert!(json.contains(r#""name":"nightly""#));

        let parsed: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn dry_run_report_round_trips() {
        let env = ResponseEnvelope::success(
            5,
            Response::DryRunReport(DryRunReport {
                summary:  "would delete feed 'nightly'".into(),
                effects:  vec!["would remove feed 'nightly' from registry".into()],
                warnings: vec!["feed 'weekly' references 'nightly' via nextstep".into()],
            }),
        );
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""kind":"dry_run_report""#));
        assert!(json.contains(r#""summary""#));
        assert!(json.contains(r#""effects""#));
        assert!(json.contains(r#""warnings""#));

        let parsed: ResponseEnvelope = serde_json::from_str(&json).unwrap();
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

        let req1 = RequestEnvelope {
            id: 1,
            caller: None,
            dry_run: false,
            request: Request::Ping,
        };
        let req2 = RequestEnvelope {
            id: 2,
            caller: None,
            dry_run: false,
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
