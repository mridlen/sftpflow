// ============================================================
// sftpflow-cluster::state - openraft TypeConfig + state machine types
// ============================================================
//
// Defines the Raft state machine's data plane:
//
//   - NodeId           -> u64               (operator-supplied in M12)
//   - Node             -> ClusterMember     (advertise addr + metadata)
//   - D (LogPayload)   -> Command           (one variant per write op)
//   - R (Result)       -> CommandResult     (success / typed error)
//
// The actual RaftStateMachine + RaftLogStorage trait impls live
// in store.rs (next M12 task) so this module stays declarative.
//
// Command variants for M12: only `NoOp` is fully wired. The other
// variants (PutConfig, PutSecret, DeleteSecret, AppendRunHistory)
// are placeholders that ParseAccept on the wire but their apply()
// arms in store.rs are todo!() stubs — no caller produces them in
// M12. This keeps the proto + log format forward-compatible so M13
// and M14 only have to implement the apply paths.

use serde::{Deserialize, Serialize};

// ============================================================
// ClusterMember - per-node metadata stored in the membership set
// ============================================================
//
// openraft replicates this struct alongside the node ID in every
// membership change. Other nodes use `advertise_addr` to dial each
// other for Raft RPCs — must be reachable from every other member.

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClusterMember {
    /// host:port the node is listening on for mTLS Raft RPCs.
    /// Other members dial this address; it must resolve from
    /// every peer's vantage point.
    pub advertise_addr: String,

    /// Unix-seconds timestamp the member was added to the cluster.
    /// Informational; set by the bootstrap node when the join
    /// completes. Used by `cluster status` to display "joined N
    /// hours ago".
    pub added_at_unix: i64,

    /// Optional human-readable label provided when the join token
    /// was minted (e.g. "west-coast replica"). Surfaced in
    /// `cluster status` and audit logs.
    pub label: Option<String>,
}

// ---- Default required by openraft's Node trait ----
impl Default for ClusterMember {
    fn default() -> Self {
        Self {
            advertise_addr: String::new(),
            added_at_unix:  0,
            label:          None,
        }
    }
}

// ---- Display: shown in logs and CLI cluster-status output ----
impl std::fmt::Display for ClusterMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.label {
            Some(l) => write!(f, "{} ({})", self.advertise_addr, l),
            None    => write!(f, "{}", self.advertise_addr),
        }
    }
}

// ============================================================
// Command - log entry payload (the "D" type in openraft)
// ============================================================
//
// Every write the state machine must process is encoded as one
// Command variant. Replication is just "send this enum to every
// follower; everyone applies it in the same order."
//
// JSON-serialized via serde — openraft does not constrain the
// wire format. We use JSON because it's the same format the
// proto-level RaftRpcRequest payload uses (see proto/cluster.proto)
// so the code path is symmetric.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    // --------------------------------------------------------
    // M12 - the only variant that actually applies
    // --------------------------------------------------------

    /// Empty entry. Used by openraft for leader-affirmation
    /// heartbeats and read barriers, and by us for smoke tests
    /// during M12 development. Applying a NoOp updates
    /// `last_applied` and returns `CommandResult::Ok`.
    NoOp,

    // --------------------------------------------------------
    // M13 stubs - parsed on the wire, apply() is todo!()
    // --------------------------------------------------------

    /// Replace the cluster's `config.yaml` with the supplied
    /// content. Whole-file replacement keeps the state machine
    /// trivial; deltas can come later if the YAML grows large.
    PutConfig { config_yaml: String },

    /// Insert or replace one entry in the sealed-secrets blob.
    /// `ciphertext` is the age-encrypted value; the passphrase
    /// stays per-node and never enters the Raft log.
    PutSecret { name: String, ciphertext: Vec<u8> },

    /// Remove one entry from the sealed-secrets blob. No-op if
    /// the name is unknown (matches existing PutSecret/Delete RPC
    /// semantics in sftpflowd).
    DeleteSecret { name: String },

    // --------------------------------------------------------
    // M14 stub - parsed on the wire, apply() is todo!()
    // --------------------------------------------------------

    /// Append one row to the replicated run-history log. The
    /// value is the JSON serialization of `history::RunRow` from
    /// the existing per-node SQLite schema, replayed by every
    /// node into a local materialized view for fast `show runs`.
    AppendRunHistory { entry_json: String },
}

// ============================================================
// CommandResult - state machine return value (the "R" type)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandResult {
    /// Apply succeeded. The caller (a forwarded write RPC) maps
    /// this to whatever reply shape the calling RPC expects.
    Ok,

    /// Apply failed in a way the caller should surface verbatim.
    /// Reserved for M13/M14; M12's NoOp never errors.
    Err(String),
}

// ============================================================
// TypeConfig - openraft's bundle of associated types
// ============================================================
//
// `declare_raft_types!` is openraft's macro for stitching the
// associated types into a single `TypeConfig` impl. This lets
// downstream openraft generics (Raft<TypeConfig>, Entry<TypeConfig>,
// LogId<TypeConfig>, ...) all key off one parameter instead of
// dragging the full bundle through every signature.

openraft::declare_raft_types!(
    pub TypeConfig:
        D            = Command,
        R            = CommandResult,
        NodeId       = u64,
        Node         = ClusterMember,
        Entry        = openraft::Entry<TypeConfig>,
        SnapshotData = std::io::Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);
