// ============================================================
// sftpflow-cluster::store - sled-backed Raft storage
// ============================================================
//
// openraft 0.9 has two storage trait surfaces:
//
//   - v1 `RaftStorage`         - single trait, externally implementable
//   - v2 `RaftLogStorage` +
//     `RaftStateMachine`       - sealed; only `Adaptor<C, S>` implements them
//
// We implement the v1 `RaftStorage` and let openraft's
// `storage::Adaptor` wrap us into the v2 pair the runtime actually
// consumes. This keeps the entire storage surface in one struct
// while still working with the modern Raft API.
//
// Sled key layout:
//
//   meta tree:
//     "vote"               -> JSON-encoded openraft::Vote
//     "last_purged_log_id" -> JSON-encoded openraft::LogId
//     "current_snapshot"   -> JSON-encoded SnapshotRecord
//
//   log tree:
//     u64-BE index bytes   -> JSON-encoded openraft::Entry<TypeConfig>
//
// In M12 the state machine's data plane is intentionally empty —
// only `last_applied` and `last_membership` are tracked, mirroring
// what openraft itself replicates. M13/M14 grow the in-memory
// `StateMachineData` struct with config, secrets blob, and run
// history; the on-disk snapshot format follows whatever serde
// produces, so adding fields is non-breaking as long as they
// default sensibly when missing from older snapshots.

use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::{
    Entry,
    EntryPayload,
    LogId,
    LogState,
    OptionalSend,
    RaftSnapshotBuilder,
    RaftStorage,
    SnapshotMeta,
    StorageError,
    StorageIOError,
    StoredMembership,
    Vote,
    storage::{RaftLogReader, Snapshot},
};
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use tokio::sync::RwLock;

use crate::state::{ClusterMember, Command, CommandResult, TypeConfig};

// ============================================================
// SledDb - thin wrapper opening + holding the trees
// ============================================================

#[derive(Clone)]
pub struct SledDb {
    pub log:  Tree,
    pub meta: Tree,
}

impl SledDb {
    /// Open or create the sled database at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, sled::Error> {
        let db: Db = sled::open(path)?;
        let log  = db.open_tree("raft_log")?;
        let meta = db.open_tree("raft_meta")?;
        // Keep the Db alive for the process lifetime — Tree handles
        // hold internal references but the user-facing Db handle
        // dropping would close the underlying file.
        Box::leak(Box::new(db));
        Ok(Self { log, meta })
    }
}

// ============================================================
// JSON ser/de helpers
// ============================================================

fn to_bytes<T: Serialize>(val: &T) -> Result<Vec<u8>, StorageError<u64>> {
    serde_json::to_vec(val).map_err(|e| {
        StorageIOError::write(&AnyError(format!("serialize: {}", e))).into()
    })
}

fn from_bytes<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, StorageError<u64>> {
    serde_json::from_slice(bytes).map_err(|e| {
        StorageIOError::read(&AnyError(format!("deserialize: {}", e))).into()
    })
}

fn sled_io<T>(res: Result<T, sled::Error>) -> Result<T, StorageError<u64>> {
    res.map_err(|e| StorageIOError::read(&AnyError(format!("sled: {}", e))).into())
}

#[derive(Debug)]
struct AnyError(String);
impl std::fmt::Display for AnyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sftpflow-cluster storage: {}", self.0)
    }
}
impl std::error::Error for AnyError {}

// ============================================================
// Log index <-> sled key
// ============================================================

fn log_key(index: u64) -> [u8; 8] {
    index.to_be_bytes()
}

// ============================================================
// In-memory state machine data
// ============================================================

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct StateMachineData {
    pub last_applied:    Option<LogId<u64>>,
    pub last_membership: StoredMembership<u64, ClusterMember>,
    // M13/M14 will add:
    //   pub config_yaml:   Option<String>,
    //   pub secrets_blob:  Option<Vec<u8>>,
    //   pub run_history:   Vec<RunRow>,
}

/// One snapshot persisted to disk. Single blob in `meta` tree.
#[derive(Serialize, Deserialize, Clone)]
struct SnapshotRecord {
    meta: SnapshotMeta<u64, ClusterMember>,
    data: Vec<u8>,
}

// ============================================================
// SledStore - the single struct implementing RaftStorage
// ============================================================
//
// `Clone` is required so openraft's adapter can hand out two
// references (one for the log half, one for the SM half). The
// shared state behind the clone lives in Arc<RwLock<...>> for the
// state machine and inside sled (already Arc'd internally) for
// the log.

#[derive(Clone)]
pub struct SledStore {
    db:           SledDb,
    sm:           Arc<RwLock<StateMachineData>>,
    snapshot_idx: Arc<std::sync::atomic::AtomicU64>,
}

impl SledStore {
    /// Open or create a SledStore at `path`. Restores any persisted
    /// snapshot into the in-memory state machine.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let db = SledDb::open(path).map_err(|e| format!("sled open: {}", e))?;

        // Re-hydrate state machine from the persisted snapshot.
        let sm = match db.meta.get(b"current_snapshot").map_err(|e| e.to_string())? {
            Some(bytes) => {
                let rec: SnapshotRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("snapshot record: {}", e))?;
                let mut data: StateMachineData = if rec.data.is_empty() {
                    StateMachineData::default()
                } else {
                    serde_json::from_slice(&rec.data)
                        .map_err(|e| format!("snapshot data: {}", e))?
                };
                data.last_applied    = rec.meta.last_log_id;
                data.last_membership = rec.meta.last_membership.clone();
                data
            }
            None => StateMachineData::default(),
        };

        Ok(Self {
            db,
            sm:           Arc::new(RwLock::new(sm)),
            snapshot_idx: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }
}

// ============================================================
// RaftLogReader - range-fetch log entries
// ============================================================

impl RaftLogReader<TypeConfig> for SledStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        let start = match range.start_bound() {
            std::ops::Bound::Included(&i) => log_key(i),
            std::ops::Bound::Excluded(&i) => log_key(i + 1),
            std::ops::Bound::Unbounded     => log_key(0),
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(&i) => log_key(i + 1),
            std::ops::Bound::Excluded(&i) => log_key(i),
            std::ops::Bound::Unbounded     => log_key(u64::MAX),
        };

        let mut out = Vec::new();
        for kv in self.db.log.range(start..end) {
            let (_, v) = sled_io(kv)?;
            out.push(from_bytes::<Entry<TypeConfig>>(&v)?);
        }
        Ok(out)
    }
}

// ============================================================
// RaftSnapshotBuilder - build a snapshot from current SM state
// ============================================================

impl RaftSnapshotBuilder<TypeConfig> for SledStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        let g = self.sm.read().await;
        let data_bytes      = to_bytes(&*g)?;
        let last_log_id     = g.last_applied;
        let last_membership = g.last_membership.clone();
        drop(g);

        let id = self.snapshot_idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let snapshot_id = format!(
            "{}-{}-{}",
            last_log_id.map(|l| l.leader_id.term).unwrap_or(0),
            last_log_id.map(|l| l.index).unwrap_or(0),
            id,
        );

        let meta = SnapshotMeta { last_log_id, last_membership, snapshot_id };

        let rec = SnapshotRecord { meta: meta.clone(), data: data_bytes.clone() };
        sled_io(self.db.meta.insert(b"current_snapshot", to_bytes(&rec)?))?;
        sled_io(self.db.meta.flush_async().await.map_err(Into::into))?;

        Ok(Snapshot { meta, snapshot: Box::new(Cursor::new(data_bytes)) })
    }
}

// ============================================================
// RaftStorage - the full v1 trait
// ============================================================

impl RaftStorage<TypeConfig> for SledStore {
    type LogReader      = Self;
    type SnapshotBuilder = Self;

    // ---- Log state ------------------------------------------

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        let last_log_id = match sled_io(self.db.log.last())? {
            Some((_, v)) => Some(from_bytes::<Entry<TypeConfig>>(&v)?.log_id),
            None         => None,
        };

        let last_purged = match sled_io(self.db.meta.get(b"last_purged_log_id"))? {
            Some(bytes) => Some(from_bytes::<LogId<u64>>(&bytes)?),
            None        => None,
        };

        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id:        last_log_id.or(last_purged),
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    // ---- Vote -----------------------------------------------

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        sled_io(self.db.meta.insert(b"vote", to_bytes(vote)?))?;
        sled_io(self.db.meta.flush_async().await.map_err(Into::into))?;
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        match sled_io(self.db.meta.get(b"vote"))? {
            Some(bytes) => Ok(Some(from_bytes(&bytes)?)),
            None        => Ok(None),
        }
    }

    // ---- Log mutation ---------------------------------------

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let mut batch = sled::Batch::default();
        for entry in entries {
            batch.insert(&log_key(entry.log_id.index), to_bytes(&entry)?);
        }
        sled_io(self.db.log.apply_batch(batch))?;
        sled_io(self.db.log.flush_async().await.map_err(Into::into))?;
        Ok(())
    }

    async fn delete_conflict_logs_since(
        &mut self,
        log_id: LogId<u64>,
    ) -> Result<(), StorageError<u64>> {
        // Remove every entry with index >= log_id.index.
        let start = log_key(log_id.index);
        let end   = log_key(u64::MAX);
        let keys: Vec<_> = self
            .db
            .log
            .range(start..=end)
            .filter_map(|kv| kv.ok().map(|(k, _)| k))
            .collect();
        let mut batch = sled::Batch::default();
        for k in keys {
            batch.remove(k);
        }
        sled_io(self.db.log.apply_batch(batch))?;
        sled_io(self.db.log.flush_async().await.map_err(Into::into))?;
        Ok(())
    }

    async fn purge_logs_upto(
        &mut self,
        log_id: LogId<u64>,
    ) -> Result<(), StorageError<u64>> {
        // Remove every entry with index <= log_id.index AND record
        // the high-water mark so get_log_state() still answers
        // correctly after the entries themselves are gone.
        let start = log_key(0);
        let end   = log_key(log_id.index + 1);
        let keys: Vec<_> = self
            .db
            .log
            .range(start..end)
            .filter_map(|kv| kv.ok().map(|(k, _)| k))
            .collect();
        let mut batch = sled::Batch::default();
        for k in keys {
            batch.remove(k);
        }
        sled_io(self.db.log.apply_batch(batch))?;
        sled_io(self.db.meta.insert(b"last_purged_log_id", to_bytes(&log_id)?))?;
        sled_io(self.db.log.flush_async().await.map_err(Into::into))?;
        sled_io(self.db.meta.flush_async().await.map_err(Into::into))?;
        Ok(())
    }

    // ---- State machine --------------------------------------

    async fn last_applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, ClusterMember>), StorageError<u64>> {
        let g = self.sm.read().await;
        Ok((g.last_applied, g.last_membership.clone()))
    }

    async fn apply_to_state_machine(
        &mut self,
        entries: &[Entry<TypeConfig>],
    ) -> Result<Vec<CommandResult>, StorageError<u64>> {
        let mut g = self.sm.write().await;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            // Update last_applied for every kind of entry — openraft
            // needs to see forward progress through blanks and
            // membership changes too, not just normal payloads.
            g.last_applied = Some(entry.log_id);

            let res = match &entry.payload {
                EntryPayload::Blank => CommandResult::Ok,

                EntryPayload::Normal(cmd) => match cmd {
                    Command::NoOp => CommandResult::Ok,
                    // M13 stubs: parsed on the wire, refused at apply
                    Command::PutConfig    { .. } => CommandResult::Err("PutConfig not yet implemented (M13)".into()),
                    Command::PutSecret    { .. } => CommandResult::Err("PutSecret not yet implemented (M13)".into()),
                    Command::DeleteSecret { .. } => CommandResult::Err("DeleteSecret not yet implemented (M13)".into()),
                    // M14 stub
                    Command::AppendRunHistory { .. } => CommandResult::Err("AppendRunHistory not yet implemented (M14)".into()),
                },

                EntryPayload::Membership(m) => {
                    g.last_membership = StoredMembership::new(Some(entry.log_id), m.clone());
                    CommandResult::Ok
                }
            };
            out.push(res);
        }
        Ok(out)
    }

    // ---- Snapshots ------------------------------------------

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, ClusterMember>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let bytes = snapshot.into_inner();

        let mut sm: StateMachineData = if bytes.is_empty() {
            StateMachineData::default()
        } else {
            from_bytes(&bytes)?
        };
        sm.last_applied    = meta.last_log_id;
        sm.last_membership = meta.last_membership.clone();
        *self.sm.write().await = sm;

        let rec = SnapshotRecord { meta: meta.clone(), data: bytes };
        sled_io(self.db.meta.insert(b"current_snapshot", to_bytes(&rec)?))?;
        sled_io(self.db.meta.flush_async().await.map_err(Into::into))?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        match sled_io(self.db.meta.get(b"current_snapshot"))? {
            Some(bytes) => {
                let rec: SnapshotRecord = from_bytes(&bytes)?;
                Ok(Some(Snapshot {
                    meta:     rec.meta,
                    snapshot: Box::new(Cursor::new(rec.data)),
                }))
            }
            None => Ok(None),
        }
    }
}

// ============================================================
// Convenience constructor
// ============================================================
//
// Returns the v2 (LogStore, StateMachine) pair that openraft's
// `Raft::new()` consumes, by wrapping our v1 SledStore in
// openraft's `Adaptor`. Bin code never sees Adaptor or SledStore
// directly — it just calls open_for_raft() and passes the pair to
// `Raft::new(..., log, sm, ...)`.

pub fn open_for_raft(
    path: impl AsRef<std::path::Path>,
) -> Result<
    (
        openraft::storage::Adaptor<TypeConfig, SledStore>,
        openraft::storage::Adaptor<TypeConfig, SledStore>,
    ),
    String,
> {
    let store = SledStore::open(path)?;
    let (log, sm) = openraft::storage::Adaptor::new(store);
    Ok((log, sm))
}

// Suppress unused-variable warnings on stub command variants
// until M13/M14 wire them in.
#[allow(dead_code)]
fn _unused_command_variants() {
    let _ = Command::NoOp;
}
