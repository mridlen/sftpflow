// ============================================================
// sftpflowd::node_state - per-node persistent cluster state
// ============================================================
//
// Layout (see docs/m12-raft-scaffolding.md §4.2):
//
//   <state_dir>/
//   ├── node.json              # { version, node_id, cluster_id,
//   │                          #   advertise_addr, label, created_at_unix }
//   ├── cluster/
//   │   ├── ca.crt             # cluster CA cert (shared across nodes)
//   │   ├── ca.key             # CA private key (bootstrap node only)
//   │   ├── node.crt           # this node's leaf cert
//   │   └── node.key           # this node's leaf private key
//   ├── raft/                  # sled DB - openraft log + snapshots
//   ├── config.yaml            # unchanged pre-M12 file (loaded by Config::load)
//   ├── secrets.age            # unchanged pre-M12 sealed store
//   └── runs.db                # unchanged pre-M12 SQLite
//
// This module owns the paths and the on-disk representation of
// `node.json`. It does NOT own the PEM content (those are strings
// that come from sftpflow_cluster::tls at `init` / `join` time);
// `write_pem` is a thin helper that enforces 0600 perms on key
// files on Unix.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ============================================================
// Reserved secret-store keys
// ============================================================

/// Sealed-store key under which the raw token-HMAC secret is
/// stored (base64-encoded). Only the bootstrap node holds a
/// populated copy in M12 — joining nodes never receive it.
pub const CLUSTER_TOKEN_SECRET_KEY: &str = "__cluster_token_key__";

// ============================================================
// NodeJson - the stable identity written once per node
// ============================================================

/// Per-node identity record. Written once by `sftpflowd init` or
/// `sftpflowd join` and then never mutated. The daemon refuses to
/// start if the recorded `node_id` disagrees with the one the
/// operator passes on the command line (a safety net against
/// accidentally starting a node with someone else's identity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeJson {
    /// Schema version. Bumped when the shape changes; M12 is v1.
    pub version: u32,

    /// Stable cluster-wide ID for this node. Operator-supplied in
    /// M12 (auto-allocation lands in M15).
    pub node_id: u64,

    /// UUID of the cluster this node belongs to. Fixed at `init`
    /// on the bootstrap node and handed to joiners via the Join
    /// RPC. Used by the token subsystem to reject tokens issued
    /// for a different cluster.
    pub cluster_id: String,

    /// host:port other members dial to reach this node for Raft
    /// RPCs. Written here as a convenience so `cluster status`
    /// can display each peer's advertised endpoint without
    /// consulting the Raft state machine.
    pub advertise_addr: String,

    /// Optional human-readable label from --label. Shown in
    /// `cluster status` output and audit logs.
    pub label: Option<String>,

    /// Unix-seconds timestamp the node was first initialized or
    /// joined. Informational.
    pub created_at_unix: i64,
}

pub const NODE_JSON_VERSION: u32 = 1;

// ============================================================
// Path helpers
// ============================================================
//
// All functions take &Path (not PathBuf) so they compose cheaply.
// The state_dir itself is whatever the operator passed via
// --state-dir, or the platform default from main.rs::default_state_dir().

pub fn node_json_path(state_dir: &Path) -> PathBuf {
    state_dir.join("node.json")
}

pub fn cluster_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("cluster")
}

pub fn ca_cert_path(state_dir: &Path) -> PathBuf {
    cluster_dir(state_dir).join("ca.crt")
}

pub fn ca_key_path(state_dir: &Path) -> PathBuf {
    cluster_dir(state_dir).join("ca.key")
}

pub fn leaf_cert_path(state_dir: &Path) -> PathBuf {
    cluster_dir(state_dir).join("node.crt")
}

pub fn leaf_key_path(state_dir: &Path) -> PathBuf {
    cluster_dir(state_dir).join("node.key")
}

pub fn raft_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("raft")
}

// ============================================================
// Time
// ============================================================

/// Seconds since the Unix epoch, saturating to 0 on clock errors.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ============================================================
// node.json I/O
// ============================================================

/// Read `<state_dir>/node.json`, if present.
pub fn read_node_json(state_dir: &Path) -> Result<Option<NodeJson>, String> {
    let path = node_json_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("reading {}: {}", path.display(), e))?;
    let parsed: NodeJson = serde_json::from_str(&raw)
        .map_err(|e| format!("parsing {}: {}", path.display(), e))?;
    Ok(Some(parsed))
}

/// Write `<state_dir>/node.json` atomically (via a .new sibling +
/// rename) so a crash mid-write cannot leave a partial file.
/// Creates `state_dir` if it doesn't exist.
pub fn write_node_json(state_dir: &Path, node: &NodeJson) -> Result<(), String> {
    fs::create_dir_all(state_dir)
        .map_err(|e| format!("creating {}: {}", state_dir.display(), e))?;

    let final_path = node_json_path(state_dir);
    let tmp_path   = state_dir.join("node.json.new");

    let serialized = serde_json::to_string_pretty(node)
        .map_err(|e| format!("serializing node.json: {}", e))?;

    {
        let mut f = fs::File::create(&tmp_path)
            .map_err(|e| format!("creating {}: {}", tmp_path.display(), e))?;
        f.write_all(serialized.as_bytes())
            .map_err(|e| format!("writing {}: {}", tmp_path.display(), e))?;
        f.sync_all()
            .map_err(|e| format!("syncing {}: {}", tmp_path.display(), e))?;
    }
    fs::rename(&tmp_path, &final_path)
        .map_err(|e| format!("renaming {} -> {}: {}", tmp_path.display(), final_path.display(), e))?;
    Ok(())
}

// ============================================================
// PEM file I/O
// ============================================================

/// Write a PEM string to `path`. When `sensitive` is true the
/// file is chmod'd to 0600 on Unix (no-op on Windows since NTFS
/// ACLs aren't exposed this way; production Windows deployments
/// should rely on %APPDATA% being per-user).
///
/// The parent directory is created if missing, and the file is
/// written via a .new sibling + rename for atomicity.
pub fn write_pem(path: &Path, pem: &str, sensitive: bool) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {}", parent.display(), e))?;
    }

    // Stage to "<path>.new" so a crash between write and rename
    // doesn't leave a half-written cert on disk.
    let tmp = path.with_extension({
        let mut ext = path.extension().map(|e| e.to_os_string()).unwrap_or_default();
        ext.push(".new");
        ext
    });

    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| format!("creating {}: {}", tmp.display(), e))?;
        f.write_all(pem.as_bytes())
            .map_err(|e| format!("writing {}: {}", tmp.display(), e))?;
        f.sync_all()
            .map_err(|e| format!("syncing {}: {}", tmp.display(), e))?;
    }

    // Restrictive mode must be set on the tmp file BEFORE the
    // rename so there is no window where the final file is
    // world-readable.
    #[cfg(unix)]
    if sensitive {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 on {}: {}", tmp.display(), e))?;
    }
    #[cfg(not(unix))]
    let _ = sensitive; // silence unused on Windows

    fs::rename(&tmp, path)
        .map_err(|e| format!("renaming {} -> {}: {}", tmp.display(), path.display(), e))
}

/// Read a PEM file into a String. Thin wrapper so call sites stay
/// single-line and errors carry the path. Consumed by `cmd_run`'s
/// cluster-mode restart branch (next PR-B commit) — marked
/// allow(dead_code) until that lands so the tree stays warning-free.
#[allow(dead_code)]
pub fn read_pem(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {}", path.display(), e))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn node_json_round_trip() {
        let dir = tempdir().unwrap();
        let n = NodeJson {
            version:          NODE_JSON_VERSION,
            node_id:          42,
            cluster_id:       "abc-123".to_string(),
            advertise_addr:   "10.0.0.7:7900".to_string(),
            label:            Some("west-coast".to_string()),
            created_at_unix:  1_700_000_000,
        };
        write_node_json(dir.path(), &n).unwrap();
        let loaded = read_node_json(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.node_id,        42);
        assert_eq!(loaded.cluster_id,     "abc-123");
        assert_eq!(loaded.advertise_addr, "10.0.0.7:7900");
        assert_eq!(loaded.label.as_deref(), Some("west-coast"));
        assert_eq!(loaded.created_at_unix, 1_700_000_000);
    }

    #[test]
    fn read_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        assert!(read_node_json(dir.path()).unwrap().is_none());
    }

    #[test]
    fn write_pem_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cluster").join("ca.crt");
        write_pem(&path, "-----BEGIN CERTIFICATE-----\n...\n", false).unwrap();
        let back = read_pem(&path).unwrap();
        assert!(back.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_pem_is_chmod_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("cluster").join("node.key");
        write_pem(&path, "-----BEGIN PRIVATE KEY-----\n", true).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "sensitive file should be 0600, got {:o}", mode);
    }
}
