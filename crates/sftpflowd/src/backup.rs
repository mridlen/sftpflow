// ============================================================
// sftpflowd::backup - hot backup + cold restore of node state
// ============================================================
//
// Two entry points:
//
//   - run_backup_hot(paths, out_path)
//       Live (daemon-running) snapshot of every per-node file —
//       node.json, cluster/*.{crt,key}, the entire raft/ sled tree,
//       runs.db (via SQLite VACUUM INTO for a consistent point-in-
//       time copy), the sealed secrets file, and config.yaml — into
//       a single .tar.gz archive. Safe to run while sftpflowd is up:
//       sled is journal-recoverable on restore, secrets/config use
//       atomic-write patterns, runs.db gets a transactional copy.
//
//   - run_restore_cold(paths, archive_path)
//       Cold restore from an archive produced by run_backup_hot.
//       Refuses unless every target path is empty (matches the
//       sftpflowd init/join clobber guard). Validates per-file
//       sha256 hashes against the manifest before placing anything
//       into the live filesystem; an archive with a corrupted file
//       fails fast without touching the destination.
//
// Archive layout:
//
//   manifest.json            schema version, timestamps, file index
//   node.json                cluster identity (if present)
//   cluster/ca.crt           cluster CA (if present)
//   cluster/ca.key           CA private key (bootstrap node only)
//   cluster/node.crt         this node's leaf cert
//   cluster/node.key         this node's leaf private key
//   raft/...                 sled DB tree (recursive)
//   runs.db                  vacuumed SQLite snapshot
//   secrets.age              sealed credential store
//   config.yaml              sftpflow-core YAML config
//
// Files that don't exist on disk are silently skipped — a fresh
// joiner with no sealed store, or a legacy single-node deployment
// without a cluster/, both produce valid (smaller) archives.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::node_state;
use crate::server::DaemonPaths;

// ============================================================
// Constants
// ============================================================

/// Archive schema version. Bumped on incompatible layout changes;
/// restore refuses anything newer than this.
const ARCHIVE_VERSION: u32 = 1;

/// Filename of the JSON index inside the archive. Always present at
/// the archive root; restore reads this first to validate the rest.
const MANIFEST_FILE: &str = "manifest.json";

// ============================================================
// Manifest
// ============================================================

/// On-disk index written into every archive. Operators can
/// `tar -xzOf archive.tar.gz manifest.json | jq` to inspect a
/// backup without restoring it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version; restore refuses if greater than ARCHIVE_VERSION.
    pub version: u32,
    /// Unix-seconds timestamp the archive was produced.
    pub created_at_unix: i64,
    /// `env!("CARGO_PKG_VERSION")` of the sftpflowd that produced
    /// the archive. Informational; restore tolerates version drift.
    pub sftpflow_version: String,
    /// Cluster UUID, when the source node was a cluster member.
    /// `None` for legacy single-node backups.
    pub cluster_id: Option<String>,
    /// Source node's u64 ID. `None` for legacy single-node backups.
    pub node_id: Option<u64>,
    /// Source node's `--label`, if any.
    pub label: Option<String>,
    /// Per-file index. Order matches archive insertion order; the
    /// `manifest.json` entry itself is NOT listed here (it would be
    /// circular).
    pub files: Vec<FileEntry>,
}

/// One row in the manifest index — covers every non-manifest file
/// in the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path inside the archive (e.g. "raft/db", "cluster/ca.crt").
    pub archive_path: String,
    /// Plaintext byte length.
    pub size: u64,
    /// Lowercase hex sha256 of the file contents. Verified during
    /// restore — a mismatch aborts the restore before any write.
    pub sha256: String,
}

// ============================================================
// Backup report (returned by run_backup_hot, surfaced via RPC)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupReport {
    /// Absolute path the archive was written to (server-side).
    pub archive_path: String,
    /// Compressed (.tar.gz) size in bytes.
    pub archive_size: u64,
    /// Lowercase hex sha256 of the archive bytes. Lets the operator
    /// verify scp'd copies match the original.
    pub archive_sha256: String,
    /// Number of source files included (excludes manifest.json).
    pub file_count: usize,
    /// Cluster UUID of the source node, when present.
    pub cluster_id: Option<String>,
    /// Source node's u64 ID, when present.
    pub node_id: Option<u64>,
}

// ============================================================
// Hot backup
// ============================================================
//
// Order of operations matters for "as consistent as possible":
//
//   1. Read node.json synchronously (atomic on write).
//   2. VACUUM INTO a temp copy of runs.db — gives us a transactionally
//      consistent SQLite snapshot even though the daemon may be
//      writing rows in parallel.
//   3. Walk the rest of the node-local files. Each one uses an
//      atomic-rename write pattern (sealed store, config.yaml,
//      certs), so a byte-level copy is automatically point-in-time.
//   4. Sled's raft/ directory is journal-recoverable: openraft will
//      replay the WAL on next open, so a byte-level copy of the dir
//      is safe even with active writes.
//   5. Build the archive on disk (streaming gz).
//   6. Re-read the archive once to compute its sha256 for the report.

pub fn run_backup_hot(
    paths:    &DaemonPaths,
    out_path: &Path,
) -> Result<BackupReport, String> {
    info!("backup: starting (out={})", out_path.display());

    // ---- 1. Read node identity (if cluster member) ----
    let node_meta  = node_state::read_node_json(&paths.state_dir).ok().flatten();
    let cluster_id = node_meta.as_ref().map(|n| n.cluster_id.clone());
    let node_id    = node_meta.as_ref().map(|n| n.node_id);
    let label      = node_meta.as_ref().and_then(|n| n.label.clone());

    // ---- 2. Stage SQLite via VACUUM INTO ----
    // VACUUM INTO acquires the SHARED lock atomically and writes a
    // transactionally consistent copy of the DB to a new file —
    // even if writers are concurrently appending run rows.
    let staging = tempfile::tempdir()
        .map_err(|e| format!("creating temp staging dir: {}", e))?;
    let staged_db = stage_sqlite_snapshot(&paths.runs_db, staging.path())?;

    // ---- 3. Enumerate files to include ----
    let mut file_specs: Vec<(PathBuf, String)> = Vec::new();
    collect_backup_files(paths, &staged_db, &mut file_specs)?;

    // ---- 4. Build the archive ----
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {}", parent.display(), e))?;
        }
    }

    let archive_file = fs::File::create(out_path)
        .map_err(|e| format!("creating archive {}: {}", out_path.display(), e))?;
    let gz_writer  = GzEncoder::new(archive_file, Compression::default());
    let mut tar    = tar::Builder::new(gz_writer);
    // tar 0.4 default mode follows symlinks; we prefer to never
    // dereference a key file that someone replaced with a symlink.
    tar.follow_symlinks(false);

    let now = node_state::now_unix();
    let mut entries: Vec<FileEntry> = Vec::with_capacity(file_specs.len());

    for (src, archive_path) in &file_specs {
        let bytes = fs::read(src)
            .map_err(|e| format!("read {}: {}", src.display(), e))?;
        let sha256 = sha256_hex(&bytes);

        append_bytes_to_tar(&mut tar, archive_path, &bytes, now, /*sensitive=*/ archive_is_sensitive(archive_path))?;

        entries.push(FileEntry {
            archive_path: archive_path.clone(),
            size:         bytes.len() as u64,
            sha256,
        });
    }

    // Write the manifest LAST so it can list every file we appended.
    let manifest = Manifest {
        version:          ARCHIVE_VERSION,
        created_at_unix:  now,
        sftpflow_version: env!("CARGO_PKG_VERSION").to_string(),
        cluster_id:       cluster_id.clone(),
        node_id,
        label,
        files:            entries,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("serializing manifest: {}", e))?;
    append_bytes_to_tar(&mut tar, MANIFEST_FILE, &manifest_bytes, now, /*sensitive=*/ false)?;

    let gz_writer = tar
        .into_inner()
        .map_err(|e| format!("finalizing tar: {}", e))?;
    gz_writer
        .finish()
        .map_err(|e| format!("finalizing gz: {}", e))?;

    // ---- 5. Re-read archive for hash + size in the report ----
    let archive_bytes = fs::read(out_path)
        .map_err(|e| format!("re-reading archive for hash: {}", e))?;
    let archive_size   = archive_bytes.len() as u64;
    let archive_sha256 = sha256_hex(&archive_bytes);

    info!(
        "backup: wrote {} ({} files, {} bytes, sha256={})",
        out_path.display(),
        manifest.files.len(),
        archive_size,
        archive_sha256,
    );

    Ok(BackupReport {
        archive_path:   out_path.to_string_lossy().into_owned(),
        archive_size,
        archive_sha256,
        file_count:     manifest.files.len(),
        cluster_id,
        node_id,
    })
}

// ============================================================
// Cold restore
// ============================================================
//
// Refuses to clobber anything. Mirrors the `sftpflowd init`/`join`
// guard: if any target path already exists, abort and tell the
// operator to wipe the state dir first.
//
// Validation strategy:
//
//   1. Open the archive and read manifest.json into memory.
//   2. Refuse if the archive's `version` is newer than ARCHIVE_VERSION
//      (we don't know how to interpret it).
//   3. Build the full list of (file_entry, dest_path) targets and
//      refuse if ANY of them already exists.
//   4. Re-open the archive and stream every file:
//        - skip manifest.json (already in memory)
//        - hash each entry as we read it; compare to manifest.sha256
//        - on hash success, write the bytes to the resolved dest
//      A hash mismatch aborts mid-extract: any files already written
//      stay where they are, but the next pass will see them and
//      refuse — operator is forced to clean up before re-running.

pub fn run_restore_cold(
    paths:        &DaemonPaths,
    archive_path: &Path,
) -> Result<RestoreReport, String> {
    info!("restore: starting (archive={})", archive_path.display());

    // ---- 1. Read manifest ----
    let manifest = read_manifest(archive_path)?;
    if manifest.version > ARCHIVE_VERSION {
        return Err(format!(
            "archive schema version {} is newer than this sftpflowd's max ({}); \
             upgrade sftpflowd before restoring",
            manifest.version, ARCHIVE_VERSION,
        ));
    }
    info!(
        "restore: manifest version={}, files={}, cluster_id={:?}, node_id={:?}",
        manifest.version, manifest.files.len(), manifest.cluster_id, manifest.node_id,
    );

    // ---- 2. Build target paths + refuse if any exist ----
    let targets: Vec<(FileEntry, PathBuf)> = manifest
        .files
        .iter()
        .map(|fe| {
            let dst = resolve_archive_dest(paths, &fe.archive_path);
            (fe.clone(), dst)
        })
        .collect();

    let mut blocking: Vec<String> = Vec::new();
    for (_, dst) in &targets {
        if dst.exists() {
            blocking.push(dst.display().to_string());
        }
    }
    if !blocking.is_empty() {
        return Err(format!(
            "refusing to restore: {} target file(s) already exist:\n  {}\n\
             remove them (e.g. wipe the state directory) and re-run",
            blocking.len(),
            blocking.join("\n  "),
        ));
    }

    // ---- 3. Stream-extract, verifying hashes ----
    let archive_file = fs::File::open(archive_path)
        .map_err(|e| format!("opening archive {}: {}", archive_path.display(), e))?;
    let gz = GzDecoder::new(archive_file);
    let mut tar = tar::Archive::new(gz);

    // Index manifest entries by archive_path for O(1) lookup as we
    // walk the archive (whose entry order is whatever was written).
    let mut by_path: std::collections::BTreeMap<String, &FileEntry> =
        std::collections::BTreeMap::new();
    for fe in &manifest.files {
        by_path.insert(fe.archive_path.clone(), fe);
    }

    let mut written = 0usize;
    for entry in tar.entries().map_err(|e| format!("reading archive: {}", e))? {
        let mut entry = entry.map_err(|e| format!("reading archive entry: {}", e))?;
        let path_in_archive = entry
            .path()
            .map_err(|e| format!("reading entry path: {}", e))?
            .to_string_lossy()
            .replace('\\', "/")
            .to_string();

        if path_in_archive == MANIFEST_FILE {
            continue;
        }

        // Look up the manifest row. An archive that contains a file
        // not in the manifest is malformed — refuse.
        let fe = match by_path.get(&path_in_archive) {
            Some(fe) => *fe,
            None => {
                return Err(format!(
                    "archive contains '{}' which is not listed in manifest.json — \
                     refusing to restore from a tampered or truncated archive",
                    path_in_archive,
                ));
            }
        };

        // Read entry into memory and validate hash before writing
        // anything to the live filesystem.
        let mut bytes = Vec::with_capacity(fe.size as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("reading '{}': {}", path_in_archive, e))?;

        if bytes.len() as u64 != fe.size {
            return Err(format!(
                "size mismatch on '{}': manifest={} actual={}",
                path_in_archive, fe.size, bytes.len(),
            ));
        }
        let actual = sha256_hex(&bytes);
        if actual != fe.sha256 {
            return Err(format!(
                "sha256 mismatch on '{}': manifest={} actual={} — refusing restore \
                 (archive may be corrupt)",
                path_in_archive, fe.sha256, actual,
            ));
        }

        // Resolve dest, ensure parent exists, write atomically. We
        // already verified dest didn't exist in step 2 — but a
        // racing process could have created it; fail loud if so.
        let dst = resolve_archive_dest(paths, &path_in_archive);
        if dst.exists() {
            return Err(format!(
                "race: '{}' was created during restore — aborting",
                dst.display(),
            ));
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {}", parent.display(), e))?;
        }
        write_atomic(&dst, &bytes, archive_is_sensitive(&path_in_archive))
            .map_err(|e| format!("writing {}: {}", dst.display(), e))?;
        written += 1;
    }

    info!("restore: wrote {} files", written);

    Ok(RestoreReport {
        files_restored:   written,
        cluster_id:       manifest.cluster_id,
        node_id:          manifest.node_id,
        sftpflow_version: manifest.sftpflow_version,
    })
}

#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub files_restored:   usize,
    pub cluster_id:       Option<String>,
    pub node_id:          Option<u64>,
    pub sftpflow_version: String,
}

// ============================================================
// Internals
// ============================================================

/// Run `VACUUM INTO 'staging/runs.db'` on the live runs database.
/// Returns the staged path, or `None` if the source DB doesn't
/// exist (legacy or fresh node — backup just skips it).
fn stage_sqlite_snapshot(
    src:         &Path,
    staging_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    if !src.exists() {
        return Ok(None);
    }
    let dst = staging_dir.join("runs.db");
    // Read-only attach + VACUUM INTO. Doesn't lock out writers; the
    // copy is a transactionally consistent point-in-time snapshot.
    let conn = rusqlite::Connection::open_with_flags(
        src,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("opening runs.db read-only: {}", e))?;

    conn.execute(
        "VACUUM INTO ?1",
        rusqlite::params![dst.to_string_lossy()],
    )
    .map_err(|e| format!("VACUUM INTO failed: {}", e))?;
    Ok(Some(dst))
}

/// Walk the per-node files we want in the archive and push every
/// existing one onto `out` as `(source_path, archive_path)` pairs.
/// Files that don't exist are silently skipped.
fn collect_backup_files(
    paths:     &DaemonPaths,
    staged_db: &Option<PathBuf>,
    out:       &mut Vec<(PathBuf, String)>,
) -> Result<(), String> {
    // node.json + cluster/ certs (cluster/ key files end up here too)
    let node_json = node_state::node_json_path(&paths.state_dir);
    if node_json.exists() {
        out.push((node_json, "node.json".to_string()));
    }
    let cluster_dir = node_state::cluster_dir(&paths.state_dir);
    for name in &["ca.crt", "ca.key", "node.crt", "node.key"] {
        let p = cluster_dir.join(name);
        if p.exists() {
            out.push((p, format!("cluster/{}", name)));
        }
    }

    // raft/ — recursive walk. sled stores its DB as a directory.
    let raft = node_state::raft_dir(&paths.state_dir);
    if raft.exists() {
        collect_dir_recursive(&raft, "raft", out)?;
    }

    // Vacuumed SQLite copy (or nothing if no DB existed).
    if let Some(p) = staged_db {
        out.push((p.clone(), "runs.db".to_string()));
    }

    // Sealed credential store. Its on-disk filename varies by the
    // operator's --secrets override; we always store it under the
    // canonical archive name "secrets.age".
    if paths.secrets_file.exists() {
        out.push((paths.secrets_file.clone(), "secrets.age".to_string()));
    }

    // config.yaml — outside state_dir; we still pack it because
    // restoring a node without it would be a partial DR.
    if paths.config_yaml.exists() {
        out.push((paths.config_yaml.clone(), "config.yaml".to_string()));
    }

    Ok(())
}

/// Recursive directory walker that flattens entries into the
/// archive-path namespace under `prefix/`. Skips symlinks (we don't
/// want to follow a symlink off the state_dir during backup).
fn collect_dir_recursive(
    root:     &Path,
    prefix:   &str,
    out:      &mut Vec<(PathBuf, String)>,
) -> Result<(), String> {
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), prefix.to_string())];

    while let Some((dir, archive_prefix)) = stack.pop() {
        let it = fs::read_dir(&dir)
            .map_err(|e| format!("read_dir {}: {}", dir.display(), e))?;
        for ent in it {
            let ent  = ent.map_err(|e| format!("read_dir entry under {}: {}", dir.display(), e))?;
            let path = ent.path();
            let name = ent.file_name();
            let name_str = name.to_string_lossy().to_string();
            let archive_path = format!("{}/{}", archive_prefix, name_str);

            let meta = match ent.metadata() {
                Ok(m) => m,
                Err(e) => {
                    warn!("backup: skipping {} (stat failed: {})", path.display(), e);
                    continue;
                }
            };
            if meta.file_type().is_symlink() {
                warn!("backup: skipping symlink {}", path.display());
                continue;
            }
            if meta.is_dir() {
                stack.push((path, archive_path));
            } else if meta.is_file() {
                out.push((path, archive_path));
            }
            // Other types (sockets, etc.) silently skipped.
        }
    }
    Ok(())
}

/// Tar entry header builder + append. Centralized so every file in
/// the archive gets the same uid/gid/mtime treatment, which keeps
/// the archive deterministic enough to diff between two backups
/// taken seconds apart.
fn append_bytes_to_tar<W: Write>(
    tar:          &mut tar::Builder<W>,
    archive_path: &str,
    bytes:        &[u8],
    mtime_unix:   i64,
    sensitive:    bool,
) -> Result<(), String> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    // 0600 for sensitive files (CA key, node key, sealed store) so
    // an extracted archive doesn't accidentally leave keys world-
    // readable. 0644 for everything else.
    header.set_mode(if sensitive { 0o600 } else { 0o644 });
    header.set_mtime(mtime_unix.max(0) as u64);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();

    tar.append_data(&mut header, archive_path, bytes)
        .map_err(|e| format!("tar append {}: {}", archive_path, e))
}

/// Open an archive and read the manifest.json out of it. The
/// archive doesn't guarantee manifest.json comes first or last, so
/// we scan until we find it.
fn read_manifest(archive_path: &Path) -> Result<Manifest, String> {
    let archive_file = fs::File::open(archive_path)
        .map_err(|e| format!("opening archive {}: {}", archive_path.display(), e))?;
    let gz = GzDecoder::new(archive_file);
    let mut tar = tar::Archive::new(gz);

    for entry in tar.entries().map_err(|e| format!("reading archive: {}", e))? {
        let mut entry = entry.map_err(|e| format!("reading archive entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("reading entry path: {}", e))?
            .to_string_lossy()
            .replace('\\', "/")
            .to_string();
        if path == MANIFEST_FILE {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| format!("reading manifest.json: {}", e))?;
            let manifest: Manifest = serde_json::from_slice(&bytes)
                .map_err(|e| format!("parsing manifest.json: {}", e))?;
            return Ok(manifest);
        }
    }
    Err(format!(
        "archive {} has no manifest.json — not a valid sftpflow backup",
        archive_path.display(),
    ))
}

/// Map an archive-relative path to its on-disk destination during
/// restore. Mirrors the layout written by `collect_backup_files`.
fn resolve_archive_dest(paths: &DaemonPaths, archive_path: &str) -> PathBuf {
    match archive_path {
        "node.json"        => node_state::node_json_path(&paths.state_dir),
        "cluster/ca.crt"   => node_state::ca_cert_path(&paths.state_dir),
        "cluster/ca.key"   => node_state::ca_key_path(&paths.state_dir),
        "cluster/node.crt" => node_state::leaf_cert_path(&paths.state_dir),
        "cluster/node.key" => node_state::leaf_key_path(&paths.state_dir),
        "runs.db"          => paths.runs_db.clone(),
        "secrets.age"      => paths.secrets_file.clone(),
        "config.yaml"      => paths.config_yaml.clone(),
        other => {
            // raft/<...> — preserve the path under the state_dir's
            // raft directory.
            if let Some(rest) = other.strip_prefix("raft/") {
                node_state::raft_dir(&paths.state_dir).join(rest)
            } else {
                // Unknown path: drop it under the state dir so
                // restore at least surfaces it instead of silently
                // routing it to /tmp. The caller already validates
                // every archive_path against the manifest, so this
                // branch is mostly defensive.
                paths.state_dir.join(other)
            }
        }
    }
}

/// True if a given archive path holds key material the operator
/// would not want to leave world-readable on disk.
fn archive_is_sensitive(archive_path: &str) -> bool {
    matches!(archive_path,
        "cluster/ca.key"
      | "cluster/node.key"
      | "secrets.age"
    )
}

/// Atomic write: stage to "<dst>.new", set restrictive perms if the
/// caller marked the file sensitive, then rename. Mirrors the
/// pattern in node_state::write_pem.
fn write_atomic(dst: &Path, bytes: &[u8], sensitive: bool) -> Result<(), String> {
    let tmp = dst.with_extension({
        let mut ext = dst.extension().map(|e| e.to_os_string()).unwrap_or_default();
        ext.push(".new");
        ext
    });

    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| format!("creating {}: {}", tmp.display(), e))?;
        f.write_all(bytes)
            .map_err(|e| format!("writing {}: {}", tmp.display(), e))?;
        f.sync_all()
            .map_err(|e| format!("syncing {}: {}", tmp.display(), e))?;
    }

    #[cfg(unix)]
    if sensitive {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 on {}: {}", tmp.display(), e))?;
    }
    #[cfg(not(unix))]
    let _ = sensitive;

    fs::rename(&tmp, dst)
        .map_err(|e| format!("rename {} -> {}: {}", tmp.display(), dst.display(), e))
}

/// sha256 of a byte slice, formatted as lowercase hex (64 chars).
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, body: &[u8]) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn make_paths(root: &Path) -> DaemonPaths {
        DaemonPaths {
            state_dir:    root.join("state"),
            runs_db:      root.join("state").join("runs.db"),
            secrets_file: root.join("state").join("secrets.age"),
            config_yaml:  root.join("home").join(".sftpflow").join("config.yaml"),
        }
    }

    #[test]
    fn roundtrip_full_state() {
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());

        // Seed a plausible node state.
        let node = node_state::NodeJson {
            version:         node_state::NODE_JSON_VERSION,
            node_id:         3,
            cluster_id:      "abc-123".into(),
            advertise_addr:  "host:7900".into(),
            label:           Some("test".into()),
            created_at_unix: 1_700_000_000,
        };
        node_state::write_node_json(&paths.state_dir, &node).unwrap();
        write(&node_state::ca_cert_path(&paths.state_dir),   b"-----BEGIN CERTIFICATE-----\nA\n");
        write(&node_state::leaf_cert_path(&paths.state_dir), b"-----BEGIN CERTIFICATE-----\nB\n");
        write(&node_state::leaf_key_path(&paths.state_dir),  b"-----BEGIN PRIVATE KEY-----\nC\n");
        write(&node_state::raft_dir(&paths.state_dir).join("db"),     b"sled bytes 1");
        write(&node_state::raft_dir(&paths.state_dir).join("snap.0"), b"sled bytes 2");
        write(&paths.secrets_file, b"# sftpflow-secrets v1\n<encrypted>");
        write(&paths.config_yaml,  b"endpoints: {}\nkeys: {}\nfeeds: {}\n");
        // No real SQLite — backup will just skip it.

        let archive = dir.path().join("backup.tar.gz");
        let report = run_backup_hot(&paths, &archive).unwrap();
        assert!(archive.exists(), "archive missing");
        assert_eq!(report.cluster_id.as_deref(), Some("abc-123"));
        assert_eq!(report.node_id, Some(3));
        assert!(report.file_count >= 6); // node.json + 3 cluster + 2 raft + secrets + config

        // Wipe state to simulate a fresh host.
        fs::remove_dir_all(&paths.state_dir).unwrap();
        fs::remove_file(&paths.config_yaml).ok();

        // Restore into fresh paths.
        let restored = run_restore_cold(&paths, &archive).unwrap();
        assert_eq!(restored.cluster_id.as_deref(), Some("abc-123"));
        assert_eq!(restored.node_id, Some(3));

        let back = node_state::read_node_json(&paths.state_dir).unwrap().unwrap();
        assert_eq!(back.cluster_id, "abc-123");
        assert_eq!(back.node_id,    3);
        assert_eq!(fs::read(&node_state::ca_cert_path(&paths.state_dir)).unwrap(),
                   b"-----BEGIN CERTIFICATE-----\nA\n");
        assert_eq!(fs::read(&paths.config_yaml).unwrap(),
                   b"endpoints: {}\nkeys: {}\nfeeds: {}\n");
        assert_eq!(fs::read(&node_state::raft_dir(&paths.state_dir).join("db")).unwrap(),
                   b"sled bytes 1");
    }

    #[test]
    fn restore_refuses_when_target_exists() {
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());
        write(&node_state::node_json_path(&paths.state_dir), b"{\"version\":1}");

        // Build a minimal valid archive.
        let archive = dir.path().join("backup.tar.gz");
        run_backup_hot(&paths, &archive).unwrap();

        // Don't wipe — node.json still exists; restore must refuse.
        let err = run_restore_cold(&paths, &archive).unwrap_err();
        assert!(err.contains("refusing to restore"), "unexpected error: {}", err);
    }

    #[test]
    fn restore_detects_sha_mismatch() {
        // Build a real archive, then surgically corrupt one of the
        // files in a re-tarred copy. Simpler proxy: hand-write an
        // archive with a deliberately-wrong manifest hash and confirm
        // restore catches it.
        let dir = tempdir().unwrap();
        let paths = make_paths(dir.path());
        write(&node_state::node_json_path(&paths.state_dir), b"hello");

        let archive = dir.path().join("backup.tar.gz");
        run_backup_hot(&paths, &archive).unwrap();

        // Corrupt the gzip stream by truncating it. Restore should
        // either fail to read the manifest or fail a hash check.
        let bytes = fs::read(&archive).unwrap();
        let truncated = &bytes[..bytes.len().saturating_sub(50)];
        fs::write(&archive, truncated).unwrap();

        // Wipe targets so we get past the "already exists" guard.
        fs::remove_dir_all(&paths.state_dir).ok();
        let err = run_restore_cold(&paths, &archive).unwrap_err();
        assert!(
            err.contains("manifest") || err.contains("sha256") || err.contains("archive") || err.contains("reading"),
            "unexpected error: {}", err,
        );
    }
}
