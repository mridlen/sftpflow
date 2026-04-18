// ============================================================
// sftpflow-transport — Transfer engine
// ============================================================
//
// Defines the Transport trait and the run_feed() orchestrator
// that moves files from sources → staging → destinations.
// v1 supports SFTP only; FTP/HTTP/HTTPS come in later milestones.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use async_trait::async_trait;
use log::{error, info, warn};
use tempfile::TempDir;

use sftpflow_core::{Endpoint, Feed, FeedPath, PgpKey, ProcessStep, Protocol};
use sftpflow_proto::{RunResult, RunStatus};

// sftp.rs — SftpTransport implementation
mod sftp;
pub use sftp::SftpTransport;

// pgp.rs — PGP encrypt/decrypt for process steps
mod pgp;

// ============================================================
// TransportError
// ============================================================

/// Errors that can occur during file transfer operations.
#[derive(Debug)]
pub enum TransportError {
    /// The referenced endpoint was not found in the config.
    EndpointNotFound(String),
    /// The endpoint's protocol is not supported yet.
    UnsupportedProtocol(String, String),
    /// A required field on the endpoint is missing.
    MissingField(String, String),
    /// SSH/SFTP connection or authentication failed.
    Connection(String),
    /// A file I/O error (local or remote).
    Io(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::EndpointNotFound(name) => {
                write!(f, "endpoint '{}' not found", name)
            }
            TransportError::UnsupportedProtocol(name, proto) => {
                write!(
                    f,
                    "endpoint '{}' uses unsupported protocol '{}'",
                    name, proto
                )
            }
            TransportError::MissingField(endpoint, field) => {
                write!(
                    f,
                    "endpoint '{}' is missing required field '{}'",
                    endpoint, field
                )
            }
            TransportError::Connection(msg) => {
                write!(f, "connection error: {}", msg)
            }
            TransportError::Io(msg) => {
                write!(f, "I/O error: {}", msg)
            }
        }
    }
}

impl std::error::Error for TransportError {}

// ============================================================
// Transport trait
// ============================================================

/// Async trait for protocol-specific file transfer operations.
///
/// Each implementation manages a single connection to one endpoint.
/// The orchestrator creates one Transport per endpoint it needs to
/// talk to, then calls the trait methods to move files.
#[async_trait]
pub trait Transport: Send + Sync {
    /// List regular files in a remote directory.
    /// Returns file names (not full paths).
    async fn list_files(
        &self,
        remote_dir: &str,
    ) -> Result<Vec<String>, TransportError>;

    /// Download a remote file to a local path.
    async fn download(
        &self,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<(), TransportError>;

    /// Upload a local file to a remote path.
    async fn upload(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), TransportError>;

    /// Delete a remote file.
    async fn delete(
        &self,
        remote_path: &str,
    ) -> Result<(), TransportError>;
}

// ============================================================
// connect_endpoint — factory for Transport from an Endpoint
// ============================================================

/// Create a connected Transport for the given endpoint.
async fn connect_endpoint(
    name: &str,
    endpoint: &Endpoint,
) -> Result<Box<dyn Transport>, TransportError> {
    match endpoint.protocol {
        Protocol::Sftp => {
            let transport =
                SftpTransport::connect(name, endpoint).await?;
            Ok(Box::new(transport))
        }
        // FTP, HTTP, HTTPS — future milestones
        ref proto => Err(TransportError::UnsupportedProtocol(
            name.to_string(),
            proto.to_string(),
        )),
    }
}

// ============================================================
// validate_feed — pre-flight checks before transferring
// ============================================================

/// Validate that all endpoints referenced by a feed exist and
/// use a supported protocol.
fn validate_feed(
    feed: &Feed,
    endpoints: &BTreeMap<String, Endpoint>,
) -> Result<(), TransportError> {
    // Check all source endpoints
    for src in &feed.sources {
        let ep = endpoints.get(&src.endpoint).ok_or_else(|| {
            TransportError::EndpointNotFound(src.endpoint.clone())
        })?;
        validate_endpoint(&src.endpoint, ep)?;
    }
    // Check all destination endpoints
    for dst in &feed.destinations {
        let ep = endpoints.get(&dst.endpoint).ok_or_else(|| {
            TransportError::EndpointNotFound(dst.endpoint.clone())
        })?;
        validate_endpoint(&dst.endpoint, ep)?;
    }
    Ok(())
}

/// Validate a single endpoint has all required fields for connection.
fn validate_endpoint(
    name: &str,
    ep: &Endpoint,
) -> Result<(), TransportError> {
    match ep.protocol {
        Protocol::Sftp => {
            if ep.host.is_none() {
                return Err(TransportError::MissingField(
                    name.to_string(),
                    "host".to_string(),
                ));
            }
            if ep.username.is_none() {
                return Err(TransportError::MissingField(
                    name.to_string(),
                    "username".to_string(),
                ));
            }
            // Must have either password or ssh_key
            if ep.password.is_none() && ep.ssh_key.is_none() {
                return Err(TransportError::MissingField(
                    name.to_string(),
                    "password or ssh_key".to_string(),
                ));
            }
            Ok(())
        }
        ref proto => Err(TransportError::UnsupportedProtocol(
            name.to_string(),
            proto.to_string(),
        )),
    }
}

// ============================================================
// run_feed — the main orchestrator
// ============================================================

/// Execute a feed: download from sources, upload to destinations,
/// optionally delete source files. Returns a RunResult suitable
/// for the RPC response.
///
/// This is an async function. The daemon calls it via
/// `tokio::runtime::Runtime::new().block_on(run_feed(...))`.
pub async fn run_feed(
    feed_name: &str,
    feed: &Feed,
    endpoints: &BTreeMap<String, Endpoint>,
    keys: &BTreeMap<String, PgpKey>,
) -> RunResult {
    info!("run_feed '{}': starting", feed_name);

    // ---- pre-flight validation ----
    if let Err(e) = validate_feed(feed, endpoints) {
        error!("run_feed '{}': validation failed: {}", feed_name, e);
        return RunResult {
            feed: feed_name.to_string(),
            status: RunStatus::Failed,
            files_transferred: 0,
            message: Some(format!("validation error: {}", e)),
        };
    }

    // Validate process-step key references up-front so we can fail
    // fast before connecting to any endpoint.
    if let Err(msg) = validate_process_keys(feed, keys) {
        error!("run_feed '{}': process validation failed: {}", feed_name, msg);
        return RunResult {
            feed: feed_name.to_string(),
            status: RunStatus::Failed,
            files_transferred: 0,
            message: Some(format!("process validation error: {}", msg)),
        };
    }

    // ---- create staging temp dir ----
    let staging_dir = match TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            error!(
                "run_feed '{}': failed to create staging dir: {}",
                feed_name, e
            );
            return RunResult {
                feed: feed_name.to_string(),
                status: RunStatus::Failed,
                files_transferred: 0,
                message: Some(format!(
                    "failed to create staging directory: {}",
                    e
                )),
            };
        }
    };

    info!(
        "run_feed '{}': staging dir at {}",
        feed_name,
        staging_dir.path().display()
    );

    // ---- phase 1: download from sources ----
    // Track which files came from which source so we can delete later.
    let mut downloaded_files: Vec<String> = Vec::new();
    // Track source files per FeedPath for deletion phase.
    let mut source_file_map: Vec<(&FeedPath, Vec<String>)> = Vec::new();

    for src in &feed.sources {
        info!(
            "run_feed '{}': downloading from {}:{}",
            feed_name, src.endpoint, src.path
        );

        let ep = &endpoints[&src.endpoint];
        let transport = match connect_endpoint(&src.endpoint, ep).await
        {
            Ok(t) => t,
            Err(e) => {
                error!(
                    "run_feed '{}': failed to connect to source \
                     endpoint '{}': {}",
                    feed_name, src.endpoint, e
                );
                return RunResult {
                    feed: feed_name.to_string(),
                    status: RunStatus::Failed,
                    files_transferred: 0,
                    message: Some(format!(
                        "failed to connect to source '{}': {}",
                        src.endpoint, e
                    )),
                };
            }
        };

        // List files in the source directory
        let files = match transport.list_files(&src.path).await {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "run_feed '{}': failed to list files at {}:{} \
                     — {}",
                    feed_name, src.endpoint, src.path, e
                );
                return RunResult {
                    feed: feed_name.to_string(),
                    status: RunStatus::Failed,
                    files_transferred: 0,
                    message: Some(format!(
                        "failed to list files at {}:{} — {}",
                        src.endpoint, src.path, e
                    )),
                };
            }
        };

        if files.is_empty() {
            info!(
                "run_feed '{}': no files found at {}:{}",
                feed_name, src.endpoint, src.path
            );
            source_file_map.push((src, Vec::new()));
            continue;
        }

        info!(
            "run_feed '{}': found {} file(s) at {}:{}",
            feed_name,
            files.len(),
            src.endpoint,
            src.path
        );

        let mut src_files = Vec::new();
        for file_name in &files {
            let remote_path = format!(
                "{}/{}",
                src.path.trim_end_matches('/'),
                file_name
            );
            let local_path = staging_dir.path().join(file_name);

            if let Err(e) =
                transport.download(&remote_path, &local_path).await
            {
                error!(
                    "run_feed '{}': failed to download '{}' from \
                     '{}': {}",
                    feed_name, remote_path, src.endpoint, e
                );
                return RunResult {
                    feed: feed_name.to_string(),
                    status: RunStatus::Failed,
                    files_transferred: 0,
                    message: Some(format!(
                        "failed to download '{}' from '{}': {}",
                        remote_path, src.endpoint, e
                    )),
                };
            }

            info!(
                "run_feed '{}': downloaded {}",
                feed_name, remote_path
            );
            downloaded_files.push(file_name.clone());
            src_files.push(file_name.clone());
        }

        source_file_map.push((src, src_files));
    }

    // If no files were downloaded from any source, return Noaction
    if downloaded_files.is_empty() {
        info!(
            "run_feed '{}': no files found across all sources",
            feed_name
        );
        return RunResult {
            feed: feed_name.to_string(),
            status: RunStatus::Noaction,
            files_transferred: 0,
            message: Some("no files found in any source".to_string()),
        };
    }

    // ---- phase 1.5: process pipeline (PGP encrypt/decrypt) ----
    // Each ProcessStep rewrites the staged files in place. The step
    // operates on whatever set of filenames phase 1 produced (or the
    // previous step left behind), and returns the new filename list
    // that the next step / upload phase should use.
    if !feed.process.is_empty() {
        match apply_process_pipeline(
            feed_name,
            &feed.process,
            keys,
            staging_dir.path(),
            downloaded_files.clone(),
        ) {
            Ok(new_files) => {
                downloaded_files = new_files;
            }
            Err(msg) => {
                error!(
                    "run_feed '{}': process pipeline failed: {}",
                    feed_name, msg
                );
                return RunResult {
                    feed: feed_name.to_string(),
                    status: RunStatus::Failed,
                    files_transferred: 0,
                    message: Some(format!(
                        "process pipeline failed: {}",
                        msg
                    )),
                };
            }
        }
    }

    // ---- phase 2: upload to destinations ----
    for dst in &feed.destinations {
        info!(
            "run_feed '{}': uploading to {}:{}",
            feed_name, dst.endpoint, dst.path
        );

        let ep = &endpoints[&dst.endpoint];
        let transport = match connect_endpoint(&dst.endpoint, ep).await
        {
            Ok(t) => t,
            Err(e) => {
                error!(
                    "run_feed '{}': failed to connect to destination \
                     endpoint '{}': {}",
                    feed_name, dst.endpoint, e
                );
                return RunResult {
                    feed: feed_name.to_string(),
                    status: RunStatus::Failed,
                    files_transferred: 0,
                    message: Some(format!(
                        "failed to connect to destination '{}': {}",
                        dst.endpoint, e
                    )),
                };
            }
        };

        for file_name in &downloaded_files {
            let local_path = staging_dir.path().join(file_name);
            let remote_path = format!(
                "{}/{}",
                dst.path.trim_end_matches('/'),
                file_name
            );

            if let Err(e) =
                transport.upload(&local_path, &remote_path).await
            {
                error!(
                    "run_feed '{}': failed to upload '{}' to '{}': {}",
                    feed_name, file_name, dst.endpoint, e
                );
                return RunResult {
                    feed: feed_name.to_string(),
                    status: RunStatus::Failed,
                    files_transferred: 0,
                    message: Some(format!(
                        "failed to upload '{}' to '{}': {}",
                        file_name, dst.endpoint, e
                    )),
                };
            }

            info!(
                "run_feed '{}': uploaded {} to {}:{}",
                feed_name, file_name, dst.endpoint, remote_path
            );
        }
    }

    let total_files = downloaded_files.len();

    // ---- phase 3: delete source files (if configured) ----
    if feed.flags.delete_source_after_transfer {
        info!(
            "run_feed '{}': deleting source files \
             (delete_source_after_transfer=yes)",
            feed_name
        );

        for (src, files) in &source_file_map {
            if files.is_empty() {
                continue;
            }

            let ep = &endpoints[&src.endpoint];
            let transport =
                match connect_endpoint(&src.endpoint, ep).await {
                    Ok(t) => t,
                    Err(e) => {
                        // Non-fatal: files were transferred but
                        // source cleanup failed
                        warn!(
                        "run_feed '{}': could not reconnect to '{}' \
                         for source cleanup: {}",
                        feed_name, src.endpoint, e
                    );
                        continue;
                    }
                };

            for file_name in files {
                let remote_path = format!(
                    "{}/{}",
                    src.path.trim_end_matches('/'),
                    file_name
                );
                if let Err(e) =
                    transport.delete(&remote_path).await
                {
                    warn!(
                        "run_feed '{}': failed to delete source file \
                         '{}' on '{}': {}",
                        feed_name, remote_path, src.endpoint, e
                    );
                    // Continue deleting other files — this is
                    // best-effort
                }
            }
        }
    }

    // ---- done ----
    info!(
        "run_feed '{}': completed — {} file(s) transferred",
        feed_name, total_files
    );

    RunResult {
        feed: feed_name.to_string(),
        status: RunStatus::Success,
        files_transferred: total_files,
        message: None,
    }
}

// ============================================================
// Process pipeline helpers
// ============================================================

/// Confirm that every key name referenced by a process step exists
/// in the keys map and has non-empty contents. Run before connecting
/// to any endpoint so misconfigured feeds fail fast.
fn validate_process_keys(
    feed: &Feed,
    keys: &BTreeMap<String, PgpKey>,
) -> Result<(), String> {
    for step in &feed.process {
        let key_name = match step {
            ProcessStep::Encrypt { key } | ProcessStep::Decrypt { key } => key,
        };
        let pgp_key = keys
            .get(key_name)
            .ok_or_else(|| format!("pgp key '{}' not found", key_name))?;
        let contents = pgp_key.contents.as_deref().unwrap_or("");
        if contents.trim().is_empty() {
            return Err(format!("pgp key '{}' has no contents", key_name));
        }
    }
    Ok(())
}

/// Run every `ProcessStep` against the staged files, threading the
/// output filenames through so each step sees the names produced
/// by the previous step. Returns the final filename list.
fn apply_process_pipeline(
    feed_name: &str,
    steps: &[ProcessStep],
    keys: &BTreeMap<String, PgpKey>,
    staging_dir: &std::path::Path,
    mut files: Vec<String>,
) -> Result<Vec<String>, String> {
    for (i, step) in steps.iter().enumerate() {
        info!(
            "run_feed '{}': process step {} of {}: {}",
            feed_name,
            i + 1,
            steps.len(),
            step
        );

        let result = match step {
            ProcessStep::Encrypt { key } => {
                let contents = keys
                    .get(key)
                    .and_then(|k| k.contents.as_deref())
                    .unwrap_or("");
                // pgp.rs — encrypt_files
                pgp::encrypt_files(key, contents, staging_dir, &files)
            }
            ProcessStep::Decrypt { key } => {
                let contents = keys
                    .get(key)
                    .and_then(|k| k.contents.as_deref())
                    .unwrap_or("");
                // pgp.rs — decrypt_files
                pgp::decrypt_files(key, contents, staging_dir, &files)
            }
        };

        files = result.map_err(|e| e.to_string())?;
    }

    Ok(files)
}
