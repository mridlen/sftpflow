// ============================================================
// sftp.rs — SFTP transport implementation via russh + russh-sftp
// ============================================================
//
// Connects to an SFTP server using the russh SSH client, opens
// an SFTP subsystem channel, and implements the Transport trait
// for listing, downloading, uploading, and deleting files.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Idle ssh connections die after this long with no traffic, so a
/// stalled remote doesn't block the orchestrator forever.
const SFTP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(120);

/// Send a keepalive every 30s; combined with russh's default
/// `keepalive_max = 3`, a black-holed remote drops within ~90s.
const SFTP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

use async_trait::async_trait;
use log::{info, warn};
use russh::client;
use russh::keys::ssh_key;
use russh::keys::PrivateKeyWithHashAlg;
use russh_sftp::client::SftpSession;

use sftpflow_core::Endpoint;

use crate::{Transport, TransportError};

// ============================================================
// SSH client handler — host-key verification
// ============================================================

/// SSH client handler that pins the server host key against an
/// operator-configured fingerprint.
///
/// Behavior controlled by `Endpoint`:
///   * `verify_host_key = Some(false)` — accept any key, log a
///     loud warning. Mirrors the FTPS `verify_tls=false` opt-out.
///   * `host_key_fingerprint = Some("SHA256:...")` — accept only
///     when the presented key's SHA-256 fingerprint matches.
///   * Neither set / `verify_host_key = None` — refuse to connect.
///     Failing closed is the right default; an unconfigured
///     endpoint is exactly the case where MITM would succeed.
struct SshHandler {
    endpoint_name: String,
    expected_fingerprint: Option<String>,
    verify_host_key: bool,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send
    {
        // Compute the SHA-256 fingerprint up front so the async
        // block below stays self-contained.
        let presented = server_public_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let endpoint_name = self.endpoint_name.clone();
        let verify = self.verify_host_key;
        let expected = self.expected_fingerprint.clone();

        async move {
            // ---- explicit opt-out ----
            // Operator set verify_host_key=false. Log loudly so
            // the audit trail makes the trade-off visible.
            if !verify {
                warn!(
                    "sftp connect: host-key verification DISABLED for \
                     endpoint '{}' (verify_host_key=false). Presented key: {}. \
                     Connection is vulnerable to MITM.",
                    endpoint_name, presented,
                );
                return Ok(true);
            }

            // ---- pin against configured fingerprint ----
            match expected {
                Some(want) => {
                    let want = want.trim();
                    if presented == want {
                        info!(
                            "sftp connect: host key verified for endpoint '{}' ({})",
                            endpoint_name, presented,
                        );
                        Ok(true)
                    } else {
                        warn!(
                            "sftp connect: host-key MISMATCH for endpoint '{}'. \
                             Expected {}, server presented {}. Refusing connection.",
                            endpoint_name, want, presented,
                        );
                        Ok(false)
                    }
                }
                None => {
                    // No fingerprint pinned and verification not
                    // explicitly disabled — fail closed. Operator
                    // must either set host_key_fingerprint or
                    // explicitly opt out via verify_host_key=false.
                    warn!(
                        "sftp connect: endpoint '{}' has no host_key_fingerprint \
                         configured and verify_host_key is not set to false. \
                         Refusing connection. Server presented: {}",
                        endpoint_name, presented,
                    );
                    Ok(false)
                }
            }
        }
    }
}

// ============================================================
// SftpTransport
// ============================================================

/// An SFTP transport backed by a single SSH connection.
pub struct SftpTransport {
    sftp: SftpSession,
    // Keep the handle alive so the SSH connection isn't dropped
    _handle: client::Handle<SshHandler>,
}

impl SftpTransport {
    /// Connect to an SFTP endpoint and open the SFTP subsystem.
    pub async fn connect(
        name: &str,
        endpoint: &Endpoint,
    ) -> Result<Self, TransportError> {
        let host = endpoint.host.as_deref().ok_or_else(|| {
            TransportError::MissingField(
                name.to_string(),
                "host".to_string(),
            )
        })?;
        let port = endpoint.port.unwrap_or(22);
        let username =
            endpoint.username.as_deref().ok_or_else(|| {
                TransportError::MissingField(
                    name.to_string(),
                    "username".to_string(),
                )
            })?;

        info!(
            "sftp connect: {}@{}:{} (endpoint '{}')",
            username, host, port, name
        );

        // ---- SSH connection ----
        // Host-key verification policy is decided per-endpoint:
        // see SshHandler::check_server_key. Default is fail-closed
        // when neither host_key_fingerprint nor verify_host_key
        // is set, so old configs surface the missing pin loudly
        // rather than silently trusting any peer.
        // Default Config has no inactivity / keepalive timeouts, so a
        // hung TCP connection blocks the orchestrator forever. Cap
        // both so a wedged peer surfaces as a connection error within
        // ~90s instead of stalling the daemon.
        let mut config = client::Config::default();
        config.inactivity_timeout = Some(SFTP_INACTIVITY_TIMEOUT);
        config.keepalive_interval = Some(SFTP_KEEPALIVE_INTERVAL);
        let config = Arc::new(config);
        let handler = SshHandler {
            endpoint_name: name.to_string(),
            expected_fingerprint: endpoint.host_key_fingerprint.clone(),
            verify_host_key: endpoint.verify_host_key.unwrap_or(true),
        };

        let mut handle = client::connect(
            config,
            (host, port),
            handler,
        )
        .await
        .map_err(|e| {
            // russh maps a `check_server_key -> Ok(false)` to a
            // "no common key" / disconnect error. Surface that as
            // an explicit host-key failure so operators can tell
            // it apart from network/auth problems.
            TransportError::Connection(format!(
                "SSH connect to {}:{} failed (this may indicate a \
                 host-key verification failure — see daemon log): {}",
                host, port, e
            ))
        })?;

        // ---- authenticate ----
        let auth_result = if let Some(ref key_path) =
            endpoint.ssh_key
        {
            // SSH key authentication
            let key = russh::keys::load_secret_key(
                key_path,
                None, // passphrase — deferred to milestone 11
            )
            .map_err(|e| {
                TransportError::Connection(format!(
                    "failed to load SSH key '{}': {}",
                    key_path, e
                ))
            })?;

            let key_with_alg = PrivateKeyWithHashAlg::new(
                Arc::new(key),
                None, // hash algorithm — auto-detected for non-RSA
            );

            handle
                .authenticate_publickey(username, key_with_alg)
                .await
                .map_err(|e| {
                    TransportError::Connection(format!(
                        "SSH key auth failed for {}@{}:{}: {}",
                        username, host, port, e
                    ))
                })?
        } else if let Some(ref password) = endpoint.password {
            // Password authentication
            handle
                .authenticate_password(username, password)
                .await
                .map_err(|e| {
                    TransportError::Connection(format!(
                        "SSH password auth failed for {}@{}:{}: {}",
                        username, host, port, e
                    ))
                })?
        } else {
            return Err(TransportError::MissingField(
                name.to_string(),
                "password or ssh_key".to_string(),
            ));
        };

        if !auth_result.success() {
            return Err(TransportError::Connection(format!(
                "authentication rejected for {}@{}:{}",
                username, host, port
            )));
        }

        info!(
            "sftp connect: authenticated as {} on {}:{}",
            username, host, port
        );

        // ---- open SFTP subsystem ----
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| {
                TransportError::Connection(format!(
                    "failed to open SSH channel: {}",
                    e
                ))
            })?;

        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| {
                TransportError::Connection(format!(
                    "failed to request SFTP subsystem: {}",
                    e
                ))
            })?;

        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| {
                TransportError::Connection(format!(
                    "failed to initialize SFTP session: {}",
                    e
                ))
            })?;

        info!(
            "sftp connect: SFTP session established for endpoint '{}'",
            name
        );

        Ok(SftpTransport {
            sftp,
            _handle: handle,
        })
    }
}

// ============================================================
// Transport trait implementation
// ============================================================

#[async_trait]
impl Transport for SftpTransport {
    async fn list_files(
        &self,
        remote_dir: &str,
    ) -> Result<Vec<String>, TransportError> {
        let entries =
            self.sftp.read_dir(remote_dir).await.map_err(|e| {
                TransportError::Io(format!(
                    "failed to list directory '{}': {}",
                    remote_dir, e
                ))
            })?;

        let mut file_names = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            // Skip . and .. entries
            if name == "." || name == ".." {
                continue;
            }
            // Only include regular files (skip directories,
            // symlinks, etc.)
            if entry.file_type().is_file() {
                file_names.push(name);
            }
        }

        Ok(file_names)
    }

    async fn download(
        &self,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<(), TransportError> {
        // Stream the remote file directly to disk. Earlier versions
        // slurped the whole file into a Vec<u8> with `read_to_end`,
        // which OOM'd the daemon on multi-GB feeds. tokio::io::copy
        // moves bytes through an internal buffer (~8 KiB by default).
        let mut remote_file = self.sftp.open(remote_path).await.map_err(|e| {
            TransportError::Io(format!(
                "failed to open remote file '{}': {}",
                remote_path, e
            ))
        })?;

        let mut local_file = tokio::fs::File::create(local_path).await.map_err(|e| {
            TransportError::Io(format!(
                "failed to create local file '{}': {}",
                local_path.display(), e,
            ))
        })?;

        tokio::io::copy(&mut remote_file, &mut local_file).await.map_err(|e| {
            TransportError::Io(format!(
                "failed to stream remote '{}' -> local '{}': {}",
                remote_path, local_path.display(), e,
            ))
        })?;

        // Flush kernel buffers so the file is fully on disk before
        // any process step / upload phase tries to read it back.
        use tokio::io::AsyncWriteExt;
        local_file.flush().await.map_err(|e| {
            TransportError::Io(format!(
                "failed to flush local file '{}': {}",
                local_path.display(), e,
            ))
        })?;

        Ok(())
    }

    async fn upload(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), TransportError> {
        // Stream local file → remote .partial → rename.
        //
        // Two improvements over the old slurp-and-write_all path:
        //   1. tokio::io::copy bounds memory at the buffer size,
        //      not the file size, so multi-GB uploads don't OOM.
        //   2. We write to `<remote>.partial` and SFTP-rename to
        //      the final name only after a successful flush, so a
        //      mid-stream failure doesn't leave a half-written file
        //      under the canonical name. The next run sees no
        //      destination file and retries cleanly.
        use tokio::io::AsyncWriteExt;

        let partial_path = format!("{}.partial", remote_path);

        let mut local_file = tokio::fs::File::open(local_path).await.map_err(|e| {
            TransportError::Io(format!(
                "failed to open local file '{}': {}",
                local_path.display(), e,
            ))
        })?;

        let mut remote_file = self.sftp.create(&partial_path).await.map_err(|e| {
            TransportError::Io(format!(
                "failed to create remote file '{}': {}",
                partial_path, e,
            ))
        })?;

        if let Err(e) = tokio::io::copy(&mut local_file, &mut remote_file).await {
            // Best-effort cleanup: remove the partial so the next
            // run isn't blocked on a stale half-write. Failures here
            // are logged and ignored — the original error is more
            // important.
            let _ = remote_file.shutdown().await;
            if let Err(rm) = self.sftp.remove_file(&partial_path).await {
                warn!(
                    "sftp upload: failed to cleanup partial '{}' after error: {}",
                    partial_path, rm,
                );
            }
            return Err(TransportError::Io(format!(
                "failed to stream local '{}' -> remote '{}': {}",
                local_path.display(), partial_path, e,
            )));
        }

        remote_file.shutdown().await.map_err(|e| {
            TransportError::Io(format!(
                "failed to flush remote file '{}': {}",
                partial_path, e,
            ))
        })?;

        // Drop the file handle before rename so the SFTP server
        // sees the file as closed (some servers refuse to rename
        // an open file).
        drop(remote_file);

        // Some servers refuse rename when the target already
        // exists; remove an existing destination first. Best-effort:
        // a "no such file" failure is fine.
        let _ = self.sftp.remove_file(remote_path).await;

        self.sftp.rename(partial_path.clone(), remote_path.to_string()).await.map_err(|e| {
            TransportError::Io(format!(
                "failed to rename '{}' -> '{}': {}",
                partial_path, remote_path, e,
            ))
        })?;

        Ok(())
    }

    async fn delete(
        &self,
        remote_path: &str,
    ) -> Result<(), TransportError> {
        // Treat "no such file" as success so a re-run after a
        // partial cleanup (where the source file was already
        // removed in a prior run) succeeds idempotently.
        // russh_sftp doesn't expose status codes through its public
        // error type, so we substring-match on the formatted
        // message — the StatusCode Display is `"No such file"`.
        if let Err(e) = self.sftp.remove_file(remote_path).await {
            let msg = e.to_string();
            if msg.to_ascii_lowercase().contains("no such file") {
                info!(
                    "sftp delete: remote '{}' already absent — treating as success",
                    remote_path,
                );
                return Ok(());
            }
            return Err(TransportError::Io(format!(
                "failed to delete remote file '{}': {}",
                remote_path, e,
            )));
        }
        Ok(())
    }
}
