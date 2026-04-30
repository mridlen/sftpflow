// ============================================================
// sftp.rs — SFTP transport implementation via russh + russh-sftp
// ============================================================
//
// Connects to an SFTP server using the russh SSH client, opens
// an SFTP subsystem channel, and implements the Transport trait
// for listing, downloading, uploading, and deleting files.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use log::{info, warn};
use russh::client;
use russh::keys::ssh_key;
use russh::keys::PrivateKeyWithHashAlg;
use russh_sftp::client::SftpSession;
use tokio::io::AsyncReadExt;

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
        let config = Arc::new(client::Config::default());
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
        // Read the remote file contents
        let mut remote_file =
            self.sftp.open(remote_path).await.map_err(|e| {
                TransportError::Io(format!(
                    "failed to open remote file '{}': {}",
                    remote_path, e
                ))
            })?;

        let mut contents = Vec::new();
        remote_file
            .read_to_end(&mut contents)
            .await
            .map_err(|e| {
                TransportError::Io(format!(
                    "failed to read remote file '{}': {}",
                    remote_path, e
                ))
            })?;

        // Write to local file
        tokio::fs::write(local_path, &contents)
            .await
            .map_err(|e| {
                TransportError::Io(format!(
                    "failed to write local file '{}': {}",
                    local_path.display(),
                    e
                ))
            })?;

        Ok(())
    }

    async fn upload(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), TransportError> {
        // Read local file
        let contents =
            tokio::fs::read(local_path).await.map_err(|e| {
                TransportError::Io(format!(
                    "failed to read local file '{}': {}",
                    local_path.display(),
                    e
                ))
            })?;

        // Write to remote via SFTP
        use tokio::io::AsyncWriteExt;
        let mut remote_file =
            self.sftp.create(remote_path).await.map_err(|e| {
                TransportError::Io(format!(
                    "failed to create remote file '{}': {}",
                    remote_path, e
                ))
            })?;

        remote_file
            .write_all(&contents)
            .await
            .map_err(|e| {
                TransportError::Io(format!(
                    "failed to write remote file '{}': {}",
                    remote_path, e
                ))
            })?;

        remote_file.shutdown().await.map_err(|e| {
            TransportError::Io(format!(
                "failed to flush remote file '{}': {}",
                remote_path, e
            ))
        })?;

        Ok(())
    }

    async fn delete(
        &self,
        remote_path: &str,
    ) -> Result<(), TransportError> {
        self.sftp.remove_file(remote_path).await.map_err(|e| {
            TransportError::Io(format!(
                "failed to delete remote file '{}': {}",
                remote_path, e
            ))
        })?;
        Ok(())
    }
}
