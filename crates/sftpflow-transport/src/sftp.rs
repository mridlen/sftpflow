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
use log::info;
use russh::client;
use russh::keys::ssh_key;
use russh::keys::PrivateKeyWithHashAlg;
use russh_sftp::client::SftpSession;
use tokio::io::AsyncReadExt;

use sftpflow_core::Endpoint;

use crate::{Transport, TransportError};

// ============================================================
// SSH client handler — accepts all host keys for now
// ============================================================

/// Minimal SSH client handler. Accepts any server host key.
/// Host-key verification is deferred to milestone 11
/// (credential security).
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send
    {
        // Accept all host keys (trust-on-first-use not yet
        // implemented)
        async { Ok(true) }
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
        let config = Arc::new(client::Config::default());
        let handler = SshHandler;

        let mut handle = client::connect(
            config,
            (host, port),
            handler,
        )
        .await
        .map_err(|e| {
            TransportError::Connection(format!(
                "SSH connect to {}:{} failed: {}",
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
