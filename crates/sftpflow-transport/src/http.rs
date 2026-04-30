// ============================================================
// http.rs — HTTP/HTTPS transport via ureq (sync API)
// ============================================================
//
// Implements the Transport trait for HTTP/HTTPS, but only as a
// read-only source: list_files returns the single file named by
// src.path, download fetches it, and upload/delete return an
// UnsupportedProtocol error. The orchestrator rejects HTTP as a
// destination in validate_feed(), so upload/delete should never
// be called in practice.
//
// Design choices:
//   - Uses ureq's sync client behind spawn_blocking (same pattern
//     as ftp.rs) to avoid mixing runtime stacks.
//   - URL is built as "{scheme}://{host}[:{port}]{path}" from the
//     endpoint config and source path.
//   - Basic auth via the Authorization header when both username
//     and password are set. Anonymous GET is the common case for
//     public download URLs.
//   - TLS uses ureq's built-in rustls defaults with webpki-roots.
//     The endpoint.verify_tls flag is currently only honored by
//     FTPS; HTTPS in v1 always validates certs.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::info;
use ureq::Agent;

/// Cap initial TCP/TLS connect to a remote HTTP source. Slower than
/// the FTP/SFTP cap because public CDNs sometimes redirect through
/// multiple hops on the first hit.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on each socket-level read/write during the body stream. A
/// stalled response (slow loris) gives up within this window rather
/// than holding a tokio blocking-pool thread forever.
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(120);

use sftpflow_core::{Endpoint, Protocol};

use crate::{Transport, TransportError};

// ============================================================
// HttpTransport
// ============================================================

pub struct HttpTransport {
    agent: Agent,
    /// "scheme://host[:port]" — the source path is appended verbatim.
    base_url: String,
    /// Pre-encoded "Basic ..." header, when credentials are set.
    auth_header: Option<String>,
}

impl HttpTransport {
    /// Construct an HTTP/HTTPS transport. No request is made here —
    /// ureq lazily opens TCP/TLS on the first call — so this can't
    /// really fail unless the endpoint is misconfigured.
    pub async fn connect(
        name: &str,
        endpoint: &Endpoint,
    ) -> Result<Self, TransportError> {
        let host = endpoint
            .host
            .clone()
            .ok_or_else(|| missing(name, "host"))?;

        let scheme = match endpoint.protocol {
            Protocol::Http  => "http",
            Protocol::Https => "https",
            // connect_endpoint only dispatches here for Http/Https,
            // so this arm is structurally unreachable.
            ref p => {
                return Err(TransportError::UnsupportedProtocol(
                    name.to_string(),
                    p.to_string(),
                ));
            }
        };

        let base_url = match endpoint.port {
            Some(p) => format!("{}://{}:{}", scheme, host, p),
            None    => format!("{}://{}", scheme, host),
        };

        // Basic auth only when *both* username and password are set.
        // Partial credentials are rejected in validate_endpoint() so
        // we don't need to handle the half-set case here.
        let auth_header = match (&endpoint.username, &endpoint.password) {
            (Some(u), Some(p)) => {
                let encoded = STANDARD.encode(format!("{}:{}", u, p));
                Some(format!("Basic {}", encoded))
            }
            _ => None,
        };

        info!(
            "http connect: {} (endpoint '{}', auth={})",
            base_url,
            name,
            if auth_header.is_some() { "basic" } else { "none" },
        );

        // Cap connect + per-socket-op timeouts so a black-holed remote
        // can't pin a tokio blocking-pool thread indefinitely.
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(HTTP_CONNECT_TIMEOUT)
            .timeout_read(HTTP_IO_TIMEOUT)
            .timeout_write(HTTP_IO_TIMEOUT)
            .build();

        Ok(HttpTransport {
            agent,
            base_url,
            auth_header,
        })
    }

    /// Build a full request URL from the configured base_url and a
    /// source path. Accepts paths with or without a leading '/'.
    fn url_for(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/{}", self.base_url, path)
        }
    }
}

fn missing(name: &str, field: &str) -> TransportError {
    TransportError::MissingField(name.to_string(), field.to_string())
}

// ============================================================
// Transport trait implementation
// ============================================================

#[async_trait]
impl Transport for HttpTransport {
    /// HTTP sources are single-file URLs, so the "remote path" the
    /// orchestrator should hand back to download() is just the
    /// configured source path — the filename list_files returned is
    /// already the basename of that path. Overrides the default
    /// `{base}/{name}` join used by SFTP/FTP.
    fn remote_path(&self, base: &str, _name: &str) -> String {
        base.to_string()
    }

    async fn list_files(
        &self,
        remote_dir: &str,
    ) -> Result<Vec<String>, TransportError> {
        // HTTP has no directory-listing concept. Treat src.path as a
        // single file URL and return its basename so the orchestrator
        // can stage the downloaded bytes under that name.
        let trimmed = remote_dir.trim_end_matches('/');
        let basename = trimmed
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();

        if basename.is_empty() {
            return Err(TransportError::Io(format!(
                "HTTP source path '{}' has no filename — give a full \
                 file URL path like '/reports/daily.csv'",
                remote_dir,
            )));
        }

        Ok(vec![basename])
    }

    async fn download(
        &self,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<(), TransportError> {
        let url = self.url_for(remote_path);
        let agent = self.agent.clone();
        let auth = self.auth_header.clone();
        let local = local_path.to_path_buf();
        let url_for_err = url.clone();

        tokio::task::spawn_blocking(move || -> Result<(), TransportError> {
            let mut req = agent.get(&url);
            if let Some(header) = auth.as_deref() {
                req = req.set("Authorization", header);
            }
            let resp = req.call().map_err(|e| {
                TransportError::Io(format!(
                    "HTTP GET '{}' failed: {}", url_for_err, e,
                ))
            })?;

            // Stream the body to disk rather than buffering it, so
            // large downloads don't blow up memory.
            let mut reader = resp.into_reader();
            let mut file = std::fs::File::create(&local).map_err(|e| {
                TransportError::Io(format!(
                    "failed to create local file '{}': {}",
                    local.display(), e,
                ))
            })?;
            std::io::copy(&mut reader, &mut file).map_err(|e| {
                TransportError::Io(format!(
                    "failed to write local file '{}': {}",
                    local.display(), e,
                ))
            })?;
            Ok(())
        })
        .await
        .map_err(|e| TransportError::Io(format!("blocking task panicked: {}", e)))?
    }

    async fn upload(
        &self,
        _local_path: &Path,
        _remote_path: &str,
    ) -> Result<(), TransportError> {
        // HTTP is source-only. validate_feed() rejects HTTP/HTTPS
        // endpoints used as destinations, so this path is unreachable
        // under normal operation; the error is here only as a guard.
        Err(TransportError::UnsupportedProtocol(
            "<http-endpoint>".to_string(),
            "upload to http/https".to_string(),
        ))
    }

    async fn delete(
        &self,
        _remote_path: &str,
    ) -> Result<(), TransportError> {
        Err(TransportError::UnsupportedProtocol(
            "<http-endpoint>".to_string(),
            "delete over http/https".to_string(),
        ))
    }
}
