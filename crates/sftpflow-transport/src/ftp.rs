// ============================================================
// ftp.rs — FTP / FTPS transport via suppaftp (sync API)
// ============================================================
//
// Implements the Transport trait for both plain FTP and FTPS
// (explicit AUTH TLS or implicit). Uses suppaftp's *sync* client
// because its async client is built on async-std and we'd rather
// not mix runtimes inside the daemon's tokio host. Each blocking
// FTP operation runs on tokio's blocking-thread pool via
// `tokio::task::spawn_blocking`.
//
// Design choices:
//   - Connection per FtpTransport, owned by the orchestrator.
//   - Wrapped in std::sync::Mutex so &self trait methods can lock
//     the connection inside the blocking task. The lock is never
//     held across an .await.
//   - TLS via rustls + webpki-roots (pure-Rust, no OpenSSL).
//   - verify_tls=false installs a NoOp ServerCertVerifier so we
//     can talk to vendor endpoints with self-signed certs. This is
//     intentionally opt-in per endpoint.

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use log::{info, warn};
use suppaftp::{FtpStream, Mode, RustlsConnector, RustlsFtpStream};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use sftpflow_core::{Endpoint, FtpsMode, Protocol};

use crate::{Transport, TransportError};

// ============================================================
// FtpClient — enum wrapping plain vs TLS streams
// ============================================================
//
// suppaftp's `FtpStream` and `RustlsFtpStream` are different
// generic instantiations of `ImplFtpStream<T>`, so they cannot
// share a trait object. The enum keeps both shapes behind one
// type so FtpTransport can hold whichever variant connect()
// produced.

enum FtpClient {
    Plain(FtpStream),
    Tls(RustlsFtpStream),
}

// Forward each FTP operation to whichever variant we hold.
impl FtpClient {
    fn login(&mut self, user: &str, pass: &str) -> Result<(), suppaftp::FtpError> {
        match self {
            FtpClient::Plain(s) => s.login(user, pass),
            FtpClient::Tls(s)   => s.login(user, pass),
        }
    }

    fn set_mode(&mut self, mode: Mode) {
        match self {
            FtpClient::Plain(s) => s.set_mode(mode),
            FtpClient::Tls(s)   => s.set_mode(mode),
        }
    }

    fn transfer_type_binary(&mut self) -> Result<(), suppaftp::FtpError> {
        let t = suppaftp::types::FileType::Binary;
        match self {
            FtpClient::Plain(s) => s.transfer_type(t),
            FtpClient::Tls(s)   => s.transfer_type(t),
        }
    }

    fn list(&mut self, path: Option<&str>) -> Result<Vec<String>, suppaftp::FtpError> {
        // We use NLST (just names) rather than LIST (full unix-style
        // listing). LIST is cosmetic; for "give me the filenames in
        // this dir" NLST is the right call and avoids brittle parsing.
        match self {
            FtpClient::Plain(s) => s.nlst(path),
            FtpClient::Tls(s)   => s.nlst(path),
        }
    }

    fn retr_as_buffer(&mut self, path: &str) -> Result<Vec<u8>, suppaftp::FtpError> {
        let cursor = match self {
            FtpClient::Plain(s) => s.retr_as_buffer(path)?,
            FtpClient::Tls(s)   => s.retr_as_buffer(path)?,
        };
        Ok(cursor.into_inner())
    }

    fn put_file(&mut self, path: &str, contents: &[u8]) -> Result<u64, suppaftp::FtpError> {
        let mut reader = std::io::Cursor::new(contents);
        match self {
            FtpClient::Plain(s) => s.put_file(path, &mut reader),
            FtpClient::Tls(s)   => s.put_file(path, &mut reader),
        }
    }

    fn rm(&mut self, path: &str) -> Result<(), suppaftp::FtpError> {
        match self {
            FtpClient::Plain(s) => s.rm(path),
            FtpClient::Tls(s)   => s.rm(path),
        }
    }
}

// ============================================================
// FtpTransport
// ============================================================

pub struct FtpTransport {
    inner: Arc<Mutex<FtpClient>>,
}

impl FtpTransport {
    /// Open a sync FTP/FTPS connection, log in, set passive/active
    /// mode, and switch to binary transfer type. Runs on the
    /// blocking thread pool so it doesn't stall the tokio reactor.
    pub async fn connect(
        name: &str,
        endpoint: &Endpoint,
    ) -> Result<Self, TransportError> {
        let host = endpoint
            .host
            .clone()
            .ok_or_else(|| missing(name, "host"))?;
        let username = endpoint
            .username
            .clone()
            .ok_or_else(|| missing(name, "username"))?;
        let password = endpoint
            .password
            .clone()
            .ok_or_else(|| missing(name, "password"))?;

        let is_ftps = matches!(endpoint.protocol, Protocol::Ftps);
        let ftps_mode = endpoint.ftps_mode.clone().unwrap_or_default();
        let port = endpoint.port.unwrap_or_else(|| {
            // FTPS-implicit defaults to 990; everything else to 21.
            match (is_ftps, &ftps_mode) {
                (true, FtpsMode::Implicit) => 990,
                _ => 21,
            }
        });
        let passive = endpoint.passive.unwrap_or(true);
        let verify_tls = endpoint.verify_tls.unwrap_or(true);
        let mode = if passive { Mode::Passive } else { Mode::Active };

        info!(
            "ftp connect: {}@{}:{} (endpoint '{}', protocol {}, mode {})",
            username, host, port, name, endpoint.protocol,
            if passive { "passive" } else { "active" },
        );

        let name_owned = name.to_string();
        let host_for_blocking = host.clone();

        // ---- run the entire connect+login sequence in one blocking
        // ---- task so we don't pay multiple thread-hops for setup.
        let client = tokio::task::spawn_blocking(move || -> Result<FtpClient, TransportError> {
            let addr = format!("{}:{}", host_for_blocking, port);

            let mut client = if is_ftps {
                let connector = build_rustls_connector(verify_tls)
                    .map_err(|e| TransportError::Connection(format!(
                        "TLS setup failed for endpoint '{}': {}", name_owned, e,
                    )))?;

                match ftps_mode {
                    FtpsMode::Implicit => {
                        // TLS from byte 0 — connect_secure_implicit
                        // dials the socket and immediately wraps it.
                        let tls = RustlsFtpStream::connect_secure_implicit(
                            &addr, connector, &host_for_blocking,
                        )
                        .map_err(|e| TransportError::Connection(format!(
                            "FTPS implicit connect to {} failed: {}", addr, e,
                        )))?;
                        FtpClient::Tls(tls)
                    }
                    FtpsMode::Explicit => {
                        // Plain TCP control channel, then AUTH TLS
                        // upgrade. Note we use RustlsFtpStream::connect
                        // (not the bare FtpStream::connect) so the
                        // type carries the TLS-stream parameter from
                        // the start; into_secure then performs the
                        // actual handshake.
                        let pre_tls = RustlsFtpStream::connect(&addr).map_err(|e| {
                            TransportError::Connection(format!(
                                "FTP connect to {} failed: {}", addr, e,
                            ))
                        })?;
                        let tls = pre_tls
                            .into_secure(connector, &host_for_blocking)
                            .map_err(|e| TransportError::Connection(format!(
                                "FTPS AUTH TLS to {} failed: {}", addr, e,
                            )))?;
                        FtpClient::Tls(tls)
                    }
                }
            } else {
                // Plain FTP.
                let plain = FtpStream::connect(&addr).map_err(|e| {
                    TransportError::Connection(format!(
                        "FTP connect to {} failed: {}", addr, e,
                    ))
                })?;
                FtpClient::Plain(plain)
            };

            client.login(&username, &password).map_err(|e| {
                TransportError::Connection(format!(
                    "FTP login as '{}' failed: {}", username, e,
                ))
            })?;
            client.set_mode(mode);
            // Always binary: text mode would corrupt non-ASCII payloads
            // (PGP-encrypted blobs, zips, etc.).
            client.transfer_type_binary().map_err(|e| {
                TransportError::Connection(format!(
                    "FTP TYPE I failed: {}", e,
                ))
            })?;

            Ok(client)
        })
        .await
        .map_err(|e| TransportError::Connection(format!("blocking task panicked: {}", e)))??;

        info!("ftp connect: ready (endpoint '{}')", name);

        Ok(FtpTransport {
            inner: Arc::new(Mutex::new(client)),
        })
    }
}

fn missing(name: &str, field: &str) -> TransportError {
    TransportError::MissingField(name.to_string(), field.to_string())
}

// ============================================================
// rustls ClientConfig builder
// ============================================================

fn build_rustls_connector(verify_tls: bool) -> Result<RustlsConnector, String> {
    // Install ring as the process-wide crypto provider on first call.
    // Idempotent: subsequent installs return Err which we ignore.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = if verify_tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        warn!("FTPS endpoint configured with verify_tls=false; \
               server certificate will NOT be validated");
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };

    Ok(RustlsConnector::from(Arc::new(config)))
}

// A ServerCertVerifier that accepts every certificate. Only used
// when the endpoint explicitly opts in via verify_tls=false. Lives
// here (not in a separate file) so the danger is visible at the
// call site.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ============================================================
// Transport trait implementation
// ============================================================

#[async_trait]
impl Transport for FtpTransport {
    async fn list_files(
        &self,
        remote_dir: &str,
    ) -> Result<Vec<String>, TransportError> {
        let inner = Arc::clone(&self.inner);
        let dir = remote_dir.to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>, TransportError> {
            let mut guard = inner.lock().unwrap();
            let names = guard.list(Some(&dir)).map_err(|e| {
                TransportError::Io(format!("FTP NLST '{}' failed: {}", dir, e))
            })?;
            // NLST sometimes returns full paths and sometimes bare names
            // depending on server. Normalize to bare basenames so the
            // orchestrator can reattach the source path consistently.
            Ok(names
                .into_iter()
                .map(|raw| {
                    raw.rsplit_once('/')
                        .map(|(_, n)| n.to_string())
                        .unwrap_or(raw)
                })
                .filter(|n| !n.is_empty() && n != "." && n != "..")
                .collect())
        })
        .await
        .map_err(|e| TransportError::Io(format!("blocking task panicked: {}", e)))?
    }

    async fn download(
        &self,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<(), TransportError> {
        let inner = Arc::clone(&self.inner);
        let remote = remote_path.to_string();
        let local = local_path.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<(), TransportError> {
            let mut guard = inner.lock().unwrap();
            let bytes = guard.retr_as_buffer(&remote).map_err(|e| {
                TransportError::Io(format!(
                    "FTP RETR '{}' failed: {}", remote, e,
                ))
            })?;
            std::fs::write(&local, &bytes).map_err(|e| {
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
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), TransportError> {
        let inner = Arc::clone(&self.inner);
        let remote = remote_path.to_string();
        let local = local_path.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<(), TransportError> {
            let bytes = std::fs::read(&local).map_err(|e| {
                TransportError::Io(format!(
                    "failed to read local file '{}': {}",
                    local.display(), e,
                ))
            })?;
            let mut guard = inner.lock().unwrap();
            guard.put_file(&remote, &bytes).map_err(|e| {
                TransportError::Io(format!(
                    "FTP STOR '{}' failed: {}", remote, e,
                ))
            })?;
            Ok(())
        })
        .await
        .map_err(|e| TransportError::Io(format!("blocking task panicked: {}", e)))?
    }

    async fn delete(
        &self,
        remote_path: &str,
    ) -> Result<(), TransportError> {
        let inner = Arc::clone(&self.inner);
        let remote = remote_path.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), TransportError> {
            let mut guard = inner.lock().unwrap();
            guard.rm(&remote).map_err(|e| {
                TransportError::Io(format!(
                    "FTP DELE '{}' failed: {}", remote, e,
                ))
            })?;
            Ok(())
        })
        .await
        .map_err(|e| TransportError::Io(format!("blocking task panicked: {}", e)))?
    }
}
