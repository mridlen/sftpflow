// ============================================================
// sftpflow-cli::rpc - RPC client for talking to sftpflowd
// ============================================================
//
// Two transport modes:
//   1. Direct socket (dev): connects to tcp:host:port or unix:/path
//   2. SSH subprocess (prod): spawns `ssh user@host sftpflow-shell`
//
// Both provide a BufRead reader and Write writer over which we
// send/receive NDJSON RequestEnvelope / ResponseEnvelope pairs.

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use log::debug;

use sftpflow_core::ServerConnection;
use sftpflow_proto::{
    framing,
    ProtoError,
    Request,
    RequestEnvelope,
    Response,
    ResponseEnvelope,
    ResponseOutcome,
};

// ============================================================
// Error type
// ============================================================

#[derive(Debug)]
pub enum RpcError {
    Io(io::Error),
    Proto(ProtoError),
    UnexpectedEof,
    ConnectionNotConfigured(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Io(e) => write!(f, "I/O error: {}", e),
            RpcError::Proto(e) => write!(f, "RPC error {}: {}", e.code, e.message),
            RpcError::UnexpectedEof => write!(f, "daemon closed connection unexpectedly"),
            RpcError::ConnectionNotConfigured(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<io::Error> for RpcError {
    fn from(e: io::Error) -> Self {
        RpcError::Io(e)
    }
}

// ============================================================
// RPC client
// ============================================================

/// Monotonic ID counter shared across all RpcClient instances in
/// this process. Each call() gets a unique id for correlation.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct RpcClient {
    reader: Box<dyn BufRead + Send>,
    writer: Box<dyn Write + Send>,
    ssh_child: Option<Child>,
}

impl RpcClient {
    // --------------------------------------------------------
    // Direct socket connection (dev / local testing)
    // --------------------------------------------------------

    /// Connect to a daemon socket address. Accepts the same address
    /// formats as sftpflowd: `tcp:host:port`, `unix:/path`, or bare
    /// `host:port` (defaults to TCP).
    pub fn connect_socket(addr: &str) -> Result<Self, RpcError> {
        let (scheme, rest) = match addr.split_once(':') {
            Some(("unix", r)) => ("unix", r),
            Some(("tcp", r))  => ("tcp", r),
            _                 => ("tcp", addr),
        };

        match scheme {
            "tcp" => Self::connect_tcp(rest),
            "unix" => {
                #[cfg(unix)]
                { Self::connect_unix(rest) }
                #[cfg(not(unix))]
                {
                    let _ = rest;
                    Err(RpcError::Io(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "unix sockets not supported on this platform; use tcp:",
                    )))
                }
            }
            _ => unreachable!(),
        }
    }

    fn connect_tcp(addr: &str) -> Result<Self, RpcError> {
        let stream = TcpStream::connect(addr)?;
        debug!("rpc: connected via tcp to {}", addr);
        let reader = stream.try_clone()?;
        Ok(RpcClient {
            reader: Box::new(BufReader::new(reader)),
            writer: Box::new(stream),
            ssh_child: None,
        })
    }

    #[cfg(unix)]
    fn connect_unix(path: &str) -> Result<Self, RpcError> {
        let stream = UnixStream::connect(path)?;
        debug!("rpc: connected via unix socket {}", path);
        let reader = stream.try_clone()?;
        Ok(RpcClient {
            reader: Box::new(BufReader::new(reader)),
            writer: Box::new(stream),
            ssh_child: None,
        })
    }

    // --------------------------------------------------------
    // SSH subprocess connection (production)
    // --------------------------------------------------------

    /// Spawn `ssh user@host sftpflow-shell` and wire its stdin/stdout
    /// as the RPC transport. Uses settings from ServerConnection.
    pub fn connect_ssh(server: &ServerConnection) -> Result<Self, RpcError> {
        let host = server.host.as_deref().ok_or_else(|| {
            RpcError::ConnectionNotConfigured(
                "server host is not configured (set it with 'server host <addr>')".into(),
            )
        })?;

        let username = server.username.as_deref().ok_or_else(|| {
            RpcError::ConnectionNotConfigured(
                "server username is not configured (set it with 'server username <user>')".into(),
            )
        })?;

        let mut cmd = Command::new("ssh");

        if let Some(port) = server.port {
            cmd.arg("-p").arg(port.to_string());
        }

        // -o BatchMode=yes prevents interactive password prompts that
        // would hang the CLI; key-based auth is expected.
        cmd.arg("-o").arg("BatchMode=yes");

        cmd.arg(format!("{}@{}", username, host));
        cmd.arg("sftpflow-shell");

        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());

        debug!("rpc: spawning ssh subprocess to {}@{}", username, host);
        let mut child = cmd.spawn().map_err(|e| {
            RpcError::Io(io::Error::new(
                e.kind(),
                format!("failed to spawn ssh: {}", e),
            ))
        })?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");

        Ok(RpcClient {
            reader: Box::new(BufReader::new(stdout)),
            writer: Box::new(stdin),
            ssh_child: Some(child),
        })
    }

    // --------------------------------------------------------
    // RPC call
    // --------------------------------------------------------

    /// Send a request to the daemon and return the response.
    /// Returns RpcError::Proto if the daemon returned an error envelope.
    pub fn call(&mut self, request: Request) -> Result<Response, RpcError> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let envelope = RequestEnvelope { id, request };

        debug!("rpc: sending id={} {:?}", id, envelope);
        framing::write_line(&mut self.writer, &envelope)?;

        let response: Option<ResponseEnvelope> = framing::read_line(&mut self.reader)?;
        let response = response.ok_or(RpcError::UnexpectedEof)?;

        debug!("rpc: received id={} {:?}", response.id, response.outcome);

        match response.outcome {
            ResponseOutcome::Success { result } => Ok(result),
            ResponseOutcome::Failure { error } => Err(RpcError::Proto(error)),
        }
    }
}

// ============================================================
// Cleanup
// ============================================================

impl Drop for RpcClient {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.ssh_child {
            // Close the SSH subprocess's stdin by replacing the writer
            // with a no-op sink. This signals EOF to sftpflow-shell.
            self.writer = Box::new(io::sink());
            let _ = child.wait();
        }
    }
}
