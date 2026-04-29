// ============================================================
// sftpflow-cli::rpc - RPC client for talking to sftpflowd
// ============================================================
//
// Two transport modes:
//   1. Direct socket (dev): persistent connection to tcp:host:port
//      or unix:/path. Persistent is fine here — both sides flush
//      per line, no shell in the middle.
//   2. SSH bridge (prod): one-shot `ssh user@host sftpflow-shell`
//      per RPC call. We *don't* keep a persistent ssh subprocess:
//      under WSL2 / OpenSSH 9.x with no remote pty, the bridge's
//      stdout doesn't flush back to the client until ssh's stdin
//      EOFs, so a long-lived subprocess deadlocks on the second
//      and subsequent calls. Closing stdin per call (which is what
//      one-shot achieves) sidesteps the issue. The downside is one
//      ssh handshake (~100-300ms) per call; acceptable for an
//      operator CLI, much better than the alternative of silently
//      hanging in cluster_join_remote's status-poll loop.
//
// Both modes provide a BufRead reader and Write writer over which
// we send/receive NDJSON RequestEnvelope / ResponseEnvelope pairs.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
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
    inner:  RpcInner,
    /// CLI-attributed caller string stamped into every RequestEnvelope
    /// for the audit log. Format: `<user>@<host>` for SSH transport,
    /// `<system-user>@local` for socket dev mode. The daemon does not
    /// authenticate this — SSH already authenticated the user — it
    /// just records what the CLI claimed.
    caller: Option<String>,
}

enum RpcInner {
    /// TCP/Unix socket — persistent, byte-streaming connection.
    /// `reader` and `writer` are halves of the same socket and
    /// stay open across calls.
    Persistent {
        reader: Box<dyn BufRead + Send>,
        writer: Box<dyn Write + Send>,
    },
    /// SSH bridge — config only. Each `call()` spawns a fresh
    /// `ssh user@host sftpflow-shell` subprocess, sends the
    /// request, reads one response line, then drops the
    /// subprocess (which EOFs the bridge's stdin and lets the
    /// daemon flush its output buffer through sshd's pipe).
    Ssh {
        username: String,
        host:     String,
        port:     Option<u16>,
    },
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
            inner: RpcInner::Persistent {
                reader: Box::new(BufReader::new(reader)),
                writer: Box::new(stream),
            },
            caller: Some(local_caller_for(addr)),
        })
    }

    #[cfg(unix)]
    fn connect_unix(path: &str) -> Result<Self, RpcError> {
        let stream = UnixStream::connect(path)?;
        debug!("rpc: connected via unix socket {}", path);
        let reader = stream.try_clone()?;
        Ok(RpcClient {
            inner: RpcInner::Persistent {
                reader: Box::new(BufReader::new(reader)),
                writer: Box::new(stream),
            },
            caller: Some(local_caller_for(path)),
        })
    }

    // --------------------------------------------------------
    // SSH "connection" (production)
    // --------------------------------------------------------

    /// Stash the SSH transport config. Doesn't actually spawn ssh
    /// here — that happens lazily in `call()`. We still validate
    /// the required fields up-front so the operator gets an
    /// immediate error instead of one per RPC.
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

        debug!("rpc: ssh transport ready for {}@{}", username, host);
        Ok(RpcClient {
            inner: RpcInner::Ssh {
                username: username.to_string(),
                host:     host.to_string(),
                port:     server.port,
            },
            // Stamp `<ssh-user>@<host>` so audit rows attribute every
            // mutating RPC to the operator who's connected.
            caller: Some(format!("{}@{}", username, host)),
        })
    }

    // --------------------------------------------------------
    // RPC call
    // --------------------------------------------------------

    /// Send a request to the daemon and return the response.
    /// Returns RpcError::Proto if the daemon returned an error envelope.
    pub fn call(&mut self, request: Request) -> Result<Response, RpcError> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let envelope = RequestEnvelope {
            id,
            caller: self.caller.clone(),
            request,
        };
        debug!("rpc: sending id={} {:?}", id, envelope);

        let response = match &mut self.inner {
            RpcInner::Persistent { reader, writer } => {
                framing::write_line(writer, &envelope)?;
                let resp: Option<ResponseEnvelope> = framing::read_line(reader)?;
                resp.ok_or(RpcError::UnexpectedEof)?
            }
            RpcInner::Ssh { username, host, port } => {
                one_shot_ssh_call(username, host, *port, &envelope)?
            }
        };

        debug!("rpc: received id={} {:?}", response.id, response.outcome);

        match response.outcome {
            ResponseOutcome::Success { result } => Ok(result),
            ResponseOutcome::Failure { error } => Err(RpcError::Proto(error)),
        }
    }
}

// ============================================================
// one_shot_ssh_call - spawn ssh, send one request, read one reply
// ============================================================
//
// The crux of the Bug-2 fix. Each invocation:
//   1. spawns `ssh [-p port] -T -o BatchMode=yes user@host sftpflow-shell`
//   2. writes the NDJSON request to ssh's stdin
//   3. closes ssh's stdin (drops the writer) — this is the part
//      that the persistent-connection variant got wrong; without
//      EOF, the bridge's output never makes it back through sshd
//   4. reads one response line from ssh's stdout
//   5. waits for ssh to exit and surfaces a non-zero exit as an error
fn one_shot_ssh_call(
    username: &str,
    host:     &str,
    port:     Option<u16>,
    envelope: &RequestEnvelope,
) -> Result<ResponseEnvelope, RpcError> {
    let mut cmd = Command::new("ssh");

    if let Some(p) = port {
        cmd.arg("-p").arg(p.to_string());
    }

    // -T: don't request a remote pty (we're piping NDJSON, not
    //     driving an interactive shell — pty would echo input back
    //     and corrupt the framing).
    // BatchMode=yes: never prompt for a password — auth is by key.
    cmd.arg("-T").arg("-o").arg("BatchMode=yes");
    cmd.arg(format!("{}@{}", username, host));
    cmd.arg("sftpflow-shell");

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    debug!("rpc(ssh one-shot): spawning ssh to {}@{}", username, host);
    let mut child = cmd.spawn().map_err(|e| {
        RpcError::Io(io::Error::new(
            e.kind(),
            format!("failed to spawn ssh: {}", e),
        ))
    })?;

    // Write the request, then drop stdin so the remote bridge sees
    // EOF and flushes its output back to us.
    {
        let mut stdin = child.stdin.take().expect("stdin was piped");
        framing::write_line(&mut stdin, envelope)?;
        // `stdin` drops here, closing the write half of the pipe.
    }

    // Read one response line from ssh stdout.
    let stdout = child.stdout.take().expect("stdout was piped");
    let mut reader = BufReader::new(stdout);
    let envelope: Option<ResponseEnvelope> = framing::read_line(&mut reader)?;

    // Drain any trailing bytes so the child's stdout pipe has no
    // pressure when we wait() on it. Bridge cleanly exits after the
    // single response, so this is usually empty.
    let mut sink = Vec::new();
    let _ = reader.read_to_end(&mut sink);

    let status = child.wait().map_err(|e| {
        RpcError::Io(io::Error::new(
            e.kind(),
            format!("waiting on ssh subprocess: {}", e),
        ))
    })?;
    if !status.success() {
        return Err(RpcError::Io(io::Error::other(format!(
            "ssh subprocess exited with status {}", status.code().unwrap_or(-1),
        ))));
    }

    envelope.ok_or(RpcError::UnexpectedEof)
}

// ============================================================
// local_caller_for - audit caller string for non-SSH transports
// ============================================================

/// Build a `<system-user>@local[:<addr>]` caller string for socket
/// dev mode (TCP loopback or Unix domain socket). The daemon stamps
/// this onto audit rows so even local development shows a non-empty
/// caller — easier than chasing down "who was that anonymous mutation
/// last Tuesday?". Falls back to `unknown@local` when the OS gives
/// no username.
fn local_caller_for(addr: &str) -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    // Keep the address suffix short — full Unix paths are noisy in
    // an audit table. Just include host:port for TCP, drop the path
    // for Unix sockets (the "@local" already conveys "this box").
    if addr.starts_with('/') {
        format!("{}@local", user)
    } else {
        format!("{}@local:{}", user, addr)
    }
}
