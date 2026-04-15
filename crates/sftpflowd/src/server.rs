// ============================================================
// sftpflowd::server - listener + connection loop + RPC dispatch
// ============================================================
//
// One thread per connection. Each connection reads NDJSON
// RequestEnvelopes and writes NDJSON ResponseEnvelopes in a
// simple request/response loop until the peer closes the stream.
//
// Shared daemon state (config, uptime) lives behind a Mutex so
// concurrent connections can read it safely. Mutating requests
// (PutFeed, DeleteFeed, ...) will take the same lock when we
// implement them in later milestones.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use log::{debug, info, warn};

use sftpflow_core::Config;
use sftpflow_proto::{
    error_code,
    framing,
    FeedSummary,
    Request,
    RequestEnvelope,
    Response,
    ResponseEnvelope,
    ServerInfo,
};

// ============================================================
// Shared daemon state
// ============================================================

/// State shared across all connections. Wrapped in Arc<Mutex<...>>
/// at the call site so handlers can read/mutate it safely.
pub struct DaemonState {
    pub config: Config,
    pub started: Instant,
}

// ============================================================
// Entry point - parse address, pick listener, serve
// ============================================================

/// Parse `addr` ("unix:/path", "tcp:host:port", or "host:port") and
/// run the appropriate accept loop until the listener errors out.
pub fn run(addr: &str, config: Config) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(DaemonState {
        config,
        started: Instant::now(),
    }));

    // Split into (scheme, rest). Anything without a known scheme
    // prefix is treated as a bare "host:port" and defaults to TCP.
    let (scheme, rest) = match addr.split_once(':') {
        Some(("unix", r)) => ("unix", r),
        Some(("tcp", r))  => ("tcp", r),
        _                 => ("tcp", addr),
    };

    match scheme {
        "tcp" => serve_tcp(rest, state),
        "unix" => {
            #[cfg(unix)]
            {
                serve_unix(rest, state)
            }
            #[cfg(not(unix))]
            {
                let _ = (rest, state); // silence unused warnings on windows
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "unix sockets are not supported on this platform; use tcp:",
                ))
            }
        }
        _ => unreachable!(),
    }
}

// ============================================================
// TCP listener
// ============================================================

fn serve_tcp(addr: &str, state: Arc<Mutex<DaemonState>>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    info!("tcp listener bound to {}", addr);

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let peer = stream.peer_addr().ok();
                info!("connection accepted from {:?}", peer);
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_tcp(stream, state) {
                        warn!("connection handler error: {}", e);
                    }
                });
            }
            Err(e) => warn!("accept error: {}", e),
        }
    }
    Ok(())
}

fn handle_tcp(stream: TcpStream, state: Arc<Mutex<DaemonState>>) -> std::io::Result<()> {
    // Split the stream into separate read/write halves so we can wrap
    // the reader in a BufReader while writing through the original.
    let writer = stream.try_clone()?;
    let reader = BufReader::new(stream);
    // connection_loop() - below
    connection_loop(reader, writer, state)
}

// ============================================================
// Unix domain socket listener (Linux production path)
// ============================================================

#[cfg(unix)]
fn serve_unix(path: &str, state: Arc<Mutex<DaemonState>>) -> std::io::Result<()> {
    // Best-effort cleanup of a stale socket file from a previous run.
    // If we can't remove it, the bind() below will surface the error.
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path)?;
    info!("unix listener bound to {}", path);

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                info!("unix connection accepted");
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_unix(stream, state) {
                        warn!("connection handler error: {}", e);
                    }
                });
            }
            Err(e) => warn!("accept error: {}", e),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn handle_unix(stream: UnixStream, state: Arc<Mutex<DaemonState>>) -> std::io::Result<()> {
    let writer = stream.try_clone()?;
    let reader = BufReader::new(stream);
    // connection_loop() - below
    connection_loop(reader, writer, state)
}

// ============================================================
// Generic connection loop (shared by TCP and Unix paths)
// ============================================================

/// Read requests until EOF, dispatch each, write the response back.
/// Any protocol-level parse error is surfaced as a PARSE_ERROR response
/// with id=0 (since we couldn't read the id); the connection stays open.
fn connection_loop<R, W>(
    mut reader: R,
    mut writer: W,
    state: Arc<Mutex<DaemonState>>,
) -> std::io::Result<()>
where
    R: BufRead,
    W: Write,
{
    loop {
        let envelope: Option<RequestEnvelope> = match framing::read_line(&mut reader) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // Malformed JSON. Tell the peer and continue.
                let err = ResponseEnvelope::failure(
                    0,
                    error_code::PARSE_ERROR,
                    format!("parse error: {}", e),
                );
                framing::write_line(&mut writer, &err)?;
                continue;
            }
            Err(e) => return Err(e),
        };

        let Some(env) = envelope else {
            debug!("peer closed connection cleanly");
            return Ok(());
        };

        // dispatch() - below
        let response = dispatch(env, &state);
        framing::write_line(&mut writer, &response)?;
    }
}

// ============================================================
// Request dispatch
// ============================================================
//
// Milestone 3 implements the read-only introspection methods:
//   Ping, GetServerInfo, ListFeeds, ListEndpoints, ListKeys,
//   GetEndpoint, GetKey, GetFeed
//
// Mutating methods (Put/Delete/Rename/RunFeedNow) return a
// "not yet implemented" error; they'll land in later milestones.

fn dispatch(env: RequestEnvelope, state: &Arc<Mutex<DaemonState>>) -> ResponseEnvelope {
    let id = env.id;
    debug!("dispatch id={} request={:?}", id, env.request);

    match env.request {
        // ---- liveness / introspection ----
        Request::Ping => ResponseEnvelope::success(id, Response::Pong),

        Request::GetServerInfo => {
            let guard = state.lock().unwrap();
            let info = ServerInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                hostname: hostname(),
                uptime_seconds: guard.started.elapsed().as_secs(),
            };
            ResponseEnvelope::success(id, Response::ServerInfo(info))
        }

        // ---- endpoints (read-only) ----
        Request::ListEndpoints => {
            let guard = state.lock().unwrap();
            let names: Vec<String> = guard.config.endpoints.keys().cloned().collect();
            ResponseEnvelope::success(id, Response::Names(names))
        }
        Request::GetEndpoint { name } => {
            let guard = state.lock().unwrap();
            let ep = guard.config.endpoints.get(&name).cloned();
            ResponseEnvelope::success(id, Response::Endpoint(ep))
        }

        // ---- keys (read-only) ----
        Request::ListKeys => {
            let guard = state.lock().unwrap();
            let names: Vec<String> = guard.config.keys.keys().cloned().collect();
            ResponseEnvelope::success(id, Response::Names(names))
        }
        Request::GetKey { name } => {
            let guard = state.lock().unwrap();
            let key = guard.config.keys.get(&name).cloned();
            ResponseEnvelope::success(id, Response::Key(key))
        }

        // ---- feeds (read-only) ----
        Request::ListFeeds => {
            let guard = state.lock().unwrap();
            let summaries: Vec<FeedSummary> = guard
                .config
                .feeds
                .iter()
                .map(|(name, feed)| FeedSummary {
                    name: name.clone(),
                    enabled: feed.flags.enabled,
                    sources: feed.sources.len(),
                    destinations: feed.destinations.len(),
                    schedules: feed.schedules.len(),
                })
                .collect();
            ResponseEnvelope::success(id, Response::FeedSummaries(summaries))
        }
        Request::GetFeed { name } => {
            let guard = state.lock().unwrap();
            let feed = guard.config.feeds.get(&name).cloned();
            ResponseEnvelope::success(id, Response::Feed(feed))
        }

        // ---- mutating methods (not yet implemented) ----
        Request::PutEndpoint { .. }
        | Request::DeleteEndpoint { .. }
        | Request::RenameEndpoint { .. }
        | Request::PutKey { .. }
        | Request::DeleteKey { .. }
        | Request::RenameKey { .. }
        | Request::PutFeed { .. }
        | Request::DeleteFeed { .. }
        | Request::RenameFeed { .. }
        | Request::RunFeedNow { .. } => ResponseEnvelope::failure(
            id,
            error_code::INTERNAL_ERROR,
            "not yet implemented",
        ),
    }
}

// ============================================================
// Helpers
// ============================================================

/// Best-effort hostname: $HOSTNAME, $COMPUTERNAME, or "unknown".
/// We avoid pulling in a dedicated crate for this — the value is
/// informational only (shown in `show server info`).
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
