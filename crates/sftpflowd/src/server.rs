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

use sftpflow_cluster::node::ClusterHandle;
use sftpflow_core::Config;
use sftpflow_proto::{
    error_code,
    framing,
    Request,
    RequestEnvelope,
    ResponseEnvelope,
};

use crate::handlers; // handlers.rs - RPC method implementations
use crate::history::RunDb; // history.rs - SQLite run history
use crate::secrets::SecretStore; // secrets.rs - sealed credential store

// ============================================================
// Shared daemon state
// ============================================================

/// State shared across all connections. Wrapped in Arc<Mutex<...>>
/// at the call site so handlers can read/mutate it safely.
pub struct DaemonState {
    pub config: Config,
    pub started: Instant,
    /// Dkron scheduler API URL (cloned from config.server.dkron_url
    /// at startup). None means scheduler sync is disabled.
    pub dkron_url: Option<String>,
    /// SQLite run history database. None if DB failed to open
    /// (runs still execute, just not recorded).
    pub run_db: Option<RunDb>,
    /// Sealed credential store. None if no passphrase was configured
    /// at startup — secret RPCs then fail with CONFIG_ERROR and feeds
    /// that use `*_ref` fields will fail to resolve at run time.
    pub secrets: Option<SecretStore>,
    /// Live Raft handle for cluster mode. None in legacy single-node
    /// mode (which M13 removes). When `Some`, mutating RPCs are
    /// gated on `is_leader()` — followers reply with NOT_LEADER
    /// instead of mutating local state.
    pub cluster: Option<ClusterHandle>,
}

// ============================================================
// Entry point - parse address, pick listener, serve
// ============================================================

/// Parse `addr` ("unix:/path", "tcp:host:port", or "host:port") and
/// run the appropriate accept loop until the listener errors out.
///
/// `cluster` is `Some` whenever the daemon is running as a Raft
/// member (init / join / cluster-mode restart). Pass `None` for
/// the legacy single-node path; mutating RPCs then run unguarded.
pub fn run(
    addr: &str,
    config: Config,
    run_db: Option<RunDb>,
    secrets: Option<SecretStore>,
    cluster: Option<ClusterHandle>,
) -> std::io::Result<()> {
    let dkron_url = config.server.dkron_url.clone();
    let state = Arc::new(Mutex::new(DaemonState {
        config,
        started: Instant::now(),
        dkron_url,
        run_db,
        secrets,
        cluster,
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
// Thin routing layer: reads from state, calls into handlers.rs for
// actual business logic. Read-only RPCs lock briefly and release;
// mutating RPCs hold the lock through the full mutation + save.
//
// Mutating RPCs additionally pass through `enforce_leader` first
// (cluster mode only) — followers fail loud with NOT_LEADER. Reads
// run unguarded so `cluster status`, `show feeds`, etc. work from
// any node. M13 turns the gate into automatic forwarding.

fn dispatch(env: RequestEnvelope, state: &Arc<Mutex<DaemonState>>) -> ResponseEnvelope {
    let id = env.id;
    debug!("dispatch id={} request={:?}", id, env.request);

    match env.request {
        // ---- liveness / introspection ----
        Request::Ping => ResponseEnvelope::success(id, handlers::ping()),

        Request::GetServerInfo => {
            let guard = state.lock().unwrap();
            ResponseEnvelope::success(id, handlers::get_server_info(guard.started))
        }

        // ---- endpoints (read) ----
        Request::ListEndpoints => {
            let guard = state.lock().unwrap();
            ResponseEnvelope::success(id, handlers::list_endpoints(&guard))
        }
        Request::GetEndpoint { name } => {
            let guard = state.lock().unwrap();
            ResponseEnvelope::success(id, handlers::get_endpoint(&guard, &name))
        }

        // ---- endpoints (mutate) ----
        Request::PutEndpoint { name, endpoint } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::put_endpoint(&mut guard, name, endpoint))
        }
        Request::DeleteEndpoint { name } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::delete_endpoint(&mut guard, &name))
        }
        Request::RenameEndpoint { from, to } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::rename_endpoint(&mut guard, from, to))
        }

        // ---- keys (read) ----
        Request::ListKeys => {
            let guard = state.lock().unwrap();
            ResponseEnvelope::success(id, handlers::list_keys(&guard))
        }
        Request::GetKey { name } => {
            let guard = state.lock().unwrap();
            ResponseEnvelope::success(id, handlers::get_key(&guard, &name))
        }

        // ---- keys (mutate) ----
        Request::PutKey { name, key } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::put_key(&mut guard, name, key))
        }
        Request::DeleteKey { name } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::delete_key(&mut guard, &name))
        }
        Request::RenameKey { from, to } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::rename_key(&mut guard, from, to))
        }

        // ---- feeds (read) ----
        Request::ListFeeds => {
            let guard = state.lock().unwrap();
            ResponseEnvelope::success(id, handlers::list_feeds(&guard))
        }
        Request::GetFeed { name } => {
            let guard = state.lock().unwrap();
            ResponseEnvelope::success(id, handlers::get_feed(&guard, &name))
        }

        // ---- feeds (mutate) ----
        Request::PutFeed { name, feed } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::put_feed(&mut guard, name, feed))
        }
        Request::DeleteFeed { name } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::delete_feed(&mut guard, &name))
        }
        Request::RenameFeed { from, to } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::rename_feed(&mut guard, from, to))
        }

        // ---- execution ----
        // Leader-gated: we don't want N replicas of the same feed
        // running on N nodes. M14 routes RunFeedNow through the
        // Raft leader (which then dispatches to a chosen member);
        // M12 just refuses on followers.
        Request::RunFeedNow { name } => {
            let guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::run_feed_now(&guard, &name))
        }

        // ---- scheduler ----
        // Leader-gated: dkron is a shared external system; only the
        // leader should reconcile schedules. M14 retires dkron and
        // makes the leader the scheduler natively.
        Request::SyncSchedules => {
            let guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            ResponseEnvelope::success(id, handlers::sync_schedules(&guard))
        }

        // ---- run history ----
        Request::GetRunHistory { feed, limit } => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::get_run_history(&guard, &feed, limit))
        }

        // ---- sealed secrets ----
        Request::PutSecret { name, value } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::put_secret(&mut guard, name, value))
        }
        Request::DeleteSecret { name } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            result_to_envelope(id, handlers::delete_secret(&mut guard, &name))
        }
        Request::ListSecrets => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::list_secrets(&guard))
        }
    }
}

// ============================================================
// enforce_leader - cluster-mode mutating-RPC guard
// ============================================================

/// Returns `Some(error_envelope)` if this node should refuse a
/// mutating RPC because it isn't the cluster leader. Returns
/// `None` to proceed.
///
/// In single-node (legacy) mode `state.cluster` is `None` and this
/// always returns `None` — mutations run as before. In cluster
/// mode we read `is_leader()` off the live Raft handle; if false,
/// we synthesize a NOT_LEADER reply and include the leader's
/// advertise address (when known) so the operator knows where to
/// retry. The leader-id-to-address lookup goes through the
/// membership map openraft already has cached.
fn enforce_leader(id: u64, state: &DaemonState) -> Option<ResponseEnvelope> {
    let handle = state.cluster.as_ref()?;
    if handle.is_leader() {
        return None;
    }

    let leader_advertise = handle
        .current_leader()
        .and_then(|leader_id| handle.members().get(&leader_id).map(|m| m.advertise_addr.clone()));

    let msg = match leader_advertise {
        Some(addr) => format!(
            "this node is not the cluster leader; current leader is reachable at {}",
            addr,
        ),
        None => "this node is not the cluster leader; election in progress or quorum unavailable"
            .to_string(),
    };
    Some(ResponseEnvelope::failure(id, error_code::NOT_LEADER, msg))
}

/// Convert a handler `Result<Response, ProtoError>` into the wire
/// envelope, attaching the request's correlation id.
fn result_to_envelope(
    id: u64,
    result: Result<sftpflow_proto::Response, sftpflow_proto::ProtoError>,
) -> ResponseEnvelope {
    match result {
        Ok(response) => ResponseEnvelope::success(id, response),
        Err(error) => ResponseEnvelope::failure(id, error.code, error.message),
    }
}
