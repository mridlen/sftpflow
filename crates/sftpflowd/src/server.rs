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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use log::{debug, info, warn};

use sftpflow_core::Config;
use sftpflow_proto::{
    error_code,
    framing,
    Request,
    RequestEnvelope,
    Response,
    ResponseEnvelope,
};

/// Public alias for the daemon's primary state container. Wrapped
/// so threads (NDJSON connections + the gRPC forward handler)
/// share the same instance behind a single Mutex.
pub type SharedDaemonState = Arc<Mutex<DaemonState>>;

use crate::audit::{self, AuditDb}; // audit.rs - SQLite mutation audit log
use crate::cluster_runtime::ClusterContext; // cluster_runtime.rs - runtime cluster bundle
use crate::handlers; // handlers.rs - RPC method implementations
use crate::history::RunDb; // history.rs - SQLite run history
use crate::secrets::SecretStore; // secrets.rs - sealed credential store

// ============================================================
// Shared daemon state
// ============================================================

/// On-disk path bundle resolved once at startup and stashed on
/// `DaemonState` so handlers don't have to re-derive defaults that
/// might disagree with `--state-dir` / `--db` / `--secrets` overrides.
///
/// `state_dir` is the cluster-state base (node.json, cluster/, raft/);
/// `runs_db` is the SQLite run-history file; `secrets_file` is the
/// sealed-credentials path; `config_yaml` is the path that
/// `Config::load`/`Config::save` use (defaults to ~/.sftpflow/config.yaml,
/// or `$SFTPFLOW_CONFIG`).
///
/// Used by the backup/restore module so it can produce a self-contained
/// archive of every node-local file.
#[derive(Clone)]
pub struct DaemonPaths {
    pub state_dir:    PathBuf,
    pub runs_db:      PathBuf,
    /// SQLite mutation-audit log. Co-located with `runs_db` under
    /// the state dir by default. Backup includes it; restore
    /// brings it back.
    pub audit_db:     PathBuf,
    pub secrets_file: PathBuf,
    pub config_yaml:  PathBuf,
}

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
    /// SQLite audit log. None if DB failed to open — mutations
    /// still apply, just not recorded. Best-effort by design.
    pub audit_db: Option<AuditDb>,
    /// Sealed credential store. None if no passphrase was configured
    /// at startup — secret RPCs then fail with CONFIG_ERROR and feeds
    /// that use `*_ref` fields will fail to resolve at run time.
    pub secrets: Option<SecretStore>,
    /// Live Raft handle + cluster identity bundle. `None` in
    /// legacy single-node mode (which M13 removes). When `Some`,
    /// mutating RPCs are gated on `is_leader()` — followers reply
    /// with NOT_LEADER instead of mutating local state — and the
    /// new `cluster_*` RPCs use the bundled `cluster_id`,
    /// `self_id`, and (on the bootstrap node) `token_secret`.
    pub cluster: Option<ClusterContext>,
    /// Resolved on-disk paths the backup handler reads from. Cloned
    /// each time so the handler doesn't have to hold the daemon
    /// mutex during the (potentially seconds-long) tar+gz pass.
    pub paths: DaemonPaths,
}

// ============================================================
// Entry point - parse address, pick listener, serve
// ============================================================

/// Build a fresh `SharedDaemonState`. Exposed so the daemon's
/// startup paths can stash a clone of the Arc into the cluster
/// forward handler *before* handing the same Arc to `run`.
pub fn build_shared_state(
    config:   Config,
    run_db:   Option<RunDb>,
    audit_db: Option<AuditDb>,
    secrets:  Option<SecretStore>,
    cluster:  Option<ClusterContext>,
    paths:    DaemonPaths,
) -> SharedDaemonState {
    let dkron_url = config.server.dkron_url.clone();
    Arc::new(Mutex::new(DaemonState {
        config,
        started: Instant::now(),
        dkron_url,
        run_db,
        audit_db,
        secrets,
        cluster,
        paths,
    }))
}

/// Parse `addr` ("unix:/path", "tcp:host:port", or "host:port") and
/// run the appropriate accept loop until the listener errors out.
///
/// Takes a pre-built `SharedDaemonState` so the daemon can wire up
/// the cluster forward handler against the same Arc before serving
/// begins. Use `build_shared_state` to construct one.
pub fn run(
    addr:  &str,
    state: SharedDaemonState,
) -> std::io::Result<()> {
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

fn serve_tcp(addr: &str, state: SharedDaemonState) -> std::io::Result<()> {
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

fn handle_tcp(stream: TcpStream, state: SharedDaemonState) -> std::io::Result<()> {
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
fn serve_unix(path: &str, state: SharedDaemonState) -> std::io::Result<()> {
    // Best-effort cleanup of a stale socket file from a previous run.
    // If we can't remove it, the bind() below will surface the error.
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path)?;
    info!("unix listener bound to {}", path);

    // The socket inherits the process umask, which on most Linux
    // distros is 0022 — leaving the socket world-readable and
    // sometimes world-writable. Tighten to 0660 so only the daemon
    // user and its group can speak NDJSON to us; operators on a
    // shared host should run sftpflow under a dedicated group.
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o660),
        ) {
            warn!("could not chmod 0660 on '{}': {}", path, e);
        }
    }

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
fn handle_unix(stream: UnixStream, state: SharedDaemonState) -> std::io::Result<()> {
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
    state: SharedDaemonState,
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
// Two entry points:
//
//   `dispatch`        - public, used by NDJSON connection threads.
//                       For mutating RPCs in cluster mode it tries
//                       to forward to the current leader first;
//                       falls back to local handling if we ARE the
//                       leader, if no cluster is configured, or if
//                       the request is read-only.
//
//   `dispatch_local`  - public, used by the cluster gRPC forward
//                       handler. Same body as `dispatch` minus the
//                       forwarding hook. Called when this node has
//                       received a forwarded envelope from a peer
//                       follower; further forwarding would loop.
//
// Mutating RPCs in `dispatch_local` still pass through
// `enforce_leader` so a stale follower (one that demoted between
// receiving a forward and processing it) returns NOT_LEADER cleanly
// instead of writing local state.

pub fn dispatch(env: RequestEnvelope, state: &SharedDaemonState) -> ResponseEnvelope {
    let id = env.id;
    debug!("dispatch id={} request={:?}", id, env.request);

    // Cluster forwarding: for mutating RPCs in cluster mode, ship
    // the whole envelope to the current leader. Follower → leader
    // routing is invisible to the CLI: it gets the same response
    // the leader produced, with the original request id preserved.
    if is_mutating(&env.request) {
        if let Some(rsp) = forward_if_follower(&env, state) {
            return rsp;
        }
    }

    dispatch_local(env, state)
}

pub fn dispatch_local(env: RequestEnvelope, state: &SharedDaemonState) -> ResponseEnvelope {
    // Snapshot the bits the audit hook needs BEFORE we move `env`
    // into the match. We only clone the request when the RPC is
    // mutating — read-only paths skip the clone entirely. Dry-run
    // previews of mutating RPCs are still audited (the operator
    // still ran a destructive-shaped command), but with a
    // `dry-run:` outcome prefix so they're trivially filterable.
    let mutating         = is_mutating(&env.request);
    let caller_for_audit = if mutating { env.caller.clone() } else { None };
    let request_for_audit = if mutating { Some(env.request.clone()) } else { None };
    let dry_run_for_audit = env.dry_run;

    // Reject `dry_run=true` on RPCs that don't have a preview path.
    // The CLI's destructive-command sites are the only callers that
    // set this flag, so reaching this guard means either an old CLI
    // talking to a new daemon (no chance — old CLIs never set the
    // bit) or a hand-crafted envelope. Either way, fail loud rather
    // than silently letting a real mutation slip through under a
    // preview-shaped command.
    if env.dry_run && !supports_dry_run(&env.request) {
        let response = ResponseEnvelope::failure(
            env.id,
            error_code::INVALID_PARAMS,
            format!(
                "dry_run is not supported for `{}` — only delete/rename of \
                 endpoints/keys/feeds, delete_secret, and cluster_remove_node \
                 honor the flag",
                method_name(&env.request),
            ),
        );
        if let Some(req) = request_for_audit {
            record_audit(state, caller_for_audit.as_deref(),
                         &req, &response, dry_run_for_audit);
        }
        return response;
    }

    let response = dispatch_local_inner(env, state);

    if let Some(req) = request_for_audit {
        record_audit(state, caller_for_audit.as_deref(),
                     &req, &response, dry_run_for_audit);
    }

    response
}

fn dispatch_local_inner(env: RequestEnvelope, state: &SharedDaemonState) -> ResponseEnvelope {
    let id      = env.id;
    let dry_run = env.dry_run;

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
            if dry_run {
                result_to_envelope(id, handlers::delete_endpoint_dry_run(&guard, &name))
            } else {
                result_to_envelope(id, handlers::delete_endpoint(&mut guard, &name))
            }
        }
        Request::RenameEndpoint { from, to } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            if dry_run {
                result_to_envelope(id, handlers::rename_endpoint_dry_run(&guard, &from, &to))
            } else {
                result_to_envelope(id, handlers::rename_endpoint(&mut guard, from, to))
            }
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
            if dry_run {
                result_to_envelope(id, handlers::delete_key_dry_run(&guard, &name))
            } else {
                result_to_envelope(id, handlers::delete_key(&mut guard, &name))
            }
        }
        Request::RenameKey { from, to } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            if dry_run {
                result_to_envelope(id, handlers::rename_key_dry_run(&guard, &from, &to))
            } else {
                result_to_envelope(id, handlers::rename_key(&mut guard, from, to))
            }
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
            if dry_run {
                result_to_envelope(id, handlers::delete_feed_dry_run(&guard, &name))
            } else {
                result_to_envelope(id, handlers::delete_feed(&mut guard, &name))
            }
        }
        Request::RenameFeed { from, to } => {
            let mut guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            if dry_run {
                result_to_envelope(id, handlers::rename_feed_dry_run(&guard, &from, &to))
            } else {
                result_to_envelope(id, handlers::rename_feed(&mut guard, from, to))
            }
        }

        // ---- execution ----
        // Leader-gated: we don't want N replicas of the same feed
        // running on N nodes. M14 routes RunFeedNow through the
        // Raft leader (which then dispatches to a chosen member);
        // M12 just refuses on followers.
        Request::RunFeedNow { name } => {
            // Three-phase run so the daemon mutex isn't held during
            // the transfer (which can take seconds to minutes and
            // would otherwise serialize every other RPC).
            //
            //   1. Lock briefly: enforce leader, snapshot config,
            //      resolve sealed-secret refs.
            //   2. Drop lock: run the SFTP/FTP/HTTP transfer.
            //   3. Re-lock briefly: record the run in SQLite.
            let prep = {
                let guard = state.lock().unwrap();
                if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
                // prepare_run_feed() in handlers.rs
                match handlers::prepare_run_feed(&guard, &name) {
                    Ok(p)  => p,
                    Err(e) => return result_to_envelope(id, Err(e)),
                }
            };

            // execute_run_feed() in handlers.rs - no daemon lock held here
            let (result, duration, started_at, feed_name) =
                handlers::execute_run_feed(prep);

            // record_run_history() in handlers.rs
            {
                let guard = state.lock().unwrap();
                handlers::record_run_history(
                    &guard, &feed_name, &started_at, duration, &result,
                );
            }

            ResponseEnvelope::success(id, Response::RunResult(result))
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

        // ---- audit log (read-only) ----
        Request::GetAuditLog { limit, since_unix } => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::get_audit_log(&guard, limit, since_unix))
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
            if dry_run {
                result_to_envelope(id, handlers::delete_secret_dry_run(&guard, &name))
            } else {
                result_to_envelope(id, handlers::delete_secret(&mut guard, &name))
            }
        }
        Request::ListSecrets => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::list_secrets(&guard))
        }

        // ---- cluster (read) ----
        // Read-only: any node answers. The CLI uses this from
        // followers to figure out who the leader is and where to
        // redirect mutating RPCs.
        Request::ClusterStatus => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::cluster_status(&guard))
        }

        // ---- cluster (mint token) ----
        // Token minting is bootstrap-node-only in M12, not
        // leader-only. The handler itself returns CONFIG_ERROR if
        // this node doesn't hold the secret; we don't gate here
        // because a follower bootstrap node should still be able
        // to mint (the seed-side BootstrapServiceImpl validates
        // and adds learners regardless of leader status).
        Request::ClusterMintToken { ttl_seconds } => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::cluster_mint_token(&guard, ttl_seconds))
        }

        // ---- cluster (mutate membership) ----
        // Leader-gated. change_membership goes through the Raft
        // log; followers can't apply it. Fail fast with NOT_LEADER
        // so the CLI's error tells the operator where to retry.
        Request::ClusterRemoveNode { node_id } => {
            let guard = state.lock().unwrap();
            if let Some(rsp) = enforce_leader(id, &guard) { return rsp; }
            if dry_run {
                result_to_envelope(id, handlers::cluster_remove_node_dry_run(&guard, node_id))
            } else {
                result_to_envelope(id, handlers::cluster_remove_node(&guard, node_id))
            }
        }

        // ---- cluster (self-leave) ----
        // Intentionally NOT leader-gated and NOT in `is_mutating()`:
        // the receiver IS the leaver, and it picks the right path
        // internally (direct change_membership if leader, otherwise
        // forward a ClusterRemoveNode for its own id to the current
        // leader). Auto-forwarding ClusterLeave would land on the
        // leader, which would then try to remove itself by mistake.
        Request::ClusterLeave => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::cluster_leave(&guard))
        }

        // ---- cluster (read CA cert) ----
        // Read-only: any cluster member serves the same CA cert
        // (it's the trust anchor every node persisted at init/join
        // time). Public material; no leader gate.
        Request::ClusterGetCa => {
            let guard = state.lock().unwrap();
            result_to_envelope(id, handlers::cluster_get_ca(&guard))
        }

        // ---- cluster (hot backup) ----
        // Acquires the daemon mutex briefly to clone `paths`, then
        // releases it BEFORE the tar+gz pass — backup is I/O bound
        // and takes seconds, so holding the lock would freeze every
        // other NDJSON connection on this node. Not leader-gated:
        // every node backs up its own per-node state, so the operator
        // can take a backup from any reachable member.
        Request::ClusterBackup { out_path } => {
            let paths = {
                let guard = state.lock().unwrap();
                guard.paths.clone()
            };
            result_to_envelope(id, handlers::cluster_backup(paths, &out_path))
        }
    }
}

// ============================================================
// is_mutating - which RPCs need to land on the leader
// ============================================================

/// Returns true for any RPC whose handling either writes config
/// state, mutates the sealed store, dispatches a feed transfer, or
/// changes Raft membership. These are the requests we forward to
/// the current leader from a follower. Read-only RPCs return false
/// and are always served locally.
fn is_mutating(req: &Request) -> bool {
    matches!(req,
        Request::PutEndpoint    { .. }
      | Request::DeleteEndpoint { .. }
      | Request::RenameEndpoint { .. }
      | Request::PutKey         { .. }
      | Request::DeleteKey      { .. }
      | Request::RenameKey      { .. }
      | Request::PutFeed        { .. }
      | Request::DeleteFeed     { .. }
      | Request::RenameFeed     { .. }
      | Request::RunFeedNow     { .. }
      | Request::SyncSchedules
      | Request::PutSecret      { .. }
      | Request::DeleteSecret   { .. }
      | Request::ClusterRemoveNode { .. }
    )
}

/// Allowlist of RPCs that honor the envelope's `dry_run` flag.
/// Anything else paired with `dry_run=true` is rejected with
/// INVALID_PARAMS in `dispatch_local` so a destructive command
/// can never silently land as a real mutation.
fn supports_dry_run(req: &Request) -> bool {
    matches!(req,
        Request::DeleteEndpoint    { .. }
      | Request::RenameEndpoint    { .. }
      | Request::DeleteKey         { .. }
      | Request::RenameKey         { .. }
      | Request::DeleteFeed        { .. }
      | Request::RenameFeed        { .. }
      | Request::DeleteSecret      { .. }
      | Request::ClusterRemoveNode { .. }
    )
}

// ============================================================
// forward_if_follower - cluster-mode forwarding gate
// ============================================================
//
// Snapshots just the bits we need under the daemon-state mutex,
// then drops the lock BEFORE doing any network I/O. Holding the
// state mutex across a gRPC round-trip would block every other
// NDJSON connection on this node for the duration of the forward
// (~tens of ms in the happy case, longer on a stale leader).
//
// Returns:
//   - `None`               -> we are the leader (or single-node);
//                             caller should dispatch locally.
//   - `Some(envelope)`     -> we are a follower; the envelope is
//                             either the leader's response or a
//                             synthesized error if forwarding
//                             couldn't complete.

fn forward_if_follower(
    env:   &RequestEnvelope,
    state: &SharedDaemonState,
) -> Option<ResponseEnvelope> {
    // ---- 1. Snapshot under the lock --------------------------
    // Capture is_leader + the bits we need to do the forward call,
    // then release the mutex so the network round-trip doesn't
    // serialize all other connections behind us.
    let snapshot: Option<(u64, String)> = {
        let guard = state.lock().unwrap();
        let cluster = guard.cluster.as_ref()?;
        if cluster.is_leader() {
            return None;
        }
        let leader_id = cluster.current_leader();
        let leader_addr = leader_id.and_then(|id|
            cluster.members().get(&id).map(|m| m.advertise_addr.clone())
        );
        match (leader_id, leader_addr) {
            (Some(lid), Some(addr)) => Some((lid, addr)),
            _ => None,
        }
    };

    let (leader_id, leader_addr) = match snapshot {
        Some(s) => s,
        None => {
            return Some(ResponseEnvelope::failure_with(
                env.id,
                sftpflow_proto::ProtoError::with_hint(
                    error_code::NOT_LEADER,
                    "this node is not the cluster leader, and no current leader is known \
                     (election in progress or quorum unavailable)",
                    "retry the command in a few seconds; if it persists, run 'cluster status' \
                     to see which voters are reachable",
                ),
            ));
        }
    };

    // ---- 2. Serialize the envelope ---------------------------
    let envelope_bytes = match serde_json::to_vec(env) {
        Ok(b) => b,
        Err(e) => {
            return Some(ResponseEnvelope::failure(
                env.id,
                error_code::INTERNAL_ERROR,
                format!("could not serialize request envelope for forwarding: {}", e),
            ));
        }
    };

    // ---- 3. Forward over the cluster gRPC channel ------------
    // Re-acquire just long enough to grab the forwarder; the
    // forward itself is async and blocks on the cluster runtime.
    let forwarder = {
        let guard = state.lock().unwrap();
        // Cluster could (in theory) have been torn down between
        // the snapshot and now. Fail loud if so.
        match guard.cluster.as_ref() {
            Some(c) => ForwarderHandle {
                runtime:       c.runtime.clone(),
                leaf_cert_pem: c.leaf_cert_pem.clone(),
                leaf_key_pem:  c.leaf_key_pem.clone(),
                ca_cert_pem:   c.ca_cert_pem.clone(),
            },
            None => {
                return Some(ResponseEnvelope::failure(
                    env.id,
                    error_code::INTERNAL_ERROR,
                    "cluster context disappeared between leader-check and forward".to_string(),
                ));
            }
        }
    };

    info!(
        "forwarding id={} method={} to leader node_id={} at {}",
        env.id,
        method_name(&env.request),
        leader_id,
        leader_addr,
    );

    let response_bytes = forwarder.forward_blocking(&leader_addr, envelope_bytes);

    let response_bytes = match response_bytes {
        Ok(b)  => b,
        Err(e) => {
            warn!(
                "forwarding id={} to leader node_id={} at {} failed: {}",
                env.id, leader_id, leader_addr, e,
            );
            return Some(ResponseEnvelope::failure_with(
                env.id,
                sftpflow_proto::ProtoError::with_hint(
                    error_code::NOT_LEADER,
                    format!(
                        "this node is not the cluster leader; failed to forward to current \
                         leader (node_id={}) at {}: {}",
                        leader_id, leader_addr, e,
                    ),
                    format!(
                        "verify network reachability to {} (the leader's advertise address); \
                         retry, or connect directly to the leader and re-run the command",
                        leader_addr,
                    ),
                ),
            ));
        }
    };

    // ---- 4. Deserialize the leader's response envelope -------
    match serde_json::from_slice::<ResponseEnvelope>(&response_bytes) {
        Ok(env) => Some(env),
        Err(e)  => Some(ResponseEnvelope::failure(
            env.id,
            error_code::INTERNAL_ERROR,
            format!("malformed response envelope from leader: {}", e),
        )),
    }
}

/// Snapshot of the cluster forward bits we need, held outside the
/// state mutex so the gRPC call doesn't block other NDJSON conns.
struct ForwarderHandle {
    runtime:       tokio::runtime::Handle,
    leaf_cert_pem: String,
    leaf_key_pem:  String,
    ca_cert_pem:   String,
}

impl ForwarderHandle {
    fn forward_blocking(
        &self,
        leader_addr:   &str,
        envelope_json: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let leaf_cert = self.leaf_cert_pem.clone();
        let leaf_key  = self.leaf_key_pem.clone();
        let ca_cert   = self.ca_cert_pem.clone();
        let addr      = leader_addr.to_string();
        self.runtime.block_on(async move {
            sftpflow_cluster::transport::forward_envelope_to_peer(
                &addr,
                &leaf_cert,
                &leaf_key,
                &ca_cert,
                envelope_json,
            ).await
        })
    }
}

/// Tiny diagnostic helper: pull a short method-name string out of
/// a Request for log lines. Avoids dumping the full Debug repr.
fn method_name(req: &Request) -> &'static str {
    match req {
        Request::Ping                       => "ping",
        Request::GetServerInfo              => "get_server_info",
        Request::ListEndpoints              => "list_endpoints",
        Request::GetEndpoint    { .. }      => "get_endpoint",
        Request::PutEndpoint    { .. }      => "put_endpoint",
        Request::DeleteEndpoint { .. }      => "delete_endpoint",
        Request::RenameEndpoint { .. }      => "rename_endpoint",
        Request::ListKeys                   => "list_keys",
        Request::GetKey         { .. }      => "get_key",
        Request::PutKey         { .. }      => "put_key",
        Request::DeleteKey      { .. }      => "delete_key",
        Request::RenameKey      { .. }      => "rename_key",
        Request::ListFeeds                  => "list_feeds",
        Request::GetFeed        { .. }      => "get_feed",
        Request::PutFeed        { .. }      => "put_feed",
        Request::DeleteFeed     { .. }      => "delete_feed",
        Request::RenameFeed     { .. }      => "rename_feed",
        Request::RunFeedNow     { .. }      => "run_feed_now",
        Request::SyncSchedules              => "sync_schedules",
        Request::GetRunHistory  { .. }      => "get_run_history",
        Request::GetAuditLog    { .. }      => "get_audit_log",
        Request::PutSecret      { .. }      => "put_secret",
        Request::DeleteSecret   { .. }      => "delete_secret",
        Request::ListSecrets                => "list_secrets",
        Request::ClusterStatus              => "cluster_status",
        Request::ClusterMintToken { .. }    => "cluster_mint_token",
        Request::ClusterRemoveNode { .. }   => "cluster_remove_node",
        Request::ClusterLeave               => "cluster_leave",
        Request::ClusterGetCa               => "cluster_get_ca",
        Request::ClusterBackup  { .. }      => "cluster_backup",
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

    let err = match leader_advertise {
        Some(addr) => sftpflow_proto::ProtoError::with_hint(
            error_code::NOT_LEADER,
            format!(
                "this node is not the cluster leader; current leader is reachable at {}",
                addr,
            ),
            format!(
                "the CLI normally auto-forwards mutating RPCs to the leader \
                 (newer CLIs only); to retry by hand, connect to {}",
                addr,
            ),
        ),
        None => sftpflow_proto::ProtoError::with_hint(
            error_code::NOT_LEADER,
            "this node is not the cluster leader; election in progress or quorum unavailable",
            "retry shortly; run 'cluster status' to confirm a leader has been elected",
        ),
    };
    Some(ResponseEnvelope::failure_with(id, err))
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

// ============================================================
// record_audit - one-shot writer for the SQLite audit log
// ============================================================
//
// Called from `dispatch_local` after every mutating RPC (success
// AND failure). The hook deliberately runs OUTSIDE the request
// dispatch arm so a single point covers all variants — adding a
// new mutating RPC variant only requires marking it in
// `is_mutating()` for the audit trail to pick it up.
//
// We brief-lock the daemon state to grab the AuditDb handle and
// drop the lock before the actual SQLite INSERT. Audit failures
// are logged but never propagated; the audit table is a reporting
// surface, not part of any consistency guarantee.

fn record_audit(
    state:    &SharedDaemonState,
    caller:   Option<&str>,
    request:  &Request,
    response: &ResponseEnvelope,
    dry_run:  bool,
) {
    // Grab a thread-local handle by cloning under the lock. Brief
    // critical section: the actual INSERT happens unlocked. We
    // can't share an AuditDb across threads behind a guard cheaply
    // (rusqlite::Connection is !Sync), so we just take the lock
    // for the whole INSERT. WAL mode keeps reads from blocking.
    //
    // Dry-runs get a `dry-run:` prefix on the outcome so live and
    // preview rows are trivially filterable in `show audit`. The
    // payload-shape (caller / rpc / args_hash) stays identical to
    // the live row so the operator can see "the same person
    // previewed and then ran this delete" by eyeballing two
    // adjacent rows.
    let live_outcome = match &response.outcome {
        sftpflow_proto::ResponseOutcome::Success { .. } => "ok".to_string(),
        sftpflow_proto::ResponseOutcome::Failure { error } => format!("err:{}", error.code),
    };
    let outcome = if dry_run {
        format!("dry-run:{}", live_outcome)
    } else {
        live_outcome
    };
    let rpc       = method_name(request);
    let args_hash = audit::args_hash(request);
    let (ts_unix, ts_iso) = audit::now_unix_and_iso();

    let guard = match state.lock() {
        Ok(g)  => g,
        Err(_) => return, // poisoned mutex; daemon is going down anyway
    };
    if let Some(ref db) = guard.audit_db {
        db.record(ts_unix, &ts_iso, caller, rpc, &args_hash, &outcome);
    }
}
