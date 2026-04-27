// ============================================================
// sftpflowd::handlers - RPC method implementations
// ============================================================
//
// One function per RPC method, split roughly by domain:
//   - server-info / ping
//   - endpoints (list, get, put, delete, rename)
//   - keys     (list, get, put, delete, rename)
//   - feeds    (list, get, put, delete, rename, run_now)
//
// Each mutating handler:
//   1. Validates preconditions (existence, name collision)
//   2. Applies the mutation to the in-memory Config
//   3. Sweeps cross-references (for renames)
//   4. Persists the Config to YAML
//   5. Logs what changed (every file-modifying path is logged)
//
// Handlers return `Result<Response, ProtoError>`. server.rs wraps
// that into a ResponseEnvelope.

use std::collections::BTreeMap;
use std::time::{Instant, SystemTime};

use log::{error, info, warn};

use sftpflow_core::{Config, Endpoint, NextStepAction, PgpKey, ProcessStep};
use sftpflow_proto::{
    error_code,
    ClusterMemberInfo,
    ClusterStatus,
    ClusterToken,
    FeedSummary,
    ProtoError,
    Response,
    ServerInfo,
    SyncReport,
};

use crate::dkron::DkronClient; // dkron.rs
use crate::secrets::SecretStore; // secrets.rs
use crate::server::DaemonState;

// ============================================================
// Helpers
// ============================================================

/// Persist the current config and wrap any save error as a CONFIG_ERROR
/// protocol error. All mutating handlers funnel through this.
fn save(config: &Config) -> Result<(), ProtoError> {
    config.save().map_err(|e| ProtoError {
        code: error_code::CONFIG_ERROR,
        message: format!("could not save config: {}", e),
    })
}

fn not_found(kind: &str, name: &str) -> ProtoError {
    ProtoError {
        code: error_code::NOT_FOUND,
        message: format!("{} '{}' does not exist", kind, name),
    }
}

fn already_exists(kind: &str, name: &str) -> ProtoError {
    ProtoError {
        code: error_code::ALREADY_EXISTS,
        message: format!("{} '{}' already exists", kind, name),
    }
}

/// Best-effort hostname for `ServerInfo`. Used in the non-mutating
/// path so we don't need to plumb this anywhere else.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ============================================================
// Server info / ping
// ============================================================

pub fn ping() -> Response {
    Response::Pong
}

pub fn get_server_info(started: Instant) -> Response {
    Response::ServerInfo(ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        hostname: hostname(),
        uptime_seconds: started.elapsed().as_secs(),
    })
}

// ============================================================
// Endpoints
// ============================================================

pub fn list_endpoints(state: &DaemonState) -> Response {
    Response::Names(state.config.endpoints.keys().cloned().collect())
}

pub fn get_endpoint(state: &DaemonState, name: &str) -> Response {
    Response::Endpoint(state.config.endpoints.get(name).cloned())
}

/// Upsert: create or replace. No collision check — `Put` is idempotent
/// from the caller's perspective.
pub fn put_endpoint(
    state: &mut DaemonState,
    name: String,
    endpoint: Endpoint,
) -> Result<Response, ProtoError> {
    let existed = state.config.endpoints.contains_key(&name);
    state.config.endpoints.insert(name.clone(), endpoint);
    save(&state.config)?;
    info!(
        "put endpoint '{}' ({})",
        name,
        if existed { "updated" } else { "created" }
    );
    Ok(Response::Ok)
}

pub fn delete_endpoint(
    state: &mut DaemonState,
    name: &str,
) -> Result<Response, ProtoError> {
    if state.config.endpoints.remove(name).is_none() {
        return Err(not_found("endpoint", name));
    }
    save(&state.config)?;
    info!("deleted endpoint '{}'", name);
    Ok(Response::Ok)
}

/// Rename an endpoint and sweep source/destination references in
/// every feed so paths like `<old>:/...` become `<new>:/...`.
pub fn rename_endpoint(
    state: &mut DaemonState,
    from: String,
    to: String,
) -> Result<Response, ProtoError> {
    if !state.config.endpoints.contains_key(&from) {
        return Err(not_found("endpoint", &from));
    }
    if state.config.endpoints.contains_key(&to) {
        return Err(already_exists("endpoint", &to));
    }

    let endpoint = state.config.endpoints.remove(&from).unwrap();
    state.config.endpoints.insert(to.clone(), endpoint);

    let mut ref_count = 0usize;
    for (_feed_name, feed) in state.config.feeds.iter_mut() {
        for src in feed.sources.iter_mut() {
            if src.endpoint == from {
                src.endpoint = to.clone();
                ref_count += 1;
            }
        }
        for dst in feed.destinations.iter_mut() {
            if dst.endpoint == from {
                dst.endpoint = to.clone();
                ref_count += 1;
            }
        }
    }

    save(&state.config)?;
    info!(
        "renamed endpoint '{}' -> '{}', updated {} feed reference(s)",
        from, to, ref_count
    );
    Ok(Response::Ok)
}

// ============================================================
// PGP keys
// ============================================================

pub fn list_keys(state: &DaemonState) -> Response {
    Response::Names(state.config.keys.keys().cloned().collect())
}

pub fn get_key(state: &DaemonState, name: &str) -> Response {
    Response::Key(state.config.keys.get(name).cloned())
}

pub fn put_key(
    state: &mut DaemonState,
    name: String,
    key: PgpKey,
) -> Result<Response, ProtoError> {
    let existed = state.config.keys.contains_key(&name);
    state.config.keys.insert(name.clone(), key);
    save(&state.config)?;
    info!(
        "put key '{}' ({})",
        name,
        if existed { "updated" } else { "created" }
    );
    Ok(Response::Ok)
}

pub fn delete_key(
    state: &mut DaemonState,
    name: &str,
) -> Result<Response, ProtoError> {
    if state.config.keys.remove(name).is_none() {
        return Err(not_found("key", name));
    }
    save(&state.config)?;
    info!("deleted key '{}'", name);
    Ok(Response::Ok)
}

/// Rename a key and sweep process-step references in every feed.
pub fn rename_key(
    state: &mut DaemonState,
    from: String,
    to: String,
) -> Result<Response, ProtoError> {
    if !state.config.keys.contains_key(&from) {
        return Err(not_found("key", &from));
    }
    if state.config.keys.contains_key(&to) {
        return Err(already_exists("key", &to));
    }

    let key = state.config.keys.remove(&from).unwrap();
    state.config.keys.insert(to.clone(), key);

    let mut ref_count = 0usize;
    for (_feed_name, feed) in state.config.feeds.iter_mut() {
        for step in feed.process.iter_mut() {
            match step {
                ProcessStep::Encrypt { key } | ProcessStep::Decrypt { key } => {
                    if *key == from {
                        *key = to.clone();
                        ref_count += 1;
                    }
                }
            }
        }
    }

    save(&state.config)?;
    info!(
        "renamed key '{}' -> '{}', updated {} process reference(s)",
        from, to, ref_count
    );
    Ok(Response::Ok)
}

// ============================================================
// Scheduler sync (best-effort after feed mutations)
// ============================================================

/// If a dkron_url is configured, sync a single feed's schedules
/// to dkron. Logs warnings on failure but never propagates errors.
fn maybe_sync_feed(state: &DaemonState, feed_name: &str) {
    if let Some(ref dkron_url) = state.dkron_url {
        let client = DkronClient::new(dkron_url); // dkron.rs
        if let Some(feed) = state.config.feeds.get(feed_name) {
            client.sync_feed(feed_name, feed);
        }
    }
}

/// If a dkron_url is configured, delete all dkron jobs for a feed.
fn maybe_delete_feed_jobs(state: &DaemonState, feed_name: &str) {
    if let Some(ref dkron_url) = state.dkron_url {
        let client = DkronClient::new(dkron_url); // dkron.rs
        if let Err(e) = client.delete_feed_jobs(feed_name) {
            warn!("dkron: failed to delete jobs for '{}': {}", feed_name, e);
        } else {
            info!("dkron: deleted jobs for '{}'", feed_name);
        }
    }
}

// ============================================================
// Feeds
// ============================================================

pub fn list_feeds(state: &DaemonState) -> Response {
    let summaries: Vec<FeedSummary> = state
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
    Response::FeedSummaries(summaries)
}

pub fn get_feed(state: &DaemonState, name: &str) -> Response {
    Response::Feed(state.config.feeds.get(name).cloned())
}

pub fn put_feed(
    state: &mut DaemonState,
    name: String,
    feed: sftpflow_core::Feed,
) -> Result<Response, ProtoError> {
    let existed = state.config.feeds.contains_key(&name);
    state.config.feeds.insert(name.clone(), feed);
    save(&state.config)?;
    info!(
        "put feed '{}' ({})",
        name,
        if existed { "updated" } else { "created" }
    );
    maybe_sync_feed(state, &name);
    Ok(Response::Ok)
}

pub fn delete_feed(
    state: &mut DaemonState,
    name: &str,
) -> Result<Response, ProtoError> {
    if state.config.feeds.remove(name).is_none() {
        return Err(not_found("feed", name));
    }
    save(&state.config)?;
    info!("deleted feed '{}'", name);
    maybe_delete_feed_jobs(state, name);
    Ok(Response::Ok)
}

/// Rename a feed and sweep nextstep references (RunFeed actions) in
/// every other feed.
pub fn rename_feed(
    state: &mut DaemonState,
    from: String,
    to: String,
) -> Result<Response, ProtoError> {
    if !state.config.feeds.contains_key(&from) {
        return Err(not_found("feed", &from));
    }
    if state.config.feeds.contains_key(&to) {
        return Err(already_exists("feed", &to));
    }

    let feed = state.config.feeds.remove(&from).unwrap();
    state.config.feeds.insert(to.clone(), feed);

    let mut ref_count = 0usize;
    for (_name, f) in state.config.feeds.iter_mut() {
        for ns in f.nextsteps.iter_mut() {
            match &mut ns.action {
                NextStepAction::RunFeed { feed } => {
                    if *feed == from {
                        *feed = to.clone();
                        ref_count += 1;
                    }
                }
                NextStepAction::SendEmail { .. } | NextStepAction::Sleep { .. } => {}
            }
        }
    }

    save(&state.config)?;
    info!(
        "renamed feed '{}' -> '{}', updated {} nextstep reference(s)",
        from, to, ref_count
    );
    maybe_delete_feed_jobs(state, &from);
    maybe_sync_feed(state, &to);
    Ok(Response::Ok)
}

/// Execute a feed: download from sources, upload to destinations,
/// optionally delete source files afterward. Records the run in
/// the SQLite history database.
///
/// Creates a short-lived tokio runtime to bridge into the async
/// transport layer (russh/russh-sftp). The runtime is dropped
/// when this function returns.
pub fn run_feed_now(
    state: &DaemonState,
    name: &str,
) -> Result<Response, ProtoError> {
    let feed = state.config.feeds.get(name).ok_or_else(|| {
        not_found("feed", name)
    })?;

    info!("run_feed_now requested for '{}'", name);

    // Clone the data we need so we can release the DaemonState
    // lock before blocking on async I/O. Resolve any `*_ref` fields
    // against the sealed secret store so the transport layer only
    // ever sees plaintext values.
    let feed = feed.clone();
    let mut endpoints = state.config.endpoints.clone();
    let mut keys = state.config.keys.clone();

    // resolve_refs() - below
    if let Err(msg) = resolve_refs(&mut endpoints, &mut keys, state.secrets.as_ref()) {
        warn!("run_feed_now '{}': secret resolution failed: {}", name, msg);
        return Err(ProtoError {
            code: error_code::CONFIG_ERROR,
            message: msg,
        });
    }

    let feed_name = name.to_string();

    // Capture the start time for history recording.
    let started_at = iso8601_now();
    let timer = Instant::now();

    // Build a single-threaded tokio runtime for the transfer.
    // The daemon is thread-per-connection, so each RunFeedNow
    // gets its own runtime. This keeps the sync↔async boundary
    // clean and self-contained.
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        error!("run_feed_now '{}': failed to create tokio runtime: {}", feed_name, e);
        ProtoError {
            code: error_code::INTERNAL_ERROR,
            message: format!("failed to create async runtime: {}", e),
        }
    })?;

    // run_feed() in sftpflow-transport (lib.rs)
    let result = rt.block_on(sftpflow_transport::run_feed(
        &feed_name,
        &feed,
        &endpoints,
        &keys,
    ));

    let duration = timer.elapsed();

    info!(
        "run_feed_now '{}': completed — status={:?}, files={}, duration={:.1}s",
        feed_name, result.status, result.files_transferred, duration.as_secs_f64()
    );

    // Record the run in SQLite (best-effort).
    if let Some(ref db) = state.run_db {
        db.record_run(&feed_name, &started_at, duration, &result);
    }

    Ok(Response::RunResult(result))
}

/// Format the current wall-clock time as ISO 8601 UTC.
fn iso8601_now() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Manual UTC formatting to avoid pulling in chrono.
    // Good enough for logging — not for leap-second correctness.
    let days_since_epoch = secs / 86400;
    let time_of_day      = secs % 86400;
    let hours   = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since 1970-01-01 to Y-M-D using a civil calendar algorithm.
    let (y, m, d) = civil_from_days(days_since_epoch as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

/// Convert days since 1970-01-01 to (year, month, day).
/// Algorithm from Howard Hinnant's chrono-compatible date library.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y   = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let m   = if mp < 10 { mp + 3 } else { mp - 9 };
    let y   = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ============================================================
// Scheduler
// ============================================================

// ============================================================
// Sealed-secret ref resolution
// ============================================================
//
// Called before every feed execution. Rewrites each endpoint's
// `password` / `ssh_key` and each key's `contents` from the
// corresponding `*_ref` field, looking up the real value in the
// sealed store. If a ref is set and the secret is missing (or
// the store isn't open), fail loudly — the operator has asked
// for a secret we can't supply.
//
// Plaintext fields still work unchanged when no ref is present,
// so configs that predate milestone 11 keep running.

fn resolve_refs(
    endpoints: &mut BTreeMap<String, Endpoint>,
    keys: &mut BTreeMap<String, PgpKey>,
    secrets: Option<&SecretStore>,
) -> Result<(), String> {
    // Endpoints: password_ref → password, ssh_key_ref → ssh_key.
    for (ep_name, ep) in endpoints.iter_mut() {
        if let Some(ref_name) = ep.password_ref.clone() {
            let value = lookup_secret(secrets, &ref_name).map_err(|e| {
                format!("endpoint '{}' password_ref: {}", ep_name, e)
            })?;
            ep.password = Some(value);
        }
        if let Some(ref_name) = ep.ssh_key_ref.clone() {
            let value = lookup_secret(secrets, &ref_name).map_err(|e| {
                format!("endpoint '{}' ssh_key_ref: {}", ep_name, e)
            })?;
            ep.ssh_key = Some(value);
        }
    }

    // PGP keys: contents_ref → contents.
    for (key_name, key) in keys.iter_mut() {
        if let Some(ref_name) = key.contents_ref.clone() {
            let value = lookup_secret(secrets, &ref_name).map_err(|e| {
                format!("key '{}' contents_ref: {}", key_name, e)
            })?;
            key.contents = Some(value);
        }
    }

    Ok(())
}

/// Look up a secret by name in the sealed store. Returns a fresh
/// owned String so the caller can stash it back into config objects.
fn lookup_secret(
    secrets: Option<&SecretStore>,
    name: &str,
) -> Result<String, String> {
    let store = secrets.ok_or_else(|| {
        "sealed secrets store is not open — start sftpflowd with \
         --passphrase-file or SFTPFLOW_PASSPHRASE".to_string()
    })?;
    store
        .get(name)
        .map(|s| s.to_string())
        .ok_or_else(|| format!("secret '{}' not found in sealed store", name))
}

// ============================================================
// Sealed-secret handlers
// ============================================================

/// Require an open secret store; otherwise return CONFIG_ERROR.
fn require_secrets<'a>(state: &'a DaemonState) -> Result<&'a SecretStore, ProtoError> {
    state.secrets.as_ref().ok_or_else(|| ProtoError {
        code: error_code::CONFIG_ERROR,
        message: "sealed secrets store is not open — start sftpflowd with \
                  --passphrase-file or SFTPFLOW_PASSPHRASE"
            .to_string(),
    })
}

fn require_secrets_mut<'a>(state: &'a mut DaemonState) -> Result<&'a mut SecretStore, ProtoError> {
    state.secrets.as_mut().ok_or_else(|| ProtoError {
        code: error_code::CONFIG_ERROR,
        message: "sealed secrets store is not open — start sftpflowd with \
                  --passphrase-file or SFTPFLOW_PASSPHRASE"
            .to_string(),
    })
}

/// Upsert a sealed secret. `value` never touches disk in plaintext.
pub fn put_secret(
    state: &mut DaemonState,
    name: String,
    value: String,
) -> Result<Response, ProtoError> {
    let store = require_secrets_mut(state)?;
    store.put(name.clone(), value).map_err(|e| ProtoError {
        code: error_code::INTERNAL_ERROR,
        message: format!("could not persist secret '{}': {}", name, e),
    })?;
    Ok(Response::Ok)
}

/// Delete a sealed secret. Idempotent — not-found is not an error.
pub fn delete_secret(
    state: &mut DaemonState,
    name: &str,
) -> Result<Response, ProtoError> {
    let store = require_secrets_mut(state)?;
    store.delete(name).map_err(|e| ProtoError {
        code: error_code::INTERNAL_ERROR,
        message: format!("could not persist secret deletion '{}': {}", name, e),
    })?;
    Ok(Response::Ok)
}

/// List the *names* of every sealed secret. Values are never sent
/// back to the client.
pub fn list_secrets(state: &DaemonState) -> Result<Response, ProtoError> {
    let store = require_secrets(state)?;
    Ok(Response::Names(store.names()))
}

// ============================================================
// Run history
// ============================================================

/// Retrieve run history for a feed from SQLite.
pub fn get_run_history(
    state: &DaemonState,
    feed: &str,
    limit: Option<u32>,
) -> Result<Response, ProtoError> {
    let db = state.run_db.as_ref().ok_or_else(|| ProtoError {
        code: error_code::INTERNAL_ERROR,
        message: "run history database is not available".to_string(),
    })?;

    let entries = db.get_runs(feed, limit).map_err(|e| ProtoError {
        code: error_code::INTERNAL_ERROR,
        message: format!("failed to query run history: {}", e),
    })?;

    Ok(Response::RunHistory(entries))
}

// ============================================================
// Scheduler
// ============================================================

/// Full reconciliation of feed schedules ↔ dkron jobs.
/// Returns a SyncReport with counts. If no dkron_url is configured,
/// returns a report with all zeros and an informational error.
pub fn sync_schedules(state: &DaemonState) -> Response {
    match &state.dkron_url {
        Some(dkron_url) => {
            info!("sync_schedules: reconciling against {}", dkron_url);
            let client = DkronClient::new(dkron_url); // dkron.rs
            let report = client.reconcile_all(&state.config.feeds);
            Response::SyncReport(report)
        }
        None => {
            info!("sync_schedules: no dkron_url configured");
            Response::SyncReport(SyncReport {
                created: 0,
                updated: 0,
                deleted: 0,
                errors: vec!["no dkron_url configured; scheduler sync disabled".to_string()],
            })
        }
    }
}

// ============================================================
// Cluster RPCs (M12+)
// ============================================================

/// Helper: extract the ClusterContext from DaemonState or return a
/// CONFIG_ERROR. Used by every `cluster_*` handler — they only make
/// sense when this daemon is running as a Raft member.
fn require_cluster<'a>(
    state: &'a DaemonState,
) -> Result<&'a crate::cluster_runtime::ClusterContext, ProtoError> {
    state.cluster.as_ref().ok_or_else(|| ProtoError {
        code: error_code::CONFIG_ERROR,
        message: "this daemon is running in legacy single-node mode (no node.json) — \
                  cluster RPCs are only available on Raft members"
            .to_string(),
    })
}

/// `cluster status`: snapshot of leader, voters, learners.
/// Read-only, any node can answer.
pub fn cluster_status(state: &DaemonState) -> Result<Response, ProtoError> {
    let ctx = require_cluster(state)?;

    let mut members: Vec<ClusterMemberInfo> = ctx
        .members_with_voter_flag()
        .into_iter()
        .map(|(node_id, (member, is_voter))| ClusterMemberInfo {
            node_id,
            advertise_addr: member.advertise_addr,
            label:          member.label,
            is_voter,
        })
        .collect();
    // BTreeMap iteration is already sorted by key, but be explicit:
    // the wire contract promises ascending node_id so the CLI can
    // render deterministically.
    members.sort_by_key(|m| m.node_id);

    Ok(Response::ClusterStatus(ClusterStatus {
        cluster_id: ctx.cluster_id.clone(),
        self_id:    ctx.self_id,
        leader_id:  ctx.current_leader(),
        members,
    }))
}

/// `cluster token`: mint a new join token. Bootstrap-node only in M12;
/// joiners return CONFIG_ERROR with a clear redirect message.
pub fn cluster_mint_token(
    state:       &DaemonState,
    ttl_seconds: Option<u32>,
) -> Result<Response, ProtoError> {
    // Cap requested TTL at 1 hour to match the gRPC AdminService
    // default. Operators rarely need longer; if they do, they'll
    // mint a second one rather than us issuing long-lived tokens.
    const MAX_TTL: u32 = 3600;
    const DEFAULT_TTL: u32 = 3600;
    let ttl = ttl_seconds.unwrap_or(DEFAULT_TTL).min(MAX_TTL);

    let ctx = require_cluster(state)?;
    let (token, expires_at_unix) = ctx.mint_token(ttl).map_err(|msg| ProtoError {
        code: error_code::CONFIG_ERROR,
        message: msg,
    })?;
    info!(
        "cluster_mint_token: minted token (ttl={}s, expires_at_unix={})",
        ttl, expires_at_unix,
    );
    Ok(Response::ClusterToken(ClusterToken { token, expires_at_unix }))
}

/// `cluster remove <node_id>`: drop a node from the voter set.
/// Leader-only — the gate in dispatch ensures we only get here on
/// the leader, and the underlying `change_membership` would itself
/// reject on followers.
pub fn cluster_remove_node(
    state:   &DaemonState,
    node_id: u64,
) -> Result<Response, ProtoError> {
    let ctx = require_cluster(state)?;

    // Refuse to remove the responding node — there's no point in a
    // node voting itself out, and the operator almost certainly
    // meant a different ID. M13 will allow it once `cluster leave`
    // is wired (which gracefully steps down first).
    if node_id == ctx.self_id {
        return Err(ProtoError {
            code: error_code::CONFIG_ERROR,
            message: format!(
                "refusing to remove the responding node (node_id={}) from the voter set; \
                 use `cluster leave` (M13+) to drain this node, or run `cluster remove` \
                 against a different node",
                node_id,
            ),
        });
    }

    info!("cluster_remove_node: removing node_id={}", node_id);
    ctx.remove_node_blocking(node_id).map_err(|msg| ProtoError {
        code: error_code::CONFIG_ERROR,
        message: msg,
    })?;
    info!("cluster_remove_node: node_id={} removed", node_id);
    Ok(Response::Ok)
}
