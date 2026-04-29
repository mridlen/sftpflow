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

use crate::backup; // backup.rs - hot snapshot + cold restore
use crate::dkron::DkronClient; // dkron.rs
use crate::secrets::SecretStore; // secrets.rs
use crate::server::{DaemonPaths, DaemonState};

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
///
/// Beyond bare membership, this fills:
///   - responder uptime (from `DaemonState.started`)
///   - responder's local last_log / last_applied indices
///   - leader-only per-peer `matched_log_index` + `lag`
///
/// Lag and matched are only meaningful when the responder is the
/// current leader (openraft only reports replication metrics on
/// leaders). When a follower answers, those fields stay `None` and
/// the CLI prints a footer noting that.
pub fn cluster_status(state: &DaemonState) -> Result<Response, ProtoError> {
    let ctx = require_cluster(state)?;

    // ---- responder-side scalars --------------------------------
    let uptime_secs              = state.started.elapsed().as_secs();
    let responder_last_log       = ctx.last_log_index();
    let responder_last_applied   = ctx.last_applied_index();
    let leader_id                = ctx.current_leader();
    let responder_is_leader      = ctx.is_leader();

    // ---- per-peer replication progress (leader-only) ----------
    // `replication_progress` is `Some(map)` exactly when this node
    // is the active leader. Followers get `None` here and we leave
    // matched_log_index / lag as None on every member row.
    let replication = if responder_is_leader {
        ctx.replication_progress()
    } else {
        None
    };

    // The leader's own matched index is its last_log_index (it is
    // trivially "caught up" to itself). We use this for the lag
    // baseline and for the leader's row.
    let leader_baseline = responder_last_log;

    let mut members: Vec<ClusterMemberInfo> = ctx
        .members_with_voter_flag()
        .into_iter()
        .map(|(node_id, (member, is_voter))| {
            let (matched_log_index, lag) = match replication.as_ref() {
                None => (None, None),
                Some(rep) => {
                    // The leader's own row: use its last_log_index
                    // as matched, lag = 0. openraft's replication
                    // map omits the leader itself from the map.
                    if node_id == ctx.self_id {
                        (leader_baseline, leader_baseline.map(|_| 0u64))
                    } else {
                        let matched = rep.get(&node_id).copied().flatten();
                        let lag = match (leader_baseline, matched) {
                            (Some(tip), Some(m)) => Some(tip.saturating_sub(m)),
                            // Peer has acknowledged nothing yet — report
                            // full tip as the lag so operators see the gap.
                            (Some(tip), None)    => Some(tip),
                            _                    => None,
                        };
                        (matched, lag)
                    }
                }
            };

            ClusterMemberInfo {
                node_id,
                advertise_addr: member.advertise_addr,
                label:          member.label,
                is_voter,
                matched_log_index,
                lag,
            }
        })
        .collect();
    // BTreeMap iteration is already sorted by key, but be explicit:
    // the wire contract promises ascending node_id so the CLI can
    // render deterministically.
    members.sort_by_key(|m| m.node_id);

    Ok(Response::ClusterStatus(ClusterStatus {
        cluster_id:                  ctx.cluster_id.clone(),
        self_id:                     ctx.self_id,
        leader_id,
        members,
        responder_uptime_secs:       uptime_secs,
        responder_last_log_index:    responder_last_log,
        responder_last_applied_index: responder_last_applied,
        responder_is_leader,
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

/// `cluster_get_ca`: serve this node's copy of `cluster/ca.crt`.
/// Read-only, no leader gate — every cluster member persists the
/// CA, and it's public material anyway. Used by the CLI's
/// `cluster join` command to ship the CA to a new host through
/// the existing SSH bridge instead of an out-of-band scp.
pub fn cluster_get_ca(state: &DaemonState) -> Result<Response, ProtoError> {
    let _ctx = require_cluster(state)?;

    // The state_dir layout is fixed by node_state::ca_cert_path.
    // We don't have a direct reference to state_dir from the handler
    // (DaemonState doesn't carry it; main.rs resolves it once at
    // startup). For now use the default location, which matches
    // every code path that constructs DaemonState in cluster mode.
    // M13 will plumb state_dir through DaemonState explicitly.
    let state_dir = default_state_dir();
    let pem = std::fs::read_to_string(crate::node_state::ca_cert_path(&state_dir))
        .map_err(|e| ProtoError {
            code: error_code::CONFIG_ERROR,
            message: format!("could not read cluster CA cert: {}", e),
        })?;
    Ok(Response::ClusterCaCert(pem))
}

/// Platform default state-dir, mirroring main.rs::default_state_dir.
/// Local copy here so handlers.rs doesn't need a reference back
/// into main.rs (which would create a cycle). Identical layout.
fn default_state_dir() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/var/lib/sftpflow")
    }
    #[cfg(not(unix))]
    {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(base).join("sftpflow")
    }
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
    // node voting itself out via this RPC, and the operator almost
    // certainly meant a different ID. The intentional self-removal
    // path is `cluster leave`, which lands on the leaver itself
    // (not the leader) and drives the membership change with
    // explicit confirmation.
    if node_id == ctx.self_id {
        return Err(ProtoError {
            code: error_code::CONFIG_ERROR,
            message: format!(
                "refusing to remove the responding node (node_id={}) from the voter set; \
                 use `cluster leave` to drain this node, or run `cluster remove` against a \
                 different node",
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

// ============================================================
// cluster_leave - graceful self-removal
// ============================================================
//
// The receiving node steps itself out of the cluster.
//
//   - Leader path: call `change_membership(voters - self_id)`
//     directly. openraft commits the new config under the current
//     term, then this node steps down. The CLI sees Response::Ok
//     once the membership change has committed.
//
//   - Follower / learner path: synthesize a
//     `ClusterRemoveNode { node_id: self_id }` envelope and forward
//     it to the current leader over the existing peer-mTLS
//     transport (the same `forward_envelope_to_peer` used by
//     server::forward_if_follower). The leader's
//     `cluster_remove_node` handler accepts it because
//     leader.self_id != leaver_id, and runs the same
//     `remove_node_blocking` it always does.
//
// We deliberately do NOT route this through dispatch's auto-forward
// hook — that would ship the ClusterLeave envelope to the leader,
// where it would read the leader's self_id and try to remove the
// wrong node. The leaver must be the one that handles ClusterLeave.

pub fn cluster_leave(state: &DaemonState) -> Result<Response, ProtoError> {
    let ctx = require_cluster(state)?;
    let self_id = ctx.self_id;

    if ctx.is_leader() {
        info!(
            "cluster_leave: this node (node_id={}) is the leader; \
             stepping down via change_membership",
            self_id,
        );
        ctx.leader_self_remove_blocking().map_err(|msg| ProtoError {
            code: error_code::CONFIG_ERROR,
            message: msg,
        })?;
        info!(
            "cluster_leave: node_id={} removed from voter set; \
             leader has stepped down",
            self_id,
        );
        return Ok(Response::Ok);
    }

    // ---- Follower / learner path: forward to current leader ----
    let leader_id = ctx.current_leader().ok_or_else(|| ProtoError {
        code: error_code::NOT_LEADER,
        message: "no current leader is known (election in progress or quorum unavailable); \
                  retry `cluster leave` shortly".to_string(),
    })?;
    let leader_addr = ctx.members().get(&leader_id).map(|m| m.advertise_addr.clone())
        .ok_or_else(|| ProtoError {
            code: error_code::INTERNAL_ERROR,
            message: format!("leader node_id={} has no advertise address in membership map", leader_id),
        })?;

    info!(
        "cluster_leave: this node (node_id={}) is a follower/learner; \
         forwarding ClusterRemoveNode to leader node_id={} at {}",
        self_id, leader_id, leader_addr,
    );

    // Build the envelope. The id is local — the leader's response
    // id is correlated against this id (we discard it; only the
    // outcome matters).
    let envelope = sftpflow_proto::RequestEnvelope {
        id: 0,
        request: sftpflow_proto::Request::ClusterRemoveNode { node_id: self_id },
    };
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| ProtoError {
        code: error_code::INTERNAL_ERROR,
        message: format!("could not serialize ClusterRemoveNode envelope: {}", e),
    })?;

    let leaf_cert = ctx.leaf_cert_pem.clone();
    let leaf_key  = ctx.leaf_key_pem.clone();
    let ca_cert   = ctx.ca_cert_pem.clone();
    let runtime   = ctx.runtime.clone();
    let response_bytes = runtime.block_on(async move {
        sftpflow_cluster::transport::forward_envelope_to_peer(
            &leader_addr,
            &leaf_cert,
            &leaf_key,
            &ca_cert,
            envelope_bytes,
        ).await
    }).map_err(|e| ProtoError {
        code: error_code::NOT_LEADER,
        message: format!(
            "failed to forward ClusterRemoveNode for self (node_id={}) to leader (node_id={}): {}",
            self_id, leader_id, e,
        ),
    })?;

    // Unwrap the leader's reply. Surface its error verbatim so the
    // operator sees exactly why the leader refused (e.g. quorum
    // would be lost, no such member, etc.).
    let response: sftpflow_proto::ResponseEnvelope = serde_json::from_slice(&response_bytes)
        .map_err(|e| ProtoError {
            code: error_code::INTERNAL_ERROR,
            message: format!("malformed response envelope from leader: {}", e),
        })?;
    match response.outcome {
        sftpflow_proto::ResponseOutcome::Success { result } => {
            info!(
                "cluster_leave: leader confirmed removal of node_id={}",
                self_id,
            );
            Ok(result)
        }
        sftpflow_proto::ResponseOutcome::Failure { error } => Err(error),
    }
}

// ============================================================
// cluster_backup - hot tar.gz snapshot of node state
// ============================================================
//
// Takes the resolved DaemonPaths by value (cloned in the dispatch
// arm BEFORE the daemon mutex is acquired) so the tar+gz pass — up
// to a few seconds for a typical node — does not block other NDJSON
// connections.
//
// Not leader-gated: every node can back up its own state. The result
// path is server-side; the operator scps it back themselves in v1.
//
// Preconditions enforced here:
//   - out_path is non-empty
//   - out_path is absolute (avoids "where am I writing?" surprises;
//     daemon CWD is whatever started it, often "/" under systemd)

pub fn cluster_backup(
    paths:    DaemonPaths,
    out_path: &str,
) -> Result<Response, ProtoError> {
    if out_path.is_empty() {
        return Err(ProtoError {
            code: error_code::INVALID_PARAMS,
            message: "out_path must not be empty".to_string(),
        });
    }
    let out = std::path::PathBuf::from(out_path);
    if !out.is_absolute() {
        return Err(ProtoError {
            code: error_code::INVALID_PARAMS,
            message: format!(
                "out_path '{}' must be absolute (server-side path); \
                 the daemon's working directory is not a stable reference",
                out_path,
            ),
        });
    }

    info!("cluster_backup: writing archive to {}", out.display());
    let report = backup::run_backup_hot(&paths, &out).map_err(|e| ProtoError {
        code: error_code::INTERNAL_ERROR,
        message: format!("backup failed: {}", e),
    })?;
    info!(
        "cluster_backup: ok ({} files, {} bytes, sha256={})",
        report.file_count, report.archive_size, report.archive_sha256,
    );

    Ok(Response::BackupReport(sftpflow_proto::BackupReport {
        archive_path:   report.archive_path,
        archive_size:   report.archive_size,
        archive_sha256: report.archive_sha256,
        file_count:     report.file_count,
        cluster_id:     report.cluster_id,
        node_id:        report.node_id,
    }))
}
