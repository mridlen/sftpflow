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

use std::time::Instant;

use log::{error, info, warn};

use sftpflow_core::{Config, Endpoint, NextStepAction, PgpKey, ProcessStep};
use sftpflow_proto::{
    error_code,
    FeedSummary,
    ProtoError,
    Response,
    ServerInfo,
    SyncReport,
};

use crate::dkron::DkronClient; // dkron.rs
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
/// optionally delete source files afterward.
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
    // lock before blocking on async I/O.
    let feed = feed.clone();
    let endpoints = state.config.endpoints.clone();
    let feed_name = name.to_string();

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
    ));

    info!(
        "run_feed_now '{}': completed — status={:?}, files={}",
        feed_name, result.status, result.files_transferred
    );

    Ok(Response::RunResult(result))
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
