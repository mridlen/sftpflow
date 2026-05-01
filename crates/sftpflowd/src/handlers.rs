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
use std::time::Instant;

use log::{error, info, warn};

use sftpflow_core::{validate_name, Config, Endpoint, Feed, NextStepAction, PgpKey, ProcessStep};
use sftpflow_proto::{
    error_code,
    ClusterMemberInfo,
    ClusterStatus,
    ClusterToken,
    DryRunReport,
    FeedSummary,
    ProtoError,
    Response,
    RunResult,
    ServerInfo,
    SyncReport,
};

use crate::backup; // backup.rs - hot snapshot + cold restore
use crate::dkron::DkronClient; // dkron.rs
use crate::secrets::SecretStore; // secrets.rs
use crate::server::{DaemonPaths, DaemonState};
use crate::time_fmt::now_unix_and_iso; // time_fmt.rs - shared UTC helpers

// ============================================================
// Helpers
// ============================================================

/// Persist the current config and wrap any save error as a CONFIG_ERROR
/// protocol error. All mutating handlers funnel through this. Adds a
/// where-to-look detail pointing at the daemon log so the operator
/// knows the exact failure (permission denied, disk full, etc.) is
/// captured server-side.
fn save(config: &Config) -> Result<(), ProtoError> {
    config.save().map_err(|e| ProtoError::full(
        error_code::CONFIG_ERROR,
        format!("could not save config: {}", e),
        "check the daemon's state directory permissions and disk space, then retry",
        "daemon log on the server has the underlying I/O error",
    ))
}

/// Pluralized noun for `kind` used in the next-action hint
/// ("use 'show <plural>' to list valid names"). Matches the
/// `show <plural>` form the CLI already accepts.
fn list_command_for(kind: &str) -> &'static str {
    match kind {
        "endpoint" => "show endpoints",
        "key"      => "show keys",
        "feed"     => "show feeds",
        "secret"   => "secret list",
        _          => "show feeds",
    }
}

fn not_found(kind: &str, name: &str) -> ProtoError {
    ProtoError::with_hint(
        error_code::NOT_FOUND,
        format!("{} '{}' does not exist", kind, name),
        format!(
            "use '{}' to list valid {} names; check spelling and case",
            list_command_for(kind),
            kind,
        ),
    )
}

fn already_exists(kind: &str, name: &str) -> ProtoError {
    ProtoError::with_hint(
        error_code::ALREADY_EXISTS,
        format!("{} '{}' already exists", kind, name),
        format!(
            "to modify it, run 'edit {} {}'; otherwise pick a different name or 'delete' the existing one first",
            kind, name,
        ),
    )
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

/// Run `validate_name` and convert any error into an INVALID_PARAMS
/// ProtoError with a uniform hint. Used by every mutating handler
/// that accepts an operator-supplied identifier (endpoint, key,
/// feed, secret) to keep the allowlist enforcement DRY.
fn require_valid_name(kind: &str, name: &str) -> Result<(), ProtoError> {
    validate_name(kind, name).map_err(|msg| {
        ProtoError::with_hint(
            error_code::INVALID_PARAMS,
            msg,
            "use letters, digits, '-', '_', '.' (max 64 chars; first char alphanumeric)",
        )
    })?;

    // Feed names additionally must not end with `-<digits>`. The
    // dkron scheduler emits jobs as `sftpflow-<feed>` for a single
    // schedule and `sftpflow-<feed>-<N>` for multi-schedule feeds;
    // a feed named e.g. `foo-1` would otherwise collide with feed
    // `foo`'s second schedule on delete/sync. Strict, surfaces the
    // collision at create time. Endpoint/key/secret names don't
    // flow through dkron, so the rule only applies to feeds.
    if kind == "feed" {
        if let Some(idx) = name.rfind('-') {
            let suffix = &name[idx + 1..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return Err(ProtoError::with_hint(
                    error_code::INVALID_PARAMS,
                    format!(
                        "feed name '{}' ends with '-<digits>' which would collide \
                         with the dkron schedule-index suffix",
                        name,
                    ),
                    "rename to use '_' instead of '-' before the digits, e.g. 'foo_1'",
                ));
            }
        }
    }

    Ok(())
}

/// Upsert: create or replace. No collision check — `Put` is idempotent
/// from the caller's perspective.
pub fn put_endpoint(
    state: &mut DaemonState,
    name: String,
    endpoint: Endpoint,
) -> Result<Response, ProtoError> {
    // Strict allowlist on endpoint names: they appear as YAML keys,
    // log identifiers, and audit rows. require_valid_name() - above.
    require_valid_name("endpoint", &name)?;

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
    // Same allowlist as put_endpoint — the new name flows into
    // YAML keys and audit rows, so unvalidated rename is the same
    // hole as unvalidated put.
    require_valid_name("endpoint", &to)?;

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
    // Strict allowlist: key names appear as YAML keys, audit rows,
    // and as referents in feed process steps. require_valid_name() - above.
    require_valid_name("key", &name)?;

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
    // Same allowlist as put_key.
    require_valid_name("key", &to)?;

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
                ProcessStep::Encrypt { key } => {
                    if *key == from {
                        *key = to.clone();
                        ref_count += 1;
                    }
                }
                ProcessStep::Decrypt { key, verify_with } => {
                    if *key == from {
                        *key = to.clone();
                        ref_count += 1;
                    }
                    // verify_with is a list of public-key names —
                    // sweep those too so a renamed verifier key
                    // doesn't silently drop signature verification
                    // on the next run.
                    if let Some(verifiers) = verify_with {
                        for v in verifiers.iter_mut() {
                            if *v == from {
                                *v = to.clone();
                                ref_count += 1;
                            }
                        }
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
//
// dkron HTTP calls used to fire from inside the handlers, while
// the daemon mutex was held — every PutFeed/DeleteFeed serialized
// behind a (potentially slow, with timeouts capped at ~10 s)
// HTTP round-trip. The new pattern: handlers return a `DkronTask`
// describing the work, and the dispatch wrapper executes it AFTER
// dropping the daemon lock. See server.rs for the call pattern.

/// Deferred dkron work, snapshotted under the daemon mutex but
/// executed without it. `run()` performs the actual HTTP and never
/// propagates errors — failures are logged and dropped, matching
/// the prior "best-effort" semantics.
pub enum DkronTask {
    /// Push a single feed's schedules to dkron.
    SyncFeed { url: String, feed_name: String, feed: sftpflow_core::Feed },
    /// Remove every dkron job belonging to a feed.
    DeleteFeedJobs { url: String, feed_name: String },
}

impl DkronTask {
    /// Run the HTTP work. Caller has already dropped the daemon
    /// mutex; the dkron client's own timeouts cap how long this
    /// blocks the dispatch thread.
    pub fn run(self) {
        match self {
            DkronTask::SyncFeed { url, feed_name, feed } => {
                let client = DkronClient::new(&url); // dkron.rs
                client.sync_feed(&feed_name, &feed);
            }
            DkronTask::DeleteFeedJobs { url, feed_name } => {
                let client = DkronClient::new(&url); // dkron.rs
                if let Err(e) = client.delete_feed_jobs(&feed_name) {
                    warn!("dkron: failed to delete jobs for '{}': {}", feed_name, e);
                } else {
                    info!("dkron: deleted jobs for '{}'", feed_name);
                }
            }
        }
    }
}

/// Build a `DkronTask::SyncFeed` for a feed that just got
/// inserted/updated. Returns None when no dkron is configured or
/// when the feed isn't in the live config (e.g. a put that
/// failed validation before mutating the BTreeMap).
pub fn dkron_sync_task(state: &DaemonState, feed_name: &str) -> Option<DkronTask> {
    let url  = state.dkron_url.as_ref()?.clone();
    let feed = state.config.feeds.get(feed_name)?.clone();
    Some(DkronTask::SyncFeed { url, feed_name: feed_name.to_string(), feed })
}

/// Build a `DkronTask::DeleteFeedJobs` for a feed that was just
/// deleted. Returns None when no dkron is configured.
pub fn dkron_delete_task(state: &DaemonState, feed_name: &str) -> Option<DkronTask> {
    let url = state.dkron_url.as_ref()?.clone();
    Some(DkronTask::DeleteFeedJobs { url, feed_name: feed_name.to_string() })
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
    // Strict allowlist on feed names. Feed names flow into the
    // dkron `shell` executor as a `sh -c "sftpflow run <name>"`
    // command string, into HTTP path components for dkron job
    // ids, and into YAML keys. Reject anything that could break
    // out of any of those contexts at the source rather than
    // escape per use site. require_valid_name() - above.
    require_valid_name("feed", &name)?;

    let existed = state.config.feeds.contains_key(&name);
    state.config.feeds.insert(name.clone(), feed);
    save(&state.config)?;
    info!(
        "put feed '{}' ({})",
        name,
        if existed { "updated" } else { "created" }
    );
    // Dkron sync happens at the dispatch layer after the daemon
    // mutex is released — see server.rs RunFeedNow / PutFeed
    // dispatch arms and `dkron_sync_task` above.
    Ok(Response::Ok)
}

pub fn delete_feed(
    state: &mut DaemonState,
    name: &str,
) -> Result<Response, ProtoError> {
    if state.config.feeds.remove(name).is_none() {
        return Err(not_found("feed", name));
    }

    // Sweep dangling nextstep references: any other feed that
    // had a `RunFeed { feed: <name> }` action would otherwise
    // silently fail at run time. We drop those entries and log
    // each one so the operator can see what they lost. rename
    // already handles the live-rename case; this is the
    // delete-counterpart.
    let mut dangling = 0usize;
    for (other_name, f) in state.config.feeds.iter_mut() {
        let before = f.nextsteps.len();
        f.nextsteps.retain(|ns| match &ns.action {
            NextStepAction::RunFeed { feed } => feed != name,
            _ => true,
        });
        let dropped = before - f.nextsteps.len();
        if dropped > 0 {
            warn!(
                "delete_feed '{}': dropped {} dangling nextstep run_feed reference(s) from feed '{}'",
                name, dropped, other_name,
            );
            dangling += dropped;
        }
    }

    save(&state.config)?;
    info!(
        "deleted feed '{}' (swept {} dangling nextstep ref(s))",
        name, dangling,
    );
    // Dkron job removal happens at the dispatch layer.
    Ok(Response::Ok)
}

/// Rename a feed and sweep nextstep references (RunFeed actions) in
/// every other feed.
pub fn rename_feed(
    state: &mut DaemonState,
    from: String,
    to: String,
) -> Result<Response, ProtoError> {
    // Same allowlist as put_feed — the new name flows to dkron's
    // shell executor, so an unvalidated rename is the same hole
    // as an unvalidated put. require_valid_name() - above.
    require_valid_name("feed", &to)?;

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
    // The dispatch layer handles both the delete-old + sync-new
    // dkron tasks after the mutex is released. See server.rs.
    Ok(Response::Ok)
}

/// Snapshot of everything `execute_run_feed` needs after the
/// daemon mutex is released. Built under the lock by
/// `prepare_run_feed` so the transfer runs without holding it.
pub struct RunPrep {
    pub feed_name:    String,
    pub feed:         Feed,
    pub endpoints:    BTreeMap<String, Endpoint>,
    pub keys:         BTreeMap<String, PgpKey>,
    pub started_at:   String,
    /// Wall-clock unix-seconds captured at the same instant as
    /// `started_at`. Stored on the run-history row so SQLite can
    /// sort by a type-correct numeric column instead of a string.
    pub started_unix: i64,
    pub timer:        Instant,
}

/// Phase 1 of RunFeedNow: validate the feed exists, clone the
/// config slices we need, and resolve any `*_ref` fields against
/// the sealed secret store. Caller holds the daemon mutex while
/// this runs (it's all in-memory + fast), then releases the lock
/// before calling `execute_run_feed`.
pub fn prepare_run_feed(
    state: &DaemonState,
    name: &str,
) -> Result<RunPrep, ProtoError> {
    // Defense in depth: every other operator-supplied name flows
    // through require_valid_name; do the same here so an attacker
    // can't sneak metachars through if they reach this RPC by some
    // other path. require_valid_name() - above.
    require_valid_name("feed", name)?;

    let feed = state.config.feeds.get(name).ok_or_else(|| {
        not_found("feed", name)
    })?;

    info!("run_feed_now requested for '{}'", name);

    let feed = feed.clone();
    let mut endpoints = state.config.endpoints.clone();
    let mut keys = state.config.keys.clone();

    // resolve_refs() - below
    if let Err(msg) = resolve_refs(&mut endpoints, &mut keys, state.secrets.as_ref()) {
        warn!("run_feed_now '{}': secret resolution failed: {}", name, msg);
        return Err(ProtoError::with_hint(
            error_code::CONFIG_ERROR,
            msg,
            "add the missing secret with 'secret add <name>', or update the *_ref to point at an existing one ('secret list')",
        ));
    }

    let (started_unix, started_at) = now_unix_and_iso();
    Ok(RunPrep {
        feed_name:  name.to_string(),
        feed,
        endpoints,
        keys,
        started_at,
        started_unix,
        timer:      Instant::now(),
    })
}

/// Phase 2 of RunFeedNow: actually move bytes. Runs WITHOUT the
/// daemon mutex held — the transfer can take seconds to minutes
/// and we don't want to block every other RPC behind it.
///
/// Returns the run result plus the timing/identity bits the caller
/// needs to record the run in SQLite afterward.
pub fn execute_run_feed(
    prep: RunPrep,
) -> (RunResult, std::time::Duration, String, i64, String) {
    let RunPrep {
        feed_name, feed, endpoints, keys, started_at, started_unix, timer,
    } = prep;

    // Build a single-threaded tokio runtime for the transfer.
    // The daemon is thread-per-connection, so each RunFeedNow
    // gets its own runtime. This keeps the sync↔async boundary
    // clean and self-contained.
    let result = match tokio::runtime::Runtime::new() {
        Ok(rt) => {
            // run_feed() in sftpflow-transport (lib.rs)
            rt.block_on(sftpflow_transport::run_feed(
                &feed_name,
                &feed,
                &endpoints,
                &keys,
            ))
        }
        Err(e) => {
            error!("run_feed_now '{}': failed to create tokio runtime: {}", feed_name, e);
            RunResult {
                feed: feed_name.clone(),
                status: sftpflow_proto::RunStatus::Failed,
                files_transferred: 0,
                message: Some(format!("failed to create async runtime: {}", e)),
            }
        }
    };

    let duration = timer.elapsed();

    info!(
        "run_feed_now '{}': completed — status={:?}, files={}, duration={:.1}s",
        feed_name, result.status, result.files_transferred, duration.as_secs_f64()
    );

    (result, duration, started_at, started_unix, feed_name)
}

/// Phase 3 of RunFeedNow: record the run in SQLite. Caller holds
/// the daemon mutex briefly for this — it's a single INSERT.
/// Best-effort: a missing `run_db` is silently skipped.
pub fn record_run_history(
    state:        &DaemonState,
    feed_name:    &str,
    started_at:   &str,
    started_unix: i64,
    duration:     std::time::Duration,
    result:       &RunResult,
) {
    if let Some(ref db) = state.run_db {
        db.record_run(feed_name, started_at, started_unix, duration, result);
    }
}

// iso8601_now / civil_from_days now live in time_fmt.rs and are
// imported at the top of this file.

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
    state.secrets.as_ref().ok_or_else(secret_store_closed_error)
}

fn require_secrets_mut<'a>(state: &'a mut DaemonState) -> Result<&'a mut SecretStore, ProtoError> {
    state.secrets.as_mut().ok_or_else(secret_store_closed_error)
}

/// Shared error for "sealed store isn't open" — every secret-touching
/// handler funnels through here so the operator sees a uniform
/// message + hint.
fn secret_store_closed_error() -> ProtoError {
    ProtoError::full(
        error_code::CONFIG_ERROR,
        "sealed secrets store is not open",
        "restart sftpflowd with --passphrase-file <path> (or set SFTPFLOW_PASSPHRASE) \
         so the daemon can unseal the store",
        "see docs/secrets.md for the passphrase setup",
    )
}

/// Upsert a sealed secret. `value` never touches disk in plaintext.
pub fn put_secret(
    state: &mut DaemonState,
    name: String,
    value: String,
) -> Result<Response, ProtoError> {
    // Strict allowlist: secret names are referenced from
    // password_ref / ssh_key_ref / contents_ref string-equality
    // lookups, so a name with whitespace or weird chars silently
    // breaks the lookup at run time. require_valid_name() - above.
    require_valid_name("secret", &name)?;

    let store = require_secrets_mut(state)?;
    store.put(name.clone(), value).map_err(|e| ProtoError::with_hint(
        error_code::INTERNAL_ERROR,
        format!("could not persist secret '{}': {}", name, e),
        "check the daemon's state directory permissions and disk space, then retry",
    ))?;
    Ok(Response::Ok)
}

/// Delete a sealed secret. Idempotent — not-found is not an error.
pub fn delete_secret(
    state: &mut DaemonState,
    name: &str,
) -> Result<Response, ProtoError> {
    let store = require_secrets_mut(state)?;
    store.delete(name).map_err(|e| ProtoError::with_hint(
        error_code::INTERNAL_ERROR,
        format!("could not persist secret deletion '{}': {}", name, e),
        "check the daemon's state directory permissions and disk space, then retry",
    ))?;
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
    let db = state.run_db.as_ref().ok_or_else(|| ProtoError::with_hint(
        error_code::INTERNAL_ERROR,
        "run history database is not available",
        "check daemon logs — the SQLite history DB failed to open at startup; \
         disk space and permissions on the daemon's state directory are the usual cause",
    ))?;

    let entries = db.get_runs(feed, limit).map_err(|e| ProtoError::new(
        error_code::INTERNAL_ERROR,
        format!("failed to query run history: {}", e),
    ))?;

    Ok(Response::RunHistory(entries))
}

// ============================================================
// Audit log
// ============================================================

/// Retrieve mutation-audit rows from SQLite, newest first.
/// Returns INTERNAL_ERROR if the audit database failed to open
/// at startup — operator should check daemon logs and disk space.
pub fn get_audit_log(
    state:      &DaemonState,
    limit:      Option<u32>,
    since_unix: Option<i64>,
) -> Result<Response, ProtoError> {
    let db = state.audit_db.as_ref().ok_or_else(|| ProtoError::with_hint(
        error_code::INTERNAL_ERROR,
        "audit log database is not available",
        "check daemon logs — the audit SQLite DB failed to open at startup; \
         disk space and permissions on the daemon's state directory are the usual cause",
    ))?;

    let entries = db.query(limit, since_unix).map_err(|e| ProtoError::new(
        error_code::INTERNAL_ERROR,
        format!("failed to query audit log: {}", e),
    ))?;

    Ok(Response::AuditLog(entries))
}

// ============================================================
// Scheduler
// ============================================================

/// Snapshot of what `sync_schedules` needs after the daemon
/// mutex is released. None when dkron isn't configured (the
/// dispatch layer then short-circuits to the "no dkron_url"
/// SyncReport without doing any HTTP).
pub struct SyncSchedulesPrep {
    pub url:   String,
    pub feeds: BTreeMap<String, sftpflow_core::Feed>,
}

/// Phase 1: snapshot the feeds map under the daemon lock so the
/// (potentially slow) HTTP reconciliation in `execute_sync_schedules`
/// runs without holding the mutex.
pub fn prepare_sync_schedules(state: &DaemonState) -> Option<SyncSchedulesPrep> {
    let url = state.dkron_url.as_ref()?.clone();
    Some(SyncSchedulesPrep {
        url,
        feeds: state.config.feeds.clone(),
    })
}

/// Phase 2: run the dkron reconciliation. Caller has already
/// dropped the daemon mutex; this function blocks on dkron's
/// own (capped) HTTP timeouts only.
pub fn execute_sync_schedules(prep: SyncSchedulesPrep) -> Response {
    info!("sync_schedules: reconciling against {}", prep.url);
    let client = DkronClient::new(&prep.url); // dkron.rs
    let report = client.reconcile_all(&prep.feeds);
    Response::SyncReport(report)
}

/// "no dkron_url" reply for the dispatch site to use when
/// `prepare_sync_schedules` returned None.
pub fn sync_schedules_disabled() -> Response {
    info!("sync_schedules: no dkron_url configured");
    Response::SyncReport(SyncReport {
        created: 0,
        updated: 0,
        deleted: 0,
        errors: vec!["no dkron_url configured; scheduler sync disabled".to_string()],
    })
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
    state.cluster.as_ref().ok_or_else(|| ProtoError::full(
        error_code::CONFIG_ERROR,
        "this daemon is running in legacy single-node mode — cluster RPCs are only available on Raft members",
        "to enable cluster mode, restart sftpflowd via 'sftpflowd init' (bootstrap node) \
         or 'sftpflowd join' (additional node) so a node.json is created",
        "see docs/cluster.md for the bootstrap / join flow",
    ))
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
    let (token, expires_at_unix) = ctx.mint_token(ttl).map_err(|msg| ProtoError::with_hint(
        error_code::CONFIG_ERROR,
        msg,
        "join tokens are minted by the bootstrap node (the original 'sftpflowd init'); \
         connect there or use 'cluster status' to find it",
    ))?;
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

    // Use state.paths.state_dir so a daemon started with a custom
    // --state-dir reads its own CA, not whatever lives at the
    // platform default. Earlier versions hard-coded
    // `default_state_dir()` here, which silently returned NOT_FOUND
    // (or a stale CA from the default path) on operators using a
    // non-default layout.
    let pem = std::fs::read_to_string(
        crate::node_state::ca_cert_path(&state.paths.state_dir),
    )
    .map_err(|e| ProtoError::with_hint(
        error_code::CONFIG_ERROR,
        format!("could not read cluster CA cert: {}", e),
        "verify $state_dir/cluster/ca.crt exists and is readable by the daemon",
    ))?;
    Ok(Response::ClusterCaCert(pem))
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
        return Err(ProtoError::with_hint(
            error_code::CONFIG_ERROR,
            format!(
                "refusing to remove the responding node (node_id={}) via 'cluster remove'",
                node_id,
            ),
            "use 'cluster leave' to drain THIS node, or send 'cluster remove' to a different node id",
        ));
    }

    info!("cluster_remove_node: removing node_id={}", node_id);
    ctx.remove_node_blocking(node_id).map_err(|msg| ProtoError::with_hint(
        error_code::CONFIG_ERROR,
        msg,
        "use 'cluster status' to confirm the node id and current voter set; \
         removing the last voter or the leader can fail until quorum recovers",
    ))?;
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
        ctx.leader_self_remove_blocking().map_err(|msg| ProtoError::with_hint(
            error_code::CONFIG_ERROR,
            msg,
            "removing the leader requires a healthy quorum of remaining voters; \
             use 'cluster status' to confirm peers are reachable, then retry",
        ))?;
        info!(
            "cluster_leave: node_id={} removed from voter set; \
             leader has stepped down",
            self_id,
        );
        return Ok(Response::Ok);
    }

    // ---- Follower / learner path: forward to current leader ----
    let leader_id = ctx.current_leader().ok_or_else(|| ProtoError::with_hint(
        error_code::NOT_LEADER,
        "no current leader is known (election in progress or quorum unavailable)",
        "retry 'cluster leave' shortly; run 'cluster status' to confirm a leader has been elected",
    ))?;
    let leader_addr = ctx.members().get(&leader_id).map(|m| m.advertise_addr.clone())
        .ok_or_else(|| ProtoError::new(
            error_code::INTERNAL_ERROR,
            format!("leader node_id={} has no advertise address in membership map", leader_id),
        ))?;

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
        caller: None,
        dry_run: false,
        request: sftpflow_proto::Request::ClusterRemoveNode { node_id: self_id },
    };
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| ProtoError::new(
        error_code::INTERNAL_ERROR,
        format!("could not serialize ClusterRemoveNode envelope: {}", e),
    ))?;

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
    }).map_err(|e| ProtoError::with_hint(
        error_code::NOT_LEADER,
        format!(
            "failed to forward ClusterRemoveNode for self (node_id={}) to leader (node_id={}): {}",
            self_id, leader_id, e,
        ),
        "verify network reachability between this node and the leader's advertise address; \
         retry, or connect directly to the leader and run 'cluster remove <self_id>' there",
    ))?;

    // Unwrap the leader's reply. Surface its error verbatim so the
    // operator sees exactly why the leader refused (e.g. quorum
    // would be lost, no such member, etc.).
    let response: sftpflow_proto::ResponseEnvelope = serde_json::from_slice(&response_bytes)
        .map_err(|e| ProtoError::new(
            error_code::INTERNAL_ERROR,
            format!("malformed response envelope from leader: {}", e),
        ))?;
    match response.outcome {
        sftpflow_proto::ResponseOutcome::Success { result } => {
            info!(
                "cluster_leave: leader confirmed removal of node_id={}",
                self_id,
            );
            Ok(result)
        }
        sftpflow_proto::ResponseOutcome::Failure { error } => Err(error),
        // We're the daemon, so the leader we forwarded to is also a
        // daemon — both sides know the same Response variants. An
        // UnknownSuccess here would mean a peer ran a future
        // version with a brand-new variant; surface as a clear
        // protocol error rather than silently dropping the leave.
        sftpflow_proto::ResponseOutcome::UnknownSuccess { kind, .. } => {
            Err(ProtoError::new(
                error_code::INTERNAL_ERROR,
                format!(
                    "leader returned unknown response kind '{}' for ClusterLeave \
                     — peer is running a newer protocol than this node",
                    kind,
                ),
            ))
        }
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
        return Err(ProtoError::with_hint(
            error_code::INVALID_PARAMS,
            "out_path must not be empty",
            "pass an absolute server-side path, e.g. /var/lib/sftpflow/backups/<name>.tar.gz",
        ));
    }
    let out = std::path::PathBuf::from(out_path);
    if !out.is_absolute() {
        return Err(ProtoError::with_hint(
            error_code::INVALID_PARAMS,
            format!(
                "out_path '{}' must be absolute — the daemon's working directory is not a stable reference",
                out_path,
            ),
            "use a fully-qualified path on the server, e.g. /var/lib/sftpflow/backups/<name>.tar.gz",
        ));
    }

    info!("cluster_backup: writing archive to {}", out.display());
    let report = backup::run_backup_hot(&paths, &out).map_err(|e| ProtoError::with_hint(
        error_code::INTERNAL_ERROR,
        format!("backup failed: {}", e),
        "check disk space at the destination and that the daemon can write the path; \
         daemon log has the underlying I/O / archive error",
    ))?;
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

// ============================================================
// Dry-run handlers
// ============================================================
//
// Each `*_dry_run` mirrors the precondition checks of its real
// counterpart (so the operator sees the same NOT_FOUND /
// ALREADY_EXISTS / CONFIG_ERROR they'd hit on a live run) but never
// calls `save()` and never invokes the dkron client. The work each
// one does is the cross-reference sweep that is normally a side
// effect of the rename / delete — surfaced upfront as a
// `DryRunReport` the CLI renders before asking for confirmation.
//
// The dispatch hook in server.rs::dispatch_local routes here when
// the envelope's `dry_run` flag is set; the audit row records the
// outcome with a `dry-run:` prefix so live mutations and previews
// are trivially filterable.

// ---- endpoints ----

/// Preview `delete endpoint <name>`. Lists every feed whose source
/// or destination would lose its referenced endpoint after deletion.
pub fn delete_endpoint_dry_run(
    state: &DaemonState,
    name:  &str,
) -> Result<Response, ProtoError> {
    if !state.config.endpoints.contains_key(name) {
        return Err(not_found("endpoint", name));
    }

    let mut effects  = vec![format!("would remove endpoint '{}' from registry", name)];
    let mut warnings = Vec::new();

    let referencing = feeds_referencing_endpoint(&state.config, name);
    if referencing.is_empty() {
        effects.push("no feeds reference this endpoint".to_string());
    } else {
        warnings.push(format!(
            "{} feed(s) reference endpoint '{}' — they will fail at run time after deletion: {}",
            referencing.len(), name, referencing.join(", "),
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would delete endpoint '{}'", name),
        effects,
        warnings,
    }))
}

/// Preview `delete key <name>`. Surfaces the encrypt/decrypt process
/// steps that would be left dangling.
pub fn delete_key_dry_run(
    state: &DaemonState,
    name:  &str,
) -> Result<Response, ProtoError> {
    if !state.config.keys.contains_key(name) {
        return Err(not_found("key", name));
    }

    let mut effects  = vec![format!("would remove PGP key '{}' from registry", name)];
    let mut warnings = Vec::new();

    let referencing = feeds_referencing_key(&state.config, name);
    if referencing.is_empty() {
        effects.push("no feeds reference this key".to_string());
    } else {
        warnings.push(format!(
            "{} feed(s) reference key '{}' in process steps — those steps will fail after deletion: {}",
            referencing.len(), name, referencing.join(", "),
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would delete PGP key '{}'", name),
        effects,
        warnings,
    }))
}

/// Preview `delete feed <name>`. Lists nextstep references in other
/// feeds that would be left dangling, and notes dkron cleanup.
pub fn delete_feed_dry_run(
    state: &DaemonState,
    name:  &str,
) -> Result<Response, ProtoError> {
    if !state.config.feeds.contains_key(name) {
        return Err(not_found("feed", name));
    }

    let mut effects  = vec![format!("would remove feed '{}' from registry", name)];
    let mut warnings = Vec::new();

    if state.dkron_url.is_some() {
        effects.push(format!("would delete dkron job(s) scheduled for feed '{}'", name));
    }

    let referencing = feeds_with_nextstep_run(&state.config, name);
    if referencing.is_empty() {
        effects.push("no feeds reference this feed via nextstep".to_string());
    } else {
        warnings.push(format!(
            "{} feed(s) have a nextstep `run feed '{}'` — they will fail after deletion: {}",
            referencing.len(), name, referencing.join(", "),
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would delete feed '{}'", name),
        effects,
        warnings,
    }))
}

/// Preview `rename endpoint <from> <to>`. Counts source/destination
/// rewrites and lists the feeds that would change.
pub fn rename_endpoint_dry_run(
    state: &DaemonState,
    from:  &str,
    to:    &str,
) -> Result<Response, ProtoError> {
    if !state.config.endpoints.contains_key(from) {
        return Err(not_found("endpoint", from));
    }
    if state.config.endpoints.contains_key(to) {
        return Err(already_exists("endpoint", to));
    }

    let referencing = feeds_referencing_endpoint(&state.config, from);
    let mut effects = vec![format!("would rename endpoint '{}' → '{}'", from, to)];
    if referencing.is_empty() {
        effects.push("no feed source/destination paths to update".to_string());
    } else {
        effects.push(format!(
            "would update source/destination paths in {} feed(s): {}",
            referencing.len(), referencing.join(", "),
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would rename endpoint '{}' → '{}'", from, to),
        effects,
        warnings: Vec::new(),
    }))
}

/// Preview `rename key <from> <to>`. Same shape as endpoint rename;
/// the sweep targets `process` steps instead of feed paths.
pub fn rename_key_dry_run(
    state: &DaemonState,
    from:  &str,
    to:    &str,
) -> Result<Response, ProtoError> {
    if !state.config.keys.contains_key(from) {
        return Err(not_found("key", from));
    }
    if state.config.keys.contains_key(to) {
        return Err(already_exists("key", to));
    }

    let referencing = feeds_referencing_key(&state.config, from);
    let mut effects = vec![format!("would rename PGP key '{}' → '{}'", from, to)];
    if referencing.is_empty() {
        effects.push("no process steps to update".to_string());
    } else {
        effects.push(format!(
            "would update encrypt/decrypt steps in {} feed(s): {}",
            referencing.len(), referencing.join(", "),
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would rename PGP key '{}' → '{}'", from, to),
        effects,
        warnings: Vec::new(),
    }))
}

/// Preview `rename feed <from> <to>`. Counts nextstep `run feed`
/// targets that would be rewritten.
pub fn rename_feed_dry_run(
    state: &DaemonState,
    from:  &str,
    to:    &str,
) -> Result<Response, ProtoError> {
    if !state.config.feeds.contains_key(from) {
        return Err(not_found("feed", from));
    }
    if state.config.feeds.contains_key(to) {
        return Err(already_exists("feed", to));
    }

    let referencing = feeds_with_nextstep_run(&state.config, from);
    let mut effects = vec![format!("would rename feed '{}' → '{}'", from, to)];
    if state.dkron_url.is_some() {
        effects.push(format!(
            "would delete dkron job(s) for old name '{}' and re-create them for '{}'",
            from, to,
        ));
    }
    if referencing.is_empty() {
        effects.push("no nextstep references to update".to_string());
    } else {
        effects.push(format!(
            "would update `run feed` nextstep targets in {} feed(s): {}",
            referencing.len(), referencing.join(", "),
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would rename feed '{}' → '{}'", from, to),
        effects,
        warnings: Vec::new(),
    }))
}

/// Preview `secret delete <name>`. Lists every endpoint /
/// PGP key in the *config* that would have a dangling `*_ref`
/// after deletion. The secret value itself is never inspected
/// (and never sent to the CLI).
pub fn delete_secret_dry_run(
    state: &DaemonState,
    name:  &str,
) -> Result<Response, ProtoError> {
    let store = require_secrets(state)?;
    let exists = store.names().iter().any(|n| n == name);

    let mut effects  = Vec::new();
    let mut warnings = Vec::new();

    if exists {
        effects.push(format!("would remove sealed secret '{}'", name));
    } else {
        // delete_secret is idempotent in the live path, so still
        // succeed — but the operator should know they're previewing
        // a no-op so they don't think it actually did something.
        effects.push(format!(
            "secret '{}' is not in the sealed store — delete is a no-op (idempotent)",
            name,
        ));
    }

    let mut referrers = Vec::new();
    for (ep_name, ep) in state.config.endpoints.iter() {
        if ep.password_ref.as_deref() == Some(name) {
            referrers.push(format!("endpoint '{}' password_ref", ep_name));
        }
        if ep.ssh_key_ref.as_deref() == Some(name) {
            referrers.push(format!("endpoint '{}' ssh_key_ref", ep_name));
        }
    }
    for (key_name, key) in state.config.keys.iter() {
        if key.contents_ref.as_deref() == Some(name) {
            referrers.push(format!("PGP key '{}' contents_ref", key_name));
        }
    }
    if referrers.is_empty() {
        effects.push("no config objects reference this secret".to_string());
    } else {
        warnings.push(format!(
            "{} config object(s) reference secret '{}' — feeds using them will fail at run time: {}",
            referrers.len(), name, referrers.join(", "),
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would delete sealed secret '{}'", name),
        effects,
        warnings,
    }))
}

/// Preview `cluster remove <node_id>`. Computes the would-be voter
/// set, prints it next to the current set, and warns when quorum
/// shrinks or the call would be rejected outright (last voter,
/// self-removal, unknown node).
pub fn cluster_remove_node_dry_run(
    state:   &DaemonState,
    node_id: u64,
) -> Result<Response, ProtoError> {
    let ctx = require_cluster(state)?;

    if node_id == ctx.self_id {
        return Err(ProtoError::with_hint(
            error_code::CONFIG_ERROR,
            format!(
                "refusing to preview removal of the responding node (node_id={})",
                node_id,
            ),
            "use 'cluster leave --dry-run' to preview self-removal, or run \
             'cluster remove --dry-run <id>' against a different node id",
        ));
    }

    let members = ctx.members_with_voter_flag();
    if !members.contains_key(&node_id) {
        return Err(ProtoError::with_hint(
            error_code::CONFIG_ERROR,
            format!("no member with node_id={} exists", node_id),
            "run 'cluster status' to see the current member list",
        ));
    }

    // Current voter set (sorted) and the would-be set after removal.
    let mut current_voters: Vec<u64> = members
        .iter()
        .filter(|(_, (_, is_voter))| *is_voter)
        .map(|(id, _)| *id)
        .collect();
    current_voters.sort_unstable();
    let new_voters: Vec<u64> = current_voters
        .iter()
        .copied()
        .filter(|id| *id != node_id)
        .collect();

    let label = members
        .get(&node_id)
        .and_then(|(m, _)| m.label.clone())
        .unwrap_or_else(|| "-".to_string());

    let current_quorum = (current_voters.len() / 2) + 1;
    let new_quorum     = if new_voters.is_empty() { 0 } else { (new_voters.len() / 2) + 1 };

    let mut effects = vec![
        format!("would remove node_id={} (label={}) from voter set", node_id, label),
        format!(
            "voter set: {:?} → {:?}  (size {} → {}, quorum {} → {})",
            current_voters,
            new_voters,
            current_voters.len(),
            new_voters.len(),
            current_quorum,
            new_quorum,
        ),
    ];

    let mut warnings = Vec::new();
    if new_voters.is_empty() {
        // The real handler refuses with CONFIG_ERROR; surface that
        // here as a warning rather than failing — the operator
        // should see both "this would happen" and "the live call
        // would refuse" so the preview is useful.
        warnings.push(format!(
            "removing node_id={} would leave the cluster with no voters; \
             the live call would refuse with CONFIG_ERROR",
            node_id,
        ));
    } else if new_voters.len() < 3 {
        // Below 3 voters the cluster is no longer HA — single
        // failure tolerance disappears.
        warnings.push(format!(
            "voter set would drop to {} (no longer HA — a single failure halts the cluster)",
            new_voters.len(),
        ));
    }
    // Members map only stores voters + learners; if the target was
    // a learner, the voter sets are unchanged — flag that so the
    // operator doesn't expect a quorum movement.
    let was_voter = members
        .get(&node_id)
        .map(|(_, is_voter)| *is_voter)
        .unwrap_or(false);
    if !was_voter {
        effects.push(format!(
            "node_id={} is currently a learner (non-voting); voter set is unchanged",
            node_id,
        ));
    }

    Ok(Response::DryRunReport(DryRunReport {
        summary: format!("would remove node_id={} from cluster", node_id),
        effects,
        warnings,
    }))
}

// ---- shared sweep helpers ----

/// Names of feeds whose source or destination paths reference the
/// given endpoint name. Order is `BTreeMap`-stable (feed name asc).
fn feeds_referencing_endpoint(config: &Config, endpoint: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (feed_name, feed) in config.feeds.iter() {
        let hits = feed.sources.iter().any(|p| p.endpoint == endpoint)
                || feed.destinations.iter().any(|p| p.endpoint == endpoint);
        if hits {
            out.push(feed_name.clone());
        }
    }
    out
}

/// Names of feeds whose process steps reference the given key.
fn feeds_referencing_key(config: &Config, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (feed_name, feed) in config.feeds.iter() {
        let hits = feed.process.iter().any(|step| match step {
            ProcessStep::Encrypt { key: k } => k == key,
            ProcessStep::Decrypt { key: k, verify_with } => {
                k == key
                    || verify_with
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .any(|v| v == key)
            }
        });
        if hits {
            out.push(feed_name.clone());
        }
    }
    out
}

/// Names of feeds whose nextstep `run feed` targets the given feed.
fn feeds_with_nextstep_run(config: &Config, target: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (feed_name, feed) in config.feeds.iter() {
        let hits = feed.nextsteps.iter().any(|ns| matches!(
            &ns.action,
            NextStepAction::RunFeed { feed: t } if t == target
        ));
        if hits {
            out.push(feed_name.clone());
        }
    }
    out
}

// ============================================================
// Tests - dry-run handlers (no live cluster)
// ============================================================
//
// These exercise the dry-run handlers that don't depend on the
// Raft runtime — every delete/rename preview, plus secret-delete.
// `cluster_remove_node_dry_run` is integration-tested in
// crates/sftpflow-cluster (it needs a live ClusterContext).

#[cfg(test)]
mod tests {
    use super::*;
    use sftpflow_core::{
        Endpoint, Feed, FeedPath, NextStep, NextStepAction, PgpKey,
        ProcessStep, TriggerCondition,
    };
    use sftpflow_proto::Response;

    // ---- DaemonState builder ----
    //
    // Construct a minimal DaemonState whose only populated fields are
    // those the dry-run handlers actually read. We never call any
    // live mutating handler from these tests, so the empty `paths` /
    // `started` placeholders are fine — `Config::save` and friends
    // are not exercised here.

    fn make_state(config: Config) -> crate::server::DaemonState {
        crate::server::DaemonState {
            config,
            started:   std::time::Instant::now(),
            dkron_url: None,
            run_db:    None,
            audit_db:  None,
            secrets:   None,
            cluster:   None,
            paths:     crate::server::DaemonPaths {
                state_dir:    std::path::PathBuf::from("/tmp/sftpflow-test"),
                runs_db:      std::path::PathBuf::from("/tmp/sftpflow-test/runs.db"),
                audit_db:     std::path::PathBuf::from("/tmp/sftpflow-test/audit.db"),
                secrets_file: std::path::PathBuf::from("/tmp/sftpflow-test/secrets.age"),
                config_yaml:  std::path::PathBuf::from("/tmp/sftpflow-test/config.yaml"),
            },
        }
    }

    /// Build a Config with one endpoint, one PGP key, two feeds
    /// where `feed_a` references endpoint `prod` (source) and
    /// key `kp` (encrypt step), and `feed_b` has a nextstep
    /// `run feed feed_a`. This is the standard fixture every
    /// reference-sweep test below uses.
    fn fixture_config() -> Config {
        let mut endpoints = std::collections::BTreeMap::new();
        endpoints.insert("prod".to_string(),  Endpoint::default());
        endpoints.insert("stage".to_string(), Endpoint::default());

        let mut keys = std::collections::BTreeMap::new();
        keys.insert("kp".to_string(),    PgpKey::default());
        keys.insert("other".to_string(), PgpKey::default());

        let feed_a = Feed {
            sources: vec![FeedPath {
                endpoint: "prod".to_string(),
                path:     "/in".to_string(),
            }],
            destinations: vec![FeedPath {
                endpoint: "prod".to_string(),
                path:     "/out".to_string(),
            }],
            process: vec![ProcessStep::Encrypt { key: "kp".to_string() }],
            ..Default::default()
        };
        let feed_b = Feed {
            sources: vec![FeedPath {
                endpoint: "stage".to_string(),
                path:     "/x".to_string(),
            }],
            nextsteps: vec![NextStep {
                action: NextStepAction::RunFeed { feed: "feed_a".to_string() },
                on:     vec![TriggerCondition::Success],
            }],
            ..Default::default()
        };
        let mut feeds = std::collections::BTreeMap::new();
        feeds.insert("feed_a".to_string(), feed_a);
        feeds.insert("feed_b".to_string(), feed_b);

        Config { endpoints, keys, feeds, ..Default::default() }
    }

    fn unwrap_report(r: Response) -> sftpflow_proto::DryRunReport {
        match r {
            Response::DryRunReport(rep) => rep,
            other => panic!("expected DryRunReport, got {:?}", other),
        }
    }

    // ---- delete_endpoint_dry_run ----

    #[test]
    fn delete_endpoint_dry_run_flags_referencing_feeds() {
        let state = make_state(fixture_config());
        let report = unwrap_report(
            delete_endpoint_dry_run(&state, "prod").unwrap(),
        );
        assert!(report.summary.contains("delete endpoint 'prod'"));
        // Two refs (source + destination) but in one feed → one warning.
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("feed_a"));
        // State must still contain the endpoint after a preview.
        assert!(state.config.endpoints.contains_key("prod"));
    }

    #[test]
    fn delete_endpoint_dry_run_unreferenced_endpoint_has_no_warnings() {
        // A fresh endpoint with no feeds touching it → zero warnings,
        // and the effects list explicitly says "no feeds reference".
        let mut config = fixture_config();
        config.endpoints.insert("solo".to_string(), Endpoint::default());
        let state = make_state(config);
        let report = unwrap_report(
            delete_endpoint_dry_run(&state, "solo").unwrap(),
        );
        assert!(report.warnings.is_empty());
        assert!(report.effects.iter().any(|e| e.contains("no feeds reference")));
    }

    #[test]
    fn delete_endpoint_dry_run_missing_endpoint_returns_not_found() {
        let state = make_state(fixture_config());
        let err = delete_endpoint_dry_run(&state, "ghost").unwrap_err();
        assert_eq!(err.code, error_code::NOT_FOUND);
        // Phase D #17: NOT_FOUND carries a next-action hint pointing
        // the operator at the listing command for that kind.
        let hint = err.hint.as_ref().expect("not_found should carry a hint");
        assert!(hint.contains("show endpoints"), "hint was: {}", hint);
    }

    #[test]
    fn already_exists_carries_edit_hint() {
        // Phase D #17: ALREADY_EXISTS hint should suggest the in-place
        // edit path so the operator doesn't have to guess. We hit it
        // through rename_endpoint_dry_run — same helper underneath.
        let state = make_state(fixture_config());
        let err = rename_endpoint_dry_run(&state, "prod", "stage").unwrap_err();
        assert_eq!(err.code, error_code::ALREADY_EXISTS);
        let hint = err.hint.as_ref().expect("already_exists should carry a hint");
        assert!(hint.contains("edit endpoint"), "hint was: {}", hint);
    }

    // ---- delete_key_dry_run / delete_feed_dry_run ----

    #[test]
    fn delete_key_dry_run_flags_process_step_references() {
        let state  = make_state(fixture_config());
        let report = unwrap_report(delete_key_dry_run(&state, "kp").unwrap());
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("feed_a"));
    }

    #[test]
    fn delete_feed_dry_run_flags_nextstep_references() {
        let state  = make_state(fixture_config());
        let report = unwrap_report(delete_feed_dry_run(&state, "feed_a").unwrap());
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("feed_b"));
    }

    #[test]
    fn delete_feed_dry_run_includes_dkron_effect_when_configured() {
        let mut state = make_state(fixture_config());
        state.dkron_url = Some("http://dkron:8080".into());
        let report = unwrap_report(delete_feed_dry_run(&state, "feed_b").unwrap());
        assert!(report.effects.iter().any(|e| e.contains("dkron job")));
    }

    // ---- rename_*_dry_run ----

    #[test]
    fn rename_endpoint_dry_run_lists_reference_count() {
        let state  = make_state(fixture_config());
        let report = unwrap_report(
            rename_endpoint_dry_run(&state, "prod", "prod-2").unwrap(),
        );
        assert!(report.summary.contains("'prod' → 'prod-2'"));
        // One feed with both source + destination references gets
        // one entry in the list (the helper de-dupes by feed name).
        assert!(report.effects.iter().any(|e| e.contains("1 feed(s)") && e.contains("feed_a")));
    }

    #[test]
    fn rename_endpoint_dry_run_already_exists_errors() {
        let state = make_state(fixture_config());
        let err = rename_endpoint_dry_run(&state, "prod", "stage").unwrap_err();
        assert_eq!(err.code, error_code::ALREADY_EXISTS);
    }

    #[test]
    fn rename_feed_dry_run_lists_nextstep_targets() {
        let state  = make_state(fixture_config());
        let report = unwrap_report(
            rename_feed_dry_run(&state, "feed_a", "feed_aa").unwrap(),
        );
        assert!(report.effects.iter().any(|e|
            e.contains("nextstep targets") && e.contains("feed_b")
        ));
    }

    // ---- delete_secret_dry_run ----

    #[test]
    fn delete_secret_dry_run_requires_open_store() {
        let state = make_state(fixture_config());
        // No secrets configured → CONFIG_ERROR (live handler does the
        // same; the dry-run path mirrors it so the operator sees the
        // same precondition message in preview mode).
        let err = delete_secret_dry_run(&state, "anything").unwrap_err();
        assert_eq!(err.code, error_code::CONFIG_ERROR);
    }

    #[test]
    fn delete_secret_dry_run_flags_endpoint_and_key_references() {
        // Real SecretStore so the existence-vs-no-op effect picks
        // the "would remove" path. Mark one endpoint password_ref
        // and one key contents_ref as referencing the secret being
        // previewed; the dry-run report should warn about both.
        use crate::secrets::SecretStore;
        use age::secrecy::SecretString;
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.age");

        // Open the store with a fixed test passphrase. The dry-run
        // handler never decrypts anything — `names()` is enough.
        let mut store = SecretStore::open(&path, SecretString::new("pw".into())).unwrap();
        store.put("db-pass".into(), "value".into()).unwrap();

        let mut config = fixture_config();
        // Endpoint references the secret via password_ref.
        if let Some(ep) = config.endpoints.get_mut("prod") {
            ep.password_ref = Some("db-pass".into());
        }
        // Key references the secret via contents_ref.
        if let Some(k) = config.keys.get_mut("kp") {
            k.contents_ref = Some("db-pass".into());
        }

        let mut state = make_state(config);
        state.secrets = Some(store);

        let report = unwrap_report(delete_secret_dry_run(&state, "db-pass").unwrap());
        assert!(report.effects.iter().any(|e| e.contains("would remove sealed secret")));
        // One warning, mentioning both referrer kinds.
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("endpoint 'prod' password_ref"));
        assert!(report.warnings[0].contains("PGP key 'kp' contents_ref"));
    }

    #[test]
    fn delete_secret_dry_run_missing_secret_is_no_op() {
        // Secret that isn't in the store → effects mention the
        // idempotent no-op explicitly, never warns.
        use crate::secrets::SecretStore;
        use age::secrecy::SecretString;
        let dir   = tempfile::tempdir().unwrap();
        let path  = dir.path().join("secrets.age");
        let store = SecretStore::open(&path, SecretString::new("pw".into())).unwrap();

        let mut state = make_state(fixture_config());
        state.secrets = Some(store);

        let report = unwrap_report(delete_secret_dry_run(&state, "ghost").unwrap());
        assert!(report.effects.iter().any(|e|
            e.contains("not in the sealed store") && e.contains("idempotent")
        ));
        assert!(report.warnings.is_empty());
    }
}
