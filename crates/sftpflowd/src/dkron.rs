// ============================================================
// sftpflowd::dkron - Dkron scheduler reconciliation
// ============================================================
//
// Pushes feed schedules to a dkron cluster as shell-executor jobs.
// Each scheduled feed becomes one or more dkron jobs named:
//   sftpflow-<feed>        (single schedule)
//   sftpflow-<feed>-<idx>  (multiple schedules)
//
// The daemon calls into this module:
//   - On startup (full reconcile)
//   - After PutFeed / DeleteFeed / RenameFeed mutations (per-feed sync)
//   - On explicit SyncSchedules RPC (full reconcile)
//
// All operations are best-effort: errors are logged and collected
// into a SyncReport, but never fail the calling RPC.

use std::collections::{BTreeMap, HashMap, HashSet};

use log::{info, warn};
use serde::{Deserialize, Serialize};

use sftpflow_core::Feed;
use sftpflow_proto::SyncReport;

// ============================================================
// Dkron API types
// ============================================================

/// Job body sent to the dkron HTTP API (POST /v1/jobs).
#[derive(Debug, Serialize)]
struct DkronJobBody {
    name: String,
    schedule: String,
    executor: String,
    executor_config: HashMap<String, String>,
    disabled: bool,
    tags: HashMap<String, String>,
    concurrency: String,
}

/// Minimal job record returned by GET /v1/jobs.
#[derive(Debug, Deserialize)]
struct DkronJobInfo {
    name: String,
    schedule: String,
    disabled: bool,
}

// ============================================================
// Client
// ============================================================

pub struct DkronClient {
    base_url: String,
}

impl DkronClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    // --------------------------------------------------------
    // Full reconciliation: config feeds ↔ dkron jobs
    // --------------------------------------------------------

    /// Compare every feed's schedules against the dkron job list
    /// and create, update, or delete jobs as needed. Orphan dkron
    /// jobs (prefixed `sftpflow-` but no matching feed) are removed.
    pub fn reconcile_all(&self, feeds: &BTreeMap<String, Feed>) -> SyncReport {
        let mut report = SyncReport {
            created: 0,
            updated: 0,
            deleted: 0,
            errors: Vec::new(),
        };

        // Fetch current dkron jobs
        let existing = match self.list_sftpflow_jobs() {
            Ok(jobs) => jobs,
            Err(e) => {
                warn!("dkron reconcile: failed to list jobs: {}", e);
                report.errors.push(format!("list jobs: {}", e));
                return report;
            }
        };

        // Build a set of job names we expect to exist
        let mut expected_names: HashSet<String> = HashSet::new();

        // Upsert jobs for each feed
        for (feed_name, feed) in feeds {
            let names = job_names_for_feed(feed_name, feed.schedules.len());
            for name in &names {
                expected_names.insert(name.clone());
            }

            for (i, schedule) in feed.schedules.iter().enumerate() {
                let job_name = &names[i];

                // Check if job already exists with same schedule + disabled state
                if let Some(existing_job) = existing.get(job_name) {
                    if existing_job.schedule == *schedule
                        && existing_job.disabled == !feed.flags.enabled
                    {
                        // Already correct, skip
                        continue;
                    }
                    // Needs update (schedule or enabled changed)
                    match self.upsert_job(job_name, schedule, feed_name, feed.flags.enabled) {
                        Ok(()) => {
                            info!("dkron: updated job '{}'", job_name);
                            report.updated += 1;
                        }
                        Err(e) => {
                            warn!("dkron: failed to update job '{}': {}", job_name, e);
                            report.errors.push(format!("update '{}': {}", job_name, e));
                        }
                    }
                } else {
                    // New job
                    match self.upsert_job(job_name, schedule, feed_name, feed.flags.enabled) {
                        Ok(()) => {
                            info!("dkron: created job '{}'", job_name);
                            report.created += 1;
                        }
                        Err(e) => {
                            warn!("dkron: failed to create job '{}': {}", job_name, e);
                            report.errors.push(format!("create '{}': {}", job_name, e));
                        }
                    }
                }
            }
        }

        // Delete orphan jobs (sftpflow-prefixed but not in expected set)
        for job_name in existing.keys() {
            if !expected_names.contains(job_name) {
                match self.delete_job(job_name) {
                    Ok(()) => {
                        info!("dkron: deleted orphan job '{}'", job_name);
                        report.deleted += 1;
                    }
                    Err(e) => {
                        warn!("dkron: failed to delete orphan '{}': {}", job_name, e);
                        report.errors.push(format!("delete '{}': {}", job_name, e));
                    }
                }
            }
        }

        info!(
            "dkron reconcile: created={}, updated={}, deleted={}, errors={}",
            report.created, report.updated, report.deleted, report.errors.len()
        );

        report
    }

    // --------------------------------------------------------
    // Per-feed operations (called after mutations)
    // --------------------------------------------------------

    /// Sync a single feed's schedules to dkron. Deletes any existing
    /// jobs for the feed first, then creates new ones.
    pub fn sync_feed(&self, feed_name: &str, feed: &Feed) {
        if let Err(e) = self.delete_feed_jobs(feed_name) {
            warn!("dkron: failed to clean up jobs for '{}': {}", feed_name, e);
        }

        for (i, schedule) in feed.schedules.iter().enumerate() {
            let job_name = if feed.schedules.len() == 1 {
                format!("sftpflow-{}", feed_name)
            } else {
                format!("sftpflow-{}-{}", feed_name, i)
            };

            match self.upsert_job(&job_name, schedule, feed_name, feed.flags.enabled) {
                Ok(()) => info!("dkron: synced job '{}'", job_name),
                Err(e) => warn!("dkron: failed to sync job '{}': {}", job_name, e),
            }
        }
    }

    /// Delete all dkron jobs belonging to a feed.
    pub fn delete_feed_jobs(&self, feed_name: &str) -> Result<(), String> {
        let jobs = self.list_sftpflow_jobs()?;
        let base = format!("sftpflow-{}", feed_name);

        for job_name in jobs.keys() {
            if is_feed_job(job_name, &base) {
                self.delete_job(job_name)?;
            }
        }

        Ok(())
    }

    // --------------------------------------------------------
    // Low-level HTTP helpers
    // --------------------------------------------------------

    /// List all dkron jobs whose name starts with "sftpflow-".
    fn list_sftpflow_jobs(&self) -> Result<HashMap<String, DkronJobInfo>, String> {
        let url = format!("{}/v1/jobs", self.base_url);
        let resp = ureq::get(&url)
            .call()
            .map_err(|e| format!("GET /v1/jobs: {}", e))?;

        let jobs: Vec<DkronJobInfo> = resp
            .into_json()
            .map_err(|e| format!("parse job list: {}", e))?;

        let mut map = HashMap::new();
        for job in jobs {
            if job.name.starts_with("sftpflow-") {
                map.insert(job.name.clone(), job);
            }
        }
        Ok(map)
    }

    /// Create or replace a single dkron job.
    fn upsert_job(
        &self,
        job_name: &str,
        schedule: &str,
        feed_name: &str,
        enabled: bool,
    ) -> Result<(), String> {
        let mut tags = HashMap::new();
        tags.insert("role".to_string(), "sftpflow-worker:1".to_string());

        let mut executor_config = HashMap::new();
        executor_config.insert(
            "command".to_string(),
            format!("sftpflow run {}", feed_name),
        );

        let body = DkronJobBody {
            name: job_name.to_string(),
            schedule: schedule.to_string(),
            executor: "shell".to_string(),
            executor_config,
            disabled: !enabled,
            tags,
            concurrency: "forbid".to_string(),
        };

        let json = serde_json::to_string(&body)
            .map_err(|e| format!("serialize: {}", e))?;

        let url = format!("{}/v1/jobs", self.base_url);
        ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&json)
            .map_err(|e| format!("POST /v1/jobs: {}", e))?;

        Ok(())
    }

    /// Delete a single dkron job by name. 404 is not an error.
    fn delete_job(&self, job_name: &str) -> Result<(), String> {
        let url = format!("{}/v1/jobs/{}", self.base_url, job_name);
        match ureq::delete(&url).call() {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(404, _)) => Ok(()), // already gone
            Err(e) => Err(format!("DELETE /v1/jobs/{}: {}", job_name, e)),
        }
    }
}

// ============================================================
// Helpers
// ============================================================

/// Build the expected job name(s) for a feed given its schedule count.
fn job_names_for_feed(feed_name: &str, schedule_count: usize) -> Vec<String> {
    if schedule_count == 0 {
        return Vec::new();
    }
    if schedule_count == 1 {
        return vec![format!("sftpflow-{}", feed_name)];
    }
    (0..schedule_count)
        .map(|i| format!("sftpflow-{}-{}", feed_name, i))
        .collect()
}

/// Check whether a dkron job name belongs to a feed.
/// Matches "sftpflow-<feed>" exactly, or "sftpflow-<feed>-<number>".
fn is_feed_job(job_name: &str, base: &str) -> bool {
    if job_name == base {
        return true;
    }
    if let Some(suffix) = job_name.strip_prefix(&format!("{}-", base)) {
        suffix.parse::<usize>().is_ok()
    } else {
        false
    }
}
