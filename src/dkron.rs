// ============================================================
// dkron.rs - Dkron scheduler API client
// ============================================================
//
// Pushes feed schedules to a dkron cluster as shell-executor jobs.
// Each scheduled feed becomes one or more dkron jobs named:
//   sftpflow-<feed>        (single schedule)
//   sftpflow-<feed>-<idx>  (multiple schedules)
//
// Workers must have the sftpflow binary in PATH and access to the
// sftpflow config (via SFTPFLOW_CONFIG or ~/.sftpflow/config.yaml).

use serde::Serialize;
use std::collections::HashMap;

// ---- Request structs sent to the dkron HTTP API ----

#[derive(Debug, Serialize)]
struct JobBody {
    name: String,
    schedule: String,
    executor: String,
    executor_config: HashMap<String, String>,
    disabled: bool,
    tags: HashMap<String, String>,
    concurrency: String,
}

#[derive(Debug, Serialize)]
struct JobRequest {
    job: JobBody,
}

// ---- Client ----

pub struct DkronClient {
    base_url: String,
}

impl DkronClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Create or replace all dkron jobs for a feed.
    /// Any previously registered jobs for the feed are deleted first.
    pub fn upsert_feed_jobs(
        &self,
        feed_name: &str,
        schedules: &[String],
        enabled: bool,
    ) -> Result<(), String> {
        self.delete_feed_jobs(feed_name)?;

        let mut tags = HashMap::new();
        // "sftpflow-worker:1" → run on exactly 1 node tagged role=sftpflow-worker
        tags.insert("role".to_string(), "sftpflow-worker:1".to_string());

        for (i, schedule) in schedules.iter().enumerate() {
            let job_name = if schedules.len() == 1 {
                format!("sftpflow-{}", feed_name)
            } else {
                format!("sftpflow-{}-{}", feed_name, i)
            };

            let mut executor_config = HashMap::new();
            executor_config.insert(
                "command".to_string(),
                format!("sftpflow run {}", feed_name),
            );

            let job = JobBody {
                name: job_name.clone(),
                schedule: schedule.clone(),
                executor: "shell".to_string(),
                executor_config,
                disabled: !enabled,
                tags: tags.clone(),
                concurrency: "forbid".to_string(),
            };

            let body = serde_json::to_string(&JobRequest { job })
                .map_err(|e| format!("serialize error: {}", e))?;

            let url = format!("{}/v1/jobs", self.base_url);
            ureq::post(&url)
                .set("Content-Type", "application/json")
                .send_string(&body)
                .map_err(|e| format!("failed to upsert job '{}': {}", job_name, e))?;
        }

        Ok(())
    }

    /// Delete all dkron jobs that belong to a feed.
    pub fn delete_feed_jobs(&self, feed_name: &str) -> Result<(), String> {
        let url = format!("{}/v1/jobs", self.base_url);
        let resp = ureq::get(&url)
            .call()
            .map_err(|e| format!("failed to list dkron jobs: {}", e))?;

        let jobs: Vec<serde_json::Value> = resp
            .into_json()
            .map_err(|e| format!("failed to parse job list: {}", e))?;

        let base = format!("sftpflow-{}", feed_name);

        for job in jobs {
            let name = match job["name"].as_str() {
                Some(n) => n.to_string(),
                None => continue,
            };

            let is_match = name == base || {
                // Also matches sftpflow-<feed>-<number>
                if let Some(suffix) = name.strip_prefix(&format!("{}-", base)) {
                    suffix.parse::<usize>().is_ok()
                } else {
                    false
                }
            };

            if is_match {
                let del_url = format!("{}/v1/jobs/{}", self.base_url, name);
                match ureq::delete(&del_url).call() {
                    Ok(_) => {}
                    // 404 is fine — job already gone
                    Err(ureq::Error::Status(404, _)) => {}
                    Err(e) => {
                        return Err(format!("failed to delete job '{}': {}", name, e));
                    }
                }
            }
        }

        Ok(())
    }
}
