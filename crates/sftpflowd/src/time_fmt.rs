// ============================================================
// sftpflowd::time_fmt - shared UTC timestamp formatting
// ============================================================
//
// Centralizes the ISO 8601 + civil-calendar helpers that used to
// be duplicated across handlers.rs and audit.rs. We hand-roll the
// formatting (rather than pulling chrono) so the daemon's runtime
// dependencies stay minimal — the algorithm is Howard Hinnant's
// civil-from-days, which is exact for any sane wall-clock value
// and doesn't need leap-second awareness for log/audit purposes.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format the current wall-clock time as `YYYY-MM-DDTHH:MM:SSZ`
/// (UTC). Falls back to the epoch if the system clock is set
/// before 1970, which is closer to "obviously wrong in the log"
/// than crashing.
pub fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso8601_from_unix(secs)
}

/// Pair the current wall-clock as both unix-seconds and ISO 8601
/// in one call. The audit log stores both; emitting them together
/// guarantees they refer to the same instant (no risk of a sub-
/// microsecond skew between formatting the two values separately).
pub fn now_unix_and_iso() -> (i64, String) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (secs, iso8601_from_unix(secs))
}

/// Format an absolute unix-seconds value as `YYYY-MM-DDTHH:MM:SSZ`.
/// Negative values clamp to the epoch.
pub fn iso8601_from_unix(unix_secs: i64) -> String {
    let secs = unix_secs.max(0) as u64;
    let days_since_epoch = secs / 86400;
    let time_of_day      = secs % 86400;
    let hours   = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (y, m, d) = civil_from_days(days_since_epoch as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds,
    )
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's
/// civil-from-days algorithm. Exact for the proleptic Gregorian
/// calendar; no leap-second handling (acceptable for log-class
/// timestamps).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_from_unix_known_values() {
        // 1970-01-01T00:00:00Z is the epoch.
        assert_eq!(iso8601_from_unix(0), "1970-01-01T00:00:00Z");
        // 2024-01-01T00:00:00Z = 1704067200 unix seconds — sanity
        // check on a known-round date.
        assert_eq!(iso8601_from_unix(1_704_067_200), "2024-01-01T00:00:00Z");
        // Negative clamps to epoch rather than panicking.
        assert_eq!(iso8601_from_unix(-1), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn civil_from_days_round_trips_recent() {
        // Day 0 is 1970-01-01.
        assert_eq!(civil_from_days(0),  (1970, 1, 1));
        // Day 19_723 is 2024-01-01 (1704067200 / 86400).
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }
}
