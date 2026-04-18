// ============================================================
// sftpflowd - entry point
// ============================================================
//
// Parses command-line arguments, initializes logging, loads the
// YAML config, and hands off to the server loop.
//
// Usage:
//   sftpflowd                                    (platform defaults)
//   sftpflowd --socket <addr>                    (override listen address)
//   sftpflowd --db <path>                        (override runs.db path)
//   sftpflowd --secrets <path>                   (override sealed store path)
//   sftpflowd --passphrase-file <path>           (unlock sealed store)
//   SFTPFLOW_PASSPHRASE=... sftpflowd            (passphrase via env)
//
// Address formats:
//   unix:/path/to/sock   - Unix domain socket (Linux only)
//   tcp:host:port        - TCP loopback
//   host:port            - bare form; defaults to tcp

use std::process;

use log::{error, info, warn};

use sftpflow_core::Config;

pub mod dkron;    // dkron.rs - Dkron scheduler reconciliation
mod handlers; // handlers.rs - RPC method implementations
mod history;  // history.rs - SQLite run history persistence
mod secrets;  // secrets.rs - sealed credential store (age-encrypted)
mod server;   // server.rs - listener + connection handling + dispatch

// ============================================================
// main
// ============================================================

fn main() {
    // Initialize logging (RUST_LOG=info to see output).
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let args: Vec<String> = std::env::args().collect();

    // Parse --socket <addr> if present; otherwise fall back to the
    // platform default (unix socket on Linux, TCP loopback on Windows).
    let socket_addr = match parse_named_arg(&args, "--socket") {
        Ok(Some(addr)) => addr,
        Ok(None)       => default_socket_addr(),
        Err(e) => {
            eprintln!("% {}", e);
            process::exit(2);
        }
    };

    // Parse --db <path> for the run-history SQLite database.
    let db_path = match parse_named_arg(&args, "--db") {
        Ok(Some(p)) => std::path::PathBuf::from(p),
        Ok(None)    => default_db_path(),
        Err(e) => {
            eprintln!("% {}", e);
            process::exit(2);
        }
    };

    // Parse --secrets <path> for the sealed-credential store.
    let secrets_path = match parse_named_arg(&args, "--secrets") {
        Ok(Some(p)) => std::path::PathBuf::from(p),
        Ok(None)    => secrets::default_secrets_path(), // secrets.rs
        Err(e) => {
            eprintln!("% {}", e);
            process::exit(2);
        }
    };

    // Parse --passphrase-file <path> (or fall back to SFTPFLOW_PASSPHRASE).
    let passphrase_file = match parse_named_arg(&args, "--passphrase-file") {
        Ok(v) => v.map(std::path::PathBuf::from),
        Err(e) => {
            eprintln!("% {}", e);
            process::exit(2);
        }
    };

    // Load the shared config. The daemon owns this at runtime; the CLI
    // will mutate it through RPC (not by editing the YAML directly).
    let config = Config::load();

    info!(
        "sftpflowd v{} starting (endpoints={}, keys={}, feeds={})",
        env!("CARGO_PKG_VERSION"),
        config.endpoints.len(),
        config.keys.len(),
        config.feeds.len(),
    );
    // Startup scheduler reconciliation: sync feed schedules to dkron
    // if a dkron_url is configured. Best-effort — warn on errors but
    // don't prevent the daemon from starting.
    if let Some(ref dkron_url) = config.server.dkron_url {
        info!("dkron startup sync → {}", dkron_url);
        let client = dkron::DkronClient::new(dkron_url); // dkron.rs
        let report = client.reconcile_all(&config.feeds);
        info!(
            "dkron startup sync complete: created={}, updated={}, deleted={}, errors={}",
            report.created, report.updated, report.deleted, report.errors.len()
        );
        for err in &report.errors {
            warn!("dkron startup sync error: {}", err);
        }
    } else {
        info!("no dkron_url configured; scheduler sync disabled");
    }

    // Open the run-history SQLite database. Best-effort — if it
    // fails, the daemon still starts but runs won't be recorded.
    let run_db = match history::RunDb::open(&db_path) {
        Ok(db) => {
            info!("run history database ready at '{}'", db_path.display());
            Some(db)
        }
        Err(e) => {
            warn!("could not open run history database: {} — runs will not be recorded", e);
            None
        }
    };

    // Load the master passphrase and unlock the sealed credential
    // store. Missing passphrase is allowed (legacy configs with
    // plaintext passwords keep working), but any feed that uses a
    // `*_ref` field will then fail at run time with a clear message.
    let secret_store = match secrets::load_passphrase(passphrase_file.as_deref()) {
        Ok(Some(passphrase)) => match secrets::SecretStore::open(&secrets_path, passphrase) {
            Ok(store) => {
                info!("sealed credential store ready at '{}'", secrets_path.display());
                Some(store)
            }
            Err(e) => {
                error!("could not open sealed credential store: {}", e);
                process::exit(1);
            }
        },
        Ok(None) => {
            warn!(
                "no master passphrase provided — sealed credential store will not be \
                 available; feeds using password_ref / ssh_key_ref / contents_ref will fail"
            );
            None
        }
        Err(e) => {
            eprintln!("% {}", e);
            process::exit(2);
        }
    };

    info!("listening on {}", socket_addr);

    // server::run() - server.rs
    if let Err(e) = server::run(&socket_addr, config, run_db, secret_store) {
        error!("server error: {}", e);
        process::exit(1);
    }
}

// ============================================================
// Argument helpers
// ============================================================

/// Scan `args` for a named flag (e.g. `--socket`, `--db`).
/// Returns:
///   Ok(Some(value)) - flag provided with a value
///   Ok(None)        - flag not present
///   Err(msg)        - flag present but missing a value
fn parse_named_arg(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == flag {
            if i + 1 >= args.len() {
                return Err(format!("{} requires an argument", flag));
            }
            return Ok(Some(args[i + 1].clone()));
        }
        i += 1;
    }
    Ok(None)
}

/// Platform default listen address.
/// - Linux (and other Unix): `/tmp/sftpflow.sock` (simple default;
///   production deployment will use `/run/sftpflow.sock` with
///   systemd managing permissions).
/// - Windows: TCP loopback on port 7777 (dev convenience).
fn default_socket_addr() -> String {
    #[cfg(unix)]
    {
        "unix:/tmp/sftpflow.sock".to_string()
    }
    #[cfg(not(unix))]
    {
        "tcp:127.0.0.1:7777".to_string()
    }
}

/// Platform default path for the run-history SQLite database.
/// - Linux: `/var/lib/sftpflow/runs.db`
/// - Windows: `%APPDATA%/sftpflow/runs.db` (dev convenience)
fn default_db_path() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/var/lib/sftpflow/runs.db")
    }
    #[cfg(not(unix))]
    {
        let base = std::env::var("APPDATA")
            .unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(base).join("sftpflow").join("runs.db")
    }
}
