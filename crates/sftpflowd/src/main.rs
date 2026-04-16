// ============================================================
// sftpflowd - entry point
// ============================================================
//
// Parses command-line arguments, initializes logging, loads the
// YAML config, and hands off to the server loop.
//
// Usage:
//   sftpflowd                        (use the platform default address)
//   sftpflowd --socket <addr>        (override the listen address)
//
// Address formats:
//   unix:/path/to/sock   - Unix domain socket (Linux only)
//   tcp:host:port        - TCP loopback
//   host:port            - bare form; defaults to tcp

use std::process;

use log::{error, info};

use sftpflow_core::Config;

mod handlers; // handlers.rs - RPC method implementations
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
    let socket_addr = match parse_socket_arg(&args) {
        Ok(Some(addr)) => addr,
        Ok(None)       => default_socket_addr(),
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
    info!("listening on {}", socket_addr);

    // server::run() - server.rs
    if let Err(e) = server::run(&socket_addr, config) {
        error!("server error: {}", e);
        process::exit(1);
    }
}

// ============================================================
// Argument helpers
// ============================================================

/// Scan `args` for `--socket <addr>`. Returns:
///   Ok(Some(addr)) - flag provided with a value
///   Ok(None)       - flag not present
///   Err(msg)       - flag present but missing a value
fn parse_socket_arg(args: &[String]) -> Result<Option<String>, String> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--socket" {
            if i + 1 >= args.len() {
                return Err("--socket requires an address argument".to_string());
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
