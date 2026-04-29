use std::process;

// sftpflow-core provides the shared data models (Endpoint, Feed, Config, ...)
// so the future daemon and transport crates can reuse them. Aliasing to
// `feed` keeps the existing `feed::Config` call sites in this crate unchanged.
pub use sftpflow_core as feed;

mod cli;       // cli.rs - interactive shell loop and command dispatch
mod commands;  // commands.rs - command implementations
mod completer; // completer.rs - rustyline tab-completion helper
pub mod rpc;   // rpc.rs - RPC client for talking to sftpflowd

fn main() {
    // Initialize logging (set RUST_LOG=info to see log output)
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    // Parse --socket <addr> for dev/direct-connect mode.
    // Falls back to SFTPFLOW_SOCKET env var (used by dkron workers).
    let socket_addr = parse_socket_arg(&args)
        .or_else(|| std::env::var("SFTPFLOW_SOCKET").ok());

    // Non-interactive mode: sftpflow run <feed-name>
    // This is how dkron worker nodes invoke sftpflow. Connects to
    // the daemon via RPC and sends RunFeedNow.
    if args.len() >= 3 && args[1] == "run" {
        let feed_name = &args[2];
        let config = feed::Config::load();

        // Connect to daemon: prefer --socket if given, otherwise SSH
        let mut client = if let Some(ref addr) = socket_addr {
            match rpc::RpcClient::connect_socket(addr) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("% Failed to connect to daemon at {}: {}", addr, e);
                    process::exit(1);
                }
            }
        } else {
            match rpc::RpcClient::connect_ssh(&config.server) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("% Failed to connect to daemon via SSH: {}", e);
                    process::exit(1);
                }
            }
        };

        // Send RunFeedNow RPC
        use sftpflow_proto::{Request, Response, RunStatus};
        match client.call(Request::RunFeedNow { name: feed_name.to_string() }) {
            Ok(Response::RunResult(result)) => {
                println!(
                    "Feed '{}': status={:?}, files_transferred={}",
                    result.feed, result.status, result.files_transferred
                );
                if let Some(ref msg) = result.message {
                    println!("  {}", msg);
                }
                match result.status {
                    RunStatus::Success | RunStatus::Noaction => process::exit(0),
                    RunStatus::Failed => process::exit(1),
                }
            }
            Ok(other) => {
                eprintln!("% Unexpected response: {:?}", other);
                process::exit(1);
            }
            Err(e) => {
                eprintln!("% RPC error: {}", e);
                process::exit(1);
            }
        }
    }

    // Interactive shell
    println!("SFTPflow v{}", env!("CARGO_PKG_VERSION"));
    println!("Type 'help' for a list of commands.\n");

    if let Err(e) = cli::run(socket_addr) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

// ============================================================
// Argument helpers
// ============================================================

/// Scan for `--socket <addr>`. Returns Some(addr) if present.
fn parse_socket_arg(args: &[String]) -> Option<String> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--socket" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}
