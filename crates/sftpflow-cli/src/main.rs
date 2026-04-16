use std::process;

// sftpflow-core provides the shared data models (Endpoint, Feed, Config, ...)
// so the future daemon and transport crates can reuse them. Aliasing to
// `feed` keeps the existing `feed::Config` call sites in this crate unchanged.
pub use sftpflow_core as feed;

mod cli;      // cli.rs - interactive shell loop and command dispatch
mod commands; // commands.rs - command implementations
mod dkron;    // dkron.rs - dkron scheduler API client
pub mod rpc;  // rpc.rs - RPC client for talking to sftpflowd

fn main() {
    // Initialize logging (set RUST_LOG=info to see log output)
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    // Parse --socket <addr> for dev/direct-connect mode.
    let socket_addr = parse_socket_arg(&args);

    // Non-interactive mode: sftpflow run <feed-name>
    // This is how dkron worker nodes invoke sftpflow.
    if args.len() >= 3 && args[1] == "run" {
        let feed_name = &args[2];
        let config = feed::Config::load();

        match config.feeds.get(feed_name.as_str()) {
            Some(_feed) => {
                // TODO: implement actual file transfer execution
                println!("Executing feed '{}'...", feed_name);
                eprintln!("% Feed execution is not yet implemented.");
                process::exit(0);
            }
            None => {
                eprintln!("% Feed '{}' not found in config.", feed_name);
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
