use std::process;

// sftpflow-core provides the shared data models (Endpoint, Feed, Config, ...)
// so the future daemon and transport crates can reuse them. Aliasing to
// `feed` keeps the existing `feed::Config` call sites in this crate unchanged.
pub use sftpflow_core as feed;

mod cli;       // cli.rs - interactive shell loop and command dispatch
mod commands;  // commands.rs - command implementations
mod completer; // completer.rs - rustyline tab-completion helper
mod output;    // output.rs - human / JSON / quiet output helpers
pub mod rpc;   // rpc.rs - RPC client for talking to sftpflowd

use crate::output::{Output, OutputMode};

fn main() {
    // Initialize logging (set RUST_LOG=info to see log output)
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    // ----------------------------------------------------------
    // Parse global flags
    // ----------------------------------------------------------
    //
    // Global flags can appear anywhere on the command line — we
    // strip them out into a separate vector so the remaining
    // tokens are just the (optional) command + its args.
    //
    //   sftpflow --json show feeds
    //   sftpflow show --json feeds        (also accepted)
    //   sftpflow -q --socket /tmp/s show feeds
    //
    // After parsing, `positional` holds whatever's left. Empty =>
    // interactive shell; non-empty => one-shot non-interactive run.
    let parsed = parse_global_flags(&args[1..]);

    // SFTPFLOW_SOCKET env var still supported as a fallback for
    // dkron workers that invoke `sftpflow run` without flags.
    let socket_addr = parsed.socket_addr
        .or_else(|| std::env::var("SFTPFLOW_SOCKET").ok());

    let out = Output {
        mode: if parsed.json { OutputMode::Json } else { OutputMode::Human },
        quiet: parsed.quiet,
    };

    // ----------------------------------------------------------
    // Non-interactive mode: run one command and exit.
    // ----------------------------------------------------------
    //
    // Triggered by any positional arg(s) being present. Replaces
    // the old special-cased `sftpflow run <feed>` block — that
    // path now goes through the same dispatch as any other
    // command, so `sftpflow show feeds`, `sftpflow cluster status`,
    // and `sftpflow run feed nightly` all work uniformly.
    if !parsed.positional.is_empty() {
        let exit_code = cli::run_one_shot(socket_addr, out, &parsed.positional);
        process::exit(exit_code);
    }

    // ----------------------------------------------------------
    // Interactive shell
    // ----------------------------------------------------------
    //
    // The startup banner is suppressed in JSON / quiet mode so a
    // script that opens an interactive session via -i (rare, but
    // possible) doesn't see a spurious version line.
    if out.is_human() && !out.quiet {
        println!("SFTPflow v{}", env!("CARGO_PKG_VERSION"));
        println!("Type 'help' for a list of commands.\n");
    }

    if let Err(e) = cli::run(socket_addr, out) {
        out.error(format!("{}", e));
        process::exit(1);
    }
}

// ============================================================
// Argument helpers
// ============================================================

#[derive(Default)]
struct ParsedArgs {
    socket_addr: Option<String>,
    json:        bool,
    quiet:       bool,
    positional:  Vec<String>,
}

/// Walk argv (excluding argv[0]), pulling out global flags and
/// leaving any non-flag tokens in `positional`. Unrecognized flags
/// pass through as positional tokens — the dispatch path handles
/// them as command syntax errors, which keeps this parser permissive.
fn parse_global_flags(args: &[String]) -> ParsedArgs {
    let mut parsed = ParsedArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                if i + 1 < args.len() {
                    parsed.socket_addr = Some(args[i + 1].clone());
                    i += 2;
                    continue;
                } else {
                    eprintln!("% --socket requires an argument");
                    process::exit(2);
                }
            }
            "--json" => {
                parsed.json = true;
                i += 1;
                continue;
            }
            "-q" | "--quiet" => {
                parsed.quiet = true;
                i += 1;
                continue;
            }
            other => {
                parsed.positional.push(other.to_string());
                i += 1;
            }
        }
    }
    parsed
}
