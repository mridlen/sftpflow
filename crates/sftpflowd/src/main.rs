// ============================================================
// sftpflowd - entry point
// ============================================================
//
// Parses command-line arguments, initializes logging, and hands
// off to one of three subcommand flows:
//
//   sftpflowd init  ...   Bootstrap a new cluster; this node
//                         becomes the solo voting leader.
//   sftpflowd join  ...   Join an existing cluster via a seed.
//   sftpflowd run  [or no subcommand]
//                         Run the daemon. If a prior `init` or
//                         `join` wrote node.json, come up as a
//                         cluster member. Otherwise fall back to
//                         legacy single-node mode (deprecated;
//                         M13 removes this fallback).
//
// M12 PR-B status:
//   - `run` is fully wired (legacy single-node path).
//   - `init` and `join` print a descriptive stub message and exit
//     with a non-zero code. Subsequent PR-B commits flesh them
//     out one at a time. Rationale: lands the subcommand shape
//     first so reviewers can see the UX before the crypto /
//     bootstrap code follows.
//
// Legacy flag compatibility:
//   --socket / --db / --secrets / --passphrase-file continue to
//   work on the top-level invocation (i.e. `sftpflowd --socket x`
//   with no subcommand) so the existing docker test env and the
//   M11 smoke procedure keep working unchanged.

use std::path::PathBuf;
use std::process;

use clap::{Args, Parser, Subcommand};
use log::{error, info, warn};

use sftpflow_core::Config;

pub mod dkron;    // dkron.rs - Dkron scheduler reconciliation
mod handlers; // handlers.rs - RPC method implementations
mod history;  // history.rs - SQLite run history persistence
mod secrets;  // secrets.rs - sealed credential store (age-encrypted)
mod server;   // server.rs - listener + connection handling + dispatch

// ============================================================
// CLI shape
// ============================================================

#[derive(Parser)]
#[command(
    name    = "sftpflowd",
    version,
    about   = "SFTPflow daemon — scheduler, transfer engine, and (M12+) Raft cluster member",
    // Present the subcommands in the order below in --help output.
    // `arg_required_else_help = false` keeps `sftpflowd` with no
    // args running the default daemon, matching pre-M12 behavior.
    arg_required_else_help = false,
)]
struct Cli {
    /// Optional subcommand. Omit to run the daemon (equivalent to
    /// `sftpflowd run`).
    #[command(subcommand)]
    command: Option<Command>,

    /// Flags shared by every run path (init, join, run). Defined
    /// once here via `#[command(flatten)]` so the shapes stay in
    /// sync and so legacy invocations like `sftpflowd --socket X`
    /// keep parsing.
    #[command(flatten)]
    daemon: DaemonArgs,
}

// ============================================================
// DaemonArgs - shared across subcommands
// ============================================================

#[derive(Args, Clone, Debug)]
struct DaemonArgs {
    // Each flag is `global = true` so it can be supplied either at
    // the top level (`sftpflowd --socket X ...`, matching the
    // pre-M12 invocation form) or on any subcommand (`sftpflowd
    // init --socket X --node-id 1 ...`). Keeping both forms valid
    // lets existing scripts keep working and lets the init / join
    // flows accept the sealed-store passphrase on the same command
    // line as the cluster bootstrap args.

    /// Address the NDJSON RPC server listens on. Examples:
    ///   unix:/tmp/sftpflow.sock
    ///   tcp:127.0.0.1:7777
    ///   host:port   (defaults to tcp)
    #[arg(long, value_name = "ADDR", global = true)]
    socket: Option<String>,

    /// Path to the run-history SQLite database.
    #[arg(long, value_name = "PATH", global = true)]
    db: Option<PathBuf>,

    /// Path to the sealed credential store file.
    #[arg(long, value_name = "PATH", global = true)]
    secrets: Option<PathBuf>,

    /// Path to a file containing the master passphrase for the
    /// sealed credential store. If omitted, falls back to the
    /// SFTPFLOW_PASSPHRASE env var; if that's also missing, the
    /// store stays locked and any *_ref field will fail at run
    /// time.
    #[arg(long, value_name = "PATH", global = true)]
    passphrase_file: Option<PathBuf>,

    /// Base directory for per-node cluster state (node.json, CA +
    /// leaf certs, Raft log). Defaults to /var/lib/sftpflow on
    /// Linux or %APPDATA%\sftpflow on Windows. Unused by the
    /// legacy single-node fallback; arrives with cluster mode.
    #[arg(long, value_name = "PATH", global = true)]
    state_dir: Option<PathBuf>,
}

// ============================================================
// Subcommands
// ============================================================

#[derive(Subcommand)]
enum Command {
    /// Bootstrap a new cluster with this node as the solo voting
    /// leader. Generates the cluster CA, this node's leaf cert,
    /// and the token-minting secret; writes node.json + cluster/;
    /// initializes Raft as a single-member voter set.
    ///
    /// Refuses to run if node.json already exists.
    Init(InitArgs),

    /// Join an existing cluster via a seed (bootstrap) node.
    /// Requires a token minted on the seed via `sftpflow cluster
    /// token` and a copy of the cluster CA cert transferred
    /// out-of-band.
    ///
    /// Refuses to run if node.json already exists.
    Join(JoinArgs),

    /// Run the daemon. Default behavior when no subcommand is
    /// given. Comes up as a cluster member if node.json exists;
    /// otherwise falls back to legacy single-node mode.
    Run,
}

// ============================================================
// InitArgs
// ============================================================

#[derive(Args, Clone, Debug)]
struct InitArgs {
    /// This node's stable u64 ID. Must be unique across the
    /// cluster. Operator-supplied in M12 (auto-allocation lands
    /// in M15).
    #[arg(long, value_name = "N")]
    node_id: u64,

    /// host:port the Raft gRPC server binds to on this machine.
    /// Example: 0.0.0.0:7900
    #[arg(long, value_name = "ADDR")]
    bind: String,

    /// host:port other cluster members will dial to reach this
    /// node. Defaults to --bind. Differs when --bind is a
    /// wildcard or when traversing NAT.
    #[arg(long, value_name = "ADDR")]
    advertise: Option<String>,

    /// Optional human-readable label shown in `cluster status`
    /// (e.g. "west-coast replica").
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,
}

// ============================================================
// JoinArgs
// ============================================================

#[derive(Args, Clone, Debug)]
struct JoinArgs {
    /// host:port of the seed (bootstrap) node. The seed's
    /// BootstrapService.Join endpoint will accept the token,
    /// sign this node's CSR, and add it to the Raft membership.
    #[arg(value_name = "SEED_ADDR")]
    seed: String,

    /// Single-use join token minted on the seed via `sftpflow
    /// cluster token`. Tokens expire (default 1 hour) and a
    /// given nonce can only be redeemed once.
    #[arg(long, value_name = "TOKEN")]
    token: String,

    /// Path to the cluster CA certificate (PEM). Copied out of
    /// band from the seed node's cluster/ca.crt. Used to
    /// authenticate the seed's TLS cert during the anonymous
    /// join handshake.
    #[arg(long, value_name = "PATH")]
    ca_cert_file: PathBuf,

    /// This node's stable u64 ID. Must not collide with an
    /// existing member of the target cluster.
    #[arg(long, value_name = "N")]
    node_id: u64,

    /// host:port the Raft gRPC server binds to on this machine.
    #[arg(long, value_name = "ADDR")]
    bind: String,

    /// host:port other cluster members will dial to reach this
    /// node. Defaults to --bind.
    #[arg(long, value_name = "ADDR")]
    advertise: Option<String>,

    /// Optional human-readable label shown in `cluster status`.
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,
}

// ============================================================
// main
// ============================================================

fn main() {
    // Initialize logging (RUST_LOG=info to see output).
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let cli = Cli::parse();

    match cli.command {
        // ---- Cluster bootstrap (stubbed in the first PR-B commit)
        Some(Command::Init(args)) => {
            if let Err(e) = cmd_init(cli.daemon, args) {
                error!("init failed: {}", e);
                process::exit(1);
            }
        }

        // ---- Cluster join (stubbed in the first PR-B commit)
        Some(Command::Join(args)) => {
            if let Err(e) = cmd_join(cli.daemon, args) {
                error!("join failed: {}", e);
                process::exit(1);
            }
        }

        // ---- Default: run the daemon (legacy single-node path)
        Some(Command::Run) | None => {
            if let Err(e) = cmd_run(cli.daemon) {
                error!("{}", e);
                process::exit(1);
            }
        }
    }
}

// ============================================================
// cmd_init - stubbed; real implementation lands in next commit
// ============================================================

fn cmd_init(_daemon: DaemonArgs, args: InitArgs) -> Result<(), String> {
    // The subcommand is wired up but the crypto + Raft bootstrap
    // flow is intentionally left for the next PR-B commit so this
    // commit stays small and reviewable. See
    // docs/m12-raft-scaffolding.md §5.1 for the 12-step procedure
    // and crates/sftpflow-cluster/src/node.rs for the API we'll
    // consume.
    warn!(
        "init --node-id {} --bind {} --advertise {:?} --label {:?} \
         parsed successfully but cluster bootstrap is not yet \
         implemented (lands in the next PR-B commit)",
        args.node_id, args.bind, args.advertise, args.label,
    );
    Err("sftpflowd init is not yet implemented".to_string())
}

// ============================================================
// cmd_join - stubbed; real implementation lands in next commit
// ============================================================

fn cmd_join(_daemon: DaemonArgs, args: JoinArgs) -> Result<(), String> {
    warn!(
        "join {} --token <redacted> --ca-cert-file {} --node-id {} \
         --bind {} --advertise {:?} --label {:?} parsed successfully \
         but cluster join is not yet implemented (lands in the next \
         PR-B commit)",
        args.seed, args.ca_cert_file.display(), args.node_id,
        args.bind, args.advertise, args.label,
    );
    Err("sftpflowd join is not yet implemented".to_string())
}

// ============================================================
// cmd_run - the existing daemon path, preserved byte-for-byte
// ============================================================
//
// Identical in behavior to the pre-M12 main(): load config,
// reconcile dkron, open run history, unlock sealed store, start
// the NDJSON server. PR-B extends this to also bring up the
// cluster runtime when node.json exists, but that's a later
// commit — this one only renames the entry point.

fn cmd_run(daemon: DaemonArgs) -> Result<(), String> {
    let socket_addr = daemon.socket.unwrap_or_else(default_socket_addr);
    let db_path     = daemon.db.unwrap_or_else(default_db_path);
    let secrets_path = daemon.secrets.unwrap_or_else(secrets::default_secrets_path);

    // Load the shared config. The daemon owns this at runtime;
    // the CLI mutates it through RPC (not by editing the YAML).
    let config = Config::load();

    info!(
        "sftpflowd v{} starting (endpoints={}, keys={}, feeds={})",
        env!("CARGO_PKG_VERSION"),
        config.endpoints.len(),
        config.keys.len(),
        config.feeds.len(),
    );

    // Startup scheduler reconciliation: sync feed schedules to
    // dkron if a dkron_url is configured. Best-effort — warn on
    // errors but don't prevent the daemon from starting.
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
            warn!(
                "could not open run history database: {} — runs will not be recorded",
                e
            );
            None
        }
    };

    // Load the master passphrase and unlock the sealed credential
    // store. Missing passphrase is allowed (legacy configs with
    // plaintext passwords keep working), but any feed that uses
    // a `*_ref` field will then fail at run time with a clear
    // message.
    let secret_store = match secrets::load_passphrase(daemon.passphrase_file.as_deref()) {
        Ok(Some(passphrase)) => match secrets::SecretStore::open(&secrets_path, passphrase) {
            Ok(store) => {
                info!("sealed credential store ready at '{}'", secrets_path.display());
                Some(store)
            }
            Err(e) => {
                return Err(format!("could not open sealed credential store: {}", e));
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
            return Err(e);
        }
    };

    info!("listening on {}", socket_addr);

    // server::run() - server.rs
    server::run(&socket_addr, config, run_db, secret_store)
        .map_err(|e| format!("server error: {}", e))
}

// ============================================================
// Platform defaults
// ============================================================

/// Platform default listen address.
/// - Linux (and other Unix): `/tmp/sftpflow.sock`.
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
fn default_db_path() -> PathBuf {
    default_state_dir().join("runs.db")
}

/// Platform default base directory for daemon state (runs.db,
/// secrets.sealed, and — in cluster mode — node.json, cluster/,
/// raft/). Exposed as a standalone helper so the init/join flows
/// (next PR-B commit) can use the same resolution.
fn default_state_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sftpflow")
    }
    #[cfg(not(unix))]
    {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base).join("sftpflow")
    }
}
