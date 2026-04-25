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

pub mod dkron;       // dkron.rs - Dkron scheduler reconciliation
mod handlers;        // handlers.rs - RPC method implementations
mod history;         // history.rs - SQLite run history persistence
mod secrets;         // secrets.rs - sealed credential store (age-encrypted)
mod server;          // server.rs - listener + connection handling + dispatch
mod node_state;      // node_state.rs - per-node persistent state (M12+)
mod cluster_runtime; // cluster_runtime.rs - async Raft orchestration (M12+)

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
// cmd_init - bootstrap a new cluster with this node as solo leader
// ============================================================
//
// Follows docs/m12-raft-scaffolding.md §5.1:
//
//   1. Refuse if node.json already exists.
//   2. Open the sealed secrets store (passphrase required — we
//      need somewhere to stash the token-HMAC secret).
//   3. Generate cluster_id + CA + leaf cert + token secret.
//   4. Persist node.json + cluster/*.{crt,key} + token secret.
//   5. Bring up the Raft runtime (tokio) and initialize_solo.
//   6. Enter the NDJSON serve loop (blocking, main thread).
//
// The Raft runtime lives on a tokio Runtime created here; the
// sync NDJSON server runs on the main thread. Tokio worker
// threads keep the gRPC server alive as long as the Runtime
// isn't dropped. On NDJSON server exit, we drop the
// ClusterNode (aborts its gRPC task) and the Runtime (shuts
// down the workers).

fn cmd_init(daemon: DaemonArgs, args: InitArgs) -> Result<(), String> {
    let state_dir = daemon.state_dir.clone().unwrap_or_else(default_state_dir);

    // ---- 1. Refuse to clobber an existing node state ----
    let node_json_path = node_state::node_json_path(&state_dir);
    if node_json_path.exists() {
        return Err(format!(
            "{} already exists — refusing to re-initialize. Run \
             `sftpflowd run` to start this node, or remove the \
             state directory if you really want to start over",
            node_json_path.display(),
        ));
    }

    // ---- 2. Sealed secrets store ----
    // Needed unconditionally during init: we must write the
    // token-HMAC secret somewhere, and the sealed store is the
    // only place the daemon encrypts at rest.
    let passphrase = secrets::load_passphrase(daemon.passphrase_file.as_deref())?
        .ok_or_else(|| {
            "sftpflowd init requires a master passphrase \
             (--passphrase-file PATH or SFTPFLOW_PASSPHRASE env var) \
             so the cluster token-HMAC secret can be sealed in the \
             credential store"
                .to_string()
        })?;
    let secrets_path = daemon.secrets.clone().unwrap_or_else(secrets::default_secrets_path);
    let mut secrets_store = secrets::SecretStore::open(&secrets_path, passphrase)
        .map_err(|e| format!("opening sealed store at '{}': {}", secrets_path.display(), e))?;

    // ---- 3. Resolve bind + advertise ----
    let bind_addr: std::net::SocketAddr = args.bind.parse().map_err(|e| {
        format!("--bind '{}' must be IP:PORT (e.g. 0.0.0.0:7900): {}", args.bind, e)
    })?;
    let advertise_addr = args.advertise.clone().unwrap_or_else(|| args.bind.clone());

    // ---- 4. Generate cluster identity + crypto ----
    let cluster_id = uuid::Uuid::new_v4().to_string();
    let ca = sftpflow_cluster::tls::ClusterCa::generate(&cluster_id)
        .map_err(|e| format!("generating cluster CA: {}", e))?;
    let leaf = sftpflow_cluster::tls::LeafKeyPair::generate(args.node_id, &advertise_addr)
        .map_err(|e| format!("generating leaf key pair: {}", e))?;
    let csr_der = leaf.csr_der()
        .map_err(|e| format!("serializing leaf CSR: {}", e))?;
    let leaf_cert_pem = ca.sign_csr(&csr_der)
        .map_err(|e| format!("self-signing leaf cert: {}", e))?;
    let token_secret = sftpflow_cluster::token::TokenSecret::generate();

    info!(
        "init: generated cluster_id={} node_id={} advertise={}",
        cluster_id, args.node_id, advertise_addr,
    );

    // ---- 5. Persist node.json + certs ----
    let node = node_state::NodeJson {
        version:         node_state::NODE_JSON_VERSION,
        node_id:         args.node_id,
        cluster_id:      cluster_id.clone(),
        advertise_addr:  advertise_addr.clone(),
        label:           args.label.clone(),
        created_at_unix: node_state::now_unix(),
    };
    node_state::write_node_json(&state_dir, &node)?;
    node_state::write_pem(&node_state::ca_cert_path(&state_dir),   &ca.cert_pem(),   false)?;
    node_state::write_pem(&node_state::ca_key_path(&state_dir),    &ca.key_pem(),    true)?;
    node_state::write_pem(&node_state::leaf_cert_path(&state_dir), &leaf_cert_pem,   false)?;
    node_state::write_pem(&node_state::leaf_key_path(&state_dir),  &leaf.key_pem(),  true)?;

    info!("init: wrote cluster state under {}", state_dir.display());

    // ---- 6. Stash the token secret in the sealed store ----
    // Base64-encode the 32 raw bytes because SecretStore values
    // are utf-8 strings. This is round-tripped via
    // `TokenSecret::from_bytes(base64::decode(...))` when the
    // daemon restarts (that code path arrives with `cmd_run`'s
    // cluster branch in a subsequent commit).
    use base64::Engine as _;
    let token_b64 = base64::engine::general_purpose::STANDARD
        .encode(token_secret.as_bytes());
    secrets_store
        .put(node_state::CLUSTER_TOKEN_SECRET_KEY.to_string(), token_b64)
        .map_err(|e| format!("sealing token secret: {}", e))?;
    info!("init: sealed {} into credential store", node_state::CLUSTER_TOKEN_SECRET_KEY);

    // ---- 7. Daemon prelude (config, run history) ----
    let config = Config::load();
    info!(
        "init: loaded config (endpoints={}, keys={}, feeds={})",
        config.endpoints.len(), config.keys.len(), config.feeds.len(),
    );
    let db_path = daemon.db.clone().unwrap_or_else(default_db_path);
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
    let ndjson_addr = daemon.socket.clone().unwrap_or_else(default_socket_addr);

    // ---- 8. Start Raft under a tokio runtime ----
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sftpflowd-cluster")
        .build()
        .map_err(|e| format!("building tokio runtime: {}", e))?;

    let cluster_node = rt.block_on(cluster_runtime::bootstrap(cluster_runtime::BootstrapParams {
        state_dir:     state_dir.clone(),
        node:          node.clone(),
        bind_addr,
        ca_cert_pem:   ca.cert_pem(),
        leaf_cert_pem,
        leaf_key_pem:  leaf.key_pem(),
        token_secret,
    }))?;

    info!(
        "init: cluster bootstrapped (node_id={}, cluster_id={})",
        node.node_id, node.cluster_id,
    );

    // ---- 9. Enter NDJSON serve loop ----
    info!("NDJSON server listening on {}", ndjson_addr);
    let serve_result = server::run(&ndjson_addr, config, run_db, Some(secrets_store))
        .map_err(|e| format!("NDJSON server: {}", e));

    // Explicit teardown order: drop cluster node first (aborts
    // its gRPC task while the runtime is still alive), then drop
    // the runtime (shuts down workers). `_` in `let _` would drop
    // them in the wrong order.
    drop(cluster_node);
    drop(rt);
    serve_result
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
    // Refuse to start in legacy single-node mode if the state
    // directory already contains a node.json written by a prior
    // `sftpflowd init` or `join`. Otherwise we'd silently ignore
    // the cluster state and come up as a single-node daemon,
    // which is confusing and unsafe (mutations wouldn't replicate).
    // Cluster-mode restart lands with the next PR-B commit;
    // surfacing the guard now prevents accidents.
    let state_dir = daemon.state_dir.clone().unwrap_or_else(default_state_dir);
    if let Some(n) = node_state::read_node_json(&state_dir)? {
        return Err(format!(
            "{} identifies this host as cluster member node_id={} of \
             cluster_id={}. Cluster-mode restart is not yet wired; it \
             lands with the next PR-B commit. Until then, to run the \
             daemon in legacy single-node mode, point --state-dir at a \
             directory that does not contain node.json.",
            node_state::node_json_path(&state_dir).display(),
            n.node_id, n.cluster_id,
        ));
    }

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
