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
// M12 PR-B status (complete):
//   - `init` and `join` are fully wired (CA + leaf cert generation,
//     sealed token secret, Raft startup, NDJSON serve loop).
//   - `run` branches on whether <state_dir>/node.json exists:
//     present → cluster-mode restart (bootstrap-node sub-path
//     re-installs the seed-side join handler; joiner sub-path
//     just brings Raft back up). Absent → legacy single-node
//     mode. The legacy fallback is removed in M13.
//   - Mutating RPCs are leader-gated: followers reply NOT_LEADER
//     instead of writing local state. M13 turns this into auto-
//     forwarding.
//   - `cluster status` / `cluster token` / `cluster remove` CLI
//     commands wired through new ClusterStatus / ClusterMintToken
//     / ClusterRemoveNode RPCs.
//   - Multi-process integration test at scripts/test-cluster.sh
//     drives docker/compose.cluster.yml through init / join /
//     status / leader-failover end-to-end (`make cluster-test`).
//
// Legacy flag compatibility:
//   --socket / --db / --secrets / --passphrase-file continue to
//   work on the top-level invocation (i.e. `sftpflowd --socket x`
//   with no subcommand) so the existing docker test env and the
//   M11 smoke procedure keep working unchanged.

use std::path::PathBuf;
use std::process;
use std::sync::Arc;

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
    Run(RunArgs),
}

// ============================================================
// RunArgs
// ============================================================

#[derive(Args, Clone, Debug, Default)]
struct RunArgs {
    /// IP:port the Raft gRPC server binds to on this machine.
    /// Only consulted in cluster mode (i.e. when node.json exists).
    /// Defaults to `0.0.0.0:<port-from-advertise>` so a no-args
    /// restart works in the common case (bind on all interfaces,
    /// port from the advertise address recorded at init/join).
    /// Override when binding to a specific interface for NAT or
    /// multi-homed hosts.
    #[arg(long, value_name = "ADDR")]
    bind: Option<String>,
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

        // ---- Default: run the daemon. Cluster restart if node.json
        //               is present, otherwise legacy single-node mode.
        Some(Command::Run(args)) => {
            if let Err(e) = cmd_run(cli.daemon, args) {
                error!("{}", e);
                process::exit(1);
            }
        }
        None => {
            if let Err(e) = cmd_run(cli.daemon, RunArgs::default()) {
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
    let ca = Arc::new(
        sftpflow_cluster::tls::ClusterCa::generate(&cluster_id)
            .map_err(|e| format!("generating cluster CA: {}", e))?,
    );
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
        ca:            ca.clone(),
        leaf_cert_pem,
        leaf_key_pem:  leaf.key_pem(),
        token_secret:  token_secret.clone(),
    }))?;

    info!(
        "init: cluster bootstrapped (node_id={}, cluster_id={})",
        node.node_id, node.cluster_id,
    );

    // ---- 9. Enter NDJSON serve loop ----
    info!("NDJSON server listening on {}", ndjson_addr);
    let cluster_ctx = cluster_runtime::ClusterContext {
        handle:       cluster_node.handle(),
        cluster_id:   node.cluster_id.clone(),
        self_id:      node.node_id,
        token_secret: Some(token_secret),
        runtime:      rt.handle().clone(),
    };
    let serve_result = server::run(&ndjson_addr, config, run_db, Some(secrets_store), Some(cluster_ctx))
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
// cmd_join - join an existing cluster via a seed node
// ============================================================
//
// Mirrors docs/m12-raft-scaffolding.md §5.2:
//
//   1. Refuse if node.json already exists.
//   2. Read the operator-supplied CA cert (out-of-band trust anchor).
//   3. Resolve bind + advertise.
//   4. Generate this node's leaf key + CSR locally.
//   5. Dial the seed's BootstrapService.Join with the token + CSR.
//   6. Cross-check the seed's CA matches what the operator handed us.
//   7. Persist node.json + ca.crt + node.crt + node.key (NO ca.key
//      — joiners don't get the CA private key in M12).
//   8. Open the optional sealed-secrets store + run-history DB.
//   9. Bring up the Raft runtime as a follower; the seed has already
//      added us as a learner and promoted us to voter, so we just
//      have to wait for the first AppendEntries to reach us.
//   10. Enter the NDJSON serve loop.

fn cmd_join(daemon: DaemonArgs, args: JoinArgs) -> Result<(), String> {
    let state_dir = daemon.state_dir.clone().unwrap_or_else(default_state_dir);

    // ---- 1. Refuse to clobber an existing node state ----
    let node_json_path = node_state::node_json_path(&state_dir);
    if node_json_path.exists() {
        return Err(format!(
            "{} already exists — refusing to re-join. Run \
             `sftpflowd run` to start this node, or remove the \
             state directory if you really want to re-join from \
             scratch",
            node_json_path.display(),
        ));
    }

    // ---- 2. Read CA cert from operator-supplied path ----
    let operator_ca_pem = std::fs::read_to_string(&args.ca_cert_file)
        .map_err(|e| format!("reading {}: {}", args.ca_cert_file.display(), e))?;
    if !operator_ca_pem.contains("BEGIN CERTIFICATE") {
        return Err(format!(
            "{} does not look like a PEM-encoded certificate",
            args.ca_cert_file.display(),
        ));
    }

    // ---- 3. Resolve bind + advertise ----
    let bind_addr: std::net::SocketAddr = args.bind.parse().map_err(|e| {
        format!("--bind '{}' must be IP:PORT (e.g. 0.0.0.0:7900): {}", args.bind, e)
    })?;
    let advertise_addr = args.advertise.clone().unwrap_or_else(|| args.bind.clone());

    // ---- 4. Generate leaf key + CSR ----
    let leaf = sftpflow_cluster::tls::LeafKeyPair::generate(args.node_id, &advertise_addr)
        .map_err(|e| format!("generating leaf key pair: {}", e))?;
    let csr_der = leaf.csr_der()
        .map_err(|e| format!("serializing leaf CSR: {}", e))?;

    info!(
        "join: dialing seed {} as node_id={} (advertise={})",
        args.seed, args.node_id, advertise_addr,
    );

    // ---- 5. Tokio runtime + dial seed ----
    cluster_runtime::install_crypto_provider_once();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sftpflowd-cluster")
        .build()
        .map_err(|e| format!("building tokio runtime: {}", e))?;

    let join_result = rt.block_on(sftpflow_cluster::node::dial_seed_join(
        sftpflow_cluster::node::SeedJoinArgs {
            seed_addr:        args.seed.clone(),
            ca_cert_pem:      operator_ca_pem.clone(),
            token:            args.token.clone(),
            desired_node_id:  args.node_id,
            advertise_addr:   advertise_addr.clone(),
            csr_der,
        },
    )).map_err(|e| format!("seed join handshake failed: {}", e))?;

    // ---- 6. Cross-check the seed's CA matches what we trusted ----
    // The operator handed us --ca-cert-file out of band. The seed
    // also returned a CA in the JoinResponse. They MUST match — if
    // they don't, either the operator pointed us at the wrong file
    // or something in the middle is rewriting bytes. Refuse rather
    // than silently trust the seed's copy.
    if normalize_pem(&operator_ca_pem) != normalize_pem(&join_result.ca_cert_pem) {
        return Err(format!(
            "seed returned a CA cert that does not match {} — refusing to join \
             (this can mean: wrong --ca-cert-file, wrong --seed, or a MITM)",
            args.ca_cert_file.display(),
        ));
    }

    info!(
        "join: handshake ok; cluster_id={}, signed leaf cert received",
        join_result.cluster_id,
    );

    // ---- 7. Persist node.json + cluster/*.{crt,key} ----
    let node = node_state::NodeJson {
        version:         node_state::NODE_JSON_VERSION,
        node_id:         args.node_id,
        cluster_id:      join_result.cluster_id.clone(),
        advertise_addr:  advertise_addr.clone(),
        label:           args.label.clone(),
        created_at_unix: node_state::now_unix(),
    };
    node_state::write_node_json(&state_dir, &node)?;
    node_state::write_pem(
        &node_state::ca_cert_path(&state_dir),
        &join_result.ca_cert_pem,
        false,
    )?;
    node_state::write_pem(
        &node_state::leaf_cert_path(&state_dir),
        &join_result.signed_leaf_cert_pem,
        false,
    )?;
    node_state::write_pem(
        &node_state::leaf_key_path(&state_dir),
        &leaf.key_pem(),
        true,
    )?;
    info!("join: wrote cluster state under {}", state_dir.display());

    // ---- 8. Daemon prelude (config, run history, optional secrets) ----
    let config = Config::load();
    info!(
        "join: loaded config (endpoints={}, keys={}, feeds={})",
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

    // The sealed-secrets store is OPTIONAL on joiners. Joiners
    // don't seal a token-HMAC secret (only the bootstrap node does
    // in M12). The operator only needs to provide a passphrase if
    // they intend to use *_ref features in feeds on this node.
    let secrets_path = daemon.secrets.clone().unwrap_or_else(secrets::default_secrets_path);
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
            info!(
                "no master passphrase provided — sealed credential store is unavailable on \
                 this joiner; feeds using *_ref fields will fail until one is set"
            );
            None
        }
        Err(e) => return Err(e),
    };

    // ---- 9. Bring up Raft as a joiner ----
    let cluster_node = rt.block_on(cluster_runtime::join_existing(
        cluster_runtime::JoinExistingParams {
            state_dir:     state_dir.clone(),
            node:          node.clone(),
            bind_addr,
            ca_cert_pem:   join_result.ca_cert_pem.clone(),
            leaf_cert_pem: join_result.signed_leaf_cert_pem.clone(),
            leaf_key_pem:  leaf.key_pem(),
        },
    ))?;

    info!(
        "join: cluster joined (node_id={}, cluster_id={})",
        node.node_id, node.cluster_id,
    );

    // ---- 10. NDJSON serve loop ----
    let ndjson_addr = daemon.socket.clone().unwrap_or_else(default_socket_addr);
    info!("NDJSON server listening on {}", ndjson_addr);
    // Joiners hold no token secret in M12 — only the bootstrap
    // node mints. `cluster token` against this node will surface
    // the asymmetry as a clear CONFIG_ERROR.
    let cluster_ctx = cluster_runtime::ClusterContext {
        handle:       cluster_node.handle(),
        cluster_id:   node.cluster_id.clone(),
        self_id:      node.node_id,
        token_secret: None,
        runtime:      rt.handle().clone(),
    };
    let serve_result = server::run(&ndjson_addr, config, run_db, secret_store, Some(cluster_ctx))
        .map_err(|e| format!("NDJSON server: {}", e));

    drop(cluster_node);
    drop(rt);
    serve_result
}

// ============================================================
// normalize_pem
// ============================================================

/// Strip ASCII whitespace and CR before comparing two PEM blobs.
/// Lets us tolerate trivial differences (CRLF vs LF, trailing
/// newline, leading BOM) without losing the security check that
/// the seed-supplied CA matches the operator-supplied one.
fn normalize_pem(pem: &str) -> String {
    pem.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

// ============================================================
// cmd_run - run the daemon
// ============================================================
//
// Two paths, picked by whether `<state_dir>/node.json` exists:
//
//   - Cluster mode (node.json present): re-open the on-disk
//     cluster state (CA cert, leaf cert + key, optional CA key
//     and sealed token secret), bring openraft back up against
//     the existing sled log, and serve NDJSON RPCs concurrently.
//     openraft replays log + membership and either rejoins quorum
//     or sits as a follower waiting for one. Implemented in
//     cmd_run_cluster.
//
//   - Legacy single-node mode (no node.json): the pre-M12 daemon
//     path — load config, reconcile dkron, open run history,
//     unlock sealed store, serve NDJSON. Removed entirely in M13;
//     kept for now so the existing test env keeps working through
//     the rest of M12 PR-B.

fn cmd_run(daemon: DaemonArgs, args: RunArgs) -> Result<(), String> {
    let state_dir = daemon.state_dir.clone().unwrap_or_else(default_state_dir);

    if let Some(node) = node_state::read_node_json(&state_dir)? {
        return cmd_run_cluster(daemon, args, state_dir, node);
    }

    if args.bind.is_some() {
        warn!(
            "--bind is only consulted in cluster mode; ignoring it because \
             {} does not exist (legacy single-node startup)",
            node_state::node_json_path(&state_dir).display(),
        );
    }
    cmd_run_legacy(daemon)
}

// ============================================================
// cmd_run_cluster - cluster-mode restart
// ============================================================
//
// Two sub-paths, distinguished by whether cluster/ca.key is on
// disk (only the original `sftpflowd init` node has it in M12):
//
//   - Bootstrap-node restart: re-load CA cert + key, re-load the
//     token-HMAC secret from the sealed store (passphrase
//     required), re-install the seed-side join handler so future
//     `sftpflowd join` flows still succeed, then resume Raft.
//
//   - Joiner restart: re-load CA cert + leaf only, no token
//     secret, no join handler. Same as the post-handshake path
//     in `cmd_join` minus the handshake itself.
//
// In both sub-paths the existing sled log under raft/ is re-used
// — there is no "re-bootstrap" or "re-join" — and the NDJSON
// server runs alongside the Raft runtime as before.
fn cmd_run_cluster(
    daemon:    DaemonArgs,
    args:      RunArgs,
    state_dir: PathBuf,
    node:      node_state::NodeJson,
) -> Result<(), String> {
    info!(
        "cluster restart: node_id={} cluster_id={} state_dir={}",
        node.node_id, node.cluster_id, state_dir.display(),
    );

    // ---- 1. Resolve bind ----
    // The bind address isn't persisted in node.json (only advertise
    // is — that's the operator-stable identity). On restart we need
    // a sensible default: extract the port from advertise_addr and
    // bind on 0.0.0.0:<that-port>. That covers the common case
    // (init/join were typically run with --bind 0.0.0.0:N --advertise
    // hostname:N) and works whether advertise is an IP or a DNS name.
    // Operators with a multi-homed / NAT'd setup pass --bind
    // explicitly to override.
    let bind_str = match args.bind.clone() {
        Some(b) => b,
        None => {
            let port = node.advertise_addr.rsplit_once(':').map(|(_, p)| p)
                .ok_or_else(|| format!(
                    "advertise_addr '{}' in node.json has no ':PORT' suffix; \
                     pass --bind explicitly",
                    node.advertise_addr,
                ))?;
            format!("0.0.0.0:{}", port)
        }
    };
    let bind_addr: std::net::SocketAddr = bind_str.parse().map_err(|e| {
        format!("--bind '{}' must be IP:PORT (e.g. 0.0.0.0:7900): {}", bind_str, e)
    })?;

    // ---- 2. Re-read on-disk certs ----
    let leaf_cert_pem = node_state::read_pem(&node_state::leaf_cert_path(&state_dir))?;
    let leaf_key_pem  = node_state::read_pem(&node_state::leaf_key_path(&state_dir))?;
    let ca_cert_pem   = node_state::read_pem(&node_state::ca_cert_path(&state_dir))?;

    // ---- 3. Detect bootstrap-vs-joiner role ----
    // Presence of cluster/ca.key is the marker: only the original
    // bootstrap node persists the CA private key. M13 may
    // distribute it to all voters for HA token minting; until then
    // this asymmetry is intentional.
    let ca_key_path = node_state::ca_key_path(&state_dir);
    let is_bootstrap = ca_key_path.exists();

    // ---- 4. Sealed credential store ----
    // Bootstrap-node restart REQUIRES the passphrase: the
    // token-HMAC secret was sealed there at init time and we
    // need it to re-install the join handler.
    // Joiner restart treats it as optional, exactly like cmd_join.
    let secrets_path = daemon.secrets.clone().unwrap_or_else(secrets::default_secrets_path);
    let mut secret_store = match secrets::load_passphrase(daemon.passphrase_file.as_deref())? {
        Some(passphrase) => Some(
            secrets::SecretStore::open(&secrets_path, passphrase)
                .map_err(|e| format!("opening sealed store at '{}': {}", secrets_path.display(), e))?,
        ),
        None => {
            if is_bootstrap {
                return Err(
                    "cluster restart on the bootstrap node requires a master \
                     passphrase (--passphrase-file PATH or SFTPFLOW_PASSPHRASE \
                     env var) to re-load the sealed token-HMAC secret"
                        .to_string(),
                );
            }
            warn!(
                "no master passphrase provided — sealed credential store will not be \
                 available; feeds using password_ref / ssh_key_ref / contents_ref will fail"
            );
            None
        }
    };

    // ---- 5. Daemon prelude (config + run history) ----
    let config = Config::load();
    info!(
        "sftpflowd v{} starting (cluster mode; endpoints={}, keys={}, feeds={})",
        env!("CARGO_PKG_VERSION"),
        config.endpoints.len(),
        config.keys.len(),
        config.feeds.len(),
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

    // ---- 6. Tokio runtime + Raft startup ----
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sftpflowd-cluster")
        .build()
        .map_err(|e| format!("building tokio runtime: {}", e))?;

    // The if/else returns the ClusterNode plus an Option<TokenSecret>
    // so the bootstrap branch can hand the secret on to ClusterContext
    // (joiners always pass None — they can't mint tokens in M12).
    let (cluster_node, token_secret_for_ctx) = if is_bootstrap {
        // ---- 6a. Bootstrap-node restart ----
        let ca_key_pem = node_state::read_pem(&ca_key_path)?;
        let ca = Arc::new(
            sftpflow_cluster::tls::ClusterCa::from_pem(&ca_cert_pem, &ca_key_pem)
                .map_err(|e| format!("loading cluster CA from '{}': {}",
                    node_state::cluster_dir(&state_dir).display(), e))?,
        );

        // Pull the sealed token secret. Always present on a healthy
        // bootstrap node (cmd_init wrote it), but a manual
        // intervention could have removed it; surface a clear
        // error in that case rather than silently breaking joins.
        let store = secret_store.as_mut()
            .expect("checked above that bootstrap has Some(store)");
        let token_b64 = store.get(node_state::CLUSTER_TOKEN_SECRET_KEY)
            .ok_or_else(|| format!(
                "sealed store has no '{}' entry — was this node initialized \
                 with `sftpflowd init`? (manual recovery: rewrite via `sftpflow \
                 secret add` is not enough; the secret must be the original \
                 32 raw bytes minted at init time)",
                node_state::CLUSTER_TOKEN_SECRET_KEY,
            ))?
            .to_string();
        use base64::Engine as _;
        let token_bytes = base64::engine::general_purpose::STANDARD.decode(&token_b64)
            .map_err(|e| format!("decoding sealed token secret: {}", e))?;
        let token_secret = sftpflow_cluster::token::TokenSecret::from_bytes(&token_bytes)
            .map_err(|e| format!("rebuilding token secret from sealed bytes: {}", e))?;

        info!("cluster restart: bootstrap-node path (CA key + token secret loaded)");

        let node_handle = rt.block_on(cluster_runtime::resume_bootstrap(cluster_runtime::BootstrapParams {
            state_dir:     state_dir.clone(),
            node:          node.clone(),
            bind_addr,
            ca,
            leaf_cert_pem,
            leaf_key_pem,
            token_secret:  token_secret.clone(),
        }))?;
        (node_handle, Some(token_secret))
    } else {
        // ---- 6b. Joiner restart ----
        info!("cluster restart: joiner path (CA cert only — no CA key, no token secret)");

        let node_handle = rt.block_on(cluster_runtime::join_existing(cluster_runtime::JoinExistingParams {
            state_dir:     state_dir.clone(),
            node:          node.clone(),
            bind_addr,
            ca_cert_pem,
            leaf_cert_pem,
            leaf_key_pem,
        }))?;
        (node_handle, None)
    };

    // ---- 7. NDJSON serve loop ----
    let socket_addr = daemon.socket.clone().unwrap_or_else(default_socket_addr);
    info!("NDJSON server listening on {}", socket_addr);
    let cluster_ctx = cluster_runtime::ClusterContext {
        handle:       cluster_node.handle(),
        cluster_id:   node.cluster_id.clone(),
        self_id:      node.node_id,
        token_secret: token_secret_for_ctx,
        runtime:      rt.handle().clone(),
    };
    let serve_result = server::run(&socket_addr, config, run_db, secret_store, Some(cluster_ctx))
        .map_err(|e| format!("NDJSON server: {}", e));

    // Same teardown order as cmd_init/cmd_join: drop the cluster
    // node first (aborts gRPC task while runtime is still alive),
    // then drop the runtime (shuts down tokio workers).
    drop(cluster_node);
    drop(rt);
    serve_result
}

// ============================================================
// cmd_run_legacy - pre-M12 single-node path
// ============================================================
//
// Identical in behavior to the pre-M12 main(): load config,
// reconcile dkron, open run history, unlock sealed store, start
// the NDJSON server. M13 deletes this; cmd_run is then just
// cmd_run_cluster.

fn cmd_run_legacy(daemon: DaemonArgs) -> Result<(), String> {
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
    // No cluster handle: legacy single-node mode runs every RPC
    // unguarded, like pre-M12. M13 deletes this fallback.
    server::run(&socket_addr, config, run_db, secret_store, None)
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
