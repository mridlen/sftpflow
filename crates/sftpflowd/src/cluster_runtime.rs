// ============================================================
// sftpflowd::cluster_runtime - async orchestration helpers
// ============================================================
//
// Thin wrapper around `sftpflow_cluster::node::ClusterNode` that
// encapsulates the tokio-flavored parts of the daemon (startup
// dance, waiting for leader election, initialize_solo). The
// main.rs command handlers stay mostly-sync and call into this
// module from inside a `Runtime::block_on`.
//
// Why the split: keeps main.rs readable and keeps the rustls
// `install_default` + tokio runtime setup in one place. No logic
// here that isn't directly tied to bringing the Raft machinery
// up on this node.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use log::info;

use sftpflow_cluster::node::{ClusterHandle, ClusterNode, StartConfig};
use sftpflow_cluster::state::ClusterMember;
use sftpflow_cluster::token::TokenSecret;
use sftpflow_cluster::transport::JoinHandler;

use crate::node_state::{self, NodeJson};

// ============================================================
// rustls crypto provider bootstrap
// ============================================================

/// Install the ring-based rustls `CryptoProvider` as process
/// default. Must be called before any TLS operation (tonic's
/// TLS config builder panics otherwise with "no default
/// CryptoProvider"). Safe to call more than once — the `Result`
/// return is ignored because the second call fails harmlessly.
pub fn install_crypto_provider_once() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ============================================================
// BootstrapParams
// ============================================================

/// Everything needed to bring this node up as the solo voter of
/// a brand-new cluster. Produced by `sftpflowd init` after it
/// has generated the CA, the leaf cert, and the token secret.
pub struct BootstrapParams {
    /// Root of this node's state tree. `raft/` hangs off this.
    pub state_dir: PathBuf,

    /// Freshly-written node.json contents (node_id, cluster_id, ...).
    pub node: NodeJson,

    /// Local socket to bind the Raft gRPC server to (e.g.
    /// 0.0.0.0:7900). Separate from `node.advertise_addr` — the
    /// advertise address is what peers dial, which may be a
    /// hostname or a NAT'd public IP.
    pub bind_addr: SocketAddr,

    /// PEM of the cluster CA cert. Every node trusts this as the
    /// root of the mTLS chain.
    pub ca_cert_pem: String,

    /// PEM of this node's leaf cert (signed by the CA).
    pub leaf_cert_pem: String,

    /// PEM of this node's leaf private key (matches leaf_cert_pem).
    pub leaf_key_pem: String,

    /// Token HMAC secret — lets this node's AdminService.MintToken
    /// hand out join tokens for future `cluster join` flows. Only
    /// the bootstrap node holds one in M12.
    pub token_secret: TokenSecret,
}

// ============================================================
// bootstrap - init-time cluster startup
// ============================================================

/// Start the Raft + gRPC machinery as a brand-new solo-voter
/// cluster. Returns once leadership is established on this node.
///
/// The `ClusterNode` returned owns the background gRPC task; keep
/// it alive for the life of the daemon. Dropping it tears down
/// the cluster.
pub async fn bootstrap(params: BootstrapParams) -> Result<ClusterNode, String> {
    install_crypto_provider_once();

    // M12: no join handler yet. The BootstrapService will refuse
    // any incoming Join RPCs with "this node cannot accept joins
    // (M12: only the bootstrap node can)" — that gets replaced
    // with a real CSR-signing handler when `sftpflowd join`
    // integration lands in the next PR-B commit.
    let join_handler: Option<JoinHandler> = None;

    let cfg = StartConfig {
        node_id:           params.node.node_id,
        bind_addr:         params.bind_addr,
        advertise_addr:    params.node.advertise_addr.clone(),
        raft_storage_path: node_state::raft_dir(&params.state_dir),
        ca_cert_pem:       params.ca_cert_pem,
        leaf_cert_pem:     params.leaf_cert_pem,
        leaf_key_pem:      params.leaf_key_pem,
        cluster_id:        params.node.cluster_id.clone(),
        token_secret:      Some(params.token_secret),
        join_handler,
    };

    info!(
        "cluster: starting node_id={} cluster_id={} bind={} advertise={}",
        params.node.node_id, params.node.cluster_id, params.bind_addr, params.node.advertise_addr,
    );
    let node = ClusterNode::start(cfg).await
        .map_err(|e| format!("ClusterNode::start: {}", e))?;
    let handle = node.handle();

    // Give tonic a beat to actually bind. Without this, the
    // initialize_solo → leader-election path sometimes loses a
    // heartbeat against its own listener. Mirrors the 500ms pause
    // in the three_node_cluster integration test.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let member = ClusterMember {
        advertise_addr: params.node.advertise_addr.clone(),
        added_at_unix:  params.node.created_at_unix,
        label:          params.node.label.clone(),
    };
    handle.initialize_solo(params.node.node_id, member).await
        .map_err(|e| format!("initialize_solo: {}", e))?;

    wait_for_leader(&handle).await?;
    info!("cluster: this node is the leader");

    Ok(node)
}

// ============================================================
// wait_for_leader
// ============================================================

/// Poll `handle.is_leader()` every 50 ms for up to ~5 seconds.
/// openraft's default election timeout is ~250-500 ms so solo
/// bootstrap should be near-instant; 5 s gives us plenty of
/// headroom on a loaded dev box.
async fn wait_for_leader(handle: &ClusterHandle) -> Result<(), String> {
    const POLL_INTERVAL: Duration = Duration::from_millis(50);
    const MAX_POLLS: u32 = 100;

    for _ in 0..MAX_POLLS {
        if handle.is_leader() {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err("timed out waiting for leader election after 5s".to_string())
}
