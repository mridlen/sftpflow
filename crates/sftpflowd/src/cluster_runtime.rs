// ============================================================
// sftpflowd::cluster_runtime - async orchestration helpers
// ============================================================
//
// Thin wrapper around `sftpflow_cluster::node::ClusterNode` that
// encapsulates the tokio-flavored parts of the daemon (startup
// dance, waiting for leader election, initialize_solo, the
// seed-side join handler). The main.rs command handlers stay
// mostly-sync and call into this module from inside a
// `Runtime::block_on`.
//
// Why the split: keeps main.rs readable and keeps the rustls
// `install_default` + tokio runtime setup in one place. No logic
// here that isn't directly tied to bringing the Raft machinery
// up on this node.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use log::{info, warn};
use tokio::sync::{Mutex, OnceCell};

use sftpflow_cluster::node::{ClusterHandle, ClusterNode, StartConfig};
use sftpflow_cluster::proto::{JoinRequest as PJoinRequest, JoinResponse as PJoinResponse};
use sftpflow_cluster::state::ClusterMember;
use sftpflow_cluster::tls::ClusterCa;
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

    /// Cluster CA. Held by the bootstrap node so the join handler
    /// can sign CSRs from incoming joiners. Not persisted by this
    /// module — main.rs writes ca.crt + ca.key to disk separately.
    pub ca: Arc<ClusterCa>,

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
// JoinExistingParams
// ============================================================

/// Inputs for bringing this node up as a joiner of an existing
/// cluster. Produced by `sftpflowd join` after it has dialed the
/// seed and received a signed leaf cert + the cluster CA.
pub struct JoinExistingParams {
    pub state_dir: PathBuf,
    pub node:      NodeJson,
    pub bind_addr: SocketAddr,

    /// PEM of the cluster CA cert (received from the seed during
    /// the join handshake; cross-checked against the operator's
    /// --ca-cert-file before this is constructed).
    pub ca_cert_pem: String,

    /// PEM of this node's leaf cert (signed by the CA, returned by
    /// the seed).
    pub leaf_cert_pem: String,

    /// PEM of this node's leaf private key (generated locally;
    /// never leaves this node).
    pub leaf_key_pem: String,
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

    // The seed-side join handler needs a `ClusterHandle` to add
    // learners and change membership. The handle only exists
    // *after* ClusterNode::start returns, but the handler itself
    // must be passed into start. Bridge the cycle with a OnceCell
    // populated immediately after start succeeds — joiners can't
    // race the handler in between because (a) the gRPC server
    // isn't bound until start completes, and (b) initialize_solo
    // hasn't run yet so even if a joiner did connect, there's no
    // leader to add them to.
    let handle_cell: Arc<OnceCell<ClusterHandle>> = Arc::new(OnceCell::new());

    // Serialize concurrent joins so two handlers don't fight over
    // change_membership (openraft rejects overlapping config
    // changes; serializing here surfaces a clearer error path).
    let join_serializer: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

    let join_handler = make_seed_join_handler(
        params.ca.clone(),
        params.node.cluster_id.clone(),
        handle_cell.clone(),
        join_serializer,
    );

    let cfg = StartConfig {
        node_id:           params.node.node_id,
        bind_addr:         params.bind_addr,
        advertise_addr:    params.node.advertise_addr.clone(),
        raft_storage_path: node_state::raft_dir(&params.state_dir),
        ca_cert_pem:       params.ca.cert_pem(),
        leaf_cert_pem:     params.leaf_cert_pem,
        leaf_key_pem:      params.leaf_key_pem,
        cluster_id:        params.node.cluster_id.clone(),
        token_secret:      Some(params.token_secret),
        join_handler:      Some(join_handler),
    };

    info!(
        "cluster: starting node_id={} cluster_id={} bind={} advertise={}",
        params.node.node_id, params.node.cluster_id, params.bind_addr, params.node.advertise_addr,
    );
    let node = ClusterNode::start(cfg).await
        .map_err(|e| format!("ClusterNode::start: {}", e))?;
    let handle = node.handle();

    // Hand the live handle to the join handler. set() returns
    // Err if the cell is already populated, which can't happen
    // here (we only call this once); ignore the result.
    let _ = handle_cell.set(handle.clone());

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
// join_existing - join-time cluster startup
// ============================================================

/// Bring up the Raft + gRPC machinery on a node that has just
/// completed the BootstrapService.Join handshake against a seed.
/// Returns once this node sees a current leader (which means the
/// seed's add_learner / change_membership round trip has reached
/// us via AppendEntries).
///
/// Joiners hold no token secret and install no join handler — only
/// the bootstrap node can mint or accept further joins in M12.
pub async fn join_existing(params: JoinExistingParams) -> Result<ClusterNode, String> {
    install_crypto_provider_once();

    let cfg = StartConfig {
        node_id:           params.node.node_id,
        bind_addr:         params.bind_addr,
        advertise_addr:    params.node.advertise_addr.clone(),
        raft_storage_path: node_state::raft_dir(&params.state_dir),
        ca_cert_pem:       params.ca_cert_pem,
        leaf_cert_pem:     params.leaf_cert_pem,
        leaf_key_pem:      params.leaf_key_pem,
        cluster_id:        params.node.cluster_id.clone(),
        token_secret:      None,
        join_handler:      None,
    };

    info!(
        "cluster: starting (joiner) node_id={} cluster_id={} bind={} advertise={}",
        params.node.node_id, params.node.cluster_id, params.bind_addr, params.node.advertise_addr,
    );
    let node = ClusterNode::start(cfg).await
        .map_err(|e| format!("ClusterNode::start: {}", e))?;
    let handle = node.handle();

    // Wait for the seed to push its first AppendEntries (which
    // both adds us to the membership and tells us who the leader
    // is). The seed already called add_learner before responding
    // to the BootstrapService.Join RPC, so this is normally a sub-
    // second wait.
    wait_for_leader(&handle).await?;
    info!(
        "cluster: joined; current leader is node_id={:?}",
        handle.current_leader(),
    );

    Ok(node)
}

// ============================================================
// make_seed_join_handler - the seed-side BootstrapService.Join callback
// ============================================================
//
// Returned closure is invoked on the bootstrap node every time a
// joining node POSTs a valid token + CSR. Steps:
//
//   1. Sign the joiner's CSR with the cluster CA.
//   2. Build a ClusterMember for the joiner from the request.
//   3. add_learner → wait briefly for catch-up → change_membership
//      to promote learner → voter.
//   4. Return JoinResponse with the signed cert + CA cert.
//
// Errors propagate verbatim back through tonic to the joiner so
// `sftpflowd join` surfaces the underlying cause (e.g. "node_id 2
// is already a member"). All work is serialized through a Mutex so
// two concurrent joins don't try to overlap openraft config
// changes (which openraft rejects).
fn make_seed_join_handler(
    ca:               Arc<ClusterCa>,
    cluster_id:       String,
    handle_cell:      Arc<OnceCell<ClusterHandle>>,
    join_serializer:  Arc<Mutex<()>>,
) -> JoinHandler {
    Arc::new(move |req: PJoinRequest| {
        let ca               = ca.clone();
        let cluster_id       = cluster_id.clone();
        let handle_cell      = handle_cell.clone();
        let join_serializer  = join_serializer.clone();
        Box::pin(async move {
            // Serialize the whole join (CSR sign is fast; the
            // openraft membership ops are the part we have to
            // serialize, but holding the lock across signing
            // keeps the handler simple).
            let _guard = join_serializer.lock().await;

            let handle = handle_cell.get().ok_or_else(|| {
                "cluster handle not yet initialized (initialize_solo \
                 hasn't run on this node yet)".to_string()
            })?;

            // ---- 1. Sign CSR ------------------------------------
            let leaf_pem = ca.sign_csr(&req.csr_der)
                .map_err(|e| format!("signing joiner CSR: {}", e))?;

            // ---- 2. Refuse duplicate node_id --------------------
            let existing = handle.members();
            if existing.contains_key(&req.desired_node_id) {
                return Err(format!(
                    "node_id {} already exists in this cluster",
                    req.desired_node_id,
                ));
            }

            // ---- 3. Add learner --------------------------------
            let member = ClusterMember {
                advertise_addr: req.advertise_addr.clone(),
                added_at_unix:  node_state::now_unix(),
                label:          None, // M13: pull label from token claims
            };
            info!(
                "join: adding node_id={} advertise={} as learner",
                req.desired_node_id, req.advertise_addr,
            );
            handle.add_learner(req.desired_node_id, member.clone()).await
                .map_err(|e| format!("add_learner: {}", e))?;

            // ---- 4. Promote to voter ---------------------------
            // Compose the new voter set from the (now-updated) member
            // map. add_learner appended the new node, but we still
            // want to be explicit about which nodes are voters vs
            // learners — collect every member id.
            let mut voters: BTreeSet<u64> = handle.members().keys().copied().collect();
            voters.insert(req.desired_node_id);
            info!("join: promoting voter set to {:?}", voters);
            handle.change_membership(voters).await
                .map_err(|e| format!("change_membership: {}", e))?;

            // ---- 5. Build response -----------------------------
            // membership_json is reserved for M13/M14 (the joiner
            // currently learns membership from the first AppendEntries
            // anyway — populating this field is forward compatibility
            // for snapshot-only joins).
            Ok(PJoinResponse {
                ca_cert_pem:          ca.cert_pem().into_bytes(),
                signed_leaf_cert_pem: leaf_pem.into_bytes(),
                membership_json:      Vec::new(),
                cluster_id:           cluster_id.clone(),
            })
        })
    })
}

// ============================================================
// wait_for_leader
// ============================================================

/// Poll `handle.current_leader()` every 50 ms for up to ~10 seconds.
/// openraft's default election timeout is ~250-500 ms so solo
/// bootstrap is near-instant; the joiner case is bounded by how
/// fast the seed's AppendEntries reaches us, which is also normally
/// sub-second. 10 s gives plenty of headroom on a loaded dev box.
async fn wait_for_leader(handle: &ClusterHandle) -> Result<(), String> {
    const POLL_INTERVAL: Duration = Duration::from_millis(50);
    const MAX_POLLS: u32 = 200;

    for _ in 0..MAX_POLLS {
        if handle.current_leader().is_some() {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    warn!("wait_for_leader: timed out after 10s");
    Err("timed out waiting for leader after 10s".to_string())
}
