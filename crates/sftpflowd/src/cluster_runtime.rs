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

use std::collections::{BTreeMap, BTreeSet};
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
use sftpflow_cluster::token::{self, TokenSecret};
use sftpflow_cluster::transport::JoinHandler;

use crate::node_state::{self, NodeJson};

// ============================================================
// ClusterContext - runtime cluster handle + identity bundle
// ============================================================
//
// Lives behind `DaemonState::cluster` (Option<ClusterContext>).
// Bundles every piece of cluster-side state the NDJSON RPC layer
// needs: the live Raft handle, this cluster's UUID, this node's
// stable u64 ID, and (on the bootstrap node only) the token-HMAC
// secret used to mint join tokens. M13 will likely add an
// `Arc<Mutex<UsedNonces>>` here once tokens get persisted across
// restarts; for M12 the seed-side BootstrapServiceImpl owns its
// own replay-protection set.

pub struct ClusterContext {
    pub handle:       ClusterHandle,
    pub cluster_id:   String,
    pub self_id:      u64,
    /// Bootstrap-node only. Populated by `cmd_init` and the
    /// bootstrap branch of `cmd_run_cluster`; joiners hold `None`
    /// and `cluster mint_token` returns an error to make the
    /// asymmetry obvious.
    pub token_secret: Option<TokenSecret>,
    /// Handle to the tokio runtime that drives the cluster's gRPC
    /// server. Stored here so the synchronous NDJSON dispatch can
    /// block on async Raft calls (e.g. `change_membership` for
    /// `cluster remove`). Safe: the NDJSON server runs on its own
    /// OS thread spawned by `std::thread::spawn`, not on a tokio
    /// worker, so `block_on` does not deadlock.
    pub runtime:      tokio::runtime::Handle,
}

impl ClusterContext {
    /// True if this node is the cluster leader. Forwards to
    /// `ClusterHandle::is_leader`.
    pub fn is_leader(&self) -> bool { self.handle.is_leader() }

    /// Node ID of the current leader from this node's view.
    pub fn current_leader(&self) -> Option<u64> { self.handle.current_leader() }

    /// All known members. Used by `enforce_leader` to look up the
    /// leader's advertise address for the NOT_LEADER error message.
    pub fn members(&self) -> BTreeMap<u64, ClusterMember> {
        self.handle.members()
    }

    /// All known members alongside their voter/learner flag.
    /// Used by the `cluster_status` handler.
    pub fn members_with_voter_flag(&self) -> BTreeMap<u64, (ClusterMember, bool)> {
        self.handle.members_with_voter_flag()
    }

    /// Mint a join token using this node's TokenSecret. Returns
    /// `(token, expires_at_unix)`. Errors if this node doesn't
    /// hold the secret (i.e. it's not the bootstrap node in M12).
    pub fn mint_token(&self, ttl_seconds: u32) -> Result<(String, i64), String> {
        let secret = self.token_secret.as_ref().ok_or_else(|| {
            "this node does not hold the token-HMAC secret; in M12 only \
             the bootstrap node can mint join tokens. Run `cluster token` \
             against the bootstrap node instead."
                .to_string()
        })?;
        let token = token::mint(secret, &self.cluster_id, ttl_seconds)
            .map_err(|e| format!("mint: {}", e))?;
        let expires_at = node_state::now_unix() + ttl_seconds as i64;
        Ok((token, expires_at))
    }

    /// Remove a node from the voter set. Leader-only.
    ///
    /// Computes the new voter set as `current_voters - {node_id}`
    /// and pushes a `change_membership` through Raft, blocking the
    /// caller (NDJSON dispatch is sync). Refuses if the target
    /// doesn't exist or removing it would leave zero voters.
    pub fn remove_node_blocking(&self, node_id: u64) -> Result<(), String> {
        let current = self.handle.members_with_voter_flag();
        if !current.contains_key(&node_id) {
            return Err(format!("no member with node_id={} exists", node_id));
        }
        let new_voters: BTreeSet<u64> = current
            .iter()
            .filter(|(id, (_, is_voter))| **id != node_id && *is_voter)
            .map(|(id, _)| *id)
            .collect();
        if new_voters.is_empty() {
            return Err(format!(
                "removing node_id={} would leave the cluster with no voters",
                node_id,
            ));
        }

        let handle = self.handle.clone();
        self.runtime.block_on(async move {
            handle
                .change_membership(new_voters)
                .await
                .map_err(|e| format!("change_membership: {}", e))
        })
    }
}

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
    let advertise_addr = params.node.advertise_addr.clone();
    let added_at_unix  = params.node.created_at_unix;
    let label          = params.node.label.clone();
    let node_id        = params.node.node_id;

    let node = start_with_join_handler(params).await?;
    let handle = node.handle();

    let member = ClusterMember {
        advertise_addr,
        added_at_unix,
        label,
    };
    handle.initialize_solo(node_id, member).await
        .map_err(|e| format!("initialize_solo: {}", e))?;

    wait_for_leader(&handle).await?;
    info!("cluster: this node is the leader");

    Ok(node)
}

// ============================================================
// resume_bootstrap - restart of a node that originally bootstrapped
// ============================================================

/// Restart path for a node that holds the cluster CA private key
/// and the token-HMAC secret — i.e. the node originally created by
/// `sftpflowd init`. Brings the Raft runtime back up with the
/// seed-side join handler installed, but does NOT call
/// `initialize_solo` (the cluster already exists; openraft replays
/// log + membership from sled).
///
/// Waits for a current leader to be observed before returning so
/// the NDJSON serve loop only starts once the node is participating.
/// This may briefly be the local node (if it wins the post-restart
/// election) or a peer (if quorum already converged elsewhere).
pub async fn resume_bootstrap(params: BootstrapParams) -> Result<ClusterNode, String> {
    let node = start_with_join_handler(params).await?;
    wait_for_leader(&node.handle()).await?;
    info!(
        "cluster: resumed; current leader is node_id={:?}",
        node.handle().current_leader(),
    );
    Ok(node)
}

// ============================================================
// start_with_join_handler - shared bootstrap/resume_bootstrap prelude
// ============================================================

/// Bring up `ClusterNode` with the seed-side BootstrapService.Join
/// handler wired in. Used by both `bootstrap` (fresh cluster) and
/// `resume_bootstrap` (restart of the bootstrap node) — the
/// difference between the two is whether `initialize_solo` is
/// called afterward.
async fn start_with_join_handler(params: BootstrapParams) -> Result<ClusterNode, String> {
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

    // Hand the live handle to the join handler. set() returns
    // Err if the cell is already populated, which can't happen
    // here (we only call this once); ignore the result.
    let _ = handle_cell.set(node.handle());

    // Give tonic a beat to actually bind. Without this, the
    // initialize_solo → leader-election path sometimes loses a
    // heartbeat against its own listener. Mirrors the 500ms pause
    // in the three_node_cluster integration test.
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(node)
}

// ============================================================
// join_existing - join-time cluster startup
// ============================================================

/// Bring up the Raft + gRPC machinery on a non-bootstrap node.
/// Used by both:
///   - `sftpflowd join`: first-time join, immediately after the
///     BootstrapService.Join handshake against a seed.
///   - `sftpflowd run`: restart of a node that joined previously
///     (no second handshake — openraft replays log + membership
///     from sled, and the seed's heartbeats reach us as soon as
///     the gRPC server is bound).
///
/// Returns once this node sees a current leader. For a fresh join
/// the leader is the seed; for a restart it can be any current
/// voter (or briefly `None` if the cluster is mid-election, which
/// `wait_for_leader` polls through).
///
/// Non-bootstrap nodes hold no token secret and install no join
/// handler — only the bootstrap node can mint or accept further
/// joins in M12.
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
// Chicken-and-egg note: the joiner can't bring up its gRPC server
// until it has a CA-signed cert, and openraft's add_learner +
// change_membership both require the new node to be reachable to
// commit. So the handler MUST return the signed cert *before* the
// joiner is ready to receive AppendEntries — otherwise the seed
// blocks forever.
//
// Solution: the handler signs the CSR (fast, sync) and **spawns**
// the membership work onto a background task. The joiner gets its
// cert immediately, brings up its server, becomes reachable, and
// the spawned task's add_learner / change_membership succeed once
// AppendEntries can flow.
//
// The background tasks are serialized through `join_serializer` —
// openraft rejects overlapping membership changes, and this is
// where the queue forms when multiple nodes join in quick
// succession.
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
            // ---- Synchronous prelude (runs while joiner waits) ----
            let handle = handle_cell.get().ok_or_else(|| {
                "cluster handle not yet initialized (initialize_solo \
                 hasn't run on this node yet)".to_string()
            })?.clone();

            // Refuse duplicate node_id up front so the joiner sees
            // a clean error instead of a successful cert + a silent
            // failure in the background task.
            if handle.members().contains_key(&req.desired_node_id) {
                return Err(format!(
                    "node_id {} already exists in this cluster",
                    req.desired_node_id,
                ));
            }

            let leaf_pem = ca.sign_csr(&req.csr_der)
                .map_err(|e| format!("signing joiner CSR: {}", e))?;

            // ---- Background membership work --------------------
            // We need this to run after the handler returns so the
            // joiner has time to bring up its server. Spawn onto
            // the runtime that's already executing this future.
            let member = ClusterMember {
                advertise_addr: req.advertise_addr.clone(),
                added_at_unix:  node_state::now_unix(),
                label:          None, // M13: pull label from token claims
            };
            let desired_node_id = req.desired_node_id;
            let advertise_addr  = req.advertise_addr.clone();
            tokio::spawn(async move {
                let _guard = join_serializer.lock().await;
                info!(
                    "join: adding node_id={} advertise={} as learner",
                    desired_node_id, advertise_addr,
                );
                if let Err(e) = handle.add_learner(desired_node_id, member).await {
                    warn!("join: add_learner({}) failed: {}", desired_node_id, e);
                    return;
                }
                let mut voters: BTreeSet<u64> =
                    handle.members().keys().copied().collect();
                voters.insert(desired_node_id);
                info!("join: promoting voter set to {:?}", voters);
                if let Err(e) = handle.change_membership(voters).await {
                    warn!(
                        "join: change_membership for node_id={} failed: {}",
                        desired_node_id, e,
                    );
                }
            });

            // membership_json is reserved for M13/M14 (the joiner
            // learns membership from the first AppendEntries anyway).
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
