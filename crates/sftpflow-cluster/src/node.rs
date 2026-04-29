// ============================================================
// sftpflow-cluster::node - public API consumed by sftpflowd
// ============================================================
//
// `ClusterNode` is what bin code (sftpflowd) holds onto for the
// lifetime of the daemon. It owns:
//
//   - the openraft Raft<TypeConfig> instance
//   - the storage backing it (sled-backed Adaptor pair)
//   - the network factory (PeerNetworkFactory)
//   - the spawned tokio task that runs the gRPC server
//
// `ClusterHandle` is a cheap clone-able view used by the
// daemon's RPC handlers (gate mutating ops on `is_leader`,
// fetch metrics for `cluster status`, drive membership ops).
//
// The cluster crate intentionally stops just below the
// "bootstrap / join / restart" decision tree — that's policy
// the daemon owns. We expose:
//
//   - `ClusterNode::start_solo()`    : init flow (PR-B init)
//   - `ClusterNode::start_existing()`: restart + join flows
//   - `dial_seed_join()`             : the BootstrapService.Join
//                                       client dance for joiners
//
// The daemon assembles these into `sftpflowd init / join / run`
// in PR-B.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use openraft::{Config, Raft};
use tokio::sync::Mutex;
use tonic::transport::Endpoint;

use crate::proto::bootstrap_service_client::BootstrapServiceClient;
use crate::proto::JoinRequest as PJoinRequest;
use crate::state::{ClusterMember, TypeConfig};
use crate::store::open_for_raft;
use crate::tls;
use crate::token::{TokenSecret, UsedNonces};
use crate::transport::{
    no_forward_handler,
    run_grpc_server,
    AdminServiceImpl,
    BootstrapServiceImpl,
    JoinHandler,
    NdjsonForwardHandler,
    NdjsonForwardServiceImpl,
    PeerNetworkFactory,
    RaftServiceImpl,
};

// ============================================================
// Errors
// ============================================================

#[derive(Debug)]
pub enum ClusterError {
    Storage(String),
    Raft(String),
    Tls(String),
    Network(String),
    Token(String),
    Other(String),
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterError::Storage(s) => write!(f, "cluster storage: {}", s),
            ClusterError::Raft(s)    => write!(f, "raft: {}", s),
            ClusterError::Tls(s)     => write!(f, "tls: {}", s),
            ClusterError::Network(s) => write!(f, "network: {}", s),
            ClusterError::Token(s)   => write!(f, "token: {}", s),
            ClusterError::Other(s)   => write!(f, "cluster: {}", s),
        }
    }
}
impl std::error::Error for ClusterError {}

// ============================================================
// Start config - the inputs every node start needs
// ============================================================

pub struct StartConfig {
    /// This node's u64 ID (operator-supplied in M12).
    pub node_id: u64,

    /// host:port the local gRPC server binds to.
    pub bind_addr: SocketAddr,

    /// host:port other peers will dial to reach this node. Often
    /// the same as `bind_addr`, but can differ when behind NAT or
    /// when the bind is `0.0.0.0:7900` and peers need a real DNS.
    pub advertise_addr: String,

    /// Path under which sled stores raft log + snapshots. Created
    /// if missing.
    pub raft_storage_path: std::path::PathBuf,

    /// PEM-encoded cluster CA cert.
    pub ca_cert_pem: String,

    /// PEM-encoded leaf cert for this node (signed by ca_cert).
    pub leaf_cert_pem: String,

    /// PEM-encoded private key matching leaf_cert.
    pub leaf_key_pem: String,

    /// Cluster identity (UUID baked into join tokens). Required
    /// for both AdminService and BootstrapService.
    pub cluster_id: String,

    /// Token HMAC key, present only on the bootstrap node in M12.
    /// `None` => AdminService.MintToken returns an error pointing
    /// to the bootstrap node, and BootstrapService.Join refuses
    /// because there's no key to validate against.
    pub token_secret: Option<TokenSecret>,

    /// Daemon-supplied callback that signs a joining node's CSR
    /// and adds them to the Raft membership. Only meaningful on
    /// the bootstrap node (where token_secret is also Some). The
    /// closure is constructed in PR-B's join handler.
    pub join_handler: Option<JoinHandler>,

    /// Daemon-supplied callback that runs a forwarded NDJSON
    /// envelope through the local-only dispatcher. Installed on
    /// every node so any current leader can accept forwards from
    /// any current follower. `None` falls back to the no-op
    /// handler (refuses every forward) — used by tests and any
    /// future single-node mode that doesn't need the gRPC server.
    pub forward_handler: Option<NdjsonForwardHandler>,
}

// ============================================================
// ClusterNode
// ============================================================

pub struct ClusterNode {
    pub raft: Raft<TypeConfig>,
    /// Background task running the gRPC server. Aborted on Drop.
    server_task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl Drop for ClusterNode {
    fn drop(&mut self) {
        self.server_task.abort();
    }
}

impl ClusterNode {
    /// Bring up the Raft + gRPC machinery for this node. Used by
    /// every entry point (init / join / restart) — the only
    /// difference between them is what happens *after* this:
    ///
    ///   - init    : caller does `node.raft.initialize(self_only)`
    ///   - join    : caller has already dialed the seed; the seed
    ///               will add this node to its membership and the
    ///               first AppendEntries will land here naturally
    ///   - restart : nothing further; openraft replays the log
    ///
    /// This split lets the daemon (PR-B) layer policy on top
    /// without the cluster crate caring about node.json / cluster
    /// directory layout.
    pub async fn start(cfg: StartConfig) -> Result<Self, ClusterError> {
        // ---- 1. Storage (log + state machine) -----------------
        let (log_store, sm_store) = open_for_raft(&cfg.raft_storage_path)
            .map_err(ClusterError::Storage)?;

        // ---- 2. Network factory ------------------------------
        let net_factory = PeerNetworkFactory::new(
            cfg.leaf_cert_pem.clone(),
            cfg.leaf_key_pem.clone(),
            cfg.ca_cert_pem.clone(),
        );

        // ---- 3. Raft instance --------------------------------
        let raft_config = Arc::new(
            Config::default()
                .validate()
                .map_err(|e| ClusterError::Raft(format!("config: {}", e)))?,
        );
        let raft = Raft::new(cfg.node_id, raft_config, net_factory, log_store, sm_store)
            .await
            .map_err(|e| ClusterError::Raft(format!("Raft::new: {}", e)))?;

        // ---- 4. gRPC services --------------------------------
        let raft_svc = RaftServiceImpl::new(raft.clone());

        let used_nonces = Arc::new(Mutex::new(UsedNonces::new()));

        // M12: AdminService and BootstrapService both need a
        // token secret to do anything useful. On non-bootstrap
        // nodes we still register them so the routes exist, but
        // they'll refuse with a clear error.
        let admin_svc = AdminServiceImpl::new(
            cfg.cluster_id.clone(),
            cfg.token_secret.clone().unwrap_or_else(TokenSecret::generate),
            used_nonces.clone(),
        );
        let bootstrap_svc = BootstrapServiceImpl::new(
            cfg.cluster_id.clone(),
            cfg.token_secret.clone().unwrap_or_else(TokenSecret::generate),
            used_nonces.clone(),
            cfg.join_handler.clone().unwrap_or_else(no_join_handler),
        );

        let forward_svc = NdjsonForwardServiceImpl::new(
            cfg.forward_handler.clone().unwrap_or_else(no_forward_handler),
        );

        // ---- 5. TLS + spawn ----------------------------------
        let tls_cfg = tls::server_tls_config(
            &cfg.leaf_cert_pem,
            &cfg.leaf_key_pem,
            &cfg.ca_cert_pem,
        );

        let bind_addr = cfg.bind_addr;
        let server_task = tokio::spawn(async move {
            run_grpc_server(bind_addr, tls_cfg, raft_svc, admin_svc, bootstrap_svc, forward_svc).await
        });

        // Touch unused field so compiler doesn't complain in M12
        // before sftpflowd consumes advertise_addr.
        let _ = cfg.advertise_addr;

        Ok(Self { raft, server_task })
    }

    /// Cheap clone-able handle. Hand one to every RPC dispatcher
    /// that needs to consult / mutate cluster state.
    pub fn handle(&self) -> ClusterHandle {
        ClusterHandle { raft: self.raft.clone() }
    }
}

/// Default no-op join handler used when the daemon hasn't supplied
/// one (i.e. this isn't the bootstrap node). Always returns an
/// error pointing the caller at the bootstrap node.
fn no_join_handler() -> JoinHandler {
    Arc::new(|_req: PJoinRequest| {
        Box::pin(async {
            Err("this node cannot accept joins (M12: only the bootstrap node can)".to_string())
        })
    })
}

// ============================================================
// ClusterHandle - thin facade for the daemon
// ============================================================

#[derive(Clone)]
pub struct ClusterHandle {
    raft: Raft<TypeConfig>,
}

impl ClusterHandle {
    /// True if this node currently believes it is the cluster's
    /// elected leader. Cheap — reads cached metrics.
    pub fn is_leader(&self) -> bool {
        let metrics = self.raft.metrics().borrow().clone();
        metrics.state.is_leader()
    }

    /// The node ID of the current leader from this node's view.
    /// `None` if this node is currently in candidate state or
    /// hasn't yet completed an election round.
    pub fn current_leader(&self) -> Option<u64> {
        self.raft.metrics().borrow().current_leader
    }

    /// Snapshot of the membership set at the last AppliedLogId.
    pub fn members(&self) -> BTreeMap<u64, ClusterMember> {
        let m = self.raft.metrics().borrow().clone();
        m.membership_config
            .nodes()
            .map(|(id, node)| (*id, node.clone()))
            .collect()
    }

    /// Members alongside their voter/learner status. Used by
    /// `cluster status` to render voters and learners distinctly.
    pub fn members_with_voter_flag(&self) -> BTreeMap<u64, (ClusterMember, bool)> {
        let m = self.raft.metrics().borrow().clone();
        let voters: std::collections::BTreeSet<u64> = m.membership_config.voter_ids().collect();
        m.membership_config
            .nodes()
            .map(|(id, node)| (*id, (node.clone(), voters.contains(id))))
            .collect()
    }

    // ------------------------------------------------------------
    // status helpers (used by `cluster status`)
    // ------------------------------------------------------------

    /// This node's local last-log index (tip of its Raft log).
    /// `None` before the first append. Cheap — reads cached metrics.
    pub fn last_log_index(&self) -> Option<u64> {
        self.raft.metrics().borrow().last_log_index
    }

    /// This node's local last-applied state-machine index.
    /// Drawn from `metrics.last_applied.index`. `None` if no entry
    /// has been applied yet.
    pub fn last_applied_index(&self) -> Option<u64> {
        self.raft
            .metrics()
            .borrow()
            .last_applied
            .as_ref()
            .map(|l| l.index)
    }

    /// Per-peer matched log index, as the *leader* sees it.
    ///
    /// Returns `None` when this node is not the current leader
    /// (openraft only populates `RaftMetrics::replication` on the
    /// leader). When `Some`, the inner map's keys match the leader's
    /// view of cluster members; values are `None` for peers that
    /// have not yet acknowledged any log entry.
    pub fn replication_progress(&self) -> Option<BTreeMap<u64, Option<u64>>> {
        let m = self.raft.metrics().borrow().clone();
        m.replication.map(|rep| {
            rep.into_iter()
                .map(|(nid, log_id_opt)| (nid, log_id_opt.map(|l| l.index)))
                .collect()
        })
    }

    /// Append an empty log entry — useful as a smoke test that the
    /// leader is alive and replication works end-to-end.
    pub async fn append_noop(&self) -> Result<(), ClusterError> {
        use crate::state::Command;
        self.raft
            .client_write(Command::NoOp)
            .await
            .map(|_| ())
            .map_err(|e| ClusterError::Raft(format!("append_noop: {}", e)))
    }

    /// Add a node as a learner (non-voting). Use before
    /// `change_membership` to promote to voter.
    pub async fn add_learner(
        &self,
        node_id: u64,
        member:  ClusterMember,
    ) -> Result<(), ClusterError> {
        self.raft
            .add_learner(node_id, member, true)
            .await
            .map(|_| ())
            .map_err(|e| ClusterError::Raft(format!("add_learner: {}", e)))
    }

    /// Replace the voter set. Pass the full new set, not a delta.
    pub async fn change_membership(
        &self,
        new_voters: std::collections::BTreeSet<u64>,
    ) -> Result<(), ClusterError> {
        // `retain = true` preserves any current learners not in
        // new_voters; `false` removes them. We use false: explicit
        // membership management.
        self.raft
            .change_membership(new_voters, false)
            .await
            .map(|_| ())
            .map_err(|e| ClusterError::Raft(format!("change_membership: {}", e)))
    }

    /// Initialize the cluster as a single-member voter set. Called
    /// once during `sftpflowd init`. Subsequent calls error.
    pub async fn initialize_solo(
        &self,
        node_id: u64,
        member:  ClusterMember,
    ) -> Result<(), ClusterError> {
        let mut m = BTreeMap::new();
        m.insert(node_id, member);
        self.raft
            .initialize(m)
            .await
            .map_err(|e| ClusterError::Raft(format!("initialize_solo: {}", e)))
    }

    /// Direct access to openraft metrics — used by `cluster
    /// status` to render a colored table.
    pub fn raw_metrics(&self) -> openraft::RaftMetrics<u64, ClusterMember> {
        self.raft.metrics().borrow().clone()
    }
}

// ============================================================
// dial_seed_join - client side of BootstrapService.Join
// ============================================================
//
// Used by `sftpflowd join`. Dials the seed node anonymously over
// TLS (the joining node has no cert yet), validates the seed's
// cert against the cluster CA, posts the token + CSR, and returns
// the issued cert + cluster identity.

pub struct SeedJoinArgs {
    /// host:port of the bootstrap node.
    pub seed_addr: String,
    /// PEM-encoded cluster CA cert. The joining node typically
    /// receives this out-of-band (from the operator running
    /// `sftpflow cluster ca-pem` on an existing node and pasting
    /// it on the joining node).
    pub ca_cert_pem: String,
    /// Single-use token minted via `sftpflow cluster token`.
    pub token: String,
    /// Operator-chosen ID for the joining node.
    pub desired_node_id: u64,
    /// Where this node will be reachable post-join.
    pub advertise_addr: String,
    /// CSR DER bytes generated by `tls::LeafKeyPair::csr_der()`.
    pub csr_der: Vec<u8>,
}

pub struct SeedJoinResult {
    pub ca_cert_pem:          String,
    pub signed_leaf_cert_pem: String,
    pub membership_json:      Vec<u8>,
    pub cluster_id:           String,
    /// Node ID the seed actually allocated to this joiner. Equals
    /// the request's `desired_node_id` when that was non-zero;
    /// otherwise it's the seed's `max(existing) + 1`. The joiner
    /// must persist this in node.json — the operator-supplied hint
    /// is advisory and may differ.
    pub assigned_node_id:     u64,
}

pub async fn dial_seed_join(args: SeedJoinArgs) -> Result<SeedJoinResult, ClusterError> {
    // SNI for the seed cert: host portion of seed_addr.
    let host = args
        .seed_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&args.seed_addr)
        .to_string();

    let tls_cfg = tls::client_tls_config_anonymous(&args.ca_cert_pem, &host);
    let endpoint = Endpoint::from_shared(format!("https://{}", args.seed_addr))
        .map_err(|e| ClusterError::Network(format!("endpoint: {}", e)))?
        .tls_config(tls_cfg)
        .map_err(|e| ClusterError::Tls(format!("client tls: {}", e)))?;
    let channel = endpoint.connect().await
        .map_err(|e| ClusterError::Network(format!("connect: {}", e)))?;

    let mut client = BootstrapServiceClient::new(channel);
    let resp = client
        .join(PJoinRequest {
            token:           args.token,
            desired_node_id: args.desired_node_id,
            advertise_addr:  args.advertise_addr,
            csr_der:         args.csr_der,
        })
        .await
        .map_err(|s| ClusterError::Network(format!("join rpc: {}", s)))?;

    let r = resp.into_inner();
    Ok(SeedJoinResult {
        ca_cert_pem:          String::from_utf8(r.ca_cert_pem)
            .map_err(|e| ClusterError::Other(format!("ca cert utf8: {}", e)))?,
        signed_leaf_cert_pem: String::from_utf8(r.signed_leaf_cert_pem)
            .map_err(|e| ClusterError::Other(format!("leaf cert utf8: {}", e)))?,
        membership_json:      r.membership_json,
        cluster_id:           r.cluster_id,
        assigned_node_id:     r.assigned_node_id,
    })
}
