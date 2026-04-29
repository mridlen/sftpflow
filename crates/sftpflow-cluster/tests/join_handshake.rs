// ============================================================
// Integration test: full BootstrapService.Join handshake
// ============================================================
//
// Sibling to three_node_cluster.rs. Where that test bypasses
// BootstrapService and drives add_learner / change_membership
// directly, this one exercises the actual production join path:
//
//   1. Bootstrap node 1 with a real JoinHandler (signs CSRs and
//      grows the voter set the same way sftpflowd's
//      cluster_runtime::bootstrap does).
//   2. Mint a join token via the token module (skipping the
//      AdminService.MintToken RPC — that's exercised separately).
//   3. Dial the bootstrap node from "node 2" via dial_seed_join,
//      using a freshly-generated leaf key + CSR with no pre-issued
//      cert. The seed signs the CSR and adds node 2 to the voter
//      set.
//   4. Bring up node 2 with the signed cert and verify it sees
//      the cluster's leader (i.e. the seed's AppendEntries reached
//      it).
//   5. Repeat for node 3 to prove the handler handles repeated
//      joins.
//
// This is the missing acceptance test that proves the seed-side
// JoinHandler the daemon installs (in cluster_runtime::bootstrap)
// is wired correctly to dial_seed_join. Without this, the only
// way to find a regression is end-to-end through sftpflowd init
// + sftpflowd join, which requires the docker test env.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, OnceCell};

use sftpflow_cluster::node::{
    dial_seed_join, ClusterHandle, ClusterNode, SeedJoinArgs, StartConfig,
};
use sftpflow_cluster::proto::{JoinRequest as PJoinRequest, JoinResponse as PJoinResponse};
use sftpflow_cluster::state::ClusterMember;
use sftpflow_cluster::tls::{ClusterCa, LeafKeyPair};
use sftpflow_cluster::token::{self, TokenSecret, UsedNonces};
use sftpflow_cluster::transport::JoinHandler;

// ============================================================
// Helpers
// ============================================================

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_for<F: Fn() -> bool>(name: &str, timeout: Duration, cond: F) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timeout waiting for: {}", name);
}

/// Build the same JoinHandler shape the daemon installs. Kept in
/// sync with `sftpflowd::cluster_runtime::make_seed_join_handler` —
/// see that function for why the membership work is spawned.
fn make_test_join_handler(
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
            let handle = handle_cell.get().ok_or_else(|| {
                "cluster handle not initialized".to_string()
            })?.clone();

            if handle.members().contains_key(&req.desired_node_id) {
                return Err(format!(
                    "node_id {} already in cluster",
                    req.desired_node_id,
                ));
            }

            let leaf_pem = ca.sign_csr(&req.csr_der)
                .map_err(|e| format!("sign csr: {}", e))?;

            let desired_node_id = req.desired_node_id;
            let advertise_addr  = req.advertise_addr.clone();
            let member = ClusterMember {
                advertise_addr: advertise_addr.clone(),
                added_at_unix:  0,
                label:          None,
            };
            tokio::spawn(async move {
                let _guard = join_serializer.lock().await;
                if let Err(e) = handle.add_learner(desired_node_id, member).await {
                    eprintln!("[bg] add_learner({}) failed: {}", desired_node_id, e);
                    return;
                }
                let mut voters: BTreeSet<u64> =
                    handle.members().keys().copied().collect();
                voters.insert(desired_node_id);
                if let Err(e) = handle.change_membership(voters).await {
                    eprintln!(
                        "[bg] change_membership for {} failed: {}",
                        desired_node_id, e,
                    );
                }
            });

            Ok(PJoinResponse {
                ca_cert_pem:          ca.cert_pem().into_bytes(),
                signed_leaf_cert_pem: leaf_pem.into_bytes(),
                membership_json:      Vec::new(),
                cluster_id,
                assigned_node_id:     desired_node_id,
            })
        })
    })
}

// ============================================================
// Test
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_handshake_end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = env_logger::builder().is_test(true).try_init();

    let temp = tempfile::tempdir().expect("tempdir");

    // ---- 1. Mint cluster CA + bootstrap node identity --------
    let cluster_id   = "join-handshake-test-cluster";
    let ca           = Arc::new(ClusterCa::generate(cluster_id).expect("ca"));
    let token_secret = TokenSecret::generate();

    // Bootstrap leaf cert (self-signed via the same CA).
    let n1_port    = pick_free_port();
    let n1_addr    = format!("127.0.0.1:{}", n1_port);
    let n1_bind: SocketAddr = n1_addr.parse().unwrap();
    let n1_leaf    = LeafKeyPair::generate(1, &n1_addr).expect("n1 leaf");
    let n1_csr     = n1_leaf.csr_der().expect("n1 csr");
    let n1_cert    = ca.sign_csr(&n1_csr).expect("n1 sign");

    // ---- 2. Wire real JoinHandler with OnceCell bridge -------
    let handle_cell: Arc<OnceCell<ClusterHandle>> = Arc::new(OnceCell::new());
    let join_serializer: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    let join_handler = make_test_join_handler(
        ca.clone(),
        cluster_id.to_string(),
        handle_cell.clone(),
        join_serializer.clone(),
    );

    // ---- 3. Start bootstrap node ------------------------------
    let n1_node = ClusterNode::start(StartConfig {
        node_id:           1,
        bind_addr:         n1_bind,
        advertise_addr:    n1_addr.clone(),
        raft_storage_path: temp.path().join("n1"),
        ca_cert_pem:       ca.cert_pem(),
        leaf_cert_pem:     n1_cert.clone(),
        leaf_key_pem:      n1_leaf.key_pem(),
        cluster_id:        cluster_id.to_string(),
        token_secret:      Some(token_secret.clone()),
        join_handler:      Some(join_handler),
        forward_handler:   None,
    }).await.expect("start n1");

    let h1 = n1_node.handle();
    if handle_cell.set(h1.clone()).is_err() {
        panic!("handle_cell already populated — test wired wrong");
    }

    // Let tonic bind before initializing.
    tokio::time::sleep(Duration::from_millis(500)).await;

    h1.initialize_solo(1, ClusterMember {
        advertise_addr: n1_addr.clone(),
        added_at_unix:  0,
        label:          None,
    }).await.expect("initialize_solo");

    wait_for("n1 elected leader", Duration::from_secs(5), || h1.is_leader()).await;

    // ---- 4. Joiner node 2 dials BootstrapService.Join ---------
    let n2_port = pick_free_port();
    let n2_addr = format!("127.0.0.1:{}", n2_port);
    let n2_bind: SocketAddr = n2_addr.parse().unwrap();
    let n2_leaf = LeafKeyPair::generate(2, &n2_addr).expect("n2 leaf");
    let n2_csr  = n2_leaf.csr_der().expect("n2 csr");

    let token_for_n2 = token::mint(&token_secret, cluster_id, 60).expect("mint n2");

    let n2_join = dial_seed_join(SeedJoinArgs {
        seed_addr:        n1_addr.clone(),
        ca_cert_pem:      ca.cert_pem(),
        token:            token_for_n2,
        desired_node_id:  2,
        advertise_addr:   n2_addr.clone(),
        csr_der:          n2_csr,
    }).await.expect("dial_seed_join n2");

    assert_eq!(n2_join.cluster_id, cluster_id);
    assert!(!n2_join.signed_leaf_cert_pem.is_empty());

    // ---- 5. Bring up node 2 with the issued cert -------------
    let n2_node = ClusterNode::start(StartConfig {
        node_id:           2,
        bind_addr:         n2_bind,
        advertise_addr:    n2_addr.clone(),
        raft_storage_path: temp.path().join("n2"),
        ca_cert_pem:       n2_join.ca_cert_pem.clone(),
        leaf_cert_pem:     n2_join.signed_leaf_cert_pem.clone(),
        leaf_key_pem:      n2_leaf.key_pem(),
        cluster_id:        cluster_id.to_string(),
        token_secret:      None,
        join_handler:      None,
        forward_handler:   None,
    }).await.expect("start n2");
    let h2 = n2_node.handle();

    // The seed has already added n2 as a learner + voter; the
    // first AppendEntries should reach n2 within a beat or two.
    wait_for("n2 sees a leader", Duration::from_secs(10), || {
        h2.current_leader().is_some()
    }).await;

    // ---- 6. Joiner node 3 — prove the handler handles repeats --
    let n3_port = pick_free_port();
    let n3_addr = format!("127.0.0.1:{}", n3_port);
    let n3_bind: SocketAddr = n3_addr.parse().unwrap();
    let n3_leaf = LeafKeyPair::generate(3, &n3_addr).expect("n3 leaf");
    let n3_csr  = n3_leaf.csr_der().expect("n3 csr");

    let token_for_n3 = token::mint(&token_secret, cluster_id, 60).expect("mint n3");

    let n3_join = dial_seed_join(SeedJoinArgs {
        seed_addr:        n1_addr.clone(),
        ca_cert_pem:      ca.cert_pem(),
        token:            token_for_n3,
        desired_node_id:  3,
        advertise_addr:   n3_addr.clone(),
        csr_der:          n3_csr,
    }).await.expect("dial_seed_join n3");

    let n3_node = ClusterNode::start(StartConfig {
        node_id:           3,
        bind_addr:         n3_bind,
        advertise_addr:    n3_addr.clone(),
        raft_storage_path: temp.path().join("n3"),
        ca_cert_pem:       n3_join.ca_cert_pem.clone(),
        leaf_cert_pem:     n3_join.signed_leaf_cert_pem.clone(),
        leaf_key_pem:      n3_leaf.key_pem(),
        cluster_id:        cluster_id.to_string(),
        token_secret:      None,
        join_handler:      None,
        forward_handler:   None,
    }).await.expect("start n3");
    let h3 = n3_node.handle();

    wait_for("n3 sees a leader", Duration::from_secs(10), || {
        h3.current_leader().is_some()
    }).await;

    wait_for("all three members visible to seed", Duration::from_secs(10), || {
        h1.members().len() == 3
    }).await;

    // Sanity: every node agrees on the leader.
    let leader = h1.current_leader().expect("h1 leader");
    assert_eq!(h2.current_leader(), Some(leader));
    assert_eq!(h3.current_leader(), Some(leader));

    // ---- 7. Reject a duplicate node_id ------------------------
    // A second join call with desired_node_id=2 should fail loudly
    // — the handler refuses members that are already in the set.
    let n_dup_leaf = LeafKeyPair::generate(2, &n2_addr).expect("dup leaf");
    let n_dup_csr  = n_dup_leaf.csr_der().expect("dup csr");
    let dup_token  = token::mint(&token_secret, cluster_id, 60).expect("mint dup");
    let dup_result = dial_seed_join(SeedJoinArgs {
        seed_addr:        n1_addr.clone(),
        ca_cert_pem:      ca.cert_pem(),
        token:            dup_token,
        desired_node_id:  2,
        advertise_addr:   n2_addr.clone(),
        csr_der:          n_dup_csr,
    }).await;
    assert!(
        dup_result.is_err(),
        "expected duplicate node_id to be rejected, got {:?}",
        dup_result.as_ref().map(|_| "Ok(_)"),
    );

    // ---- 8. Reject a replayed token ---------------------------
    // n2's token was already used in step 5. A second dial with
    // the same token must fail with a Replayed-style error.
    // (We can't reuse the exact token string here because we don't
    // hold onto it past dial_seed_join — instead we mint a fresh
    // token, use it once, then try to use it again.)
    let one_shot = token::mint(&token_secret, cluster_id, 60).expect("mint one-shot");
    {
        // First use: mint a node 4 to consume it.
        let n4_port = pick_free_port();
        let n4_addr = format!("127.0.0.1:{}", n4_port);
        let n4_leaf = LeafKeyPair::generate(4, &n4_addr).expect("n4 leaf");
        let n4_csr  = n4_leaf.csr_der().expect("n4 csr");
        let _used = dial_seed_join(SeedJoinArgs {
            seed_addr:        n1_addr.clone(),
            ca_cert_pem:      ca.cert_pem(),
            token:            one_shot.clone(),
            desired_node_id:  4,
            advertise_addr:   n4_addr.clone(),
            csr_der:          n4_csr,
        }).await.expect("first use of one_shot token");
    }
    // Replay attempt: same token, different desired_node_id.
    let n5_port = pick_free_port();
    let n5_addr = format!("127.0.0.1:{}", n5_port);
    let n5_leaf = LeafKeyPair::generate(5, &n5_addr).expect("n5 leaf");
    let n5_csr  = n5_leaf.csr_der().expect("n5 csr");
    let replay = dial_seed_join(SeedJoinArgs {
        seed_addr:        n1_addr.clone(),
        ca_cert_pem:      ca.cert_pem(),
        token:            one_shot.clone(),
        desired_node_id:  5,
        advertise_addr:   n5_addr,
        csr_der:          n5_csr,
    }).await;
    assert!(
        replay.is_err(),
        "expected replayed token to be rejected, got {:?}",
        replay.as_ref().map(|_| "Ok(_)"),
    );

    // Touch UsedNonces so the import isn't dead — we don't read
    // the seed's used-nonces set directly from this test (it lives
    // inside BootstrapServiceImpl), but the rejection above
    // exercises that code path end-to-end.
    let _ = UsedNonces::new();

    // Tear down.
    drop(n3_node);
    drop(n2_node);
    drop(n1_node);
}
