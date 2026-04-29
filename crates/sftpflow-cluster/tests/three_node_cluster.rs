// ============================================================
// Integration test: in-process 3-node cluster
// ============================================================
//
// Spins up three real ClusterNode instances on three localhost
// ports with three real mTLS-signed leaf certs and exercises:
//
//   1. Bootstrap node 1 as solo voter via initialize_solo.
//   2. Add nodes 2 and 3 as learners.
//   3. Promote {1, 2, 3} as voting members.
//   4. Wait for the cluster to converge (leader elected, all
//      three followers seeing the same last_log_id).
//   5. Append a NoOp on the leader; verify it replicates.
//
// This is the M12 acceptance test: "a working 3-node cluster
// that knows its members." If this passes, the cluster crate is
// done as far as PR-A is concerned.
//
// We bypass the BootstrapService.Join flow here — that path
// requires a JoinHandler that signs CSRs and drives membership
// changes, which is daemon-side code (PR-B). The Raft
// machinery itself is what this test validates.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use sftpflow_cluster::node::{ClusterHandle, ClusterNode, StartConfig};
use sftpflow_cluster::state::ClusterMember;
use sftpflow_cluster::tls::{ClusterCa, LeafKeyPair};

// ============================================================
// Helpers
// ============================================================

/// Find a free localhost port by binding and immediately closing.
/// Race-prone in principle (something else can take the port
/// between bind and use) but fine for local-only tests.
fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct NodeFixture {
    id:             u64,
    advertise_addr: String,
    bind_addr:      SocketAddr,
    leaf_cert_pem:  String,
    leaf_key_pem:   String,
}

fn mint_node(id: u64, ca: &ClusterCa) -> NodeFixture {
    let port = pick_free_port();
    let advertise_addr = format!("127.0.0.1:{}", port);
    let leaf = LeafKeyPair::generate(id, &advertise_addr).expect("leaf gen");
    let csr_der = leaf.csr_der().expect("csr");
    let leaf_cert_pem = ca.sign_csr(&csr_der).expect("sign");
    NodeFixture {
        id,
        advertise_addr: advertise_addr.clone(),
        bind_addr:      advertise_addr.parse().unwrap(),
        leaf_cert_pem,
        leaf_key_pem: leaf.key_pem(),
    }
}

async fn start_node(
    f:           &NodeFixture,
    ca_cert_pem: &str,
    cluster_id:  &str,
    raft_dir:    std::path::PathBuf,
) -> ClusterNode {
    let cfg = StartConfig {
        node_id:           f.id,
        bind_addr:         f.bind_addr,
        advertise_addr:    f.advertise_addr.clone(),
        raft_storage_path: raft_dir,
        ca_cert_pem:       ca_cert_pem.to_string(),
        leaf_cert_pem:     f.leaf_cert_pem.clone(),
        leaf_key_pem:      f.leaf_key_pem.clone(),
        cluster_id:        cluster_id.to_string(),
        token_secret:      None,
        join_handler:      None,
        forward_handler:   None,
    };
    ClusterNode::start(cfg).await.expect("start node")
}

/// Poll `cond` every 50 ms for up to `timeout`. Panics on timeout.
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

fn member_for(f: &NodeFixture) -> ClusterMember {
    ClusterMember {
        advertise_addr: f.advertise_addr.clone(),
        added_at_unix:  0,
        label:          None,
    }
}

// ============================================================
// Test
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_cluster_elects_replicates_and_resizes() {
    // Init the rustls crypto provider once. Otherwise tonic's
    // tls config builder panics with "no default CryptoProvider".
    let _ = rustls::crypto::ring::default_provider().install_default();

    let _ = env_logger::builder().is_test(true).try_init();

    let temp = tempfile::tempdir().expect("tempdir");

    // ---- 1. Mint cluster CA + per-node leaf certs ------------
    let cluster_id = "test-cluster-001";
    let ca = ClusterCa::generate(cluster_id).expect("ca");
    let ca_cert_pem = ca.cert_pem();

    let n1 = mint_node(1, &ca);
    let n2 = mint_node(2, &ca);
    let n3 = mint_node(3, &ca);

    // ---- 2. Start three nodes --------------------------------
    let node1 = start_node(&n1, &ca_cert_pem, cluster_id, temp.path().join("n1")).await;
    let node2 = start_node(&n2, &ca_cert_pem, cluster_id, temp.path().join("n2")).await;
    let node3 = start_node(&n3, &ca_cert_pem, cluster_id, temp.path().join("n3")).await;

    let h1: ClusterHandle = node1.handle();
    let h2: ClusterHandle = node2.handle();
    let h3: ClusterHandle = node3.handle();

    // Give tonic servers a moment to bind their listeners. Without
    // this, the first add_learner can race the listener and fail
    // with "connection refused".
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ---- 3. Bootstrap node 1 as solo voter -------------------
    h1.initialize_solo(n1.id, member_for(&n1))
        .await
        .expect("initialize_solo");

    wait_for("node 1 elected leader", Duration::from_secs(5), || {
        h1.is_leader()
    })
    .await;

    // ---- 4. Add learners 2 and 3 -----------------------------
    h1.add_learner(n2.id, member_for(&n2)).await.expect("add_learner 2");
    h1.add_learner(n3.id, member_for(&n3)).await.expect("add_learner 3");

    // ---- 5. Promote to a 3-voter cluster ---------------------
    let voters: BTreeSet<u64> = [1u64, 2, 3].into_iter().collect();
    h1.change_membership(voters).await.expect("change_membership");

    // ---- 6. Wait for convergence -----------------------------
    // All three nodes should agree on a leader and have membership
    // size 3.
    wait_for("nodes 2 and 3 see leader", Duration::from_secs(10), || {
        h2.current_leader().is_some() && h3.current_leader().is_some()
    })
    .await;

    wait_for("all three see 3 members", Duration::from_secs(10), || {
        h1.members().len() == 3 && h2.members().len() == 3 && h3.members().len() == 3
    })
    .await;

    // The leader election should agree across the cluster.
    let leader = h1.current_leader().expect("leader on node 1");
    assert_eq!(h2.current_leader(), Some(leader));
    assert_eq!(h3.current_leader(), Some(leader));

    // ---- 7. Replicate a NoOp ---------------------------------
    let leader_handle = match leader {
        1 => &h1,
        2 => &h2,
        3 => &h3,
        other => panic!("unexpected leader id {}", other),
    };

    let last_before_n2 = h2.raw_metrics().last_applied;
    leader_handle.append_noop().await.expect("append_noop");

    wait_for("noop replicated to node 2", Duration::from_secs(5), || {
        let m = h2.raw_metrics().last_applied;
        m != last_before_n2
    })
    .await;

    wait_for("noop replicated to node 3", Duration::from_secs(5), || {
        h3.raw_metrics().last_applied >= h2.raw_metrics().last_applied
    })
    .await;

    // ---- 8. Exercise the new status helpers ------------------
    // After replication the leader's `replication_progress()` map
    // must be `Some` and contain the two followers, both caught up
    // to the leader's last_log_index. Followers must report `None`
    // for `replication_progress` (per openraft 0.9 semantics).
    let leader_h = leader_handle;
    let follower_handles: Vec<&ClusterHandle> = [&h1, &h2, &h3]
        .into_iter()
        .filter(|h| !std::ptr::eq(*h, leader_h))
        .collect();

    // Wait for the leader's view of replication to fully catch up.
    // Right after `append_noop`, the leader's matched-index map can
    // briefly trail; poll until both followers match leader.tip.
    wait_for(
        "leader replication map caught up",
        Duration::from_secs(5),
        || {
            let tip = match leader_h.last_log_index() {
                Some(i) => i,
                None => return false,
            };
            let rep = match leader_h.replication_progress() {
                Some(r) => r,
                None => return false,
            };
            follower_handles.iter().all(|fh| {
                let id = fh.raw_metrics().id;
                matches!(rep.get(&id), Some(Some(matched)) if *matched >= tip)
            })
        },
    )
    .await;

    // Followers don't expose replication metrics — confirm that.
    for fh in &follower_handles {
        assert!(
            fh.replication_progress().is_none(),
            "non-leader should report None for replication_progress",
        );
    }

    // Sanity-check the index helpers themselves.
    assert!(
        leader_h.last_log_index().is_some(),
        "leader should have a last_log_index after append_noop",
    );
    assert!(
        leader_h.last_applied_index().is_some(),
        "leader should have a last_applied_index after append_noop",
    );

    // Tear down — Drop on each ClusterNode aborts the gRPC task.
    drop(node1);
    drop(node2);
    drop(node3);
}
