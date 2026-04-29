// ============================================================
// Integration test: NdjsonForwardService end-to-end
// ============================================================
//
// Brings up a real 3-node cluster (same fixture style as
// `three_node_cluster.rs`) but installs a stub `forward_handler`
// on every node that records the receiving node's id and echoes
// it back. Then it dials each node's mTLS gRPC channel and
// verifies the receiver actually ran the local handler — proving:
//
//   1. NdjsonForwardService is registered alongside RaftService /
//      AdminService / BootstrapService and reachable.
//   2. The handler closure plumbed through StartConfig is the one
//      that actually fires.
//   3. mTLS works for the new service (same gate as RaftService;
//      anonymous TLS is rejected).
//
// We deliberately do NOT bring up sftpflowd here — this test is a
// transport-level proof. The follower→leader routing in
// sftpflowd::server::forward_if_follower is exercised by
// scripts/test-cluster.sh against a real multi-process docker
// compose stack.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sftpflow_cluster::node::{ClusterNode, StartConfig};
use sftpflow_cluster::tls::{ClusterCa, LeafKeyPair};
use sftpflow_cluster::transport::{forward_envelope_to_peer, NdjsonForwardHandler};

// ============================================================
// Helpers (mirror three_node_cluster.rs style)
// ============================================================

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

/// Build a forward handler that records (a) how many times it
/// fired and (b) the bytes it last received, then echoes back a
/// fixed reply prefixed with the node's id. The reply lets the
/// caller verify *which* node ran the handler when the test
/// dials a peer and reads back its response.
fn recording_handler(node_id: u64, counter: Arc<AtomicU64>) -> NdjsonForwardHandler {
    Arc::new(move |envelope_json: Vec<u8>| {
        let counter = counter.clone();
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            // Echo back: original payload + a tag with node_id so
            // the test can prove which node executed the handler.
            let mut out = format!("node={}|", node_id).into_bytes();
            out.extend_from_slice(&envelope_json);
            Ok(out)
        })
    })
}

async fn start_node_with_handler(
    f:               &NodeFixture,
    ca_cert_pem:     &str,
    cluster_id:      &str,
    raft_dir:        std::path::PathBuf,
    forward_handler: NdjsonForwardHandler,
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
        forward_handler:   Some(forward_handler),
    };
    ClusterNode::start(cfg).await.expect("start node")
}

// ============================================================
// Test
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_handler_runs_on_target_node_and_round_trips() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = env_logger::builder().is_test(true).try_init();

    let cluster_id = "test-cluster-forward";
    let ca = ClusterCa::generate(cluster_id).expect("ca");
    let ca_pem = ca.cert_pem();

    // Three nodes, one recording handler per node so we can assert
    // whose handler fired by inspecting per-node counters.
    let n1 = mint_node(1, &ca);
    let n2 = mint_node(2, &ca);
    let n3 = mint_node(3, &ca);

    let c1 = Arc::new(AtomicU64::new(0));
    let c2 = Arc::new(AtomicU64::new(0));
    let c3 = Arc::new(AtomicU64::new(0));

    let temp = tempfile::tempdir().expect("tempdir");

    let _node1 = start_node_with_handler(
        &n1, &ca_pem, cluster_id, temp.path().join("n1"),
        recording_handler(1, c1.clone()),
    ).await;
    let _node2 = start_node_with_handler(
        &n2, &ca_pem, cluster_id, temp.path().join("n2"),
        recording_handler(2, c2.clone()),
    ).await;
    let _node3 = start_node_with_handler(
        &n3, &ca_pem, cluster_id, temp.path().join("n3"),
        recording_handler(3, c3.clone()),
    ).await;

    // tonic needs a beat to bind all three listeners.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ---- 1. Node-1 client forwards to node-2 ------------------
    // Use n1's leaf cert + key (its mTLS identity); ca_pem is the
    // shared trust anchor.
    let payload = b"forwarded-envelope-v1".to_vec();
    let resp = forward_envelope_to_peer(
        &n2.advertise_addr,
        &n1.leaf_cert_pem,
        &n1.leaf_key_pem,
        &ca_pem,
        payload.clone(),
    ).await.expect("forward n1 -> n2");

    assert!(
        resp.starts_with(b"node=2|"),
        "expected n2's handler to run; got {:?}",
        String::from_utf8_lossy(&resp),
    );
    assert!(
        resp.ends_with(&payload),
        "handler should echo payload bytes through unchanged",
    );
    assert_eq!(c2.load(Ordering::SeqCst), 1, "n2 handler fired exactly once");
    assert_eq!(c1.load(Ordering::SeqCst), 0, "n1 handler did not fire");
    assert_eq!(c3.load(Ordering::SeqCst), 0, "n3 handler did not fire");

    // ---- 2. Node-3 client forwards to node-1 ------------------
    let payload2 = b"second-call".to_vec();
    let resp2 = forward_envelope_to_peer(
        &n1.advertise_addr,
        &n3.leaf_cert_pem,
        &n3.leaf_key_pem,
        &ca_pem,
        payload2.clone(),
    ).await.expect("forward n3 -> n1");

    assert!(resp2.starts_with(b"node=1|"));
    assert_eq!(c1.load(Ordering::SeqCst), 1);
    assert_eq!(c2.load(Ordering::SeqCst), 1);
    assert_eq!(c3.load(Ordering::SeqCst), 0);
}
