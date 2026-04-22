// ============================================================
// sftpflow-cluster - Raft-based clustering for sftpflowd
// ============================================================
//
// Public surface (consumed by sftpflowd):
//   - ClusterNode      - owns a tokio runtime + openraft instance
//   - ClusterHandle    - thread-safe handle for sync code
//   - ClusterStatus    - snapshot of membership + leader for RPC
//   - InitOptions      - parameters for sftpflowd init
//   - JoinOptions      - parameters for sftpflowd join
//
// Internal modules:
//   - state            - openraft TypeConfig + state machine
//   - store            - sled-backed Raft log + snapshot store
//   - transport        - tonic mTLS client/server for Raft RPCs
//   - bootstrap        - anonymous TLS server for token-gated joins
//   - tls              - cluster CA + leaf cert generation (rcgen)
//   - token            - join token mint/validate (HMAC-SHA256)
//   - membership       - add_learner / change_membership helpers
//
// All modules are stubs in the initial M12 skeleton; subsequent
// M12 tasks fill them in one at a time.
//
// Design doc: docs/m12-raft-scaffolding.md

// ---- Internal modules (added incrementally during M12) ----
// pub mod state;       // openraft TypeConfig + StateMachine
// pub mod store;       // sled-backed RaftStorage impl
// pub mod transport;   // tonic mTLS RaftService client/server
// pub mod bootstrap;   // anonymous TLS BootstrapService
// pub mod tls;         // CA + leaf cert generation
// pub mod token;       // join token mint/validate
// pub mod membership;  // membership change helpers

// ============================================================
// Crate version (used in startup logs and protocol negotiation)
// ============================================================

pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
