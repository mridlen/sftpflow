# M12 — Raft scaffolding (design doc)

Status: **accepted 2026-04-22** — user approved all recommendations.
Target: working 3-node cluster that knows its members. No replicated data yet — that's M13.
Dependencies: none (starts from current `dev` branch at 964a01f).

## Decisions locked (from the "open questions" section, now resolved)

1. **clap** added to `sftpflowd` for subcommand dispatch. ✔
2. **Same port** for `BootstrapService` (anonymous, token-gated) and mTLS `RaftService`. SNI/ALPN routes the two. ✔
3. **sled** backs the Raft log. Pure-Rust, consistent with the existing crypto story. ✔
4. **Operator-supplied `--node-id`** in M12. Auto-allocation deferred to M15. ✔
5. **`cluster remove`** uses quorum-via-Raft-membership (openraft default). ✔

Plus three scope calls:

- **Split M12 into two PRs:** (a) `sftpflow-cluster` crate + storage + Raft runtime, buildable in isolation; (b) daemon integration + CLI commands + compose test env. ✔
- **No write forwarding from follower → leader in M12.** Mutating RPCs on a follower return `NOT_LEADER` with the leader's advertise address so the CLI can retry. M13 adds automatic forwarding. ✔
- **`cluster status` prints a red warning when `voters == 2`.** Two-node is not HA. ✔

## 1. Goal and non-goals

### Goal

At the end of M12, a newcomer can run:

```sh
# Node 1: bootstrap
sftpflowd init --node-id 1 --bind 0.0.0.0:7900 --advertise node1.example.com:7900
sftpflow cluster token                         # prints a single-use join token

# Node 2, 3: join
sftpflowd join node1.example.com:7900 --node-id 2 --bind 0.0.0.0:7900 --token <tok>
sftpflowd join node1.example.com:7900 --node-id 3 --bind 0.0.0.0:7900 --token <tok>

# From any node:
sftpflow cluster status
# => 3 members: node1 (leader), node2 (follower), node3 (follower)
```

…and `cluster leave` / `cluster remove` cleanly de-register a member.

### Non-goals (deferred to M13+)

- Replicating `config.yaml` through Raft. Still per-node in M12.
- Replicating the sealed secrets blob. Still per-node in M12.
- Run-history on the Raft log. Still per-node SQLite in M12.
- Forwarding mutating RPCs from follower → leader. M12 rejects writes on non-leaders with a clear error message.
- Retiring dkron. Untouched in M12 — scheduler still runs via dkron, still per-node.
- HTTP healthcheck endpoint. M15.
- Rolling-upgrade / state-machine schema migrations. Out of scope for v1.

The intent is to land the wiring (Raft runtime, mTLS, membership, CLI) on an otherwise unchanged daemon. M13–M14 then move each state domain onto the log one at a time.

## 2. New dependencies

Add to [Cargo.toml](../Cargo.toml) `[workspace.dependencies]`:

```toml
openraft = { version = "0.9", features = ["serde"] }
tonic       = "0.12"            # gRPC transport for Raft RPCs
tonic-build = "0.12"            # build-time codegen for the service
prost       = "0.13"            # protobuf for tonic
rcgen       = "0.13"            # cluster CA + leaf cert generation
rustls-pemfile = "2"
tokio-rustls   = "0.26"
uuid           = { version = "1", features = ["v4", "serde"] }
```

`rustls` is already a workspace dep (pulled in via `suppaftp`); reuse the existing version.

Rationale: `openraft` is async-native and actively maintained, which is the decision locked on 2026-04-22. `tonic` gives us a typed, streaming-capable RPC surface for Raft AppendEntries / InstallSnapshot — openraft's examples use it. `rcgen` lets us mint the cluster CA in pure Rust with no openssl dependency (consistent with the existing pure-Rust crypto stance from milestones 10/11).

## 3. Crate layout

Add one new crate:

```
crates/
  sftpflow-cluster/        # NEW - Raft runtime, state machine, node transport
    src/
      lib.rs               # public API: ClusterNode, ClusterHandle
      state.rs             # openraft TypeConfig, state machine skeleton
      store.rs             # log + snapshot persistence (sled-backed)
      transport.rs         # tonic client/server for Raft RPCs
      membership.rs        # add_learner / change_membership helpers
      tls.rs               # cluster CA + leaf cert generation (rcgen)
      token.rs             # join token minting / validation
      proto/
        cluster.proto      # Raft service + token exchange service
```

Add one bin target to `sftpflowd`:

- [crates/sftpflowd/src/main.rs](../crates/sftpflowd/src/main.rs) grows three subcommands: `init`, `join`, and the existing default "run" behavior. Today the daemon parses its own `--flag` args; M12 introduces clap to handle the subcommand dispatch cleanly. Add `clap = { version = "4", features = ["derive"] }` to the workspace deps.

Add new CLI subcommands to [crates/sftpflow-cli/src/commands.rs](../crates/sftpflow-cli/src/commands.rs):

- `cluster status`
- `cluster token` (request a new join token from the leader)
- `cluster remove <node-id>` (forcefully remove a member — used when a node is permanently dead)

`cluster join` and `cluster leave` are daemon-side (`sftpflowd join` / `sftpflowd leave`) because they're node operations, not config operations. The user-facing CLI shell does not need them — administrators run them with shell access on the host.

## 4. Data shapes

### 4.1 Raft state machine (skeleton only — stubs until M13)

```rust
// crates/sftpflow-cluster/src/state.rs

use openraft::{LogId, Entry};

openraft::declare_raft_types!(
    pub TypeConfig:
        D = Command,       // log entry payload
        R = CommandResult, // state machine output
        NodeId = u64,
        Node = ClusterMember,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMember {
    pub advertise_addr: String,     // host:port other nodes dial
    pub added_at:       DateTime<Utc>,
    pub label:          Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    // M12: only membership changes produce log entries.
    //      All variants below are placeholders for M13/M14.
    NoOp,                                          // used for leader health
    PutConfig(Config),            // M13
    PutSecret { name: String, ciphertext: Vec<u8> }, // M13
    DeleteSecret(String),                          // M13
    AppendRunHistory(RunHistoryEntry),             // M14
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandResult {
    Ok,
    Err(String),
}

pub struct StateMachine {
    // M12: these are empty / stubbed. Real content arrives in M13.
    last_applied: Option<LogId<u64>>,
    // reserved for M13:
    // config: Option<Config>,
    // secrets_blob: Option<Vec<u8>>,
    // run_history: Vec<RunHistoryEntry>,
}
```

The key point: **the state machine compiles and applies `NoOp` entries** in M12. The other variants parse and are accepted by the log but their `apply()` arms are `todo!()` (and no code ever produces them yet). This lets the Raft plumbing be tested end-to-end without touching `DaemonState`.

### 4.2 On-disk layout per node

```
/var/lib/sftpflow/          (Linux)   |   %APPDATA%/sftpflow/   (Windows)
├── node.json                # { node_id, advertise_addr, cluster_id, created_at }
├── cluster/
│   ├── ca.crt               # cluster CA public cert (shared across nodes)
│   ├── ca.key               # CA private key (only on the bootstrap node)
│   ├── node.crt             # this node's leaf cert
│   ├── node.key             # this node's leaf private key
│   └── peers.json           # cached member list (advisory; Raft is source of truth)
├── raft/
│   ├── log/                 # sled DB - openraft log entries
│   └── snapshots/           # periodic state-machine snapshots
├── config.yaml              # existing - UNCHANGED in M12
├── secrets.sealed           # existing - UNCHANGED in M12
└── runs.db                  # existing - UNCHANGED in M12
```

Stable node identity: `node.json` is written once at `init` or `join` and never mutated. The daemon refuses to start if `node.json` exists but `--node-id` on the command line disagrees.

`ca.key` lives only on the **bootstrap node** by default — other nodes get only the public cert. This means only the bootstrap node can mint new join tokens. M15 adds a `cluster ca rotate` flow to distribute the CA private key to a second node for HA of the bootstrap role; out of scope for M12.

### 4.3 Join token format

```
sftpflow-join-v1.<cluster_id>.<expiry_unix>.<nonce_b64>.<hmac_b64>
```

- `cluster_id`: UUID v4 generated at `init`, stored in `node.json`.
- `expiry_unix`: token expires 1 hour after minting (configurable).
- `nonce_b64`: 128 bits of randomness, single-use.
- `hmac_b64`: HMAC-SHA256 over the preceding fields, keyed with a per-cluster token secret (32 random bytes generated at `init`, stored encrypted in the secrets blob under the reserved name `__cluster_token_key__`).

Used nonces are recorded in a small `cluster/tokens_used.json` file on the bootstrap node so tokens cannot be replayed. Single-use is the right default even though the HMAC alone would let us skip the used-nonce list — replay protection is cheap insurance against a leaked token.

`cluster token` calls an RPC on the leader that mints and returns a token; the leader coordinates with the bootstrap node (in M12 they are the same node) to register the nonce.

### 4.4 Cluster mTLS certs

- CA generated at `init`: 10-year validity, ed25519, CN=`sftpflow-cluster-<uuid>`.
- Leaf certs per node: 1-year validity, ed25519, CN=`node-<id>`, SAN=`advertise_addr` (DNS or IP). Rotation is out of scope for M12 — M15 adds `cluster cert rotate`.
- Both sides do mTLS on every Raft RPC. The server-side handler verifies the client cert chains to the cluster CA and extracts the node ID from the CN.
- TLS config uses rustls with the existing `ring` crate feature (already in `[workspace.dependencies]`).

## 5. Control flow — init and join

### 5.1 `sftpflowd init`

```
1. Refuse if node.json already exists (don't clobber an existing node).
2. Generate cluster_id (UUID v4).
3. Generate cluster CA (rcgen).
4. Generate leaf cert signed by CA for this node.
5. Generate 32-byte token HMAC key.
6. Open sealed secrets store, write __cluster_token_key__.
7. Write node.json, ca.{crt,key}, node.{crt,key}.
8. openraft::Raft::new() with this node as sole voting member.
9. Call raft.initialize({ this_node }) — bootstrap as solo leader.
10. Start tonic server on --bind for Raft RPCs (mTLS).
11. Start the existing NDJSON RPC server on its normal socket.
12. Log "cluster bootstrapped, node_id=1, cluster_id=<uuid>".
```

A fresh `init` produces a single-member cluster that is already a "leader" in Raft terms. `cluster token` works immediately.

### 5.2 `sftpflowd join <seed> --token <tok>`

```
1. Refuse if node.json already exists.
2. Dial <seed> over TLS (no client cert yet — seed accepts anonymous connections only on the join port).
3. Call seed's BootstrapService.Join(token, desired_node_id, advertise_addr, csr).
   - Seed validates: HMAC, expiry, nonce-not-used, cluster_id match,
     node_id not already taken.
   - Seed signs the CSR with the cluster CA.
   - Seed returns: { ca_cert, signed_leaf_cert, current_membership, cluster_id, token_hmac_key? }
   - NOTE: token_hmac_key is NOT returned in M12 — only the bootstrap node can mint tokens.
4. Write ca.crt, node.crt, node.key, node.json.
5. Start tonic server on --bind with the issued cert.
6. openraft::Raft::new() in "learner" state (empty log).
7. Seed (as current leader) calls raft.add_learner(this_node).
8. Raft replicates log to the new learner.
9. Once caught up, seed calls raft.change_membership to promote learner → voter.
10. Start the existing NDJSON RPC server.
11. Log "joined cluster <uuid>, node_id=<n>, current_leader=<id>".
```

The seed-side join handler is a `BootstrapService` distinct from the `RaftService`. It runs on the same port but uses SNI / ALPN to route: Raft RPCs require a valid client cert; `BootstrapService` methods allow anonymous TLS (just authenticates the server to the joining node). Once the join completes, all further traffic is mTLS.

### 5.3 Leader discovery after restart

After a crash or restart, the node:

1. Reads `node.json`, leaf cert, CA.
2. Opens the sled log.
3. Calls `Raft::new()` — openraft replays the log and contacts known peers from the last-applied membership set.
4. If a quorum responds, it becomes follower / candidate / leader per normal Raft.
5. If no quorum, it stays in follower state and logs warnings.

There's no "rejoin" path — once a node has a place in the membership set, restarting is transparent. `cluster remove` on the remaining members is how you permanently de-register a dead node.

## 6. Wire protocol — new services

```protobuf
// crates/sftpflow-cluster/src/proto/cluster.proto

service RaftService {
  rpc AppendEntries(AppendEntriesRequest) returns (AppendEntriesResponse);
  rpc InstallSnapshot(stream InstallSnapshotChunk) returns (InstallSnapshotResponse);
  rpc Vote(VoteRequest) returns (VoteResponse);
}

service BootstrapService {
  rpc Join(JoinRequest) returns (JoinResponse);
  rpc MintToken(MintTokenRequest) returns (MintTokenResponse);
}

message JoinRequest {
  string token           = 1;
  uint64 desired_node_id = 2;
  string advertise_addr  = 3;
  bytes  csr_der         = 4;   // leaf cert signing request
}

message JoinResponse {
  bytes  ca_cert_pem         = 1;
  bytes  signed_leaf_cert_pem = 2;
  bytes  membership_json      = 3;  // JSON-serialized current membership
  string cluster_id          = 4;
}
```

Every method except `BootstrapService.Join` requires a valid mTLS client cert; `Join` is the one anonymous endpoint (authenticated out-of-band by the HMAC'd token).

## 7. Changes to existing code

Minimal. The goal of M12 is that the existing daemon keeps doing what it does today while the Raft runtime spins alongside.

### 7.1 [crates/sftpflowd/src/main.rs](../crates/sftpflowd/src/main.rs)

- Switch argument parsing to `clap` derive.
- Three subcommands: `init`, `join <seed>`, and (default) run.
- For `run`: load `node.json`, start the Raft runtime, *then* start the existing `server::run()` — both run concurrently.
- For `init` / `join`: do the bootstrap/join dance, write state, exit.

### 7.2 [crates/sftpflowd/src/server.rs](../crates/sftpflowd/src/server.rs)

Add one field to `DaemonState`:

```rust
pub cluster: Option<ClusterHandle>,   // None during pre-M12 single-node mode
```

Gate mutating handlers (PutEndpoint, PutFeed, PutSecret, etc.) on `cluster.is_leader()` when `cluster.is_some()`. Non-leaders return a new `Response::Error` variant `NotLeader { leader_advertise: Option<String> }` so the CLI can display a useful message. M13 turns this into automatic forwarding; M12 is fail-loud so we catch every call site.

### 7.3 [crates/sftpflow-proto/src/lib.rs](../crates/sftpflow-proto/src/lib.rs)

Add three requests:

```rust
Request::ClusterStatus,
Request::ClusterMintToken,
Request::ClusterRemoveNode { node_id: u64 },
```

Add responses:

```rust
Response::ClusterStatus(ClusterStatus),  // member list + leader + self_id
Response::ClusterToken(String),
```

Add error code:

```rust
pub const NOT_LEADER: &str = "NOT_LEADER";
```

### 7.4 [crates/sftpflow-cli/src/commands.rs](../crates/sftpflow-cli/src/commands.rs)

Three new commands under a `cluster` namespace:

- `cluster status` — pretty-print leader, followers, learners with a color for role and an "⚠ unreachable" marker. Calls `ClusterStatus`.
- `cluster token` — calls `ClusterMintToken`, prints the opaque token string.
- `cluster remove <node-id>` — double-confirms, then calls `ClusterRemoveNode`.

## 8. Testing plan

1. **Unit:** token mint / validate round-trip, reject on expired, reject on reused nonce, reject on wrong cluster_id. `tls::generate_ca_and_leaf` produces certs that verify. State machine applies `NoOp` and updates `last_applied`.
2. **Integration (single-process, in-memory):** three-node cluster in one test binary using openraft's `MemStore` — verify election, log replication of NoOps, `add_learner` → voter promotion, `remove_node` takes effect.
3. **Integration (multi-process):** extend the existing [docker/compose.test.yml](../docker/compose.test.yml) with three `sftpflow-server` replicas. Test: `init` on one, `join` on the other two, `cluster status` from any member shows all three. Kill the leader; within 10s a new leader is elected. Restart the killed node; it rejoins without operator action.
4. **Manual smoke:** on the user's WSL dev box, run three `sftpflowd` processes on different ports (unix sockets for NDJSON, TCP for Raft), reproduce the integration test without containers.

## 9. Rollout / backward compatibility

This is a breaking change to the daemon startup sequence — pre-M12 just runs `sftpflowd` with no subcommand. To preserve the existing test env during development, `sftpflowd` **with no subcommand and no `node.json` present** keeps working in the old single-node mode (logs a deprecation warning). M13 removes that fallback.

The docker compose file stays unchanged in M12 except for adding the new `cluster/` volume mount. dkron still runs. `config.yaml` bind-mount still works. The user's existing WSL test setup (`make test-up`) should continue to function with only the addition of one `sftpflowd init` step before `test-up`.

## 10. Risks and open questions

1. **openraft API surface is non-trivial.** The `RaftStorage` trait requires 15+ methods. We should implement it against `sled` following openraft's `rocksstore` example. Estimate: ~600 LOC for a correct implementation. Risk: bugs in snapshot/install-snapshot are the classic Raft footgun.
2. **Node ID allocation.** M12 requires `--node-id` to be user-supplied. This is ugly but correct — auto-allocation needs a separate coordination mechanism (e.g. a monotonic counter in the state machine). M15 adds `sftpflowd join --auto-id`.
3. **Two-node cluster footgun.** `init` + one `join` produces a 2-node cluster with quorum=2: any single node failure stalls the cluster. Documentation must be explicit. Consider: `cluster status` prints a red warning when `voters == 2`.
4. **Windows.** openraft + tonic + rustls all build on MSVC, but the on-disk paths differ. sled works on Windows; we've used it via `rusqlite` (different crate, but similar portability profile). Flag for testing.
5. **Time skew.** Join token expiry uses wall clock. Nodes with drifted clocks will mint / accept inconsistent tokens. Not addressed in M12; document the 1-hour window as an operator concern.
6. **What happens if the bootstrap node dies permanently before `cluster ca rotate` exists (M15)?** You lose the ability to mint new join tokens. The cluster keeps running; existing members keep working; you just can't add new ones. For M12 this is an acknowledged gap — document it, plan the rotation story for M15.

## 11. Out-of-scope (explicit list, to prevent scope creep)

- TLS cert rotation.
- CA key backup/restore.
- Raft snapshot schedule tuning (use openraft's default).
- Auto node-id allocation.
- Rolling upgrades.
- Follower → leader write forwarding (fail fast in M12; proxy in M13).
- HTTP API / metrics endpoint.
- Healthcheck endpoint for Docker.
- Pre-built images. (All M15.)

## 12. Estimated size

- `sftpflow-cluster` crate: ~1500 LOC (storage impl is the bulk).
- `sftpflowd` main.rs / server.rs changes: ~200 LOC.
- `sftpflow-proto` additions: ~50 LOC.
- `sftpflow-cli` additions: ~200 LOC.
- Tests + docker compose updates: ~400 LOC.

**Total: ~2400 LOC.** Bigger than prior milestones, but the majority is boilerplate inside `sftpflow-cluster` and could be split across two PRs (storage + runtime, then CLI + protocol) if it turns out too unwieldy in review.

## 13. Open questions

All resolved — see "Decisions locked" at the top of this doc.
