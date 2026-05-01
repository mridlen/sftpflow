// ============================================================
// sftpflow-cluster::transport - tonic gRPC node-to-node transport
// ============================================================
//
// Two halves living in one module because they share quite a bit
// of TLS/encoding/error-mapping plumbing:
//
//   1. CLIENT side (RaftNetwork + RaftNetworkFactory)
//      Implements the openraft `RaftNetwork<TypeConfig>` trait.
//      openraft's runtime calls into PeerNetwork::append_entries /
//      vote / install_snapshot; we encode the openraft request as
//      JSON, ship it over gRPC via the generated tonic client, and
//      decode the response.
//
//   2. SERVER side (RaftServiceImpl + AdminServiceImpl +
//                   BootstrapServiceImpl + run_grpc_server)
//      Implements the three gRPC services from cluster.proto.
//      RaftService and AdminService require a valid mTLS client
//      cert (enforced per-handler via tonic::Request::peer_certs
//      because tonic doesn't have a per-service auth filter).
//      BootstrapService allows anonymous TLS — the joining node
//      doesn't yet have a cert.
//
// Wire encoding for Raft RPCs: JSON-serialize openraft's typed
// request/response into the proto's `bytes payload_json` field.
// This keeps the proto schema stable across openraft upgrades
// (the JSON shape is what we own), and avoids hand-mapping every
// openraft type into protobuf fields.

use std::sync::Arc;

use openraft::error::{NetworkError, RPCError, RaftError, RemoteError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest,
    AppendEntriesResponse,
    InstallSnapshotRequest,
    InstallSnapshotResponse,
    VoteRequest,
    VoteResponse,
};
use openraft::Raft;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use crate::proto::raft_service_client::RaftServiceClient;
use crate::proto::raft_service_server::{RaftService, RaftServiceServer};
use crate::proto::admin_service_server::{AdminService, AdminServiceServer};
use crate::proto::bootstrap_service_server::{BootstrapService, BootstrapServiceServer};
use crate::proto::ndjson_forward_service_client::NdjsonForwardServiceClient;
use crate::proto::ndjson_forward_service_server::{
    NdjsonForwardService, NdjsonForwardServiceServer,
};
use crate::proto::{
    JoinRequest as PJoinRequest,
    JoinResponse as PJoinResponse,
    MintTokenRequest as PMintTokenRequest,
    MintTokenResponse as PMintTokenResponse,
    NdjsonForwardRequest as PNdjsonForwardRequest,
    NdjsonForwardResponse as PNdjsonForwardResponse,
    RaftRpcRequest,
    RaftRpcResponse,
};
use crate::state::{ClusterMember, TypeConfig};
use crate::tls;
use crate::token::{self, TokenSecret, UsedNonces};

// ============================================================
// Client side: RaftNetwork + RaftNetworkFactory
// ============================================================

/// Factory that hands openraft a fresh `PeerNetwork` for each
/// remote target. Holds this node's mTLS identity so every spawned
/// client presents the right cert.
#[derive(Clone)]
pub struct PeerNetworkFactory {
    leaf_cert_pem: String,
    leaf_key_pem:  String,
    ca_cert_pem:   String,
}

impl PeerNetworkFactory {
    pub fn new(leaf_cert_pem: String, leaf_key_pem: String, ca_cert_pem: String) -> Self {
        Self { leaf_cert_pem, leaf_key_pem, ca_cert_pem }
    }
}

impl RaftNetworkFactory<TypeConfig> for PeerNetworkFactory {
    type Network = PeerNetwork;

    async fn new_client(&mut self, target: u64, node: &ClusterMember) -> Self::Network {
        // Connection happens lazily on the first RPC — openraft
        // calls `new_client` even for offline peers and we don't
        // want to block here.
        PeerNetwork {
            target,
            advertise_addr: node.advertise_addr.clone(),
            leaf_cert_pem:  self.leaf_cert_pem.clone(),
            leaf_key_pem:   self.leaf_key_pem.clone(),
            ca_cert_pem:    self.ca_cert_pem.clone(),
            channel:        None,
        }
    }
}

/// Per-target client. Caches the tonic Channel after the first
/// successful connect so repeated AppendEntries don't pay the TLS
/// handshake each time.
pub struct PeerNetwork {
    target:         u64,
    advertise_addr: String,
    leaf_cert_pem:  String,
    leaf_key_pem:   String,
    ca_cert_pem:    String,
    channel:        Option<Channel>,
}

impl PeerNetwork {
    /// Lazy connect. Returns a clone of the cached channel on
    /// subsequent calls (Channel is cheap to clone — internally an
    /// Arc).
    async fn channel(&mut self) -> Result<Channel, tonic::transport::Error> {
        if let Some(ch) = &self.channel {
            return Ok(ch.clone());
        }

        // Expected DNS for the server cert is the host part of
        // advertise_addr. For IP-only deployments the server cert
        // SAN must include the IP, which our cert generation does.
        let host = self
            .advertise_addr
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&self.advertise_addr);

        let tls = tls::client_tls_config(
            &self.leaf_cert_pem,
            &self.leaf_key_pem,
            &self.ca_cert_pem,
            host,
        );

        let endpoint = Endpoint::from_shared(format!("https://{}", self.advertise_addr))?
            .tls_config(tls)?;
        let ch = endpoint.connect().await?;
        self.channel = Some(ch.clone());
        Ok(ch)
    }
}

// JSON-encode the openraft request, ship it, JSON-decode the response.
async fn send_raft_rpc<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
    target:   u64,
    channel:  Channel,
    method:   RaftMethod,
    payload:  &Req,
) -> Result<Resp, RPCError<u64, ClusterMember, RaftError<u64>>> {
    let payload_json = serde_json::to_vec(payload)
        .map_err(|e| RPCError::Network(NetworkError::new(&AnyErr(format!("encode: {}", e)))))?;
    let req = Request::new(RaftRpcRequest { payload_json });

    let mut client = RaftServiceClient::new(channel);
    let resp = match method {
        RaftMethod::AppendEntries => client.append_entries(req).await,
        RaftMethod::Vote          => client.vote(req).await,
    };
    let resp = resp
        .map_err(|s| RPCError::Network(NetworkError::new(&AnyErr(format!(
            "rpc to node {} ({:?}): {}",
            target, method, s
        )))))?;

    let bytes = resp.into_inner().payload_json;
    let typed: Resp = serde_json::from_slice(&bytes)
        .map_err(|e| RPCError::Network(NetworkError::new(&AnyErr(format!("decode: {}", e)))))?;
    Ok(typed)
}

#[derive(Debug, Clone, Copy)]
enum RaftMethod {
    AppendEntries,
    Vote,
    // InstallSnapshot is dispatched via its own code path in
    // PeerNetwork::install_snapshot — its error type differs from
    // the other two RPCs, so the generic helper would need a
    // second type parameter that pulls its weight only there.
}

#[derive(Debug)]
struct AnyErr(String);
impl std::fmt::Display for AnyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport: {}", self.0)
    }
}
impl std::error::Error for AnyErr {}

impl RaftNetwork<TypeConfig> for PeerNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<u64>,
        RPCError<u64, ClusterMember, RaftError<u64>>,
    > {
        let target = self.target;
        let channel = self
            .channel()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&AnyErr(format!("connect: {}", e)))))?;
        send_raft_rpc(target, channel, RaftMethod::AppendEntries, &rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, ClusterMember, RaftError<u64>>> {
        let target = self.target;
        let channel = self
            .channel()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&AnyErr(format!("connect: {}", e)))))?;
        send_raft_rpc(target, channel, RaftMethod::Vote, &rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, ClusterMember, RaftError<u64, openraft::error::InstallSnapshotError>>,
    > {
        // Re-shape error type via a tiny adapter — InstallSnapshot
        // uses a different RaftError variant than the other two.
        let target = self.target;
        let channel = self
            .channel()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&AnyErr(format!("connect: {}", e)))))?;

        let payload_json = serde_json::to_vec(&rpc).map_err(|e| {
            RPCError::Network(NetworkError::new(&AnyErr(format!("encode: {}", e))))
        })?;
        let req = Request::new(RaftRpcRequest { payload_json });
        let mut client = RaftServiceClient::new(channel);
        let resp = client.install_snapshot(req).await.map_err(|s| {
            RPCError::Network(NetworkError::new(&AnyErr(format!(
                "rpc to node {} (InstallSnapshot): {}", target, s
            ))))
        })?;

        let bytes = resp.into_inner().payload_json;
        let typed: InstallSnapshotResponse<u64> = serde_json::from_slice(&bytes)
            .map_err(|e| RPCError::Network(NetworkError::new(&AnyErr(format!(
                "decode: {}", e
            )))))?;
        Ok(typed)
    }
}

// ============================================================
// Server side: RaftServiceImpl
// ============================================================

/// Wraps a local Raft handle so peer RPCs can drive it. Cloned per
/// connection by tonic; the underlying Raft handle is itself an
/// Arc so this is cheap.
#[derive(Clone)]
pub struct RaftServiceImpl {
    raft: Raft<TypeConfig>,
}

impl RaftServiceImpl {
    pub fn new(raft: Raft<TypeConfig>) -> Self {
        Self { raft }
    }
}

#[tonic::async_trait]
impl RaftService for RaftServiceImpl {
    async fn append_entries(
        &self,
        request: Request<RaftRpcRequest>,
    ) -> Result<Response<RaftRpcResponse>, Status> {
        require_mtls(&request)?;
        let bytes = request.into_inner().payload_json;
        let req: AppendEntriesRequest<TypeConfig> = serde_json::from_slice(&bytes)
            .map_err(|e| Status::invalid_argument(format!("append_entries decode: {}", e)))?;
        let res = self.raft.append_entries(req).await
            .map_err(|e| Status::internal(format!("append_entries: {}", e)))?;
        let payload_json = serde_json::to_vec(&res)
            .map_err(|e| Status::internal(format!("append_entries encode: {}", e)))?;
        Ok(Response::new(RaftRpcResponse { payload_json }))
    }

    async fn vote(
        &self,
        request: Request<RaftRpcRequest>,
    ) -> Result<Response<RaftRpcResponse>, Status> {
        require_mtls(&request)?;
        let bytes = request.into_inner().payload_json;
        let req: VoteRequest<u64> = serde_json::from_slice(&bytes)
            .map_err(|e| Status::invalid_argument(format!("vote decode: {}", e)))?;
        let res = self.raft.vote(req).await
            .map_err(|e| Status::internal(format!("vote: {}", e)))?;
        let payload_json = serde_json::to_vec(&res)
            .map_err(|e| Status::internal(format!("vote encode: {}", e)))?;
        Ok(Response::new(RaftRpcResponse { payload_json }))
    }

    async fn install_snapshot(
        &self,
        request: Request<RaftRpcRequest>,
    ) -> Result<Response<RaftRpcResponse>, Status> {
        require_mtls(&request)?;
        let bytes = request.into_inner().payload_json;
        let req: InstallSnapshotRequest<TypeConfig> = serde_json::from_slice(&bytes)
            .map_err(|e| Status::invalid_argument(format!("install_snapshot decode: {}", e)))?;
        let res = self.raft.install_snapshot(req).await
            .map_err(|e| Status::internal(format!("install_snapshot: {}", e)))?;
        let payload_json = serde_json::to_vec(&res)
            .map_err(|e| Status::internal(format!("install_snapshot encode: {}", e)))?;
        Ok(Response::new(RaftRpcResponse { payload_json }))
    }
}

// ============================================================
// Server side: AdminServiceImpl
// ============================================================

#[derive(Clone)]
pub struct AdminServiceImpl {
    cluster_id:   String,
    token_secret: TokenSecret,
    used_nonces:  Arc<Mutex<UsedNonces>>,
    /// Cap on token TTL even if the caller asks for longer. Operator
    /// expectation is "tokens are short-lived"; an hour by default
    /// matches the design doc.
    max_ttl:      u32,
    default_ttl:  u32,
}

impl AdminServiceImpl {
    pub fn new(
        cluster_id:   String,
        token_secret: TokenSecret,
        used_nonces:  Arc<Mutex<UsedNonces>>,
    ) -> Self {
        Self {
            cluster_id,
            token_secret,
            used_nonces,
            max_ttl:     3600,  // 1 hour
            default_ttl: 3600,
        }
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn mint_token(
        &self,
        request: Request<PMintTokenRequest>,
    ) -> Result<Response<PMintTokenResponse>, Status> {
        require_mtls(&request)?;
        let req = request.into_inner();
        let ttl = if req.ttl_seconds == 0 {
            self.default_ttl
        } else {
            req.ttl_seconds.min(self.max_ttl)
        };

        let token = token::mint(&self.token_secret, &self.cluster_id, ttl)
            .map_err(|e| Status::internal(format!("mint: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _label = req.label;  // M13/M14: stored alongside nonce when redeemed
        let _ = &self.used_nonces;  // touched here for future audit logging

        Ok(Response::new(PMintTokenResponse {
            token,
            expires_at_unix: (now + ttl as u64) as i64,
        }))
    }
}

// ============================================================
// Server side: BootstrapServiceImpl (anonymous TLS allowed)
// ============================================================

/// Callback the bootstrap node hands the service so the heavy
/// work (CSR signing, Raft membership change) lives near the
/// daemon, not buried in the transport module.
pub type JoinHandler = Arc<
    dyn Fn(PJoinRequest)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PJoinResponse, String>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct BootstrapServiceImpl {
    cluster_id:   String,
    token_secret: TokenSecret,
    used_nonces:  Arc<Mutex<UsedNonces>>,
    join_handler: JoinHandler,
}

impl BootstrapServiceImpl {
    pub fn new(
        cluster_id:   String,
        token_secret: TokenSecret,
        used_nonces:  Arc<Mutex<UsedNonces>>,
        join_handler: JoinHandler,
    ) -> Self {
        Self { cluster_id, token_secret, used_nonces, join_handler }
    }
}

#[tonic::async_trait]
impl BootstrapService for BootstrapServiceImpl {
    async fn join(
        &self,
        request: Request<PJoinRequest>,
    ) -> Result<Response<PJoinResponse>, Status> {
        // No mTLS check — join is the one anonymous endpoint. Token
        // HMAC + nonce is the auth.
        let req = request.into_inner();

        // 0. Sanitize the wire-supplied advertise_addr. The string
        //    flows into ClusterMember.advertise_addr → the Raft log
        //    → every peer's `Endpoint::from_shared("https://{}", ...)`
        //    on each restart. A name with `/`, `@`, or whitespace
        //    in it would let a hostile joiner steer the URL parser
        //    in unexpected directions on every node. Require
        //    `host:port` shape and parseable port.
        // validate_advertise_addr() - below
        if let Err(e) = validate_advertise_addr(&req.advertise_addr) {
            return Err(Status::invalid_argument(format!(
                "advertise_addr '{}' rejected: {}", req.advertise_addr, e,
            )));
        }

        // 1. Validate AND reserve the nonce in one critical section
        //    so two concurrent joiners can't both pass validation
        //    before either inserts. Without this, a single token
        //    could be redeemed by N peers in parallel.
        let validated = {
            let mut used = self.used_nonces.lock().await;
            let v = token::validate(
                &self.token_secret,
                &req.token,
                &self.cluster_id,
                &used,
            )
            .map_err(|e| Status::permission_denied(format!("token: {}", e)))?;
            used.insert(v.nonce_b64.clone());
            v
        };

        // 2. Hand off to the daemon-side handler (CSR sign, Raft
        //    add_learner, promote to voter). On failure we roll back
        //    the reservation so a transient error doesn't burn the
        //    operator's one-shot token.
        let resp = match (self.join_handler)(req).await {
            Ok(r)  => r,
            Err(e) => {
                self.used_nonces.lock().await.remove(&validated.nonce_b64);
                return Err(Status::internal(format!("join: {}", e)));
            }
        };

        Ok(Response::new(resp))
    }
}

// ============================================================
// NdjsonForwardService server impl
// ============================================================
//
// The daemon hands us a callback that consumes a serialized
// RequestEnvelope and returns a serialized ResponseEnvelope. We
// just unwrap the gRPC envelope around it; loop prevention,
// leader checks, and actual handler dispatch all live behind the
// callback (in sftpflowd::server::dispatch_local).

/// Closure type the daemon supplies to handle forwarded NDJSON
/// envelopes. Async because the underlying NDJSON dispatch may
/// block on locks; running on its own task lets the gRPC server
/// keep accepting other RPCs in the meantime.
pub type NdjsonForwardHandler = Arc<
    dyn Fn(Vec<u8>)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct NdjsonForwardServiceImpl {
    handler: NdjsonForwardHandler,
}

impl NdjsonForwardServiceImpl {
    pub fn new(handler: NdjsonForwardHandler) -> Self {
        Self { handler }
    }
}

#[tonic::async_trait]
impl NdjsonForwardService for NdjsonForwardServiceImpl {
    async fn forward(
        &self,
        request: Request<PNdjsonForwardRequest>,
    ) -> Result<Response<PNdjsonForwardResponse>, Status> {
        require_mtls(&request)?;
        let envelope_json = request.into_inner().envelope_json;

        let response_json = (self.handler)(envelope_json)
            .await
            .map_err(|e| Status::internal(format!("forward dispatch: {}", e)))?;

        Ok(Response::new(PNdjsonForwardResponse {
            envelope_json: response_json,
        }))
    }
}

/// Default no-op forward handler installed when the daemon hasn't
/// supplied one (legacy / single-node startup paths). Always
/// returns an error — callers shouldn't be reaching this on a
/// node that isn't supposed to accept forwards.
pub fn no_forward_handler() -> NdjsonForwardHandler {
    Arc::new(|_envelope| {
        Box::pin(async {
            Err("this node does not have an NDJSON forward handler installed".to_string())
        })
    })
}

// ============================================================
// Client helper: dial a peer and forward an NDJSON envelope
// ============================================================
//
// Used by followers to ship a serialized RequestEnvelope to the
// current leader. Returns the leader's serialized ResponseEnvelope
// so the caller can write it back to the CLI verbatim. mTLS uses
// the same leaf cert + cluster CA every other peer-to-peer call
// uses.

pub async fn forward_envelope_to_peer(
    peer_advertise_addr: &str,
    leaf_cert_pem:       &str,
    leaf_key_pem:        &str,
    ca_cert_pem:         &str,
    envelope_json:       Vec<u8>,
) -> Result<Vec<u8>, String> {
    // Match the SNI rule used elsewhere in this file: host portion
    // of the advertise address. IPv4-literal advertise addresses
    // need the SAN-IP entry that cert generation already emits.
    let host = peer_advertise_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(peer_advertise_addr);

    let tls = tls::client_tls_config(leaf_cert_pem, leaf_key_pem, ca_cert_pem, host);

    let endpoint = Endpoint::from_shared(format!("https://{}", peer_advertise_addr))
        .map_err(|e| format!("endpoint: {}", e))?
        .tls_config(tls)
        .map_err(|e| format!("tls: {}", e))?;
    let channel = endpoint.connect().await
        .map_err(|e| format!("connect: {}", e))?;

    let mut client = NdjsonForwardServiceClient::new(channel);
    let resp = client
        .forward(PNdjsonForwardRequest { envelope_json })
        .await
        .map_err(|s| format!("forward rpc: {}", s))?;

    Ok(resp.into_inner().envelope_json)
}

// ============================================================
// mTLS gate for RaftService and AdminService
// ============================================================

fn require_mtls<T>(req: &Request<T>) -> Result<(), Status> {
    match req.peer_certs() {
        Some(certs) if !certs.is_empty() => Ok(()),
        _ => Err(Status::unauthenticated("client cert required for this method")),
    }
}

// ============================================================
// run_grpc_server - wires the three services onto one TCP port
// ============================================================

pub async fn run_grpc_server(
    bind_addr:     std::net::SocketAddr,
    tls_cfg:       ServerTlsConfig,
    raft_svc:      RaftServiceImpl,
    admin_svc:     AdminServiceImpl,
    bootstrap_svc: BootstrapServiceImpl,
    forward_svc:   NdjsonForwardServiceImpl,
) -> Result<(), tonic::transport::Error> {
    log::info!("cluster gRPC server listening on {}", bind_addr);
    Server::builder()
        .tls_config(tls_cfg)?
        .add_service(RaftServiceServer::new(raft_svc))
        .add_service(AdminServiceServer::new(admin_svc))
        .add_service(BootstrapServiceServer::new(bootstrap_svc))
        .add_service(NdjsonForwardServiceServer::new(forward_svc))
        .serve(bind_addr)
        .await
}

/// Variant of `run_grpc_server` that takes a pre-bound TCP
/// listener. Lets `ClusterNode::start` bind synchronously before
/// returning so the caller doesn't need a post-start sleep to
/// "let tonic catch up" — the listener is already accepting
/// connections when `start` returns.
pub async fn run_grpc_server_with_listener(
    listener:      tokio::net::TcpListener,
    tls_cfg:       ServerTlsConfig,
    raft_svc:      RaftServiceImpl,
    admin_svc:     AdminServiceImpl,
    bootstrap_svc: BootstrapServiceImpl,
    forward_svc:   NdjsonForwardServiceImpl,
) -> Result<(), tonic::transport::Error> {
    let local = listener.local_addr().ok();
    log::info!("cluster gRPC server listening (pre-bound) on {:?}", local);
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    Server::builder()
        .tls_config(tls_cfg)?
        .add_service(RaftServiceServer::new(raft_svc))
        .add_service(AdminServiceServer::new(admin_svc))
        .add_service(BootstrapServiceServer::new(bootstrap_svc))
        .add_service(NdjsonForwardServiceServer::new(forward_svc))
        .serve_with_incoming(incoming)
        .await
}

// Suppress unused warnings on RemoteError import (kept for future
// use when we forward leader-side errors back to the caller).
#[allow(dead_code)]
fn _silence_unused() {
    let _: Option<RemoteError<u64, ClusterMember, RaftError<u64>>> = None;
}

/// Reject anything that doesn't look like `host:port` so a hostile
/// joiner can't poison the cluster's shared `advertise_addr` field
/// with a string the URL parser would interpret as a different
/// host on every peer (slashes, `@` userinfo, whitespace, etc.).
fn validate_advertise_addr(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("empty".into());
    }
    if addr.len() > 253 {
        return Err("longer than 253 chars".into());
    }
    if addr.contains(|c: char| {
        c == '/' || c == '\\' || c == '@' || c == '?' || c == '#'
            || c == ' ' || c == '\t' || c.is_control()
    }) {
        return Err("contains a disallowed character (/, \\, @, ?, #, whitespace, or control)".into());
    }
    let (host, port_str) = addr.rsplit_once(':')
        .ok_or_else(|| "missing ':port' suffix".to_string())?;
    if host.is_empty() {
        return Err("empty host before ':'".into());
    }
    let port: u16 = port_str.parse()
        .map_err(|_| format!("port '{}' is not a u16", port_str))?;
    if port == 0 {
        return Err("port 0 is not a valid destination".into());
    }
    Ok(())
}

#[cfg(test)]
mod validate_advertise_addr_tests {
    use super::validate_advertise_addr;

    #[test]
    fn accepts_dns_and_ip() {
        validate_advertise_addr("node1.example.com:7900").unwrap();
        validate_advertise_addr("10.0.0.1:7900").unwrap();
    }

    #[test]
    fn rejects_url_smuggling() {
        for bad in [
            "evil.com/path:7900",
            "user@evil.com:7900",
            "host:7900/foo",
            "host with space:7900",
            "no-port-here",
            "host:99999",
            "host:0",
            ":7900",
            "",
        ] {
            assert!(
                validate_advertise_addr(bad).is_err(),
                "expected '{}' to be rejected",
                bad,
            );
        }
    }
}
