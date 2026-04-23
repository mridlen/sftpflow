// ============================================================
// sftpflow-cluster::token - join token mint + validate
// ============================================================
//
// Wire format (single ASCII string the operator copy-pastes):
//
//   sftpflow-join-v1.<cluster_id>.<exp_unix>.<nonce_b64>.<hmac_b64>
//
// Where:
//   - cluster_id  - UUID generated at `sftpflowd init`
//   - exp_unix    - u64 expiry timestamp, wall-clock seconds since UNIX epoch
//   - nonce_b64   - 16 random bytes, URL-safe base64 (no padding)
//   - hmac_b64    - HMAC-SHA256 of "<v1>.<cluster_id>.<exp_unix>.<nonce_b64>"
//                   keyed with the cluster's TokenSecret, URL-safe base64
//
// Replay protection: the bootstrap node maintains a set of nonces
// already redeemed (`UsedNonces`); validate() rejects any nonce in
// that set. The set is persisted at the call site (in cluster/
// tokens_used.json — see the bootstrap module in M12 PR-B).
//
// The HMAC alone authenticates the token — adding nonce tracking
// is belt-and-suspenders. Cheap insurance against a leaked token
// being grabbed off a chat log and used twice.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const PREFIX:    &str = "sftpflow-join-v1";
const NONCE_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

// ============================================================
// TokenSecret - the HMAC key
// ============================================================
//
// 32 random bytes. Generated at `sftpflowd init` and stored in the
// sealed-secrets store under the reserved name
// `__cluster_token_key__` so the existing age-encrypted store
// protects it at rest. Only the bootstrap node holds a copy in M12.

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenSecret([u8; 32]);

impl TokenSecret {
    /// Generate a fresh 32-byte secret from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Reconstruct from previously-stored bytes (e.g. from the
    /// sealed secrets store at startup).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        if bytes.len() != 32 {
            return Err(TokenError::InvalidSecretLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

// ============================================================
// Errors
// ============================================================

#[derive(Debug)]
pub enum TokenError {
    InvalidSecretLength(usize),
    Malformed(&'static str),
    BadHmac,
    Expired,
    /// Nonce already redeemed — replay attempt.
    Replayed,
    /// Token's cluster_id doesn't match this cluster.
    WrongCluster { expected: String, got: String },
    /// Wall clock is unreadable. Should not happen in practice.
    ClockError,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::InvalidSecretLength(n) =>
                write!(f, "token secret must be 32 bytes, got {}", n),
            TokenError::Malformed(why)         => write!(f, "malformed token: {}", why),
            TokenError::BadHmac                => write!(f, "token HMAC does not validate"),
            TokenError::Expired                => write!(f, "token has expired"),
            TokenError::Replayed               => write!(f, "token nonce already used (replay)"),
            TokenError::WrongCluster { expected, got } =>
                write!(f, "token is for cluster {}, this cluster is {}", got, expected),
            TokenError::ClockError             => write!(f, "system clock unreadable"),
        }
    }
}

impl std::error::Error for TokenError {}

// ============================================================
// UsedNonces - replay-protection set
// ============================================================
//
// Trivial wrapper so the call site can choose the persistence
// strategy. The bootstrap node persists this to disk; tests use
// the in-memory default.

#[derive(Default, Serialize, Deserialize)]
pub struct UsedNonces {
    nonces: HashSet<String>,
}

impl UsedNonces {
    pub fn new() -> Self { Self::default() }
    pub fn contains(&self, nonce_b64: &str) -> bool { self.nonces.contains(nonce_b64) }
    pub fn insert(&mut self, nonce_b64: String) { self.nonces.insert(nonce_b64); }
    pub fn len(&self) -> usize { self.nonces.len() }
    pub fn is_empty(&self) -> bool { self.nonces.is_empty() }
}

// ============================================================
// Mint
// ============================================================

/// Mint a fresh token. `ttl_seconds` is added to the current wall
/// clock to compute the expiry. Caller is responsible for capping
/// ttl_seconds at some operator-friendly maximum (1 hour by
/// default in the AdminService.MintToken handler).
pub fn mint(
    secret:      &TokenSecret,
    cluster_id:  &str,
    ttl_seconds: u32,
) -> Result<String, TokenError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenError::ClockError)?
        .as_secs();
    let exp = now + (ttl_seconds as u64);

    // Random nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce_b64 = B64.encode(nonce_bytes);

    let signed_part = format!("{}.{}.{}.{}", PREFIX, cluster_id, exp, nonce_b64);

    // HMAC the signed part. `Mac::update` cannot fail; key length
    // is fixed so `new_from_slice` only fails on programmer error.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("hmac key length is constant");
    mac.update(signed_part.as_bytes());
    let hmac_b64 = B64.encode(mac.finalize().into_bytes());

    Ok(format!("{}.{}", signed_part, hmac_b64))
}

// ============================================================
// Validate
// ============================================================

/// Result of a successful validate(). Carries the nonce so the
/// caller can mark it used after taking the cluster-mutating
/// actions the token authorizes.
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub cluster_id: String,
    pub nonce_b64:  String,
    pub exp_unix:   u64,
}

/// Validate a token against the supplied cluster and used-nonces
/// set. On success, returns the parsed token; the caller must
/// `used.insert(token.nonce_b64.clone())` after the action that
/// the token authorizes succeeds (so a failed join doesn't burn
/// the operator's token).
pub fn validate(
    secret:     &TokenSecret,
    token:      &str,
    cluster_id: &str,
    used:       &UsedNonces,
) -> Result<ValidatedToken, TokenError> {
    // ---- 1. Split into 5 dot-separated parts ---------------
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 {
        return Err(TokenError::Malformed("expected 5 dot-separated parts"));
    }
    let (prefix, cid, exp_str, nonce_b64, hmac_b64) =
        (parts[0], parts[1], parts[2], parts[3], parts[4]);

    if prefix != PREFIX {
        return Err(TokenError::Malformed("wrong prefix / version"));
    }

    // ---- 2. Cluster identity match -------------------------
    if cid != cluster_id {
        return Err(TokenError::WrongCluster {
            expected: cluster_id.to_string(),
            got:      cid.to_string(),
        });
    }

    // ---- 3. HMAC verification ------------------------------
    let signed_part = format!("{}.{}.{}.{}", prefix, cid, exp_str, nonce_b64);
    let supplied_hmac = B64
        .decode(hmac_b64)
        .map_err(|_| TokenError::Malformed("hmac not valid base64"))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("hmac key length is constant");
    mac.update(signed_part.as_bytes());
    // verify_slice does constant-time comparison.
    mac.verify_slice(&supplied_hmac).map_err(|_| TokenError::BadHmac)?;

    // ---- 4. Expiry -----------------------------------------
    let exp_unix: u64 = exp_str
        .parse()
        .map_err(|_| TokenError::Malformed("expiry not a u64"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenError::ClockError)?
        .as_secs();
    if now > exp_unix {
        return Err(TokenError::Expired);
    }

    // ---- 5. Replay protection ------------------------------
    if used.contains(nonce_b64) {
        return Err(TokenError::Replayed);
    }

    Ok(ValidatedToken {
        cluster_id: cid.to_string(),
        nonce_b64:  nonce_b64.to_string(),
        exp_unix,
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (TokenSecret, &'static str, UsedNonces) {
        (TokenSecret::generate(), "cluster-aaa-111", UsedNonces::new())
    }

    #[test]
    fn mint_then_validate_round_trip() {
        let (secret, cluster, used) = fresh();
        let token = mint(&secret, cluster, 60).unwrap();
        let v = validate(&secret, &token, cluster, &used).unwrap();
        assert_eq!(v.cluster_id, cluster);
        assert!(v.exp_unix > 0);
    }

    #[test]
    fn validate_rejects_tampered_hmac() {
        let (secret, cluster, used) = fresh();
        let token = mint(&secret, cluster, 60).unwrap();

        // Flip a char in the MIDDLE of the HMAC segment. Flipping
        // the last char of a URL_SAFE_NO_PAD encoding can violate
        // the trailing-bits check and surface as Malformed before
        // the HMAC compare runs.
        let last_dot = token.rfind('.').unwrap();
        let target_idx = last_dot + 3;
        let mut bytes = token.into_bytes();
        bytes[target_idx] = if bytes[target_idx] == b'a' { b'b' } else { b'a' };
        let bad = String::from_utf8(bytes).unwrap();

        match validate(&secret, &bad, cluster, &used) {
            Err(TokenError::BadHmac) => {}
            other => panic!("expected BadHmac, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_wrong_cluster() {
        let (secret, cluster, used) = fresh();
        let token = mint(&secret, cluster, 60).unwrap();
        match validate(&secret, &token, "different-cluster", &used) {
            Err(TokenError::WrongCluster { .. }) => {}
            other => panic!("expected WrongCluster, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_expired() {
        let (secret, cluster, used) = fresh();
        // ttl 0 -> exp == now -> any non-zero clock advance is
        // already past. We rely on the wall clock advancing at
        // least a microsecond between mint and validate; in
        // practice the test runs in ms.
        let token = mint(&secret, cluster, 0).unwrap();
        // Sleep a tiny bit to guarantee `now > exp`.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        match validate(&secret, &token, cluster, &used) {
            Err(TokenError::Expired) => {}
            other => panic!("expected Expired, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_replay() {
        let (secret, cluster, mut used) = fresh();
        let token = mint(&secret, cluster, 60).unwrap();

        // First validate succeeds; caller marks the nonce used.
        let v = validate(&secret, &token, cluster, &used).unwrap();
        used.insert(v.nonce_b64);

        // Second validate with the same nonce in `used` is a replay.
        match validate(&secret, &token, cluster, &used) {
            Err(TokenError::Replayed) => {}
            other => panic!("expected Replayed, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_malformed() {
        let (secret, cluster, used) = fresh();
        match validate(&secret, "not.even.close", cluster, &used) {
            Err(TokenError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {:?}", other),
        }
    }

    #[test]
    fn token_secret_round_trip() {
        let s1 = TokenSecret::generate();
        let s2 = TokenSecret::from_bytes(s1.as_bytes()).unwrap();
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn token_secret_rejects_wrong_length() {
        // Don't `{:?}` the Result — TokenSecret intentionally has
        // no Debug impl (it would leak key material in panics).
        match TokenSecret::from_bytes(&[0u8; 16]) {
            Err(TokenError::InvalidSecretLength(16)) => {}
            Err(e)  => panic!("wrong error variant: {}", e),
            Ok(_)   => panic!("expected error for 16-byte secret"),
        }
    }
}
