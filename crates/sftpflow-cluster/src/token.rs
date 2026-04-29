// ============================================================
// sftpflow-cluster::token - join token mint + validate
// ============================================================
//
// Wire format (single ASCII string the operator copy-pastes):
//
//   sjv2.<cluster_fp>.<exp_unix>.<nonce_b64>.<hmac_b64>
//
// Where:
//   - sjv2        - format version tag ("sftpflow join v2", short).
//                   v1 was the 131-char form with the literal
//                   "sftpflow-join-v1" prefix and a full UUID
//                   cluster_id; v2 trims it to ~60 chars.
//   - cluster_fp  - first 6 chars of URL-safe-base64( SHA256(cluster_id) ),
//                   ~36 bits. Advisory only — the HMAC keyed on the
//                   cluster's TokenSecret is the actual authentication.
//                   Server validates by recomputing the fingerprint
//                   from its own cluster_id and comparing.
//   - exp_unix    - u64 expiry timestamp, wall-clock seconds since UNIX epoch
//   - nonce_b64   - 12 random bytes, URL-safe base64 (no padding) → 16 chars.
//                   96 bits is plenty against random collision; replay
//                   protection lives in `UsedNonces`, not in nonce length.
//   - hmac_b64    - HMAC-SHA256 of "<sjv2>.<cluster_fp>.<exp_unix>.<nonce_b64>"
//                   keyed with the cluster's TokenSecret, then truncated
//                   to the leftmost 16 bytes (HMAC-SHA-256-128 per
//                   RFC 4868), URL-safe base64 → 22 chars.
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
use sha2::{Digest, Sha256};

const PREFIX:    &str = "sjv2";
const NONCE_LEN: usize = 12;
const HMAC_LEN:  usize = 16;
const FP_LEN:    usize = 6;

type HmacSha256 = Hmac<Sha256>;

// ============================================================
// Cluster fingerprint
// ============================================================

/// Derive the 6-char fingerprint embedded in v2 tokens.
///
/// Why a fingerprint instead of the raw cluster_id: the raw form
/// is a 36-char UUID and dominates token length. Replacing it with
/// `b64(sha256(cluster_id))[..6]` saves 30 chars while staying a
/// stable, deterministic identifier per cluster. ~36 bits of
/// collision space is adequate because the fingerprint is *only*
/// an early-rejection / friendly-error aid; the HMAC, keyed on the
/// cluster's secret, is what actually authenticates the token.
fn cluster_fingerprint(cluster_id: &str) -> String {
    let digest = Sha256::digest(cluster_id.as_bytes());
    let encoded = B64.encode(digest);
    encoded.chars().take(FP_LEN).collect()
}

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

    let cluster_fp  = cluster_fingerprint(cluster_id);
    let signed_part = format!("{}.{}.{}.{}", PREFIX, cluster_fp, exp, nonce_b64);

    // HMAC the signed part, then truncate to HMAC_LEN bytes
    // (HMAC-SHA-256-128 per RFC 4868). `Mac::update` cannot fail;
    // key length is fixed so `new_from_slice` only fails on
    // programmer error.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("hmac key length is constant");
    mac.update(signed_part.as_bytes());
    let full_tag = mac.finalize().into_bytes();
    let hmac_b64 = B64.encode(&full_tag[..HMAC_LEN]);

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
    let (prefix, supplied_fp, exp_str, nonce_b64, hmac_b64) =
        (parts[0], parts[1], parts[2], parts[3], parts[4]);

    if prefix != PREFIX {
        return Err(TokenError::Malformed("wrong prefix / version"));
    }

    // ---- 2. Cluster identity match -------------------------
    // The token carries only a fingerprint; recompute ours and
    // compare. Fingerprint mismatch → token was minted for a
    // different cluster (or the operator pasted the wrong one).
    let our_fp = cluster_fingerprint(cluster_id);
    if supplied_fp != our_fp {
        return Err(TokenError::WrongCluster {
            expected: our_fp,
            got:      supplied_fp.to_string(),
        });
    }

    // ---- 3. HMAC verification ------------------------------
    let signed_part = format!("{}.{}.{}.{}", prefix, supplied_fp, exp_str, nonce_b64);
    let supplied_hmac = B64
        .decode(hmac_b64)
        .map_err(|_| TokenError::Malformed("hmac not valid base64"))?;
    if supplied_hmac.len() != HMAC_LEN {
        return Err(TokenError::Malformed("hmac wrong length"));
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("hmac key length is constant");
    mac.update(signed_part.as_bytes());
    let full_tag = mac.finalize().into_bytes();
    // Constant-time comparison of the truncated MAC. We don't use
    // `verify_truncated_left` because the API is awkward across
    // hmac crate versions; a manual constant-time loop on the
    // already-decoded bytes is equivalent and obvious.
    if !ct_eq(&full_tag[..HMAC_LEN], &supplied_hmac) {
        return Err(TokenError::BadHmac);
    }

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
        cluster_id: cluster_id.to_string(),
        nonce_b64:  nonce_b64.to_string(),
        exp_unix,
    })
}

/// Constant-time byte-slice equality. Length-mismatched inputs
/// short-circuit (length is not secret here).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    fn v2_token_is_compact() {
        // Locks in the size win that justified the v2 format change.
        // For a typical 2026-era epoch the token lands around 62
        // chars; allow a small slack for exp_unix growing a digit.
        let (secret, cluster, _) = fresh();
        let token = mint(&secret, cluster, 3600).unwrap();
        assert!(token.starts_with("sjv2."), "expected sjv2 prefix, got {}", token);
        assert!(
            token.len() <= 70,
            "v2 token should be ≤70 chars, was {}: {}", token.len(), token,
        );
    }

    #[test]
    fn fingerprint_is_stable_per_cluster() {
        // Same cluster_id → same fingerprint; different clusters →
        // (overwhelmingly) different fingerprints.
        assert_eq!(
            cluster_fingerprint("cluster-aaa-111"),
            cluster_fingerprint("cluster-aaa-111"),
        );
        assert_ne!(
            cluster_fingerprint("cluster-aaa-111"),
            cluster_fingerprint("cluster-bbb-222"),
        );
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
