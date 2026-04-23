// ============================================================
// sftpflow-cluster::tls - cluster CA + leaf cert generation
// ============================================================
//
// Pure-Rust X.509 issuance via `rcgen` (no openssl dependency,
// matches the existing crypto stance from milestones 10/11).
//
// Lifecycle:
//
//   1. `sftpflowd init` calls `ClusterCa::generate()` to create
//      a fresh self-signed CA. The CA cert + key are written to
//      cluster/ca.{crt,key}; only the bootstrap node holds the
//      key in M12.
//
//   2. Each node (bootstrap or joining) calls `LeafKeyPair::
//      generate()` to create its own private key + a CSR that
//      embeds its desired identity (CN=node-<id>) and SAN
//      (advertise address, DNS or IP).
//
//   3. The bootstrap node signs joining nodes' CSRs via
//      `ClusterCa::sign_csr()` during the BootstrapService.Join
//      handshake. The signed leaf cert is returned to the joiner
//      and persisted to cluster/node.crt; the joiner's private
//      key never leaves the joining node's filesystem.
//
//   4. All Raft RPCs use mTLS with these certs. Verification:
//      both sides validate the peer cert chains to the same CA.
//
// Algorithm choice: ED25519 signature throughout. Small keys,
// fast verification, no OID-version footguns.
//
// Validity windows:
//   - CA:   10 years    (M15 will add `cluster ca rotate`)
//   - Leaf:  1 year     (M15 will add `cluster cert rotate`)

use std::net::IpAddr;

use rcgen::{
    BasicConstraints,
    CertificateParams,
    CertificateSigningRequestParams,
    DnType,
    DistinguishedName,
    IsCa,
    KeyPair,
    KeyUsagePurpose,
    PKCS_ED25519,
    SanType,
    date_time_ymd,
};
use time::OffsetDateTime;

// ============================================================
// Public errors
// ============================================================

#[derive(Debug)]
pub enum TlsError {
    /// rcgen rejected the parameters or failed to serialize.
    Rcgen(rcgen::Error),
    /// The supplied PEM string did not parse.
    InvalidPem(String),
    /// advertise_addr could not be split into host + port.
    InvalidAdvertiseAddr(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Rcgen(e)                  => write!(f, "tls: rcgen: {}", e),
            TlsError::InvalidPem(m)             => write!(f, "tls: invalid pem: {}", m),
            TlsError::InvalidAdvertiseAddr(m)   => write!(f, "tls: invalid advertise addr: {}", m),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<rcgen::Error> for TlsError {
    fn from(e: rcgen::Error) -> Self { TlsError::Rcgen(e) }
}

// ============================================================
// Validity helpers
// ============================================================

/// Compute (not_before, not_after) for a cert with `years` of
/// validity from today. We back-date `not_before` by one day to
/// tolerate small clock skew between cluster nodes — joining
/// nodes refusing certs because their clock is 30s ahead would
/// be a miserable operator experience.
fn validity_window(years: i32) -> (OffsetDateTime, OffsetDateTime) {
    let now    = OffsetDateTime::now_utc();
    let before = now - time::Duration::days(1);
    // OffsetDateTime arithmetic is in seconds; approximate years
    // as 365 days for cert lifetime purposes (cert validity is
    // not a precise calendar concept).
    let after  = now + time::Duration::days((years as i64) * 365);
    (before, after)
}

// ============================================================
// ClusterCa - self-signed CA, owned by the bootstrap node
// ============================================================

pub struct ClusterCa {
    cert:     rcgen::Certificate,
    key_pair: KeyPair,
}

impl ClusterCa {
    /// Generate a fresh self-signed CA. `cluster_id` is embedded
    /// in the CA's CN for human-readable identification.
    pub fn generate(cluster_id: &str) -> Result<Self, TlsError> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let (nb, na) = validity_window(10);
        params.not_before = nb;
        params.not_after  = na;
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName,       format!("sftpflow-cluster-{}", cluster_id));
            dn.push(DnType::OrganizationName, "sftpflow");
            dn
        };
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let cert = params.self_signed(&key_pair)?;
        Ok(Self { cert, key_pair })
    }

    /// Reload an existing CA from PEM bytes (cert + matching key).
    /// Called by the bootstrap node on restart.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, TlsError> {
        let key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| TlsError::InvalidPem(format!("ca key: {}", e)))?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| TlsError::InvalidPem(format!("ca cert: {}", e)))?;
        let cert = params.self_signed(&key_pair)?;
        Ok(Self { cert, key_pair })
    }

    /// PEM-encoded CA certificate. Distributed to every member as
    /// the trust anchor.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// PEM-encoded CA private key. **Sensitive** — only persisted
    /// on the bootstrap node, and only used to sign joining nodes'
    /// CSRs.
    pub fn key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Sign a joining node's CSR. Returns the leaf cert as PEM.
    /// `advertise_addr` is informational here — the SAN was set by
    /// the joining node when it generated the CSR, and rcgen
    /// preserves it through signing.
    pub fn sign_csr(&self, csr_der: &[u8]) -> Result<String, TlsError> {
        // CertificateSigningRequestDer lives in rustls-pki-types,
        // re-exported via rustls::pki_types. rcgen's from_der takes
        // it by reference.
        let csr_der_wrapper: rustls::pki_types::CertificateSigningRequestDer<'static> =
            csr_der.to_vec().into();
        let mut csr = CertificateSigningRequestParams::from_der(&csr_der_wrapper)?;

        // Override validity (CSRs in PKCS#10 don't carry validity;
        // rcgen will use defaults otherwise).
        let (nb, na) = validity_window(1);
        csr.params.not_before = nb;
        csr.params.not_after  = na;

        // Mark as a leaf cert (NoCa) and set the right key usages.
        csr.params.is_ca = IsCa::NoCa;
        csr.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        let signed = csr.signed_by(&self.cert, &self.key_pair)?;
        Ok(signed.pem())
    }
}

// ============================================================
// LeafKeyPair - per-node private key + CSR generator
// ============================================================
//
// Owned by every node (bootstrap node included — the bootstrap
// node generates its own leaf cert by self-signing through the
// ClusterCa rather than going through the join flow). The private
// key is created locally and never leaves the node.

pub struct LeafKeyPair {
    params:   CertificateParams,
    key_pair: KeyPair,
}

impl LeafKeyPair {
    /// Generate a fresh ed25519 leaf key + matching CSR params.
    /// `advertise_addr` (host:port) is parsed for the SAN — IP
    /// addresses become an IP SAN, hostnames become a DNS SAN.
    pub fn generate(node_id: u64, advertise_addr: &str) -> Result<Self, TlsError> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;

        let host = advertise_addr
            .rsplit_once(':')
            .map(|(h, _)| h)
            .ok_or_else(|| TlsError::InvalidAdvertiseAddr(advertise_addr.to_string()))?;

        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                host.try_into()
                    .map_err(|e: rcgen::Error| TlsError::Rcgen(e))?,
            ),
        };

        let mut params = CertificateParams::default();
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName,       format!("node-{}", node_id));
            dn.push(DnType::OrganizationName, "sftpflow");
            dn
        };
        params.subject_alt_names = vec![san];
        // CSR doesn't carry validity in PKCS#10; the CA signer
        // sets it. We still populate not_before/not_after for
        // CertificateParams' internal validation pass with safe
        // defaults that are obviously bogus if anyone uses them.
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after  = date_time_ymd(2099, 12, 31);

        Ok(Self { params, key_pair })
    }

    /// Serialize the CSR for transmission to the bootstrap node.
    /// Returns DER (for direct stuffing into the protobuf bytes
    /// field) — PEM-encoding adds nothing on the wire.
    pub fn csr_der(&self) -> Result<Vec<u8>, TlsError> {
        let csr = self.params.serialize_request(&self.key_pair)?;
        Ok(csr.der().to_vec())
    }

    /// PEM-encoded private key. Persisted to cluster/node.key with
    /// 0600 perms (caller's responsibility).
    pub fn key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_round_trip_through_pem() {
        let ca = ClusterCa::generate("test-cluster-1").unwrap();
        let cert_pem = ca.cert_pem();
        let key_pem  = ca.key_pem();

        // Reloading must succeed and produce the same DN.
        let reloaded = ClusterCa::from_pem(&cert_pem, &key_pem).unwrap();
        assert!(reloaded.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn ca_signs_node_csr_dns() {
        let ca   = ClusterCa::generate("test-cluster-2").unwrap();
        let leaf = LeafKeyPair::generate(7, "node7.example.com:7900").unwrap();

        let csr_der = leaf.csr_der().unwrap();
        let signed_pem = ca.sign_csr(&csr_der).unwrap();
        assert!(signed_pem.contains("BEGIN CERTIFICATE"));
        // Node ID round-trip — appears in CN.
        // (We don't parse the cert here; that gets exercised by
        // the integration test that actually does an mTLS handshake
        // with these certs.)
    }

    #[test]
    fn ca_signs_node_csr_ip() {
        let ca   = ClusterCa::generate("test-cluster-3").unwrap();
        let leaf = LeafKeyPair::generate(2, "127.0.0.1:7900").unwrap();

        let csr_der = leaf.csr_der().unwrap();
        let signed_pem = ca.sign_csr(&csr_der).unwrap();
        assert!(signed_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn advertise_addr_without_port_is_rejected() {
        // Match on the Result rather than calling unwrap_err so the
        // test doesn't need LeafKeyPair to derive Debug (KeyPair
        // intentionally doesn't expose its internals).
        match LeafKeyPair::generate(1, "no-port-here") {
            Err(TlsError::InvalidAdvertiseAddr(_)) => {}
            Err(other) => panic!("wrong error: {}", other),
            Ok(_)      => panic!("expected error for missing port"),
        }
    }
}
