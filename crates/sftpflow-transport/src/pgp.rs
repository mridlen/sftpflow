// ============================================================
// pgp.rs — PGP encrypt / decrypt for process pipeline steps
// ============================================================
//
// Uses sequoia-openpgp to apply ProcessStep::Encrypt and
// ProcessStep::Decrypt to files staged in a local temp dir
// between the source-download and destination-upload phases
// of run_feed().
//
// Key contents are taken from the `PgpKey.contents` field in
// the config (armored ASCII or binary keyring data). Encrypted
// output files gain a `.pgp` extension; decrypted output files
// have a trailing `.pgp`/`.gpg`/`.asc` stripped when present.
//
// v1 scope: no passphrase support on private keys (that lands
// with milestone 11 credential security) — unencrypted secret
// keys only.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use log::{info, warn};

use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure,
    VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message};
use openpgp::types::SymmetricAlgorithm;

// ============================================================
// PgpError
// ============================================================

#[derive(Debug)]
pub enum PgpError {
    /// The key is present but has no contents field set.
    EmptyKeyContents(String),
    /// Operation requires a public key but a private key was given
    /// (or vice-versa), or the key has no suitable subkey.
    WrongKeyType(String, String),
    /// Failed to parse the armored/binary key material.
    KeyParse(String, String),
    /// Local I/O error reading or writing a staged file.
    Io(String),
    /// sequoia-openpgp raised an error during encrypt/decrypt.
    Crypto(String),
}

impl std::fmt::Display for PgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PgpError::EmptyKeyContents(name) => {
                write!(f, "pgp key '{}' has no contents", name)
            }
            PgpError::WrongKeyType(name, detail) => {
                write!(f, "pgp key '{}': {}", name, detail)
            }
            PgpError::KeyParse(name, msg) => {
                write!(f, "could not parse pgp key '{}': {}", name, msg)
            }
            PgpError::Io(msg) => write!(f, "pgp i/o error: {}", msg),
            PgpError::Crypto(msg) => write!(f, "pgp crypto error: {}", msg),
        }
    }
}

impl std::error::Error for PgpError {}

// ============================================================
// Public API — apply a single process step to all files
// ============================================================

/// Encrypt every file in `files` (paths relative to `staging_dir`)
/// using the public key material in `key_contents`. Replaces each
/// file with its `<name>.pgp` equivalent and returns the new names.
pub fn encrypt_files(
    key_name: &str,
    key_contents: &str,
    staging_dir: &Path,
    files: &[String],
) -> Result<Vec<String>, PgpError> {
    // Parse the recipient cert once — reuse for every file.
    let cert = parse_cert(key_name, key_contents)?;

    let policy = StandardPolicy::new();
    let recipients: Vec<_> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();

    if recipients.is_empty() {
        return Err(PgpError::WrongKeyType(
            key_name.to_string(),
            "no valid encryption-capable subkey found (need a public key \
             with an encryption subkey)"
                .to_string(),
        ));
    }

    let mut new_names: Vec<String> = Vec::with_capacity(files.len());

    for file_name in files {
        let in_path = staging_dir.join(file_name);
        let new_name = format!("{}.pgp", file_name);
        let out_path = staging_dir.join(&new_name);

        let plaintext = fs::read(&in_path).map_err(|e| {
            PgpError::Io(format!(
                "read {}: {}",
                in_path.display(),
                e
            ))
        })?;

        // ---- streaming encrypt pipeline ----
        let mut sink = Vec::with_capacity(plaintext.len() + 512);
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message).build().map_err(|e| {
                PgpError::Crypto(format!("armorer: {}", e))
            })?;
            let message = Encryptor2::for_recipients(
                message,
                recipients.clone(),
            )
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()
            .map_err(|e| {
                PgpError::Crypto(format!("encryptor: {}", e))
            })?;
            let mut literal = LiteralWriter::new(message)
                .build()
                .map_err(|e| {
                    PgpError::Crypto(format!("literal writer: {}", e))
                })?;
            literal.write_all(&plaintext).map_err(|e| {
                PgpError::Crypto(format!("literal write: {}", e))
            })?;
            literal.finalize().map_err(|e| {
                PgpError::Crypto(format!("finalize: {}", e))
            })?;
        }

        fs::write(&out_path, &sink).map_err(|e| {
            PgpError::Io(format!(
                "write {}: {}",
                out_path.display(),
                e
            ))
        })?;

        // Remove the original plaintext — the pipeline replaces it.
        if let Err(e) = fs::remove_file(&in_path) {
            warn!(
                "pgp encrypt: could not remove plaintext {} after \
                 producing {}: {}",
                in_path.display(),
                out_path.display(),
                e
            );
        }

        info!(
            "pgp encrypt: {} -> {} using key '{}'",
            file_name, new_name, key_name
        );
        new_names.push(new_name);
    }

    Ok(new_names)
}

/// Decrypt every file in `files` (paths relative to `staging_dir`)
/// using the private key material in `key_contents`. Replaces each
/// file with its plaintext equivalent; the `.pgp`/`.gpg`/`.asc`
/// extension is stripped from the output filename when present.
pub fn decrypt_files(
    key_name: &str,
    key_contents: &str,
    staging_dir: &Path,
    files: &[String],
) -> Result<Vec<String>, PgpError> {
    let cert = parse_cert(key_name, key_contents)?;

    if !cert.is_tsk() {
        return Err(PgpError::WrongKeyType(
            key_name.to_string(),
            "cannot decrypt with a public key — the key block does not \
             contain private key material"
                .to_string(),
        ));
    }

    let mut new_names: Vec<String> = Vec::with_capacity(files.len());

    for file_name in files {
        let in_path = staging_dir.join(file_name);
        let new_name = strip_pgp_extension(file_name);
        let out_path = staging_dir.join(&new_name);

        let ciphertext = fs::read(&in_path).map_err(|e| {
            PgpError::Io(format!(
                "read {}: {}",
                in_path.display(),
                e
            ))
        })?;

        let policy = StandardPolicy::new();
        let helper = PrivateKeyDecryptor { cert: cert.clone() };

        let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext[..])
            .map_err(|e| {
                PgpError::Crypto(format!(
                    "decryptor setup for {}: {}",
                    in_path.display(),
                    e
                ))
            })?
            .with_policy(&policy, None, helper)
            .map_err(|e| {
                PgpError::Crypto(format!(
                    "decrypt {}: {}",
                    in_path.display(),
                    e
                ))
            })?;

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        std::io::copy(&mut decryptor, &mut plaintext).map_err(|e| {
            PgpError::Crypto(format!(
                "read plaintext from {}: {}",
                in_path.display(),
                e
            ))
        })?;

        fs::write(&out_path, &plaintext).map_err(|e| {
            PgpError::Io(format!(
                "write {}: {}",
                out_path.display(),
                e
            ))
        })?;

        // Remove the ciphertext unless the input and output paths
        // collide (i.e. there was no pgp/gpg/asc extension to strip).
        if in_path != out_path {
            if let Err(e) = fs::remove_file(&in_path) {
                warn!(
                    "pgp decrypt: could not remove ciphertext {} after \
                     producing {}: {}",
                    in_path.display(),
                    out_path.display(),
                    e
                );
            }
        }

        info!(
            "pgp decrypt: {} -> {} using key '{}'",
            file_name, new_name, key_name
        );
        new_names.push(new_name);
    }

    Ok(new_names)
}

// ============================================================
// Helpers
// ============================================================

/// Parse a key-contents blob (armored or binary) into a Cert.
fn parse_cert(key_name: &str, key_contents: &str) -> Result<Cert, PgpError> {
    if key_contents.trim().is_empty() {
        return Err(PgpError::EmptyKeyContents(key_name.to_string()));
    }

    Cert::from_bytes(key_contents.as_bytes())
        .map_err(|e| PgpError::KeyParse(key_name.to_string(), e.to_string()))
}

/// Strip a single trailing `.pgp`/`.gpg`/`.asc` extension, case-insensitive.
/// Returns the original filename unchanged if no such extension is present.
fn strip_pgp_extension(name: &str) -> String {
    let path = PathBuf::from(name);
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if ext_lower == "pgp" || ext_lower == "gpg" || ext_lower == "asc" {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                return stem.to_string();
            }
        }
    }
    name.to_string()
}

// ============================================================
// Decryption helper — feeds sequoia the private key(s) from our Cert
// ============================================================

struct PrivateKeyDecryptor {
    cert: Cert,
}

impl VerificationHelper for PrivateKeyDecryptor {
    fn get_certs(
        &mut self,
        _ids: &[openpgp::KeyHandle],
    ) -> openpgp::Result<Vec<Cert>> {
        // v1 does not verify signatures on decrypted messages.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        // Accept any message structure. Signature verification lands
        // in a later milestone if we ever need it.
        Ok(())
    }
}

impl DecryptionHelper for PrivateKeyDecryptor {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool,
    {
        let policy = StandardPolicy::new();

        // Try every decryption-capable secret subkey against every PKESK.
        for ka in self
            .cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .secret()
            .for_transport_encryption()
            .for_storage_encryption()
        {
            let mut pair = match ka
                .key()
                .clone()
                .parts_into_secret()
                .and_then(|k| {
                    // v1: no passphrase support. Error loudly on
                    // encrypted secret keys.
                    if k.secret().is_encrypted() {
                        Err(anyhow::anyhow!(
                            "secret key is passphrase-protected; \
                             passphrase-protected keys are not yet \
                             supported (milestone 11)"
                        ))
                    } else {
                        Ok(k)
                    }
                })
                .and_then(|k| k.into_keypair())
            {
                Ok(p) => p,
                Err(_) => continue,
            };

            for pkesk in pkesks {
                if pkesk.recipient() != &ka.key().keyid() {
                    continue;
                }
                if pkesk
                    .decrypt(&mut pair, sym_algo)
                    .is_some_and(|(algo, sk)| decrypt(algo, &sk))
                {
                    return Ok(Some(self.cert.fingerprint()));
                }
            }
        }

        Err(anyhow::anyhow!(
            "no matching decryption-capable secret subkey found"
        ))
    }
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use openpgp::serialize::SerializeInto;
    use tempfile::TempDir;

    #[test]
    fn strip_pgp_extension_handles_common_suffixes() {
        assert_eq!(strip_pgp_extension("report.csv.pgp"), "report.csv");
        assert_eq!(strip_pgp_extension("report.csv.GPG"), "report.csv");
        assert_eq!(strip_pgp_extension("report.csv.asc"), "report.csv");
        assert_eq!(strip_pgp_extension("plain.csv"), "plain.csv");
        assert_eq!(strip_pgp_extension("no_ext"), "no_ext");
    }

    /// Generate a test cert with an encryption subkey, return
    /// (public-key armor, private-key armor).
    fn generate_test_keys() -> (String, String) {
        let (cert, _rev) = CertBuilder::general_purpose(
            None::<openpgp::cert::CipherSuite>,
            Some("sftpflow test <test@example.com>"),
        )
        .generate()
        .expect("cert generation");
        let public = String::from_utf8(
            cert.armored().to_vec().expect("armor public"),
        )
        .unwrap();
        let private = String::from_utf8(
            cert.as_tsk()
                .armored()
                .to_vec()
                .expect("armor private"),
        )
        .unwrap();
        (public, private)
    }

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let (public_key, private_key) = generate_test_keys();

        let staging = TempDir::new().unwrap();
        let plaintext = b"hello sftpflow milestone 10\n";
        let file_name = "payload.txt";
        std::fs::write(staging.path().join(file_name), plaintext).unwrap();

        // Encrypt with the public key.
        let encrypted = encrypt_files(
            "test-key",
            &public_key,
            staging.path(),
            &[file_name.to_string()],
        )
        .expect("encrypt");
        assert_eq!(encrypted, vec!["payload.txt.pgp".to_string()]);
        assert!(staging.path().join("payload.txt.pgp").exists());
        assert!(!staging.path().join("payload.txt").exists());

        // Decrypt with the private key.
        let decrypted = decrypt_files(
            "test-key",
            &private_key,
            staging.path(),
            &encrypted,
        )
        .expect("decrypt");
        assert_eq!(decrypted, vec!["payload.txt".to_string()]);

        let round_tripped =
            std::fs::read(staging.path().join("payload.txt")).unwrap();
        assert_eq!(round_tripped, plaintext);
    }

    #[test]
    fn decrypt_rejects_public_key() {
        let (public_key, _) = generate_test_keys();
        let staging = TempDir::new().unwrap();
        std::fs::write(staging.path().join("foo.txt.pgp"), b"garbage").unwrap();

        let err = decrypt_files(
            "pub-only",
            &public_key,
            staging.path(),
            &["foo.txt.pgp".to_string()],
        )
        .unwrap_err();
        match err {
            PgpError::WrongKeyType(name, _) => assert_eq!(name, "pub-only"),
            other => panic!("expected WrongKeyType, got {:?}", other),
        }
    }
}
