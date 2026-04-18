// ============================================================
// sftpflowd::secrets - sealed credential store
// ============================================================
//
// An encrypted file that holds the raw values for credentials
// (endpoint passwords, SSH private keys, PGP key material).
// The on-disk config.yaml keeps only `*_ref` names that point
// into this store — nothing sensitive is committable.
//
// The store is encrypted with the `age` crate in passphrase /
// scrypt mode. The daemon reads the passphrase from a file or
// environment variable at startup, decrypts the file once, and
// keeps the plaintext map in memory for the lifetime of the
// process.
//
// File layout on disk (a single file):
//   header line:  "# sftpflow-secrets v1"
//   body:         age-encrypted JSON object { name -> value }
//
// Names are case-sensitive strings. Values are arbitrary UTF-8
// strings (so SSH keys and PGP key blocks pass through intact).

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use log::{info, warn};

// ============================================================
// SecretStore
// ============================================================

/// In-memory, decrypted view of the sealed secrets file, plus
/// the passphrase needed to re-seal it after mutations.
pub struct SecretStore {
    path: PathBuf,
    passphrase: SecretString,
    values: BTreeMap<String, String>,
}

/// File header sentinel. Detects accidental writes to the wrong file.
const MAGIC_HEADER: &str = "# sftpflow-secrets v1\n";

impl SecretStore {
    // --------------------------------------------------------
    // Open / create
    // --------------------------------------------------------

    /// Open the secrets file at `path` using `passphrase`.
    /// If the file does not exist, returns an empty store that
    /// will be written on the first mutation.
    pub fn open(path: &Path, passphrase: SecretString) -> Result<Self, String> {
        if !path.exists() {
            info!(
                "secrets: file '{}' does not exist — starting with empty store",
                path.display()
            );
            return Ok(SecretStore {
                path: path.to_path_buf(),
                passphrase,
                values: BTreeMap::new(),
            });
        }

        let raw = fs::read(path).map_err(|e| {
            format!("could not read secrets file '{}': {}", path.display(), e)
        })?;

        // Strip the magic header if present; tolerate older files
        // that were saved without one.
        let encrypted = match raw.strip_prefix(MAGIC_HEADER.as_bytes()) {
            Some(rest) => rest,
            None       => &raw[..],
        };

        // Decrypt with scrypt (passphrase-based) age identity.
        let decryptor = match age::Decryptor::new(encrypted) {
            Ok(d) => d,
            Err(e) => {
                return Err(format!(
                    "secrets file '{}' is corrupt or not age-encrypted: {}",
                    path.display(), e
                ));
            }
        };

        let decryptor = match decryptor {
            age::Decryptor::Passphrase(d) => d,
            age::Decryptor::Recipients(_) => {
                return Err(format!(
                    "secrets file '{}' uses recipient-based encryption; \
                     passphrase expected", path.display()
                ));
            }
        };

        let mut plaintext = Vec::new();
        let mut reader = decryptor
            .decrypt(&passphrase, None)
            .map_err(|e| format!("incorrect passphrase or corrupt secrets file: {}", e))?;
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| format!("failed to decrypt secrets: {}", e))?;

        let values: BTreeMap<String, String> = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("secrets file '{}' is not valid JSON: {}", path.display(), e))?;

        info!(
            "secrets: loaded {} entry(ies) from '{}'",
            values.len(),
            path.display()
        );

        Ok(SecretStore {
            path: path.to_path_buf(),
            passphrase,
            values,
        })
    }

    // --------------------------------------------------------
    // Read
    // --------------------------------------------------------

    /// Return the names of every secret, in sorted order.
    pub fn names(&self) -> Vec<String> {
        self.values.keys().cloned().collect()
    }

    /// Look up the value for `name`, if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(|s| s.as_str())
    }

    // --------------------------------------------------------
    // Write
    // --------------------------------------------------------

    /// Insert or replace a secret and persist the store.
    pub fn put(&mut self, name: String, value: String) -> Result<(), String> {
        self.values.insert(name.clone(), value);
        self.save()?;
        info!("secrets: put '{}'", name);
        Ok(())
    }

    /// Remove a secret (if present) and persist the store.
    /// Returns true if a value was actually removed.
    pub fn delete(&mut self, name: &str) -> Result<bool, String> {
        let existed = self.values.remove(name).is_some();
        if existed {
            self.save()?;
            info!("secrets: deleted '{}'", name);
        } else {
            warn!("secrets: delete '{}' — not found", name);
        }
        Ok(existed)
    }

    // --------------------------------------------------------
    // Internals
    // --------------------------------------------------------

    /// Re-encrypt the in-memory map back to disk.
    fn save(&self) -> Result<(), String> {
        // Ensure the parent directory exists.
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!("could not create directory '{}': {}", parent.display(), e)
                })?;
            }
        }

        // Serialise the plaintext map as compact JSON.
        let plaintext = serde_json::to_vec(&self.values)
            .map_err(|e| format!("could not serialize secrets map: {}", e))?;

        // Encrypt with age / scrypt (passphrase-based).
        let encryptor = age::Encryptor::with_user_passphrase(self.passphrase.clone());

        let mut encrypted: Vec<u8> = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| format!("failed to begin encryption: {}", e))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| format!("failed to encrypt secrets: {}", e))?;
        writer
            .finish()
            .map_err(|e| format!("failed to finalize encryption: {}", e))?;

        // Prepend the magic header for quick sanity-check on load.
        let mut final_bytes = Vec::with_capacity(MAGIC_HEADER.len() + encrypted.len());
        final_bytes.extend_from_slice(MAGIC_HEADER.as_bytes());
        final_bytes.extend_from_slice(&encrypted);

        // Write atomically: write to a sibling tempfile, then rename.
        let tmp_path = self.path.with_extension("new");
        fs::write(&tmp_path, &final_bytes).map_err(|e| {
            format!("could not write secrets to '{}': {}", tmp_path.display(), e)
        })?;

        // On Unix we'd chmod 0600 here; the daemon is expected to run
        // as a dedicated service user so directory-level perms protect it.
        fs::rename(&tmp_path, &self.path).map_err(|e| {
            format!(
                "could not rename '{}' -> '{}': {}",
                tmp_path.display(), self.path.display(), e
            )
        })?;

        info!(
            "secrets: saved {} entry(ies) to '{}'",
            self.values.len(),
            self.path.display()
        );
        Ok(())
    }
}

// ============================================================
// Passphrase loading helpers
// ============================================================

/// Read the daemon master passphrase, preferring (in order):
///   1. `--passphrase-file <path>` CLI argument
///   2. `SFTPFLOW_PASSPHRASE` environment variable
/// Leading / trailing whitespace (and a trailing newline) is stripped.
///
/// Returns `None` when neither source is set; callers decide whether
/// that means "no secrets store" or "hard error".
pub fn load_passphrase(
    passphrase_file: Option<&Path>,
) -> Result<Option<SecretString>, String> {
    // 1. Explicit file, if provided.
    if let Some(path) = passphrase_file {
        let raw = fs::read_to_string(path).map_err(|e| {
            format!("could not read passphrase file '{}': {}", path.display(), e)
        })?;
        let trimmed = raw.trim_matches(|c: char| c == '\n' || c == '\r' || c == ' ' || c == '\t');
        if trimmed.is_empty() {
            return Err(format!("passphrase file '{}' is empty", path.display()));
        }
        return Ok(Some(SecretString::new(trimmed.to_string())));
    }

    // 2. Environment variable fallback.
    if let Ok(value) = std::env::var("SFTPFLOW_PASSPHRASE") {
        if !value.is_empty() {
            return Ok(Some(SecretString::new(value)));
        }
    }

    Ok(None)
}

/// Default path for the sealed secrets file.
/// - Linux: `/var/lib/sftpflow/secrets.age`
/// - Windows: `%APPDATA%/sftpflow/secrets.age`
pub fn default_secrets_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sftpflow/secrets.age")
    }
    #[cfg(not(unix))]
    {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base).join("sftpflow").join("secrets.age")
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::SecretString;

    #[test]
    fn put_get_delete_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("secrets.age");
        let pass = SecretString::new("correct-horse-battery-staple".to_string());

        // Fresh store — put a secret and persist.
        {
            let mut store = SecretStore::open(&path, pass.clone()).unwrap();
            store.put("myhost_pw".into(), "hunter2".into()).unwrap();
            store.put("archive_ssh_key".into(), "-----BEGIN-----\n...\n-----END-----".into()).unwrap();
        }

        // Re-open with the same passphrase — entries should be present.
        {
            let store = SecretStore::open(&path, pass.clone()).unwrap();
            assert_eq!(store.get("myhost_pw"), Some("hunter2"));
            assert!(store.get("archive_ssh_key").unwrap().contains("BEGIN"));
            let mut names = store.names();
            names.sort();
            assert_eq!(names, vec!["archive_ssh_key".to_string(), "myhost_pw".to_string()]);
        }

        // Delete and confirm persisted.
        {
            let mut store = SecretStore::open(&path, pass.clone()).unwrap();
            assert!(store.delete("myhost_pw").unwrap());
            assert!(!store.delete("nope").unwrap());
        }
        {
            let store = SecretStore::open(&path, pass).unwrap();
            assert!(store.get("myhost_pw").is_none());
            assert_eq!(store.names(), vec!["archive_ssh_key".to_string()]);
        }
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("secrets.age");

        {
            let mut store = SecretStore::open(&path, SecretString::new("right".into())).unwrap();
            store.put("x".into(), "y".into()).unwrap();
        }

        let err = match SecretStore::open(&path, SecretString::new("wrong".into())) {
            Ok(_) => panic!("wrong passphrase should not have decrypted"),
            Err(e) => e,
        };
        assert!(err.contains("passphrase") || err.contains("decrypt"));
    }
}
