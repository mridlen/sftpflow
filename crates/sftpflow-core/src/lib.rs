// ============================================================
// feed.rs - Data models and YAML persistence
// ============================================================

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use log::info;

// ============================================================
// Identifier validation
// ============================================================

/// Strict allowlist for operator-supplied identifiers (feed names,
/// endpoint names, key names, secret names, connection names).
///
/// Allowed: ASCII letters, digits, dash, underscore, dot. The first
/// character must be alphanumeric to keep names from looking like
/// CLI flags. Length capped at 64 bytes.
///
/// Why an allowlist rather than escaping at the use site: these
/// names flow into shell command strings (dkron `shell` executor),
/// HTTP path components (dkron job names), filesystem paths
/// (audit/history exports), and YAML keys. Centralizing the rule
/// here closes the door on injection across every downstream sink.
pub fn validate_name(kind: &str, name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{} name cannot be empty", kind));
    }
    if name.len() > 64 {
        return Err(format!(
            "{} name '{}' exceeds 64-character limit",
            kind, name,
        ));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(format!(
            "{} name '{}' must start with a letter or digit",
            kind, name,
        ));
    }
    for c in name.chars() {
        let ok = c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == '.';
        if !ok {
            return Err(format!(
                "{} name '{}' contains invalid character '{}'; \
                 use letters, digits, '-', '_', '.'",
                kind, name, c,
            ));
        }
    }
    Ok(())
}

// ============================================================
// Endpoint - connection details
// ============================================================

/// Supported transfer protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Sftp,
    Ftp,
    Ftps,
    Http,
    Https,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Sftp
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Sftp  => write!(f, "sftp"),
            Protocol::Ftp   => write!(f, "ftp"),
            Protocol::Ftps  => write!(f, "ftps"),
            Protocol::Http  => write!(f, "http"),
            Protocol::Https => write!(f, "https"),
        }
    }
}

/// FTPS negotiation style.
///
/// - `Explicit` — AUTH TLS on the existing port 21 control channel
///   (the modern, common pattern for B2B partners).
/// - `Implicit` — TLS from the first byte on port 990 (legacy).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FtpsMode {
    Explicit,
    Implicit,
}

impl Default for FtpsMode {
    fn default() -> Self {
        FtpsMode::Explicit
    }
}

impl std::fmt::Display for FtpsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FtpsMode::Explicit => write!(f, "explicit"),
            FtpsMode::Implicit => write!(f, "implicit"),
        }
    }
}

/// An endpoint with connection credentials.
///
/// Secrets can be supplied two ways:
///   - `password` / `ssh_key` — plaintext in the YAML (legacy / dev only).
///   - `password_ref` / `ssh_key_ref` — the *name* of a secret in the
///     daemon's sealed store; the daemon resolves the name to the real
///     value at run time. Prefer refs so config.yaml is committable.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Endpoint {
    #[serde(default)]
    pub protocol: Protocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<String>,
    /// Name of a sealed-store secret holding the password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_ref: Option<String>,
    /// Name of a sealed-store secret holding an SSH private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_ref: Option<String>,

    // ---- SFTP-specific options ----
    /// Expected SSH host-key fingerprint (SFTP only).
    ///
    /// Format: standard OpenSSH SHA-256 form, e.g.
    /// `SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8`
    /// (the same string `ssh-keygen -lf <known_hosts>` prints).
    ///
    /// When set, the daemon refuses to authenticate unless the
    /// server's presented host key hashes to this value. This
    /// stops an on-path attacker from impersonating the partner
    /// SFTP server and harvesting credentials/data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
    /// Whether to enforce host-key verification (SFTP only).
    /// None = default true. Operators may set `Some(false)` for
    /// dev/legacy endpoints where a fingerprint is not yet known,
    /// matching the FTPS `verify_tls` opt-out pattern. Disabling
    /// host-key verification exposes the connection to MITM —
    /// the daemon logs a loud warning each time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_host_key: Option<bool>,

    // ---- FTP/FTPS-specific options ----
    /// TLS negotiation style (FTPS only). None = default Explicit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftps_mode: Option<FtpsMode>,
    /// PASV vs active mode (FTP/FTPS). None = default passive.
    /// Active mode requires the FTP server to open a data
    /// connection *back* to us — the firewall in front of the
    /// client must permit that. Passive is the modern default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive: Option<bool>,
    /// Whether to verify the server's TLS certificate (FTPS only).
    /// None = default true. Set to `Some(false)` for vendor
    /// endpoints that present self-signed certs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_tls: Option<bool>,
}

impl Endpoint {
    pub fn new() -> Self {
        Endpoint::default()
    }

    /// Pretty-print the endpoint configuration.
    pub fn display(&self, name: &str) {
        println!("Endpoint: {}", name);
        println!("  protocol    {}", self.protocol);
        println!("  host        {}", self.host.as_deref().unwrap_or("(not set)"));
        println!("  port        {}", self.port.map_or("(not set)".to_string(), |p| p.to_string()));
        println!("  username    {}", self.username.as_deref().unwrap_or("(not set)"));
        // Credentials: prefer refs over plaintext, show both if both are set.
        match (&self.password_ref, &self.password) {
            (Some(r), _)    => println!("  password    (ref: {})", r),
            (None, Some(_)) => println!("  password    ********"),
            (None, None)    => println!("  password    (not set)"),
        }
        match (&self.ssh_key_ref, &self.ssh_key) {
            (Some(r), _)    => println!("  ssh_key     (ref: {})", r),
            // Don't dump the PEM body — it would scroll the terminal
            // and could be shoulder-surfed. Show shape only; if the
            // operator needs the actual key they have it in their
            // sealed store (or the source they pasted from).
            (None, Some(v)) => println!("  ssh_key     (inline, {} bytes)", v.len()),
            (None, None)    => println!("  ssh_key     (not set)"),
        }

        // SFTP host-key fields only printed for SFTP endpoints.
        if matches!(self.protocol, Protocol::Sftp) {
            let verify = self.verify_host_key.unwrap_or(true);
            println!("  verify_host_key  {}", verify);
            println!("  host_key_fp      {}",
                self.host_key_fingerprint.as_deref().unwrap_or("(not set)"));
        }

        // FTP/FTPS extras only printed when relevant, to avoid
        // cluttering SFTP endpoint output.
        if matches!(self.protocol, Protocol::Ftp | Protocol::Ftps) {
            let pasv = self.passive.unwrap_or(true);
            println!("  mode        {}", if pasv { "passive" } else { "active" });
        }
        if matches!(self.protocol, Protocol::Ftps) {
            let mode = self.ftps_mode.clone().unwrap_or_default();
            let verify = self.verify_tls.unwrap_or(true);
            println!("  ftps_mode   {}", mode);
            println!("  verify_tls  {}", verify);
        }
    }
}

// ============================================================
// PGP Key - key management
// ============================================================

/// The type of PGP key (public for encrypt, private for decrypt).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Public,
    Private,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Public  => write!(f, "public"),
            KeyType::Private => write!(f, "private"),
        }
    }
}

/// A PGP key with its contents stored in the config.
///
/// Contents can be supplied two ways:
///   - `contents` — the PGP armour block inline in YAML (legacy / dev).
///   - `contents_ref` — the *name* of a secret in the daemon's sealed
///     store; the daemon resolves the name to the real key at run time.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct PgpKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contents: Option<String>,
    /// Name of a sealed-store secret holding the key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contents_ref: Option<String>,
}

impl PgpKey {
    pub fn new() -> Self {
        PgpKey::default()
    }

    /// Pretty-print the key configuration.
    pub fn display(&self, name: &str) {
        println!("Key: {}", name);
        println!("  type        {}",
            self.key_type.as_ref().map_or("(not set)".to_string(), |t| t.to_string()));
        match (&self.contents_ref, &self.contents) {
            (Some(r), _) => {
                println!("  contents    (ref: {})", r);
            }
            (None, Some(c)) => {
                // Show first line and length as a summary
                let first_line = c.lines().next().unwrap_or("(empty)");
                let line_count = c.lines().count();
                println!("  contents    {} ({} lines)", first_line, line_count);
            }
            (None, None) => println!("  contents    (not set)"),
        }
    }
}

// ============================================================
// Feed - transfer definition referencing endpoints
// ============================================================

/// A source or destination: an endpoint name + remote path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedPath {
    pub endpoint: String,
    pub path: String,
}

impl std::fmt::Display for FeedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.endpoint, self.path)
    }
}

/// Helper module for serializing bools as "yes"/"no" strings in YAML.
mod yes_no {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(if *value { "yes" } else { "no" })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "yes" | "true" | "on"  => Ok(true),
            "no" | "false" | "off" => Ok(false),
            _ => Err(serde::de::Error::custom(format!("expected yes/no, got '{}'", s))),
        }
    }
}

/// Boolean flags that control feed behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedFlags {
    #[serde(with = "yes_no")]
    pub enabled: bool,
    #[serde(with = "yes_no")]
    pub delete_source_after_transfer: bool,
}

impl Default for FeedFlags {
    fn default() -> Self {
        FeedFlags {
            enabled: true,
            delete_source_after_transfer: false,
        }
    }
}

impl FeedFlags {
    /// Pretty-print the flags.
    pub fn display(&self) {
        println!("  flags");
        println!("    enabled                      {}",
            if self.enabled { "yes" } else { "no" });
        println!("    delete_source_after_transfer  {}",
            if self.delete_source_after_transfer { "yes" } else { "no" });
    }
}

// ============================================================
// Process steps - ordered pipeline between source and destination
// ============================================================

/// A processing step that runs between source retrieval and destination delivery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action")]
pub enum ProcessStep {
    /// Encrypt files using a PGP public key.
    #[serde(rename = "encrypt")]
    Encrypt { key: String },
    /// Decrypt files using a PGP private key.
    ///
    /// `verify_with`, when present and non-empty, requires the
    /// PGP message to carry at least one valid signature from one
    /// of the named public keys; messages with no good signature
    /// from this set are rejected and the feed fails. When `None`
    /// or empty, decryption proceeds without checking signatures
    /// (the legacy behavior — kept so existing configs keep
    /// working, but operators handling sensitive data should
    /// always set this).
    #[serde(rename = "decrypt")]
    Decrypt {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verify_with: Option<Vec<String>>,
    },
}

impl std::fmt::Display for ProcessStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessStep::Encrypt { key } => write!(f, "encrypt key:{}", key),
            ProcessStep::Decrypt { key, verify_with } => match verify_with {
                Some(keys) if !keys.is_empty() => {
                    write!(f, "decrypt key:{} verify_with:{}", key, keys.join(","))
                }
                _ => write!(f, "decrypt key:{}", key),
            },
        }
    }
}

// ============================================================
// Next steps - actions triggered after feed completion
// ============================================================

/// Conditions that trigger a next step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum TriggerCondition {
    Success,
    Noaction,
    Failed,
}

impl std::fmt::Display for TriggerCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriggerCondition::Success  => write!(f, "success"),
            TriggerCondition::Noaction => write!(f, "noaction"),
            TriggerCondition::Failed   => write!(f, "failed"),
        }
    }
}

/// The action type for a next step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action")]
pub enum NextStepAction {
    /// Run another feed.
    #[serde(rename = "feed")]
    RunFeed { feed: String },
    /// Send an email notification.
    #[serde(rename = "email")]
    SendEmail { emails: Vec<String> },
    /// Sleep for a number of seconds before continuing.
    #[serde(rename = "sleep")]
    Sleep { seconds: u64 },
}

impl std::fmt::Display for NextStepAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NextStepAction::RunFeed { feed } => write!(f, "run feed '{}'", feed),
            NextStepAction::SendEmail { emails } => write!(f, "email {}", emails.join(",")),
            NextStepAction::Sleep { seconds } => write!(f, "sleep {}s", seconds),
        }
    }
}

/// A next step: an action + the conditions that trigger it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NextStep {
    #[serde(flatten)]
    pub action: NextStepAction,
    pub on: Vec<TriggerCondition>,
}

impl NextStep {
    /// Pretty-print the next step.
    pub fn display_inline(&self) -> String {
        let conditions: Vec<String> = self.on.iter().map(|c| c.to_string()).collect();
        format!("{} on: {}", self.action, conditions.join(", "))
    }
}

/// A feed definition (many sources → many destinations, multiple schedules).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Feed {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<FeedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process: Vec<ProcessStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<FeedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nextsteps: Vec<NextStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schedules: Vec<String>,
    #[serde(default)]
    pub flags: FeedFlags,
}

impl Feed {
    pub fn new() -> Self {
        Feed::default()
    }

    /// Pretty-print the feed configuration.
    pub fn display(&self, name: &str) {
        println!("Feed: {}", name);

        // Sources
        if self.sources.is_empty() {
            println!("  sources       (none)");
        } else {
            for (i, src) in self.sources.iter().enumerate() {
                if i == 0 {
                    println!("  sources       {}", src);
                } else {
                    println!("                {}", src);
                }
            }
        }

        // Process pipeline
        if self.process.is_empty() {
            println!("  process       (none)");
        } else {
            for (i, step) in self.process.iter().enumerate() {
                if i == 0 {
                    println!("  process       {}", step);
                } else {
                    println!("                {}", step);
                }
            }
        }

        // Destinations
        if self.destinations.is_empty() {
            println!("  destinations  (none)");
        } else {
            for (i, dst) in self.destinations.iter().enumerate() {
                if i == 0 {
                    println!("  destinations  {}", dst);
                } else {
                    println!("                {}", dst);
                }
            }
        }

        // Next steps
        if self.nextsteps.is_empty() {
            println!("  nextsteps     (none)");
        } else {
            for (i, ns) in self.nextsteps.iter().enumerate() {
                if i == 0 {
                    println!("  nextsteps     [{}] {}", i + 1, ns.display_inline());
                } else {
                    println!("                [{}] {}", i + 1, ns.display_inline());
                }
            }
        }

        // Schedules
        if self.schedules.is_empty() {
            println!("  schedules     (none)");
        } else {
            for (i, sched) in self.schedules.iter().enumerate() {
                if i == 0 {
                    println!("  schedules     {}", sched);
                } else {
                    println!("                {}", sched);
                }
            }
        }

        // Flags
        self.flags.display();
    }
}

// ============================================================
// Server connection - SSH settings for client→server
// ============================================================

/// SSH connection settings for reaching the SFTPflow server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConnection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// URL of the dkron scheduler API (e.g. http://dkron-server:8080).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkron_url: Option<String>,
}

impl ServerConnection {
    /// Pretty-print the server connection settings.
    pub fn display(&self) {
        println!("Server connection:");
        println!("  host        {}", self.host.as_deref().unwrap_or("(not set)"));
        println!("  port        {}", self.port.map_or("(not set)".to_string(), |p| p.to_string()));
        println!("  username    {}", self.username.as_deref().unwrap_or("(not set)"));
        println!("  dkron       {}", self.dkron_url.as_deref().unwrap_or("(not set)"));
    }
}

// ============================================================
// Config - top-level persistence
// ============================================================

/// Top-level config containing server connection, endpoints, keys, and feeds.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Live/active SSH connection settings the CLI uses when it
    /// runs `connect`. Always populated from whichever named entry
    /// is active, or set directly via `config` mode.
    #[serde(default)]
    pub server: ServerConnection,
    /// Named-connection registry. Operators bookmark cluster nodes
    /// here ("connection add prod-1 admin@10.0.0.1:22") and switch
    /// between them with "connect NAME" instead of re-typing host/port.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub connections: BTreeMap<String, ServerConnection>,
    /// Name of the currently active entry in `connections`, if any.
    /// `config commit` writes `server` back into `connections[active]`
    /// so registry entries stay in sync with on-the-fly edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_connection: Option<String>,
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
    #[serde(default)]
    pub keys: BTreeMap<String, PgpKey>,
    #[serde(default)]
    pub feeds: BTreeMap<String, Feed>,
}

impl Config {
    /// Load config from the YAML file, or return a default if it doesn't exist.
    ///
    /// Returns Err on read or parse failure rather than silently
    /// falling back to defaults — silently defaulting on a typo
    /// causes the next `save()` to clobber the original config,
    /// which has eaten user data in practice. Callers (CLI startup,
    /// daemon startup) are expected to surface the error and refuse
    /// to keep going rather than ship over the operator's work.
    pub fn load() -> Result<Self, String> {
        let path = config_path();
        if !path.exists() {
            info!("No config file found at {}, using defaults", path.display());
            return Ok(Config::default());
        }

        let contents = fs::read_to_string(&path).map_err(|e| {
            format!("could not read config file '{}': {}", path.display(), e)
        })?;

        let cfg: Config = serde_yaml::from_str(&contents).map_err(|e| {
            format!(
                "could not parse config file '{}': {} \
                 (refusing to load defaults — fix or remove the file before retrying)",
                path.display(), e,
            )
        })?;

        info!("Loaded config from {}", path.display());
        Ok(cfg)
    }

    /// Save the config to the YAML file.
    ///
    /// Atomic-rename pattern: serialize → write to `<path>.tmp` →
    /// fsync the temp file → set 0600 perms (Unix) → rename onto
    /// the live path → fsync the parent directory. A crash at any
    /// point leaves either the previous good file OR the new file,
    /// never a half-written one. The 0600 perms keep credentials
    /// (passwords/keys/dkron tokens that may be embedded inline) off
    /// the world-readable bucket — `fs::write` would otherwise honor
    /// the process umask.
    pub fn save(&self) -> Result<(), String> {
        let path = config_path();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Could not create config directory: {}", e))?;
        }

        let yaml = serde_yaml::to_string(self)
            .map_err(|e| format!("Could not serialize config: {}", e))?;

        // atomic_write_yaml() - below
        atomic_write_yaml(&path, yaml.as_bytes())?;

        info!("Config saved to {}", path.display());
        Ok(())
    }
}

/// Write `bytes` to `path` atomically with restrictive permissions.
///
/// Steps:
///   1. Stage to `<path>.tmp` (clobbering any leftover from a prior
///      crashed run).
///   2. `write_all` + `sync_all` so the data hits stable storage.
///   3. On Unix, `chmod 0600` so an inline secret never lands in a
///      world-readable file.
///   4. Rename onto `path` (atomic on POSIX and modern NTFS).
///   5. Best-effort fsync of the parent directory so the rename
///      survives a crash on filesystems that decouple metadata
///      durability (ext4 with default options).
fn atomic_write_yaml(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    let tmp = {
        let mut name = path.file_name()
            .ok_or_else(|| format!("config path '{}' has no filename", path.display()))?
            .to_os_string();
        name.push(".tmp");
        path.with_file_name(name)
    };

    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| format!("Could not create {}: {}", tmp.display(), e))?;
        f.write_all(bytes)
            .map_err(|e| format!("Could not write {}: {}", tmp.display(), e))?;
        f.sync_all()
            .map_err(|e| format!("Could not fsync {}: {}", tmp.display(), e))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 on {}: {}", tmp.display(), e))?;
    }

    fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} -> {}: {}", tmp.display(), path.display(), e))?;

    // Best-effort: fsync the parent directory so the rename is
    // durable on filesystems that don't auto-flush directory
    // entries. Failures here are logged-and-ignored — the file is
    // already on disk.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(d) = fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }

    Ok(())
}

/// Return the path to the config file.
/// Checks SFTPFLOW_CONFIG env var first, then falls back to ~/.sftpflow/config.yaml.
///
/// Public so the daemon's backup/restore module can copy this file
/// alongside the cluster state — the YAML lives outside `state_dir`
/// so plumbing the path through is the only way to find it.
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("SFTPFLOW_CONFIG") {
        return PathBuf::from(p);
    }

    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    home.join(".sftpflow").join("config.yaml")
}