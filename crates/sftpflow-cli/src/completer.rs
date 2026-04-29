// ============================================================
// completer.rs - Mode-aware tab completion for the shell
// ============================================================
//
// Implements rustyline's Helper trait stack so the interactive
// shell gets contextual tab-completion. The Completer impl looks
// at:
//   1. The current shell Mode (Exec / EndpointEdit / KeyEdit /
//      FeedEdit / NextStepEdit / ConfigEdit).
//   2. The tokens already typed before the cursor.
//   3. A NameCache populated from the daemon (endpoints, keys,
//      feeds, secrets) plus the local connection registry.
//
// The cache is refreshed lazily by the main shell loop in cli.rs
// — only after dispatching commands that may have mutated names
// (commit / delete / rename / secret / connection / connect).
// On non-mutating commands we skip the round-trip entirely.

use std::cell::RefCell;
use std::rc::Rc;

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper, Result as RlResult};

use crate::cli::Mode; // cli.rs

// ============================================================
// Static keyword tables — kept in sync with cli::dispatch_*
// ============================================================

const EXEC_COMMANDS: &[&str] = &[
    "help", "create", "edit", "delete", "rename", "show",
    "run", "connect", "connection", "sync", "secret",
    "cluster", "config", "version", "exit", "quit",
];

const ENDPOINT_EDIT_KEYWORDS: &[&str] = &[
    "help", "protocol", "host", "port", "username", "password",
    "password_ref", "ssh_key", "ssh_key_ref", "ftps_mode",
    "passive", "verify_tls", "no", "show", "commit", "abort",
    "exit", "end",
];

const KEY_EDIT_KEYWORDS: &[&str] = &[
    "help", "type", "contents", "contents_ref", "load", "no",
    "show", "commit", "abort", "exit", "end",
];

const FEED_EDIT_KEYWORDS: &[&str] = &[
    "help", "source", "destination", "process", "schedule",
    "flag", "nextstep", "move", "no", "show", "commit",
    "abort", "exit", "end",
];

const NEXTSTEP_EDIT_KEYWORDS: &[&str] = &[
    "help", "type", "target", "on", "no", "show", "done", "abort",
];

const CONFIG_EDIT_KEYWORDS: &[&str] = &[
    "help", "host", "port", "username", "dkron", "no", "show",
    "commit", "abort", "exit", "end",
];

// Object-type token following create/edit/delete/rename/show.
const TYPE_TOKENS: &[&str] = &["endpoint", "key", "feed"];

// `show <subcommand>` — singular forms route to detail views,
// plural forms list everything.
const SHOW_TOKENS: &[&str] = &[
    "endpoints", "endpoint", "keys", "key", "feeds", "feed",
    "runs", "secrets", "server", "version",
];

// Subcommand families.
const CLUSTER_SUBS:    &[&str] = &["status", "token", "remove", "leave", "join", "bootstrap", "backup"];
const CONNECTION_SUBS: &[&str] = &["add", "list", "delete"];
const SECRET_SUBS:     &[&str] = &["add", "list", "delete"];
const SYNC_SUBS:       &[&str] = &["schedules"];
const RUN_SUBS:        &[&str] = &["feed"];

// Value tables for typed properties.
const PROTOCOL_VALUES:      &[&str] = &["sftp", "ftp", "ftps", "http", "https"];
const FTPS_MODE_VALUES:     &[&str] = &["explicit", "implicit"];
const YESNO_VALUES:         &[&str] = &["yes", "no"];
const KEY_TYPE_VALUES:      &[&str] = &["public", "private"];
const NEXTSTEP_TYPE_VALUES: &[&str] = &["feed", "email", "sleep"];
const TRIGGER_VALUES:       &[&str] = &["success", "noaction", "failed"];
const PROCESS_VERBS:        &[&str] = &["encrypt", "decrypt"];

// Properties that follow `no <prop>` per mode.
const NO_ENDPOINT_PROPS: &[&str] = &[
    "protocol", "host", "port", "username", "password",
    "password_ref", "ssh_key", "ssh_key_ref", "ftps_mode",
    "passive", "verify_tls",
];
const NO_KEY_PROPS:      &[&str] = &["type", "contents", "contents_ref"];
const NO_FEED_PROPS:     &[&str] = &["source", "process", "destination", "nextstep", "schedule"];
const NO_SERVER_PROPS:   &[&str] = &["host", "port", "username", "dkron"];
const NO_NEXTSTEP_PROPS: &[&str] = &["on"];

const FEED_FLAG_NAMES: &[&str] = &["enabled"];

// ============================================================
// Shared cache & helper data
// ============================================================

/// Names known to the daemon + local connection registry.
/// Populated by cli::sync_helper() when the cache is dirty.
#[derive(Default)]
pub struct NameCache {
    pub endpoints:   Vec<String>,
    pub keys:        Vec<String>,
    pub feeds:       Vec<String>,
    pub secrets:     Vec<String>,
    pub connections: Vec<String>,
}

/// Mutable state shared between the main shell loop and the
/// rustyline helper. The loop writes here just before each
/// readline; the Completer reads here when tab is pressed.
pub struct HelperData {
    pub mode:        Mode,
    pub names:       NameCache,
    /// True when the cache should be refreshed before the next
    /// prompt. Starts true so the first prompt triggers a fetch.
    pub names_dirty: bool,
}

impl Default for HelperData {
    fn default() -> Self {
        HelperData {
            mode:        Mode::Exec,
            names:       NameCache::default(),
            names_dirty: true,
        }
    }
}

/// rustyline Helper. Wraps a shared HelperData so the main loop
/// can update mode/names without owning the helper outright.
pub struct ShellHelper {
    pub data: Rc<RefCell<HelperData>>,
}

// ============================================================
// rustyline Helper trait stack
// ============================================================
//
// We only need Completer; the others are required as supertraits
// of Helper but get default no-op impls.

impl Helper      for ShellHelper {}
impl Validator   for ShellHelper {}
impl Highlighter for ShellHelper {}
impl Hinter      for ShellHelper {
    type Hint = String;
}

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> RlResult<(usize, Vec<Pair>)> {
        let data = self.data.borrow();

        // ---- Identify the partial word being completed ----
        //
        // prefix_start points at the first character of the
        // current token. Anything before it counts as "prior"
        // tokens that have already been typed.
        let prefix_end   = pos;
        let prefix_start = line[..prefix_end]
            .rfind(char::is_whitespace)
            .map(|i| i + 1)
            .unwrap_or(0);
        let partial = &line[prefix_start..prefix_end];

        let prior_str    = &line[..prefix_start];
        let prior_tokens: Vec<&str> = prior_str.split_whitespace().collect();

        // ---- Pick the candidate set from the current mode ----
        let mut candidates: Vec<String> = match &data.mode {
            Mode::Exec             => exec_candidates(&prior_tokens, &data.names),
            Mode::EndpointEdit(_)  => endpoint_edit_candidates(&prior_tokens),
            Mode::KeyEdit(_)       => key_edit_candidates(&prior_tokens),
            Mode::FeedEdit(_)      => feed_edit_candidates(&prior_tokens, &data.names),
            Mode::NextStepEdit(_)  => nextstep_edit_candidates(&prior_tokens, &data.names),
            Mode::ConfigEdit       => config_edit_candidates(&prior_tokens),
        };

        candidates.sort();
        candidates.dedup();

        let pairs: Vec<Pair> = candidates
            .into_iter()
            .filter(|c| c.starts_with(partial))
            .map(|c| Pair { display: c.clone(), replacement: c })
            .collect();

        Ok((prefix_start, pairs))
    }
}

// ============================================================
// Per-mode candidate logic
// ============================================================

// ---- Exec mode ----

fn exec_candidates(prior: &[&str], names: &NameCache) -> Vec<String> {
    match prior.first().copied() {
        // No command typed yet: complete top-level commands.
        None => to_strings(EXEC_COMMANDS),

        Some("create") | Some("edit") | Some("delete") => match prior.len() {
            1 => to_strings(TYPE_TOKENS),
            2 => names_for_type(prior[1], names),
            _ => Vec::new(),
        },

        Some("rename") => match prior.len() {
            1 => to_strings(TYPE_TOKENS),
            2 => names_for_type(prior[1], names),
            // arg 3 is the new name — freeform
            _ => Vec::new(),
        },

        Some("show") => match prior.len() {
            1 => to_strings(SHOW_TOKENS),
            2 => match prior[1] {
                "endpoint" => names.endpoints.clone(),
                "key"      => names.keys.clone(),
                "feed"     => names.feeds.clone(),
                "runs"     => names.feeds.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        },

        Some("run") => match prior.len() {
            1 => to_strings(RUN_SUBS),
            2 if prior[1] == "feed" => names.feeds.clone(),
            _ => Vec::new(),
        },

        Some("secret") => match prior.len() {
            1 => to_strings(SECRET_SUBS),
            2 if prior[1] == "delete" => names.secrets.clone(),
            // `secret add <name>` is a new name — freeform.
            _ => Vec::new(),
        },

        Some("cluster") => match prior.len() {
            1 => to_strings(CLUSTER_SUBS),
            // remove <node-id>, join/bootstrap user@host — freeform
            _ => Vec::new(),
        },

        Some("connection") => match prior.len() {
            1 => to_strings(CONNECTION_SUBS),
            2 if prior[1] == "delete" => names.connections.clone(),
            _ => Vec::new(),
        },

        Some("connect") => match prior.len() {
            1 => names.connections.clone(),
            _ => Vec::new(),
        },

        Some("sync") => match prior.len() {
            1 => to_strings(SYNC_SUBS),
            _ => Vec::new(),
        },

        _ => Vec::new(),
    }
}

// ---- Edit modes ----

fn endpoint_edit_candidates(prior: &[&str]) -> Vec<String> {
    match prior.first().copied() {
        None                         => to_strings(ENDPOINT_EDIT_KEYWORDS),
        Some("protocol")             => to_strings(PROTOCOL_VALUES),
        Some("ftps_mode")            => to_strings(FTPS_MODE_VALUES),
        Some("passive")              => to_strings(YESNO_VALUES),
        Some("verify_tls")           => to_strings(YESNO_VALUES),
        Some("no") if prior.len() == 1 => to_strings(NO_ENDPOINT_PROPS),
        _                            => Vec::new(),
    }
}

fn key_edit_candidates(prior: &[&str]) -> Vec<String> {
    match prior.first().copied() {
        None                         => to_strings(KEY_EDIT_KEYWORDS),
        Some("type")                 => to_strings(KEY_TYPE_VALUES),
        Some("no") if prior.len() == 1 => to_strings(NO_KEY_PROPS),
        _                            => Vec::new(),
    }
}

fn feed_edit_candidates(prior: &[&str], names: &NameCache) -> Vec<String> {
    match prior.first().copied() {
        None => to_strings(FEED_EDIT_KEYWORDS),

        // `process encrypt|decrypt <keyname>`
        Some("process") if prior.len() == 1 => to_strings(PROCESS_VERBS),
        Some("process") if prior.len() == 2 => names.keys.clone(),

        // `flag <name> <yes|no>`
        Some("flag") if prior.len() == 1 => to_strings(FEED_FLAG_NAMES),
        Some("flag") if prior.len() == 2 => to_strings(YESNO_VALUES),

        // `move nextstep <from> <to>` — only the first token is fixed.
        Some("move") if prior.len() == 1 => vec!["nextstep".to_string()],

        Some("no") if prior.len() == 1 => to_strings(NO_FEED_PROPS),

        _ => Vec::new(),
    }
}

fn nextstep_edit_candidates(prior: &[&str], names: &NameCache) -> Vec<String> {
    match prior.first().copied() {
        None                          => to_strings(NEXTSTEP_EDIT_KEYWORDS),
        Some("type")                  => to_strings(NEXTSTEP_TYPE_VALUES),
        Some("on")                    => to_strings(TRIGGER_VALUES),
        // `target <feed>` — only meaningful when the next-step is
        // a RunFeed action, but completing feed names is harmless
        // for the email/sleep cases too (operator just won't pick
        // one). Keeps the completer dumb-but-helpful.
        Some("target")                => names.feeds.clone(),
        Some("no") if prior.len() == 1 => to_strings(NO_NEXTSTEP_PROPS),
        Some("no") if prior.len() == 2 && prior[1] == "on"
                                       => to_strings(TRIGGER_VALUES),
        _                              => Vec::new(),
    }
}

fn config_edit_candidates(prior: &[&str]) -> Vec<String> {
    match prior.first().copied() {
        None                         => to_strings(CONFIG_EDIT_KEYWORDS),
        Some("no") if prior.len() == 1 => to_strings(NO_SERVER_PROPS),
        _                            => Vec::new(),
    }
}

// ============================================================
// Helpers
// ============================================================

/// Resolve a `create|edit|delete <type>` token to the matching
/// name list. Unknown types yield an empty Vec so the operator
/// just sees no completions rather than getting a hint to a list
/// that wouldn't apply.
fn names_for_type(ty: &str, names: &NameCache) -> Vec<String> {
    match ty {
        "endpoint" => names.endpoints.clone(),
        "key"      => names.keys.clone(),
        "feed"     => names.feeds.clone(),
        _          => Vec::new(),
    }
}

fn to_strings(slice: &[&str]) -> Vec<String> {
    slice.iter().map(|s| s.to_string()).collect()
}
