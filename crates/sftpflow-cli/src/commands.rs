// ============================================================
// commands.rs - Command implementations
// ============================================================
//
// Commands that read or mutate daemon state go through RPC.
// The staging pattern (pending_*) stays local — only commit
// sends the final object to the daemon via PutEndpoint/Key/Feed.
// Server connection settings are CLI-local (not managed by daemon).

use log::info;
use serde_json::json;

use sftpflow_proto::{ProtoError, Request, Response}; // lib.rs (sftpflow-proto)

use crate::cli::{Mode, ShellState};
use crate::feed::{Endpoint, Feed, FeedPath, FtpsMode, KeyType, NextStep, NextStepAction, PgpKey, ProcessStep, Protocol, TriggerCondition}; // feed.rs
use crate::output::Output; // output.rs
use crate::rpc::RpcError; // rpc.rs

// ============================================================
// RPC helper
// ============================================================

/// Emit a standard "not connected" error and mark the shell's exit
/// code. Returns true if an RPC connection is available, false if
/// not. Callers should return early on false.
fn has_rpc(state: &mut ShellState) -> bool {
    if state.rpc.is_some() {
        true
    } else {
        state.out.error_full(
            "NOT_CONNECTED",
            "Not connected to daemon.",
            Some("run 'connection list' to see saved connections, then 'connect <name>'; \
                  or 'config' to (re)configure the active server"),
            Some("CLI config: ~/.sftpflow/config.yaml"),
        );
        state.exit_code = 1;
        false
    }
}

// ============================================================
// RPC error rendering
// ============================================================
//
// All command handlers funnel RpcError reporting through these two
// helpers so the human/JSON branching stays consistent. Both also
// stamp `state.exit_code = 1` so non-interactive invocations exit
// non-zero on RPC failure.

/// Render a daemon-side `ProtoError` and bump the exit code.
/// Plumbs `hint` and `details` through `error_full` so the operator
/// sees the daemon's next-action suggestion and where-to-look line
/// (when present) without losing them at the wire boundary.
fn report_proto_err(out: Output, err: &ProtoError, exit_code: &mut i32) {
    out.error_full(
        format!("E{}", err.code),
        &err.message,
        err.hint.as_deref(),
        err.details.as_deref(),
    );
    *exit_code = 1;
}

/// Render any RpcError that's not a ProtoError (I/O, EOF, missing
/// config). These don't carry a structured code, so we tag them
/// with a CLI-side label and add a per-variant hint when one helps.
fn report_rpc_err(out: Output, err: &RpcError, exit_code: &mut i32) {
    let (code, hint, details): (&str, Option<&str>, Option<&str>) = match err {
        RpcError::Io(_) => (
            "RPC_IO",
            Some("check the daemon's network reachability and that sftpflowd is running"),
            Some("daemon log: $state_dir/log/sftpflowd.log on the server"),
        ),
        RpcError::UnexpectedEof => (
            "RPC_EOF",
            Some("the daemon closed the connection mid-reply; retry the command, then check the server log"),
            Some("daemon log: $state_dir/log/sftpflowd.log on the server"),
        ),
        RpcError::ConnectionNotConfigured(_) => (
            "NOT_CONFIGURED",
            Some("set host/username with 'config' (or 'connection add <name> user@host')"),
            Some("CLI config: ~/.sftpflow/config.yaml"),
        ),
        RpcError::Proto(_) => ("RPC_PROTO", None, None), // shouldn't be reached
    };
    out.error_full(code, format!("{}", err), hint, details);
    *exit_code = 1;
}

/// Convenience wrapper that funnels any RpcError variant to the
/// right reporter. Same shape as the inline `match` blocks the
/// original code repeated 50+ times.
fn report_err(out: Output, err: &RpcError, exit_code: &mut i32) {
    match err {
        RpcError::Proto(p)  => report_proto_err(out, p, exit_code),
        other               => report_rpc_err(out, other, exit_code),
    }
}

// ============================================================
// --dry-run argument handling
// ============================================================
//
// Destructive commands (delete, rename, secret delete, cluster
// remove) accept `--dry-run` (or `-n`) anywhere in their argument
// list. `take_dry_run_flag` strips the flag and returns
// (dry_run, remaining_args), so the per-type handler logic stays
// unchanged whether the operator typed it or not.
//
// We accept the flag in any position so command-line muscle memory
// (`delete feed nightly --dry-run` and `delete --dry-run feed
// nightly` both work). Anything that matches `--dry-run` or `-n`
// is removed; any other token survives unchanged.

/// Strip `--dry-run` / `-n` from `args`, returning the flag value
/// and the remaining tokens in their original order.
fn take_dry_run_flag<'a>(args: &[&'a str]) -> (bool, Vec<&'a str>) {
    let mut dry_run   = false;
    let mut remaining = Vec::with_capacity(args.len());
    for arg in args {
        if *arg == "--dry-run" || *arg == "-n" {
            dry_run = true;
        } else {
            remaining.push(*arg);
        }
    }
    (dry_run, remaining)
}

/// Render a daemon-side `DryRunReport`. In human mode formats as:
///
///   DRY RUN: <summary>
///   Effects:
///     - <effect>
///   Warnings:
///     - <warning>
///   (no changes were made)
///
/// In JSON mode emits the report directly with a `dry_run: true`
/// envelope marker so consumers can distinguish a preview from a
/// real mutation result.
fn render_dry_run_report(out: Output, report: &sftpflow_proto::DryRunReport) {
    out.result(
        || {
            println!("DRY RUN: {}", report.summary);
            println!("Effects:");
            if report.effects.is_empty() {
                println!("  (none)");
            } else {
                for effect in &report.effects {
                    println!("  - {}", effect);
                }
            }
            println!("Warnings:");
            if report.warnings.is_empty() {
                println!("  (none)");
            } else {
                for warning in &report.warnings {
                    println!("  ! {}", warning);
                }
            }
            println!("(no changes were made)");
        },
        || json!({
            "dry_run": true,
            "summary":  report.summary,
            "effects":  report.effects,
            "warnings": report.warnings,
        }),
    );
}

// ============================================================
// Exec mode commands
// ============================================================

/// Print help for exec mode.
pub fn help_exec(state: &mut ShellState) {
    let out = state.out;
    if out.is_json() {
        // Help is an interactive aid; in JSON mode we emit a sentinel
        // so consumers see one line of output rather than nothing.
        out.json(&json!({"help": "exec", "interactive": true}));
        return;
    }
    if !out.is_human() { return; }
    println!("Object types: endpoint, key, feed");
    println!();
    println!("  create <type> <name>         Create a new object");
    println!("  edit <type> <name>           Edit an existing object");
    println!("  delete [--dry-run] <type> <name>");
    println!("                               Delete an object (preview with --dry-run)");
    println!("  rename [--dry-run] <type> <old> <new>");
    println!("                               Rename (preview with --dry-run; updates references)");
    println!();
    println!("  show endpoints|keys|feeds    List all of a type");
    println!("  show secrets                 List sealed secret names");
    println!("  show <type> <name>           Show details for one object");
    println!("  show runs <feed> [limit]     Show run history for a feed");
    println!("  show audit [limit]           Show recent cluster mutations");
    println!("  show version                 Show SFTPflow version");
    println!();
    println!("  secret add <name>            Add/replace a sealed secret (prompts for value)");
    println!("  secret delete [--dry-run] <name>");
    println!("                               Remove a sealed secret (preview with --dry-run)");
    println!("  secret list                  List sealed secret names");
    println!();
    println!("  cluster status               Show cluster leader / members");
    println!("  cluster token [ttl]          Mint a join token (bootstrap node only)");
    println!("  cluster bootstrap [user@host[:port]]");
    println!("                               ssh-drive sftpflowd init on a fresh host");
    println!("                               (run with no args to enter the interactive wizard)");
    println!("  cluster join <user@host[:port]>");
    println!("                               Mint+ship a token, then ssh-drive sftpflowd join");
    println!("  cluster remove [--dry-run] <node-id>");
    println!("                               Remove another node (preview with --dry-run)");
    println!("  cluster leave                Step the connected node out of the cluster");
    println!("  cluster backup <server-path> Hot backup the connected node to <path>.tar.gz");
    println!();
    println!("  run feed <name>              Manually run a feed (outside of schedule)");
    println!("  sync schedules               Reconcile feed schedules with dkron");
    println!();
    println!("  connection add NAME user@host[:port] [dkron URL]");
    println!("                               Save a named server connection");
    println!("  connection list              List saved connections");
    println!("  connection delete NAME       Forget a saved connection");
    println!("  connect [NAME]               Connect (or reconnect); optionally switch");
    println!("                               to a named connection first");
    println!("  config                       Edit active server connection settings");
    println!();
    println!("  exit                         Exit SFTPflow");
    println!("  help / ?                     Show this help");
}

// ---- connect ----

/// Connect (or reconnect) to the daemon.
///
/// With no args: just retries the current `server` connection.
/// With a NAME arg: switches the active connection to the named
/// registry entry first, persists the change, then connects.
pub fn connect(args: &[&str], state: &mut ShellState) {
    if let Some(name) = args.first() {
        if !switch_active_connection(name, state) {
            return;
        }
    }
    state.try_connect(); // cli.rs - ShellState::try_connect()
    if state.rpc.is_none() {
        state.exit_code = 1;
    }
}

// ---- connection <subcommand> ----

/// Route 'connection add|list|delete ...'.
pub fn connection(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        let out = state.out;
        out.human(|| {
            println!("% Usage: connection <add|list|delete> [args]");
            println!("  connection add NAME user@host[:port] [dkron URL]");
            println!("  connection list");
            println!("  connection delete NAME");
        });
        out.json(&json!({"error": {"code": "USAGE", "message": "connection requires a subcommand"}}));
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "add"    => connection_add(&args[1..], state),
        "list"   => connection_list(state),
        "delete" => connection_delete(&args[1..], state),
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown connection subcommand '{}'. Use add, list, or delete.", other),
            );
            state.exit_code = 2;
        }
    }
}

/// Validate that a connection NAME contains only safe characters.
/// Reuses the same allowlist policy as endpoint/feed names: ASCII
/// alphanumerics, dash, underscore, dot. Reject empty / whitespace
/// / shell-metacharacter strings up front so the registry stays
/// trivially safe to display, persist, and key on.
fn validate_connection_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("connection name cannot be empty".into());
    }
    for c in name.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
        if !ok {
            return Err(format!(
                "connection name '{}' contains invalid character '{}'; \
                 use letters, digits, '-', '_', '.'",
                name, c,
            ));
        }
    }
    Ok(())
}

/// Parse 'user@host[:port]'. Same shape as parse_ssh_target() down
/// in the cluster section, copied here to keep the two helpers from
/// growing coupled — connection-add doesn't actually invoke ssh.
fn parse_user_at_host(target: &str) -> Result<(String, String, Option<u16>), String> {
    let (user, host_port) = target.split_once('@')
        .ok_or_else(|| format!("expected user@host[:port], got '{}'", target))?;
    if user.is_empty() {
        return Err(format!("empty user in '{}'", target));
    }
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port = port_str.parse::<u16>()
            .map_err(|_| format!("'{}' is not a valid port number", port_str))?;
        if host.is_empty() {
            return Err(format!("empty host in '{}'", target));
        }
        Ok((user.to_string(), host.to_string(), Some(port)))
    } else {
        if host_port.is_empty() {
            return Err(format!("empty host in '{}'", target));
        }
        Ok((user.to_string(), host_port.to_string(), None))
    }
}

/// `connection add NAME user@host[:port] [dkron URL]`
///
/// Stores a named server connection in the CLI registry. If no
/// active connection is currently set (i.e. this is the first
/// entry the operator has added), the new entry also becomes the
/// active one and gets copied into `state.config.server`.
fn connection_add(args: &[&str], state: &mut ShellState) {
    let out = state.out;
    if args.len() < 2 {
        out.error_coded("USAGE", "Usage: connection add NAME user@host[:port] [dkron URL]");
        state.exit_code = 2;
        return;
    }

    let name = args[0];
    if let Err(e) = validate_connection_name(name) {
        out.error_coded("VALIDATION", e);
        state.exit_code = 2;
        return;
    }

    let (user, host, port) = match parse_user_at_host(args[1]) {
        Ok(t) => t,
        Err(msg) => {
            out.error_coded("PARSE", msg);
            state.exit_code = 2;
            return;
        }
    };

    // Optional `dkron URL` trailing pair. Strict pairing keeps the
    // grammar simple — bare URLs without the keyword get rejected.
    let mut dkron_url: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i] {
            "dkron" => {
                if i + 1 >= args.len() {
                    out.error_coded("USAGE", "'dkron' requires a URL argument");
                    state.exit_code = 2;
                    return;
                }
                dkron_url = Some(args[i + 1].to_string());
                i += 2;
            }
            other => {
                out.error_coded(
                    "USAGE",
                    format!("Unexpected argument '{}'. Expected 'dkron URL'.", other),
                );
                state.exit_code = 2;
                return;
            }
        }
    }

    if state.config.connections.contains_key(name) {
        out.error_coded(
            "ALREADY_EXISTS",
            format!("Connection '{}' already exists. Use 'connection delete {}' first.", name, name),
        );
        state.exit_code = 1;
        return;
    }

    let entry = sftpflow_core::ServerConnection {
        host:      Some(host.clone()),
        port,
        username:  Some(user.clone()),
        dkron_url,
    };

    info!("Added connection '{}' = {}@{}", name, user, host);
    state.config.connections.insert(name.to_string(), entry.clone());

    // First entry → also activate, so 'connect' Just Works without
    // a separate 'connect NAME' step.
    let activated = if state.config.active_connection.is_none() {
        state.config.active_connection = Some(name.to_string());
        state.config.server = entry;
        true
    } else {
        false
    };

    if let Err(e) = state.config.save() {
        out.error_coded("CONFIG_SAVE", format!("Error saving config: {}", e));
        state.exit_code = 1;
        return;
    }

    out.ok_with(
        || {
            println!("Added connection '{}': {}@{}{}",
                name, user, host,
                port.map_or(String::new(), |p| format!(":{}", p)));
            if activated {
                println!("This is the first connection — set as active.");
                println!("Run 'connect' to dial the daemon.");
            }
        },
        &json!({
            "name":      name,
            "user":      user,
            "host":      host,
            "port":      port,
            "activated": activated,
        }),
    );
}

/// `connection list` — show all registered connections, marking
/// the active one with a leading '*'.
fn connection_list(state: &mut ShellState) {
    let out = state.out;
    let active = state.config.active_connection.as_deref();

    if out.is_json() {
        let entries: Vec<_> = state.config.connections.iter().map(|(name, conn)| {
            json!({
                "name":      name,
                "active":    active == Some(name.as_str()),
                "host":      conn.host,
                "port":      conn.port,
                "username":  conn.username,
                "dkron_url": conn.dkron_url,
            })
        }).collect();
        out.json(&entries);
        return;
    }

    if state.config.connections.is_empty() {
        println!("No connections configured.");
        println!("Use 'connection add NAME user@host[:port]' to add one.");
        return;
    }

    println!("Configured connections:");
    println!("    {:<16} {:<32} {}", "NAME", "TARGET", "DKRON");
    println!("    {:-<16} {:-<32} {:-<32}", "", "", "");
    for (name, conn) in &state.config.connections {
        let marker = if active == Some(name.as_str()) { "*" } else { " " };
        let host = conn.host.as_deref().unwrap_or("(no host)");
        let user = conn.username.as_deref().unwrap_or("(no user)");
        let port = conn.port.map_or(String::new(), |p| format!(":{}", p));
        let target = format!("{}@{}{}", user, host, port);
        let dkron = conn.dkron_url.as_deref().unwrap_or("-");
        println!("  {} {:<16} {:<32} {}", marker, name, target, dkron);
    }
}

/// `connection delete NAME` — remove a registry entry. Clears
/// `active_connection` if it was the active entry.
fn connection_delete(args: &[&str], state: &mut ShellState) {
    let out = state.out;
    if args.is_empty() {
        out.error_coded("USAGE", "Usage: connection delete NAME");
        state.exit_code = 2;
        return;
    }
    let name = args[0];

    if state.config.connections.remove(name).is_none() {
        out.error_coded("NOT_FOUND", format!("Connection '{}' does not exist.", name));
        state.exit_code = 1;
        return;
    }

    let was_active = state.config.active_connection.as_deref() == Some(name);
    if was_active {
        state.config.active_connection = None;
    }

    if let Err(e) = state.config.save() {
        out.error_coded("CONFIG_SAVE", format!("Error saving config: {}", e));
        state.exit_code = 1;
        return;
    }

    info!("Deleted connection '{}'", name);
    out.ok_with(
        || {
            println!("Connection '{}' deleted.", name);
            if was_active {
                println!("(Was the active connection — `server` settings retained but no entry is now active.)");
            }
        },
        &json!({"name": name, "deleted": true, "was_active": was_active}),
    );
}

/// Switch the active connection to a named registry entry.
/// Copies the entry into `state.config.server`, persists, and
/// returns whether the switch happened. Used by `connect NAME`.
fn switch_active_connection(name: &str, state: &mut ShellState) -> bool {
    let out = state.out;
    let entry = match state.config.connections.get(name) {
        Some(e) => e.clone(),
        None => {
            out.error_coded(
                "NOT_FOUND",
                format!("Connection '{}' does not exist. Use 'connection list' to see registered names.", name),
            );
            state.exit_code = 1;
            return false;
        }
    };

    info!("Switching active connection to '{}'", name);
    state.config.server = entry;
    state.config.active_connection = Some(name.to_string());

    if let Err(e) = state.config.save() {
        out.error_coded("CONFIG_SAVE", format!("Error saving config: {}", e));
        state.exit_code = 1;
        return false;
    }

    out.info(format!("Active connection: {}", name));
    true
}

// ---- create <type> <name> ----

/// Route 'create endpoint|key|feed <name>'.
pub fn create(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        state.out.error_coded("USAGE", "Usage: create <endpoint|key|feed> <name>");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "endpoint" => create_endpoint(args[1], state),
        "key"      => create_key(args[1], state),
        "feed"     => create_feed(args[1], state),
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", other),
            );
            state.exit_code = 2;
        }
    }
}

fn create_endpoint(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetEndpoint { name: name.to_string() }) {
            Ok(Response::Endpoint(Some(_))) => {
                out.error_coded(
                    "ALREADY_EXISTS",
                    format!("Endpoint '{}' already exists. Use 'edit endpoint {}' to modify it.", name, name),
                );
                state.exit_code = 1;
                return;
            }
            Ok(Response::Endpoint(None)) => {}
            Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
            _ => return,
        }
    }

    info!("Creating new endpoint '{}'", name);
    out.info(format!("Creating new endpoint '{}'.", name));
    state.pending_endpoint = Some(Endpoint::new());
    state.mode = Mode::EndpointEdit(name.to_string());
    out.info("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn create_key(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetKey { name: name.to_string() }) {
            Ok(Response::Key(Some(_))) => {
                out.error_coded(
                    "ALREADY_EXISTS",
                    format!("Key '{}' already exists. Use 'edit key {}' to modify it.", name, name),
                );
                state.exit_code = 1;
                return;
            }
            Ok(Response::Key(None)) => {}
            Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
            _ => return,
        }
    }

    info!("Creating new key '{}'", name);
    out.info(format!("Creating new key '{}'.", name));
    state.pending_key = Some(PgpKey::new());
    state.mode = Mode::KeyEdit(name.to_string());
    out.info("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn create_feed(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetFeed { name: name.to_string() }) {
            Ok(Response::Feed(Some(_))) => {
                out.error_coded(
                    "ALREADY_EXISTS",
                    format!("Feed '{}' already exists. Use 'edit feed {}' to modify it.", name, name),
                );
                state.exit_code = 1;
                return;
            }
            Ok(Response::Feed(None)) => {}
            Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
            _ => return,
        }
    }

    info!("Creating new feed '{}'", name);
    out.info(format!("Creating new feed '{}'.", name));
    state.pending_feed = Some(Feed::new());
    state.mode = Mode::FeedEdit(name.to_string());
    out.info("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

// ---- edit <type> <name> ----

/// Route 'edit endpoint|key|feed <name>'.
pub fn edit(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        state.out.error_coded("USAGE", "Usage: edit <endpoint|key|feed> <name>");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "endpoint" => edit_endpoint(args[1], state),
        "key"      => edit_key(args[1], state),
        "feed"     => edit_feed(args[1], state),
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", other),
            );
            state.exit_code = 2;
        }
    }
}

fn edit_endpoint(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    let endpoint = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetEndpoint { name: name.to_string() }) {
            Ok(Response::Endpoint(Some(ep))) => ep,
            Ok(Response::Endpoint(None)) => {
                out.error_coded(
                    "NOT_FOUND",
                    format!("Endpoint '{}' does not exist. Use 'create endpoint {}' to create it.", name, name),
                );
                state.exit_code = 1;
                return;
            }
            Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
            _ => return,
        }
    };

    info!("Editing endpoint '{}'", name);
    out.info(format!("Editing endpoint '{}'.", name));
    state.pending_endpoint = Some(endpoint);
    state.mode = Mode::EndpointEdit(name.to_string());
    out.info("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn edit_key(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    let key = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetKey { name: name.to_string() }) {
            Ok(Response::Key(Some(k))) => k,
            Ok(Response::Key(None)) => {
                out.error_coded(
                    "NOT_FOUND",
                    format!("Key '{}' does not exist. Use 'create key {}' to create it.", name, name),
                );
                state.exit_code = 1;
                return;
            }
            Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
            _ => return,
        }
    };

    info!("Editing key '{}'", name);
    out.info(format!("Editing key '{}'.", name));
    state.pending_key = Some(key);
    state.mode = Mode::KeyEdit(name.to_string());
    out.info("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn edit_feed(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    let feed = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetFeed { name: name.to_string() }) {
            Ok(Response::Feed(Some(f))) => f,
            Ok(Response::Feed(None)) => {
                out.error_coded(
                    "NOT_FOUND",
                    format!("Feed '{}' does not exist. Use 'create feed {}' to create it.", name, name),
                );
                state.exit_code = 1;
                return;
            }
            Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
            _ => return,
        }
    };

    info!("Editing feed '{}'", name);
    out.info(format!("Editing feed '{}'.", name));
    state.pending_feed = Some(feed);
    state.mode = Mode::FeedEdit(name.to_string());
    out.info("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

// ---- delete <type> <name> ----

/// Route 'delete [--dry-run] endpoint|key|feed <name>'.
pub fn delete(args: &[&str], state: &mut ShellState) {
    let (dry_run, args) = take_dry_run_flag(args);
    if args.len() < 2 {
        state.out.error_coded("USAGE", "Usage: delete [--dry-run] <endpoint|key|feed> <name>");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "endpoint" => delete_endpoint(args[1], dry_run, state),
        "key"      => delete_key(args[1], dry_run, state),
        "feed"     => delete_feed(args[1], dry_run, state),
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", other),
            );
            state.exit_code = 2;
        }
    }
}

fn delete_endpoint(name: &str, dry_run: bool, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();
    let req = Request::DeleteEndpoint { name: name.to_string() };

    if dry_run {
        match rpc.call_dry_run(req) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    match rpc.call(req) {
        Ok(Response::Ok) => {
            info!("Deleted endpoint '{}'", name);
            out.ok(format!("Endpoint '{}' deleted.", name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

fn delete_key(name: &str, dry_run: bool, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();
    let req = Request::DeleteKey { name: name.to_string() };

    if dry_run {
        match rpc.call_dry_run(req) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    match rpc.call(req) {
        Ok(Response::Ok) => {
            info!("Deleted key '{}'", name);
            out.ok(format!("Key '{}' deleted.", name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

fn delete_feed(name: &str, dry_run: bool, state: &mut ShellState) {
    // Dkron cleanup is handled daemon-side after DeleteFeed.
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();
    let req = Request::DeleteFeed { name: name.to_string() };

    if dry_run {
        match rpc.call_dry_run(req) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    match rpc.call(req) {
        Ok(Response::Ok) => {
            info!("Deleted feed '{}'", name);
            out.ok(format!("Feed '{}' deleted.", name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

// ---- rename <type> <old> <new> ----

/// Route 'rename [--dry-run] endpoint|key|feed <old> <new>'.
pub fn rename(args: &[&str], state: &mut ShellState) {
    let (dry_run, args) = take_dry_run_flag(args);
    if args.len() < 3 {
        state.out.error_coded("USAGE", "Usage: rename [--dry-run] <endpoint|key|feed> <oldname> <newname>");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "endpoint" => rename_endpoint(args[1], args[2], dry_run, state),
        "key"      => rename_key(args[1], args[2], dry_run, state),
        "feed"     => rename_feed(args[1], args[2], dry_run, state),
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", other),
            );
            state.exit_code = 2;
        }
    }
}

fn rename_endpoint(old_name: &str, new_name: &str, dry_run: bool, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();
    let req = Request::RenameEndpoint { from: old_name.to_string(), to: new_name.to_string() };

    if dry_run {
        match rpc.call_dry_run(req) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    match rpc.call(req) {
        Ok(Response::Ok) => {
            info!("Renamed endpoint '{}' → '{}'", old_name, new_name);
            out.ok(format!("Endpoint '{}' renamed to '{}'.", old_name, new_name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

fn rename_key(old_name: &str, new_name: &str, dry_run: bool, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();
    let req = Request::RenameKey { from: old_name.to_string(), to: new_name.to_string() };

    if dry_run {
        match rpc.call_dry_run(req) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    match rpc.call(req) {
        Ok(Response::Ok) => {
            info!("Renamed key '{}' → '{}'", old_name, new_name);
            out.ok(format!("Key '{}' renamed to '{}'.", old_name, new_name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

fn rename_feed(old_name: &str, new_name: &str, dry_run: bool, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();
    let req = Request::RenameFeed { from: old_name.to_string(), to: new_name.to_string() };

    if dry_run {
        match rpc.call_dry_run(req) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    match rpc.call(req) {
        Ok(Response::Ok) => {
            info!("Renamed feed '{}' → '{}'", old_name, new_name);
            out.ok(format!("Feed '{}' renamed to '{}'.", old_name, new_name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Print version info.
pub fn version(state: &mut ShellState) {
    let out = state.out;
    out.result(
        || println!("SFTPflow v{}", env!("CARGO_PKG_VERSION")),
        || json!({"version": env!("CARGO_PKG_VERSION")}),
    );
}

/// Exit the shell entirely.
pub fn exit_shell(state: &mut ShellState) {
    state.out.info("Goodbye.");
    state.running = false;
}

// ---- run feed <name> ----

/// Route 'run feed <name>'.
pub fn run(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        state.out.error_coded("USAGE", "Usage: run feed <name>");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "feed" => run_feed(args[1], state),
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown run target '{}'. Usage: run feed <name>", other),
            );
            state.exit_code = 2;
        }
    }
}

fn run_feed(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::RunFeedNow { name: name.to_string() }) {
        Ok(Response::RunResult(result)) => {
            info!("Run result for '{}': {:?}", name, result.status);
            // RunStatus::Failed escalates to a non-zero exit code for
            // non-interactive (cron / Ansible) callers. Success and
            // Noaction stay at 0 — Noaction means "feed ran cleanly,
            // there was just nothing to transfer".
            if matches!(result.status, sftpflow_proto::RunStatus::Failed) {
                state.exit_code = 1;
            }
            if out.is_json() {
                out.json(&result);
                return;
            }
            println!("Feed '{}': {:?}", name, result.status);
            if let Some(msg) = result.message {
                println!("  {}", msg);
            }
            if result.files_transferred > 0 {
                println!("  {} file(s) transferred.", result.files_transferred);
            }
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

// ============================================================
// Scheduler sync
// ============================================================

/// Handle `sync <target>` in exec mode.
pub fn sync(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: sync schedules");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "schedules" => sync_schedules(state),
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown sync target '{}'. Usage: sync schedules", other),
            );
            state.exit_code = 2;
        }
    }
}

/// Send SyncSchedules RPC and print the report.
fn sync_schedules(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::SyncSchedules) {
        Ok(Response::SyncReport(report)) => {
            info!(
                "sync schedules: created={}, updated={}, deleted={}, errors={}",
                report.created, report.updated, report.deleted, report.errors.len()
            );
            // Any per-feed errors bump the exit code so cron/Ansible
            // callers don't silently skip past partial-failure runs.
            if !report.errors.is_empty() {
                state.exit_code = 1;
            }
            if out.is_json() {
                out.json(&report);
                return;
            }
            println!("Schedule sync complete:");
            println!("  Created: {}", report.created);
            println!("  Updated: {}", report.updated);
            println!("  Deleted: {}", report.deleted);
            if !report.errors.is_empty() {
                println!("  Errors:");
                for err in &report.errors {
                    println!("    - {}", err);
                }
            }
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

// ============================================================
// Config-edit mode commands (server connection)
// ============================================================
//
// Server connection settings are CLI-local (not daemon-managed).
// They control how the CLI connects to the daemon.

/// Enter the server config edit mode.
pub fn enter_config(state: &mut ShellState) {
    state.pending_server = Some(state.config.server.clone());
    state.mode = Mode::ConfigEdit;
    state.out.info("Editing server connection settings. Type 'help' for options.");
}

/// Print help for config-edit mode.
pub fn help_config_edit(state: &mut ShellState) {
    let out = state.out;
    if out.is_json() { out.json(&json!({"help": "config-edit", "interactive": true})); return; }
    if !out.is_human() { return; }
    println!("Server connection configuration:");
    println!("  host <address>           Set the server hostname or IP");
    println!("  port <number>            Set the SSH port (default: 22)");
    println!("  username <user>          Set the SSH username");
    println!("  dkron <url>              Set the dkron scheduler API URL");
    println!("  no <property>            Clear a property (host, port, username, dkron)");
    println!("  show                     Show pending configuration");
    println!("  commit                   Save changes to config file");
    println!("  abort                    Discard changes and return to exec mode");
    println!("  exit / end               Same as abort (warns if uncommitted changes)");
    println!("  help / ?                 Show this help");
}

/// Set the server host.
pub fn set_server_host(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: host <address>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    if let Some(ref mut server) = state.pending_server {
        info!("Set server host = {}", args[0]);
        server.host = Some(args[0].to_string());
        out.info(format!("  host → {}", args[0]));
    }
}

/// Set the server port.
pub fn set_server_port(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: port <number>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    match args[0].parse::<u16>() {
        Ok(p) => {
            if let Some(ref mut server) = state.pending_server {
                info!("Set server port = {}", p);
                server.port = Some(p);
                out.info(format!("  port → {}", p));
            }
        }
        Err(_) => {
            out.error_coded("PARSE", format!("Invalid port number: '{}'", args[0]));
            state.exit_code = 2;
        }
    }
}

/// Set the server username.
pub fn set_server_username(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: username <user>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    if let Some(ref mut server) = state.pending_server {
        info!("Set server username = {}", args[0]);
        server.username = Some(args[0].to_string());
        out.info(format!("  username → {}", args[0]));
    }
}

/// Set the dkron scheduler API URL.
pub fn set_dkron_url(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: dkron <url>  (e.g. http://dkron-server:8080)");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    if let Some(ref mut server) = state.pending_server {
        info!("Set dkron_url = {}", args[0]);
        server.dkron_url = Some(args[0].to_string());
        out.info(format!("  dkron → {}", args[0]));
    }
}

/// Handle 'no <property>' in config-edit mode.
pub fn no_server_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: no <host|port|username|dkron>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    if let Some(ref mut server) = state.pending_server {
        match args[0] {
            "host"     => { server.host = None;      out.info("  host cleared."); }
            "port"     => { server.port = None;      out.info("  port cleared."); }
            "username" => { server.username = None;  out.info("  username cleared."); }
            "dkron"    => { server.dkron_url = None; out.info("  dkron cleared."); }
            other => {
                out.error_coded("USAGE", format!("Unknown property: '{}'", other));
                state.exit_code = 2;
            }
        }
    }
}

/// Show the pending server connection settings.
pub fn show_pending_server(state: &ShellState) {
    let out = state.out;
    match &state.pending_server {
        Some(server) => out.result(
            || server.display(),
            || json!({
                "host":      server.host,
                "port":      server.port,
                "username":  server.username,
                "dkron_url": server.dkron_url,
            }),
        ),
        None => out.error("No pending configuration."),
    }
}

/// Commit the pending server connection to disk.
///
/// If a named connection is active, the same edits are mirrored
/// into `connections[active]` so the registry entry stays in sync
/// with edits made via `config` mode.
pub fn commit_server(state: &mut ShellState) {
    let out = state.out;
    if let Some(server) = state.pending_server.take() {
        state.config.server = server.clone();
        if let Some(name) = state.config.active_connection.clone() {
            state.config.connections.insert(name, server);
        }
        match state.config.save() {
            Ok(()) => {
                info!("Committed server connection settings");
                out.ok("Server connection settings committed.");
            }
            Err(e) => {
                out.error_coded("CONFIG_SAVE", format!("Error saving config: {}", e));
                state.exit_code = 1;
                return;
            }
        }
        state.mode = Mode::Exec;
    }
}

/// Abort server config editing, discard pending changes.
pub fn abort_server(state: &mut ShellState) {
    info!("Aborted server config edit, discarding changes");
    state.out.info("Changes discarded.");
    state.pending_server = None;
    state.mode = Mode::Exec;
}

/// Exit config-edit mode (warns if uncommitted changes).
pub fn exit_config_edit(state: &mut ShellState) {
    if state.pending_server.is_some() {
        state.out.error("You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
        state.exit_code = 1;
        return;
    }
    state.mode = Mode::Exec;
}

// ============================================================
// Endpoint-edit mode commands
// ============================================================

/// Print help for endpoint-edit mode.
pub fn help_endpoint_edit(state: &mut ShellState) {
    let out = state.out;
    if out.is_json() { out.json(&json!({"help": "endpoint-edit", "interactive": true})); return; }
    if !out.is_human() { return; }
    println!("Endpoint configuration commands:");
    println!("  protocol <proto>         Set protocol: sftp (default), ftp, ftps, http, https");
    println!("  host <address>           Set the hostname or IP address");
    println!("  port <number>            Set the port");
    println!("  username <user>          Set the username");
    println!("  password <pass>          Set an inline password (plaintext in YAML)");
    println!("  password_ref <name>      Set a sealed-store secret name for the password");
    println!("  ssh_key <path>           Set an inline SSH private key (plaintext in YAML)");
    println!("  ssh_key_ref <name>       Set a sealed-store secret name for the SSH key");
    println!("  ftps_mode <mode>         FTPS only: explicit (default) or implicit");
    println!("  passive <yes|no>         FTP/FTPS: PASV (default) or active mode");
    println!("  verify_tls <yes|no>      FTPS only: validate server cert (default yes)");
    println!("  no <property>            Clear a property");
    println!("  show                     Show pending configuration");
    println!("  commit                   Save changes to config file");
    println!("  abort                    Discard changes and return to exec mode");
    println!("  exit / end               Same as abort (warns if uncommitted changes)");
    println!("  help / ?                 Show this help");
}

/// Set the protocol on the pending endpoint.
pub fn set_protocol(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: protocol <sftp|ftp|http|https>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let proto = match args[0].to_lowercase().as_str() {
        "sftp"  => Protocol::Sftp,
        "ftp"   => Protocol::Ftp,
        "ftps"  => Protocol::Ftps,
        "http"  => Protocol::Http,
        "https" => Protocol::Https,
        _ => {
            out.error_coded(
                "USAGE",
                format!("Unknown protocol '{}'. Available: sftp, ftp, ftps, http, https", args[0]),
            );
            state.exit_code = 2;
            return;
        }
    };

    if let Some(ref mut ep) = state.pending_endpoint {
        info!("Set protocol = {}", proto);
        ep.protocol = proto.clone();
        out.info(format!("  protocol → {}", proto));
    }
}

/// Set the host on the pending endpoint.
pub fn set_host(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: host <address>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let value = args[0].to_string();
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.host = Some(value.clone());
        info!("Set host to '{}'", value);
        out.info(format!("  host → {}", value));
    }
}

/// Set the port on the pending endpoint.
pub fn set_port(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: port <number>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let value: u16 = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            out.error_coded("PARSE", format!("Invalid port number: '{}'", args[0]));
            state.exit_code = 2;
            return;
        }
    };

    if let Some(ref mut ep) = state.pending_endpoint {
        ep.port = Some(value);
        info!("Set port to {}", value);
        out.info(format!("  port → {}", value));
    }
}

/// Set the username on the pending endpoint.
pub fn set_username(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: username <user>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let value = args[0].to_string();
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.username = Some(value.clone());
        info!("Set username to '{}'", value);
        out.info(format!("  username → {}", value));
    }
}

/// Set the password on the pending endpoint.
pub fn set_password(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: password <pass>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let value = args.join(" ");
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.password = Some(value);
        info!("Set password");
        out.info("  password → ********");
    }
}

/// Set the SSH key path on the pending endpoint.
pub fn set_ssh_key(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: ssh_key <path>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let value = args.join(" ");
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.ssh_key = Some(value.clone());
        info!("Set ssh_key to '{}'", value);
        out.info(format!("  ssh_key → {}", value));
    }
}

// ---- FTP/FTPS-specific setters ----

/// Set FTPS negotiation mode (explicit | implicit). Only meaningful
/// when the endpoint protocol is `ftps` — but we don't enforce that
/// here; the field is harmless on other protocols.
pub fn set_ftps_mode(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: ftps_mode <explicit|implicit>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let mode = match args[0].to_lowercase().as_str() {
        "explicit" => FtpsMode::Explicit,
        "implicit" => FtpsMode::Implicit,
        _ => {
            out.error_coded(
                "USAGE",
                format!("Unknown ftps_mode '{}'. Available: explicit, implicit", args[0]),
            );
            state.exit_code = 2;
            return;
        }
    };
    if let Some(ref mut ep) = state.pending_endpoint {
        info!("Set ftps_mode = {}", mode);
        out.info(format!("  ftps_mode → {}", mode));
        ep.ftps_mode = Some(mode);
    }
}

/// Set passive (true) or active (false) FTP mode.
pub fn set_passive(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: passive <yes|no>  (yes=PASV, no=active mode)");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let value = match args[0].to_lowercase().as_str() {
        "yes" | "true"  | "on"  => true,
        "no"  | "false" | "off" => false,
        _ => {
            out.error_coded("PARSE", format!("Expected yes/no, got '{}'", args[0]));
            state.exit_code = 2;
            return;
        }
    };
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.passive = Some(value);
        info!("Set passive = {}", value);
        out.info(format!("  passive → {} ({} mode)", value, if value { "passive" } else { "active" }));
    }
}

/// Set whether FTPS server certificates are validated.
pub fn set_verify_tls(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: verify_tls <yes|no>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;
    let value = match args[0].to_lowercase().as_str() {
        "yes" | "true"  | "on"  => true,
        "no"  | "false" | "off" => false,
        _ => {
            out.error_coded("PARSE", format!("Expected yes/no, got '{}'", args[0]));
            state.exit_code = 2;
            return;
        }
    };
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.verify_tls = Some(value);
        info!("Set verify_tls = {}", value);
        if !value {
            out.info("  verify_tls → no  (WARNING: server cert will not be validated)");
        } else {
            out.info("  verify_tls → yes");
        }
    }
}

/// Handle 'no <property>' in endpoint-edit mode.
pub fn no_endpoint_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded(
            "USAGE",
            "Usage: no <protocol|host|port|username|password|password_ref|ssh_key|ssh_key_ref|ftps_mode|passive|verify_tls>",
        );
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    if let Some(ref mut ep) = state.pending_endpoint {
        match args[0] {
            "protocol"     => { ep.protocol = Protocol::Sftp; out.info("  protocol reset to sftp (default)."); }
            "host"         => { ep.host = None;         out.info("  host cleared."); }
            "port"         => { ep.port = None;         out.info("  port cleared."); }
            "username"     => { ep.username = None;     out.info("  username cleared."); }
            "password"     => { ep.password = None;     out.info("  password cleared."); }
            "password_ref" => { ep.password_ref = None; out.info("  password_ref cleared."); }
            "ssh_key"      => { ep.ssh_key = None;      out.info("  ssh_key cleared."); }
            "ssh_key_ref"  => { ep.ssh_key_ref = None;  out.info("  ssh_key_ref cleared."); }
            "ftps_mode"    => { ep.ftps_mode = None;    out.info("  ftps_mode reset to default (explicit)."); }
            "passive"      => { ep.passive = None;      out.info("  passive reset to default (yes)."); }
            "verify_tls"   => { ep.verify_tls = None;   out.info("  verify_tls reset to default (yes)."); }
            other => {
                out.error_coded("USAGE", format!("Unknown property: '{}'", other));
                state.exit_code = 2;
            }
        }
    }
}

/// Show the pending endpoint configuration.
pub fn show_pending_endpoint(state: &ShellState) {
    let out = state.out;
    let ep_name = match &state.mode {
        Mode::EndpointEdit(name) => name.clone(),
        _ => return,
    };

    match &state.pending_endpoint {
        Some(ep) => out.result(
            || ep.display(&ep_name),
            || json!({"name": ep_name, "endpoint": ep}),
        ),
        None => out.error("No pending configuration."),
    }
}

/// Commit the pending endpoint to the daemon via RPC.
pub fn commit_endpoint(state: &mut ShellState) {
    let ep_name = match &state.mode {
        Mode::EndpointEdit(name) => name.clone(),
        _ => return,
    };

    let ep = match &state.pending_endpoint {
        Some(ep) => ep.clone(),
        None => return,
    };

    if !has_rpc(state) { return; }
    let out = state.out;
    let success = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::PutEndpoint { name: ep_name.clone(), endpoint: ep }) {
            Ok(Response::Ok) => true,
            Err(e) => { report_err(out, &e, &mut state.exit_code); false }
            _ => false,
        }
    };

    if success {
        state.pending_endpoint = None;
        info!("Committed endpoint '{}'", ep_name);
        out.ok(format!("Endpoint '{}' committed.", ep_name));
        state.mode = Mode::Exec;
    }
}

/// Abort endpoint editing, discard pending changes.
pub fn abort_endpoint(state: &mut ShellState) {
    info!("Aborted endpoint edit, discarding changes");
    state.out.info("Changes discarded.");
    state.pending_endpoint = None;
    state.mode = Mode::Exec;
}

/// Exit endpoint-edit mode (warns if uncommitted changes).
pub fn exit_endpoint_edit(state: &mut ShellState) {
    if state.pending_endpoint.is_some() {
        state.out.error("You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
        state.exit_code = 1;
        return;
    }
    state.mode = Mode::Exec;
}

// ============================================================
// Key-edit mode commands
// ============================================================

/// Print help for key-edit mode.
pub fn help_key_edit(state: &mut ShellState) {
    let out = state.out;
    if out.is_json() { out.json(&json!({"help": "key-edit", "interactive": true})); return; }
    if !out.is_human() { return; }
    println!("Key configuration commands:");
    println!("  type <public|private>    Set the key type");
    println!("  contents                 Enter multi-line paste mode (end with '.' on its own line)");
    println!("  load <filepath>          Load key contents inline from a file (plaintext in YAML)");
    println!("  contents_ref <name>      Set a sealed-store secret name for the key material");
    println!("  no <property>            Clear a property (type, contents, contents_ref)");
    println!("  show                     Show pending configuration");
    println!("  commit                   Save changes to config file");
    println!("  abort                    Discard changes and return to exec mode");
    println!("  exit / end               Same as abort (warns if uncommitted changes)");
    println!("  help / ?                 Show this help");
}

/// Set the key type (public or private).
pub fn set_key_type(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: type <public|private>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let key_type = match args[0].to_lowercase().as_str() {
        "public"  => KeyType::Public,
        "private" => KeyType::Private,
        _ => {
            out.error_coded("USAGE", format!("Invalid key type '{}'. Use 'public' or 'private'.", args[0]));
            state.exit_code = 2;
            return;
        }
    };

    if let Some(ref mut k) = state.pending_key {
        info!("Set key type to '{}'", key_type);
        out.info(format!("  type → {}", key_type));
        k.key_type = Some(key_type);
    }
}

/// Set the key contents via multi-line paste mode.
/// Reads from stdin until a line containing only '.' is entered.
pub fn set_key_contents(_args: &[&str], state: &mut ShellState) {
    if state.pending_key.is_none() {
        return;
    }
    let out = state.out;
    out.info("Paste key contents below. Enter a single '.' on its own line to finish:");

    let mut lines: Vec<String> = Vec::new();
    let stdin = std::io::stdin();
    loop {
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r');
                if trimmed == "." {
                    break;
                }
                lines.push(trimmed.to_string());
            }
            Err(e) => {
                out.error(format!("Read error: {}", e));
                state.exit_code = 1;
                return;
            }
        }
    }

    if lines.is_empty() {
        out.error("No content entered.");
        state.exit_code = 1;
        return;
    }

    let value = lines.join("\n");
    let line_count = lines.len();

    if let Some(ref mut k) = state.pending_key {
        k.contents = Some(value);
        info!("Set key contents ({} lines)", line_count);
        out.info(format!("  contents set ({} lines)", line_count));
    }
}

/// Load key contents from a file on disk.
pub fn load_key_file(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: load <filepath>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let filepath = args.join(" ");
    let contents = match std::fs::read_to_string(&filepath) {
        Ok(c) => c,
        Err(e) => {
            out.error_coded("FILE_READ", format!("Could not read file '{}': {}", filepath, e));
            state.exit_code = 1;
            return;
        }
    };

    if let Some(ref mut k) = state.pending_key {
        let line_count = contents.lines().count();
        k.contents = Some(contents);
        info!("Loaded key contents from '{}' ({} lines)", filepath, line_count);
        out.info(format!("  contents loaded from '{}' ({} lines)", filepath, line_count));
    }
}

/// Handle 'no <property>' in key-edit mode.
pub fn no_key_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: no <type|contents|contents_ref>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    if let Some(ref mut k) = state.pending_key {
        match args[0] {
            "type"         => { k.key_type = None;     out.info("  type cleared."); }
            "contents"     => { k.contents = None;     out.info("  contents cleared."); }
            "contents_ref" => { k.contents_ref = None; out.info("  contents_ref cleared."); }
            other => {
                out.error_coded("USAGE", format!("Unknown property: '{}'", other));
                state.exit_code = 2;
            }
        }
    }
}

/// Show the pending key configuration.
pub fn show_pending_key(state: &ShellState) {
    let out = state.out;
    let key_name = match &state.mode {
        Mode::KeyEdit(name) => name.clone(),
        _ => return,
    };

    match &state.pending_key {
        Some(k) => out.result(
            || k.display(&key_name),
            || json!({"name": key_name, "key": k}),
        ),
        None => out.error("No pending configuration."),
    }
}

/// Commit the pending key to the daemon via RPC.
pub fn commit_key(state: &mut ShellState) {
    let key_name = match &state.mode {
        Mode::KeyEdit(name) => name.clone(),
        _ => return,
    };

    let k = match &state.pending_key {
        Some(k) => k.clone(),
        None => return,
    };

    if !has_rpc(state) { return; }
    let out = state.out;
    let success = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::PutKey { name: key_name.clone(), key: k }) {
            Ok(Response::Ok) => true,
            Err(e) => { report_err(out, &e, &mut state.exit_code); false }
            _ => false,
        }
    };

    if success {
        state.pending_key = None;
        info!("Committed key '{}'", key_name);
        out.ok(format!("Key '{}' committed.", key_name));
        state.mode = Mode::Exec;
    }
}

/// Abort key editing, discard pending changes.
pub fn abort_key(state: &mut ShellState) {
    info!("Aborted key edit, discarding changes");
    state.out.info("Changes discarded.");
    state.pending_key = None;
    state.mode = Mode::Exec;
}

/// Exit key-edit mode (warns if uncommitted changes).
pub fn exit_key_edit(state: &mut ShellState) {
    if state.pending_key.is_some() {
        state.out.error("You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
        state.exit_code = 1;
        return;
    }
    state.mode = Mode::Exec;
}

// ============================================================
// Feed-edit mode commands
// ============================================================

/// Print help for feed-edit mode.
pub fn help_feed_edit(state: &mut ShellState) {
    let out = state.out;
    if out.is_json() { out.json(&json!({"help": "feed-edit", "interactive": true})); return; }
    if !out.is_human() { return; }
    println!("Feed configuration commands:");
    println!("  source <endpoint>:<path>         Add a source (e.g. myserver:/inbound)");
    println!("  process encrypt <keyname>        Add an encrypt step using a public key");
    println!("  process decrypt <keyname>        Add a decrypt step using a private key");
    println!("  destination <endpoint>:<path>    Add a destination (e.g. archive:/backup)");
    println!("  schedule <cron>                  Add a cron schedule (e.g. '* * * * *')");
    println!("  flag <name> <yes|no>             Set a flag");
    println!("  nextstep                         Enter nextstep submenu to add a new next step");
    println!("  move nextstep <from> <to>        Reorder next steps (1-based indices)");
    println!("  no source [<endpoint>:<path>]    Remove one or all sources");
    println!("  no process [<index>]             Remove a process step by index (1-based) or all");
    println!("  no destination [<ep>:<path>]     Remove one or all destinations");
    println!("  no nextstep [<index>]            Remove a next step by index (1-based) or all");
    println!("  no schedule [<cron>]             Remove one or all schedules");
    println!("  show                             Show pending configuration");
    println!("  commit                           Save changes to config file");
    println!("  abort                            Discard changes and return to exec mode");
    println!("  exit / end                       Same as abort (warns if uncommitted changes)");
    println!("  help / ?                         Show this help");
}

/// Parse an "endpoint:/path" string into a FeedPath.
fn parse_feed_path(input: &str) -> Option<FeedPath> {
    let colon_pos = input.find(':')?;
    let endpoint = input[..colon_pos].to_string();
    let path = input[colon_pos + 1..].to_string();

    if endpoint.is_empty() || path.is_empty() {
        return None;
    }

    Some(FeedPath { endpoint, path })
}

/// Check if two FeedPaths match (same endpoint + path).
fn feed_paths_match(a: &FeedPath, b: &FeedPath) -> bool {
    a.endpoint == b.endpoint && a.path == b.path
}

/// Add a source to the pending feed.
pub fn set_source(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded(
            "USAGE",
            "Usage: source <endpoint>:<path>  (e.g. source myserver:/inbound/data)",
        );
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let input = args.join("");
    let feed_path = match parse_feed_path(&input) {
        Some(fp) => fp,
        None => {
            out.error_coded("PARSE", "Invalid format. Use: source <endpoint>:<path>");
            state.exit_code = 2;
            return;
        }
    };

    // Warn if endpoint doesn't exist (best-effort RPC check)
    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Endpoint(None)) = rpc.call(Request::GetEndpoint { name: feed_path.endpoint.clone() }) {
            out.info(format!("  (warning: endpoint '{}' does not exist yet)", feed_path.endpoint));
        }
    }

    if let Some(ref mut feed) = state.pending_feed {
        if feed.sources.iter().any(|s| feed_paths_match(s, &feed_path)) {
            out.error_coded("ALREADY_EXISTS", format!("Source '{}' already exists in this feed.", feed_path));
            state.exit_code = 1;
            return;
        }
        info!("Added source '{}'", feed_path);
        out.info(format!("  source + {}", feed_path));
        feed.sources.push(feed_path);
    }
}

/// Add a destination to the pending feed.
pub fn set_destination(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded(
            "USAGE",
            "Usage: destination <endpoint>:<path>  (e.g. destination archive:/backup/landing)",
        );
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let input = args.join("");
    let feed_path = match parse_feed_path(&input) {
        Some(fp) => fp,
        None => {
            out.error_coded("PARSE", "Invalid format. Use: destination <endpoint>:<path>");
            state.exit_code = 2;
            return;
        }
    };

    // Warn if endpoint doesn't exist (best-effort RPC check)
    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Endpoint(None)) = rpc.call(Request::GetEndpoint { name: feed_path.endpoint.clone() }) {
            out.info(format!("  (warning: endpoint '{}' does not exist yet)", feed_path.endpoint));
        }
    }

    if let Some(ref mut feed) = state.pending_feed {
        if feed.destinations.iter().any(|d| feed_paths_match(d, &feed_path)) {
            out.error_coded("ALREADY_EXISTS", format!("Destination '{}' already exists in this feed.", feed_path));
            state.exit_code = 1;
            return;
        }
        info!("Added destination '{}'", feed_path);
        out.info(format!("  destination + {}", feed_path));
        feed.destinations.push(feed_path);
    }
}

/// Add a process step to the pending feed.
/// Usage: process encrypt <keyname>
///        process decrypt <keyname>
pub fn add_process(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        state.out.error_coded(
            "USAGE",
            "Usage: process <encrypt|decrypt> <keyname>  \
             (e.g. process decrypt vendor-private-key, process encrypt partner-public-key)",
        );
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let action = args[0];
    let key_name = args[1].to_string();

    // Validate key exists and is the right type (best-effort RPC check)
    if let Some(ref mut rpc) = state.rpc {
        match rpc.call(Request::GetKey { name: key_name.clone() }) {
            Ok(Response::Key(Some(k))) => {
                if action == "encrypt" && k.key_type.as_ref() != Some(&KeyType::Public) {
                    out.info(format!("  (warning: key '{}' is not marked as public — encrypt requires a public key)", key_name));
                }
                if action == "decrypt" && k.key_type.as_ref() != Some(&KeyType::Private) {
                    out.info(format!("  (warning: key '{}' is not marked as private — decrypt requires a private key)", key_name));
                }
            }
            Ok(Response::Key(None)) => {
                out.info(format!("  (warning: key '{}' does not exist yet)", key_name));
            }
            _ => {}
        }
    }

    let step = match action {
        "encrypt" => ProcessStep::Encrypt { key: key_name },
        // verify_with starts unset; operators add verifier keys via
        // a separate edit-mode command (added in a follow-up CLI
        // change). Configs that don't set it keep the legacy
        // no-signature-verification behavior.
        "decrypt" => ProcessStep::Decrypt { key: key_name, verify_with: None },
        other => {
            out.error_coded(
                "USAGE",
                format!("Unknown process action '{}'. Use 'encrypt' or 'decrypt'.", other),
            );
            state.exit_code = 2;
            return;
        }
    };

    if let Some(ref mut feed) = state.pending_feed {
        info!("Added process step: {}", step);
        out.info(format!("  process + {}", step));
        feed.process.push(step);
    }
}

/// Add a cron schedule to the pending feed.
pub fn set_schedule(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded(
            "USAGE",
            "Usage: schedule <cron expression>  \
             (format: min hour day month weekday — e.g. '* * * * *' or '0 */6 * * *')",
        );
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let cron_expr = args.join(" ");
    if let Some(ref mut feed) = state.pending_feed {
        if feed.schedules.contains(&cron_expr) {
            out.error_coded("ALREADY_EXISTS", format!("Schedule '{}' already exists in this feed.", cron_expr));
            state.exit_code = 1;
            return;
        }
        feed.schedules.push(cron_expr.clone());
        info!("Added schedule '{}'", cron_expr);
        out.info(format!("  schedule + {}", cron_expr));
    }
}

/// Parse a yes/no value from user input.
fn parse_yes_no(input: &str) -> Option<bool> {
    match input.to_lowercase().as_str() {
        "yes" | "true" | "on"  => Some(true),
        "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

/// Set a flag on the pending feed.
pub fn set_flag(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        state.out.error_coded(
            "USAGE",
            "Usage: flag <name> <yes|no>  (available: enabled, delete_source_after_transfer)",
        );
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let flag_name = args[0];
    let value = match parse_yes_no(args[1]) {
        Some(v) => v,
        None => {
            out.error_coded("PARSE", format!("Invalid value '{}'. Use 'yes' or 'no'.", args[1]));
            state.exit_code = 2;
            return;
        }
    };

    if let Some(ref mut feed) = state.pending_feed {
        match flag_name {
            "enabled" => {
                feed.flags.enabled = value;
                info!("Set flag enabled = {}", if value { "yes" } else { "no" });
                out.info(format!("  enabled → {}", if value { "yes" } else { "no" }));
            }
            "delete_source_after_transfer" => {
                feed.flags.delete_source_after_transfer = value;
                info!("Set flag delete_source_after_transfer = {}", if value { "yes" } else { "no" });
                out.info(format!("  delete_source_after_transfer → {}", if value { "yes" } else { "no" }));
            }
            other => {
                out.error_coded(
                    "USAGE",
                    format!(
                        "Unknown flag: '{}'. Available: enabled, delete_source_after_transfer",
                        other,
                    ),
                );
                state.exit_code = 2;
            }
        }
    }
}

/// Handle 'no <property> [value]' in feed-edit mode.
pub fn no_feed_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: no <source|process|destination|schedule> [value]");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    if let Some(ref mut feed) = state.pending_feed {
        let property = args[0];
        let value_args = &args[1..];

        match property {
            "source" => {
                if value_args.is_empty() {
                    let count = feed.sources.len();
                    feed.sources.clear();
                    out.info(format!("  All sources removed ({} cleared).", count));
                } else {
                    let input = value_args.join("");
                    if let Some(fp) = parse_feed_path(&input) {
                        if let Some(pos) = feed.sources.iter().position(|s| feed_paths_match(s, &fp)) {
                            feed.sources.remove(pos);
                            out.info(format!("  source - {}", fp));
                        } else {
                            out.error_coded("NOT_FOUND", format!("Source '{}' not found.", fp));
                            state.exit_code = 1;
                        }
                    } else {
                        out.error_coded("PARSE", "Invalid format. Use: no source <endpoint>:<path>");
                        state.exit_code = 2;
                    }
                }
            }
            "process" => {
                if value_args.is_empty() {
                    let count = feed.process.len();
                    feed.process.clear();
                    out.info(format!("  All process steps removed ({} cleared).", count));
                } else {
                    let index_str = value_args[0];
                    match index_str.parse::<usize>() {
                        Ok(idx) if idx >= 1 && idx <= feed.process.len() => {
                            let removed = feed.process.remove(idx - 1);
                            out.info(format!("  process - [{}] {}", idx, removed));
                        }
                        _ => {
                            out.error_coded(
                                "PARSE",
                                format!(
                                    "Invalid index '{}'. Use 1-{} or omit to clear all.",
                                    index_str, feed.process.len(),
                                ),
                            );
                            state.exit_code = 2;
                        }
                    }
                }
            }
            "destination" => {
                if value_args.is_empty() {
                    let count = feed.destinations.len();
                    feed.destinations.clear();
                    out.info(format!("  All destinations removed ({} cleared).", count));
                } else {
                    let input = value_args.join("");
                    if let Some(fp) = parse_feed_path(&input) {
                        if let Some(pos) = feed.destinations.iter().position(|d| feed_paths_match(d, &fp)) {
                            feed.destinations.remove(pos);
                            out.info(format!("  destination - {}", fp));
                        } else {
                            out.error_coded("NOT_FOUND", format!("Destination '{}' not found.", fp));
                            state.exit_code = 1;
                        }
                    } else {
                        out.error_coded("PARSE", "Invalid format. Use: no destination <endpoint>:<path>");
                        state.exit_code = 2;
                    }
                }
            }
            "nextstep" => {
                if value_args.is_empty() {
                    let count = feed.nextsteps.len();
                    feed.nextsteps.clear();
                    out.info(format!("  All next steps removed ({} cleared).", count));
                } else {
                    let index_str = value_args[0];
                    match index_str.parse::<usize>() {
                        Ok(idx) if idx >= 1 && idx <= feed.nextsteps.len() => {
                            let removed = feed.nextsteps.remove(idx - 1);
                            out.info(format!("  nextstep - [{}] {}", idx, removed.display_inline()));
                        }
                        _ => {
                            out.error_coded(
                                "PARSE",
                                format!(
                                    "Invalid index '{}'. Use 1-{} or omit to clear all.",
                                    index_str, feed.nextsteps.len(),
                                ),
                            );
                            state.exit_code = 2;
                        }
                    }
                }
            }
            "schedule" => {
                if value_args.is_empty() {
                    let count = feed.schedules.len();
                    feed.schedules.clear();
                    out.info(format!("  All schedules removed ({} cleared).", count));
                } else {
                    let expr = value_args.join(" ");
                    if let Some(pos) = feed.schedules.iter().position(|s| s == &expr) {
                        feed.schedules.remove(pos);
                        out.info(format!("  schedule - {}", expr));
                    } else {
                        out.error_coded("NOT_FOUND", format!("Schedule '{}' not found.", expr));
                        state.exit_code = 1;
                    }
                }
            }
            other => {
                out.error_coded("USAGE", format!("Unknown property: '{}'", other));
                state.exit_code = 2;
            }
        }
    }
}

/// Move a nextstep from one position to another (1-based indices).
pub fn move_nextstep(args: &[&str], state: &mut ShellState) {
    if args.len() < 3 || args[0] != "nextstep" {
        state.out.error_coded("USAGE", "Usage: move nextstep <from> <to>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    if let Some(ref mut feed) = state.pending_feed {
        let len = feed.nextsteps.len();
        if len < 2 {
            out.error("Need at least 2 next steps to reorder.");
            state.exit_code = 1;
            return;
        }

        let from = match args[1].parse::<usize>() {
            Ok(i) if i >= 1 && i <= len => i,
            _ => {
                out.error_coded("PARSE", format!("Invalid 'from' index '{}'. Use 1-{}.", args[1], len));
                state.exit_code = 2;
                return;
            }
        };

        let to = match args[2].parse::<usize>() {
            Ok(i) if i >= 1 && i <= len => i,
            _ => {
                out.error_coded("PARSE", format!("Invalid 'to' index '{}'. Use 1-{}.", args[2], len));
                state.exit_code = 2;
                return;
            }
        };

        if from == to {
            out.error("Indices are the same, nothing to move.");
            state.exit_code = 1;
            return;
        }

        let ns = feed.nextsteps.remove(from - 1);
        feed.nextsteps.insert(to - 1, ns);
        info!("Moved nextstep from position {} to {}", from, to);
        out.info(format!("  Moved nextstep [{}] → [{}].", from, to));
        for (i, ns) in feed.nextsteps.iter().enumerate() {
            out.info(format!("    [{}] {}", i + 1, ns.display_inline()));
        }
    }
}

/// Show the pending feed configuration.
pub fn show_pending_feed(state: &ShellState) {
    let out = state.out;
    let feed_name = match &state.mode {
        Mode::FeedEdit(name) => name.clone(),
        _ => return,
    };

    match &state.pending_feed {
        Some(feed) => out.result(
            || feed.display(&feed_name),
            || json!({"name": feed_name, "feed": feed}),
        ),
        None => out.error("No pending configuration."),
    }
}

/// Commit the pending feed to the daemon via RPC.
pub fn commit_feed(state: &mut ShellState) {
    let feed_name = match &state.mode {
        Mode::FeedEdit(name) => name.clone(),
        _ => return,
    };

    let feed = match &state.pending_feed {
        Some(f) => f.clone(),
        None => return,
    };

    if !has_rpc(state) { return; }
    let out = state.out;
    let success = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::PutFeed { name: feed_name.clone(), feed }) {
            Ok(Response::Ok) => true,
            Err(e) => { report_err(out, &e, &mut state.exit_code); false }
            _ => false,
        }
    };

    if success {
        state.pending_feed = None;
        info!("Committed feed '{}'", feed_name);
        out.ok(format!("Feed '{}' committed.", feed_name));
        // Dkron schedule sync is handled daemon-side after PutFeed.

        state.mode = Mode::Exec;
    }
}

/// Abort feed editing, discard pending changes.
pub fn abort_feed(state: &mut ShellState) {
    info!("Aborted feed edit, discarding changes");
    state.out.info("Changes discarded.");
    state.pending_feed = None;
    state.mode = Mode::Exec;
}

/// Exit feed-edit mode (warns if uncommitted changes).
pub fn exit_feed_edit(state: &mut ShellState) {
    if state.pending_feed.is_some() {
        state.out.error("You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
        state.exit_code = 1;
        return;
    }
    state.mode = Mode::Exec;
}

// ============================================================
// NextStep-edit submenu commands
// ============================================================

/// Enter the nextstep submenu from feed-edit mode.
pub fn enter_nextstep(state: &mut ShellState) {
    let feed_name = match &state.mode {
        Mode::FeedEdit(name) => name.clone(),
        _ => return,
    };

    state.pending_nextstep = Some(NextStep {
        action: NextStepAction::RunFeed { feed: String::new() },
        on: Vec::new(),
    });
    state.mode = Mode::NextStepEdit(feed_name);
    state.out.info("Configuring a new next step. Type 'help' for options, 'done' to add it.");
}

/// Print help for nextstep-edit mode.
pub fn help_nextstep_edit(state: &mut ShellState) {
    let out = state.out;
    if out.is_json() { out.json(&json!({"help": "nextstep-edit", "interactive": true})); return; }
    if !out.is_human() { return; }
    println!("Next step configuration:");
    println!("  type <feed|email|sleep>      Set action type");
    println!("  target <value>               Set target (varies by type, see below)");
    println!("  on <condition>               Add a trigger: success, noaction, failed");
    println!("  no on <condition>            Remove a trigger condition");
    println!("  show                         Show pending next step");
    println!("  done                         Add this next step and return to feed config");
    println!("  abort                        Discard and return to feed config");
    println!("  help / ?                     Show this help");
    println!();
    println!("  Target values by type:");
    println!("    feed:  target <feedname>");
    println!("    email: target <addr1, addr2, ...>");
    println!("    sleep: target <seconds>");
}

/// Set the nextstep action type.
pub fn set_nextstep_type(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: type <feed|email|sleep>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    match args[0] {
        "feed" => {
            if let Some(ref mut ns) = state.pending_nextstep {
                ns.action = NextStepAction::RunFeed { feed: String::new() };
                out.info("  type → feed");
            }
        }
        "email" => {
            if let Some(ref mut ns) = state.pending_nextstep {
                ns.action = NextStepAction::SendEmail { emails: Vec::new() };
                out.info("  type → email");
            }
        }
        "sleep" => {
            if let Some(ref mut ns) = state.pending_nextstep {
                ns.action = NextStepAction::Sleep { seconds: 0 };
                out.info("  type → sleep");
            }
        }
        other => {
            out.error_coded(
                "USAGE",
                format!("Unknown type '{}'. Available: feed, email, sleep", other),
            );
            state.exit_code = 2;
        }
    }
}

/// Set the nextstep target.
pub fn set_nextstep_target(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded(
            "USAGE",
            "Usage: target <name> (feed type) | <email1,email2,...> (email type) | <seconds> (sleep type)",
        );
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    // For RunFeed targets, check if the feed exists (best-effort RPC check)
    let is_run_feed = matches!(
        state.pending_nextstep.as_ref().map(|ns| &ns.action),
        Some(NextStepAction::RunFeed { .. })
    );
    if is_run_feed {
        let target = args[0].to_string();
        let editing_self = match &state.mode {
            Mode::NextStepEdit(name) => name == &target,
            _ => false,
        };
        if !editing_self {
            if let Some(ref mut rpc) = state.rpc {
                if let Ok(Response::Feed(None)) = rpc.call(Request::GetFeed { name: target.clone() }) {
                    out.info(format!("  (warning: feed '{}' does not exist yet)", target));
                }
            }
        }
    }

    if let Some(ref mut ns) = state.pending_nextstep {
        match &mut ns.action {
            NextStepAction::RunFeed { feed } => {
                let target = args[0].to_string();
                *feed = target.clone();
                out.info(format!("  target → {}", target));
            }
            NextStepAction::SendEmail { emails } => {
                let raw = args.join(" ");
                let parsed: Vec<String> = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if parsed.is_empty() {
                    out.error("No email addresses provided.");
                    state.exit_code = 2;
                    return;
                }
                *emails = parsed.clone();
                out.info(format!("  target → {}", parsed.join(", ")));
            }
            NextStepAction::Sleep { seconds } => {
                match args[0].parse::<u64>() {
                    Ok(secs) => {
                        *seconds = secs;
                        out.info(format!("  target → {}s", secs));
                    }
                    Err(_) => {
                        out.error_coded(
                            "PARSE",
                            format!("Invalid number '{}'. Provide seconds as a whole number.", args[0]),
                        );
                        state.exit_code = 2;
                    }
                }
            }
        }
    }
}

/// Parse a trigger condition string.
fn parse_trigger(input: &str) -> Option<TriggerCondition> {
    match input.to_lowercase().as_str() {
        "success"  => Some(TriggerCondition::Success),
        "noaction" => Some(TriggerCondition::Noaction),
        "failed"   => Some(TriggerCondition::Failed),
        _ => None,
    }
}

/// Add a trigger condition to the pending nextstep.
pub fn add_nextstep_condition(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: on <success|noaction|failed>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    let condition = match parse_trigger(args[0]) {
        Some(c) => c,
        None => {
            out.error_coded(
                "USAGE",
                format!("Unknown condition '{}'. Use: success, noaction, failed", args[0]),
            );
            state.exit_code = 2;
            return;
        }
    };

    if let Some(ref mut ns) = state.pending_nextstep {
        if ns.on.contains(&condition) {
            out.error_coded("ALREADY_EXISTS", format!("Condition '{}' already set.", condition));
            state.exit_code = 1;
            return;
        }
        ns.on.push(condition.clone());
        ns.on.sort();
        out.info(format!("  on + {}", condition));
    }
}

/// Handle 'no on <condition>' in nextstep-edit mode.
pub fn no_nextstep_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: no on <success|noaction|failed>");
        state.exit_code = 2;
        return;
    }
    let out = state.out;

    if args[0] != "on" {
        out.error_coded("USAGE", "Usage: no on <success|noaction|failed>");
        state.exit_code = 2;
        return;
    }

    if args.len() < 2 {
        if let Some(ref mut ns) = state.pending_nextstep {
            ns.on.clear();
            out.info("  All conditions cleared.");
        }
        return;
    }

    let condition = match parse_trigger(args[1]) {
        Some(c) => c,
        None => {
            out.error_coded(
                "USAGE",
                format!("Unknown condition '{}'. Use: success, noaction, failed", args[1]),
            );
            state.exit_code = 2;
            return;
        }
    };

    if let Some(ref mut ns) = state.pending_nextstep {
        if let Some(pos) = ns.on.iter().position(|c| c == &condition) {
            ns.on.remove(pos);
            out.info(format!("  on - {}", condition));
        } else {
            out.error_coded("NOT_FOUND", format!("Condition '{}' not set.", condition));
            state.exit_code = 1;
        }
    }
}

/// Show the pending nextstep configuration.
pub fn show_pending_nextstep(state: &ShellState) {
    let out = state.out;
    match &state.pending_nextstep {
        Some(ns) => out.result(
            || {
                println!("Next step (pending):");
                match &ns.action {
                    NextStepAction::RunFeed { feed } => {
                        println!("  type      feed");
                        println!("  target    {}", if feed.is_empty() { "(not set)" } else { feed.as_str() });
                    }
                    NextStepAction::SendEmail { emails } => {
                        println!("  type      email");
                        if emails.is_empty() {
                            println!("  target    (not set)");
                        } else {
                            println!("  target    {}", emails.join(", "));
                        }
                    }
                    NextStepAction::Sleep { seconds } => {
                        println!("  type      sleep");
                        if *seconds == 0 {
                            println!("  target    (not set)");
                        } else {
                            println!("  target    {}s", seconds);
                        }
                    }
                }
                if ns.on.is_empty() {
                    println!("  on        (none)");
                } else {
                    let conditions: Vec<String> = ns.on.iter().map(|c| c.to_string()).collect();
                    println!("  on        {}", conditions.join(", "));
                }
            },
            || json!({"nextstep": ns}),
        ),
        None => out.error("No pending next step."),
    }
}

/// Finish building the nextstep and add it to the pending feed.
pub fn done_nextstep(state: &mut ShellState) {
    let feed_name = match &state.mode {
        Mode::NextStepEdit(name) => name.clone(),
        _ => return,
    };
    let out = state.out;

    if let Some(ref ns) = state.pending_nextstep {
        match &ns.action {
            NextStepAction::RunFeed { feed } => {
                if feed.is_empty() {
                    out.error("Target feed not set. Use 'target <feedname>'.");
                    state.exit_code = 2;
                    return;
                }
            }
            NextStepAction::SendEmail { emails } => {
                if emails.is_empty() {
                    out.error("No email addresses set. Use 'target <email1,email2,...>'.");
                    state.exit_code = 2;
                    return;
                }
            }
            NextStepAction::Sleep { seconds } => {
                if *seconds == 0 {
                    out.error("Sleep duration not set. Use 'target <seconds>'.");
                    state.exit_code = 2;
                    return;
                }
            }
        }

        if ns.on.is_empty() {
            out.error("No trigger conditions set. Use 'on <success|noaction|failed>'.");
            state.exit_code = 2;
            return;
        }
    }

    if let Some(ns) = state.pending_nextstep.take() {
        info!("Added next step: {}", ns.display_inline());
        out.info(format!("  nextstep + {}", ns.display_inline()));
        if let Some(ref mut feed) = state.pending_feed {
            feed.nextsteps.push(ns);
        }
        state.mode = Mode::FeedEdit(feed_name);
    }
}

/// Abort nextstep editing and return to feed-edit mode.
pub fn abort_nextstep(state: &mut ShellState) {
    let feed_name = match &state.mode {
        Mode::NextStepEdit(name) => name.clone(),
        _ => return,
    };

    state.out.info("Next step discarded.");
    state.pending_nextstep = None;
    state.mode = Mode::FeedEdit(feed_name);
}

// ============================================================
// Shared / show commands (exec mode)
// ============================================================
//
// Show commands fetch data from the daemon via RPC.
// "show server" stays local (CLI connection settings).

/// Handle 'show' subcommands in exec mode.
pub fn show(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        let out = state.out;
        out.human(|| {
            println!("Usage: show <subcommand>");
            println!("  endpoints          List all endpoints");
            println!("  endpoint <name>    Show endpoint details");
            println!("  keys               List all keys");
            println!("  key <name>         Show key details");
            println!("  feeds              List all feeds");
            println!("  feed <name>        Show feed details");
            println!("  runs <feed> [N]    Show run history for a feed (default: 25)");
            println!("  audit [N]          Show recent cluster mutations (default: 50)");
            println!("  server             Show server connection settings");
            println!("  version            Show SFTPflow version");
        });
        out.json(&json!({"error": {"code": "USAGE", "message": "show requires a subcommand"}}));
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "version"   => version(state),
        "server"    => show_server(state),
        "secrets"   => show_secrets(state),
        "endpoints" => show_endpoints(state),
        "endpoint"  => {
            if args.len() < 2 {
                state.out.error_coded("USAGE", "Usage: show endpoint <name>");
                state.exit_code = 2;
                return;
            }
            show_endpoint_detail(args[1], state);
        }
        "keys"      => show_keys(state),
        "key"       => {
            if args.len() < 2 {
                state.out.error_coded("USAGE", "Usage: show key <name>");
                state.exit_code = 2;
                return;
            }
            show_key_detail(args[1], state);
        }
        "feeds"     => show_feeds(state),
        "feed"      => {
            if args.len() < 2 {
                state.out.error_coded("USAGE", "Usage: show feed <name>");
                state.exit_code = 2;
                return;
            }
            show_feed_detail(args[1], state);
        }
        "runs"      => {
            if args.len() < 2 {
                state.out.error_coded("USAGE", "Usage: show runs <feed> [limit]");
                state.exit_code = 2;
                return;
            }
            let limit = args.get(2).and_then(|s| s.parse::<u32>().ok());
            show_runs(args[1], limit, state);
        }
        "audit"     => {
            let limit = args.get(1).and_then(|s| s.parse::<u32>().ok());
            show_audit(limit, state);
        }
        other => {
            state.out.error_coded("USAGE", format!("Unknown show subcommand: '{}'", other));
            state.exit_code = 2;
        }
    }
}

/// `show server` — print the active server connection. Local config,
/// no RPC. JSON mode mirrors the same fields as the human display.
fn show_server(state: &mut ShellState) {
    let out = state.out;
    let s = &state.config.server;
    out.result(
        || s.display(),
        || json!({
            "host":      s.host,
            "port":      s.port,
            "username":  s.username,
            "dkron_url": s.dkron_url,
        }),
    );
}

/// List all configured endpoints (fetched from daemon).
fn show_endpoints(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    let names = match rpc.call(Request::ListEndpoints) {
        Ok(Response::Names(n)) => n,
        Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
        _ => return,
    };

    // Fetch every endpoint up-front so JSON mode emits a single
    // self-contained array. Errors fetching individual endpoints
    // are folded into a per-row error field rather than aborting
    // the whole listing.
    let mut entries: Vec<(String, Option<Endpoint>)> = Vec::with_capacity(names.len());
    for name in &names {
        let ep = match rpc.call(Request::GetEndpoint { name: name.clone() }) {
            Ok(Response::Endpoint(Some(ep))) => Some(ep),
            _ => None,
        };
        entries.push((name.clone(), ep));
    }

    if out.is_json() {
        let v: Vec<_> = entries.iter().map(|(n, ep)| match ep {
            Some(ep) => json!({"name": n, "endpoint": ep}),
            None     => json!({"name": n, "error": "could not fetch details"}),
        }).collect();
        out.json(&v);
        return;
    }

    if entries.is_empty() {
        println!("No endpoints configured.");
        return;
    }

    println!("Configured endpoints:");
    for (name, ep) in &entries {
        match ep {
            Some(ep) => {
                let host = ep.host.as_deref().unwrap_or("(no host)");
                let port = ep.port.map_or(String::new(), |p| format!(":{}", p));
                let user = ep.username.as_deref().unwrap_or("(no user)");
                println!("  {:20} {}@{}{}", name, user, host, port);
            }
            None => println!("  {:20} (error fetching details)", name),
        }
    }
}

/// Show detail for a single endpoint (fetched from daemon).
fn show_endpoint_detail(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetEndpoint { name: name.to_string() }) {
        Ok(Response::Endpoint(Some(ep))) => {
            out.result(
                || ep.display(name),
                || json!({"name": name, "endpoint": ep}),
            );
        }
        Ok(Response::Endpoint(None)) => {
            out.error_coded("NOT_FOUND", format!("Endpoint '{}' does not exist.", name));
            state.exit_code = 1;
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// List all configured keys (fetched from daemon).
fn show_keys(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    let names = match rpc.call(Request::ListKeys) {
        Ok(Response::Names(n)) => n,
        Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
        _ => return,
    };

    let mut entries: Vec<(String, Option<PgpKey>)> = Vec::with_capacity(names.len());
    for name in &names {
        let key = match rpc.call(Request::GetKey { name: name.clone() }) {
            Ok(Response::Key(Some(k))) => Some(k),
            _ => None,
        };
        entries.push((name.clone(), key));
    }

    if out.is_json() {
        let v: Vec<_> = entries.iter().map(|(n, k)| match k {
            Some(k) => json!({"name": n, "key": k}),
            None    => json!({"name": n, "error": "could not fetch details"}),
        }).collect();
        out.json(&v);
        return;
    }

    if entries.is_empty() {
        println!("No keys configured.");
        return;
    }

    println!("Configured keys:");
    for (name, key) in &entries {
        match key {
            Some(key) => {
                let ktype = key.key_type.as_ref().map_or("(no type)", |t| match t {
                    KeyType::Public  => "public",
                    KeyType::Private => "private",
                });
                let has_contents = if key.contents.is_some() { "loaded" } else { "empty" };
                println!("  {:20} {:10} {}", name, ktype, has_contents);
            }
            None => println!("  {:20} (error fetching details)", name),
        }
    }
}

/// Show detail for a single key (fetched from daemon).
fn show_key_detail(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetKey { name: name.to_string() }) {
        Ok(Response::Key(Some(key))) => {
            out.result(
                || key.display(name),
                || json!({"name": name, "key": key}),
            );
        }
        Ok(Response::Key(None)) => {
            out.error_coded("NOT_FOUND", format!("Key '{}' does not exist.", name));
            state.exit_code = 1;
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// List all configured feeds (fetched from daemon via FeedSummaries).
fn show_feeds(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    let summaries = match rpc.call(Request::ListFeeds) {
        Ok(Response::FeedSummaries(s)) => s,
        Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
        _ => return,
    };

    if out.is_json() {
        out.json(&summaries);
        return;
    }

    if summaries.is_empty() {
        println!("No feeds configured.");
        return;
    }

    println!("Configured feeds:");
    for fs in &summaries {
        let colored_name = if fs.enabled {
            format!("\x1b[32m{:20}\x1b[0m", fs.name)
        } else {
            format!("\x1b[31m{:20}\x1b[0m", fs.name)
        };
        println!("  {} {} source(s), {} destination(s), {} schedule(s)",
            colored_name, fs.sources, fs.destinations, fs.schedules);
    }
}

/// Show detail for a single feed (fetched from daemon).
fn show_feed_detail(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetFeed { name: name.to_string() }) {
        Ok(Response::Feed(Some(feed))) => {
            out.result(
                || feed.display(name),
                || json!({"name": name, "feed": feed}),
            );
        }
        Ok(Response::Feed(None)) => {
            out.error_coded("NOT_FOUND", format!("Feed '{}' does not exist.", name));
            state.exit_code = 1;
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Show run history for a feed (fetched from daemon).
fn show_runs(feed: &str, limit: Option<u32>, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetRunHistory { feed: feed.to_string(), limit }) {
        Ok(Response::RunHistory(entries)) => {
            if out.is_json() {
                out.json(&json!({"feed": feed, "entries": entries}));
                return;
            }
            if entries.is_empty() {
                println!("No run history for feed '{}'.", feed);
                return;
            }

            println!("Run history for '{}' ({} entries):", feed, entries.len());
            println!(
                "  {:<4} {:<22} {:>8} {:>9} {:>6}  {}",
                "#", "Started", "Duration", "Status", "Files", "Message"
            );
            println!("  {}", "-".repeat(76));

            for entry in &entries {
                let status_str = match entry.status {
                    sftpflow_proto::RunStatus::Success  => "\x1b[32msuccess\x1b[0m ",
                    sftpflow_proto::RunStatus::Noaction => "\x1b[33mnoaction\x1b[0m",
                    sftpflow_proto::RunStatus::Failed   => "\x1b[31mfailed\x1b[0m  ",
                };
                let duration = format_duration(entry.duration_secs);
                let msg = entry.message.as_deref().unwrap_or("");
                println!(
                    "  {:<4} {:<22} {:>8} {:>9} {:>6}  {}",
                    entry.id,
                    &entry.started_at[..19.min(entry.started_at.len())],
                    duration,
                    status_str,
                    entry.files_transferred,
                    msg
                );
            }
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Show recent cluster mutation audit rows (fetched from daemon).
///
/// The audit log records one row per mutating RPC: timestamp,
/// CLI-attributed caller, method name, sha256 args fingerprint,
/// and outcome (`ok` vs `err:<code>`). Read-only RPCs do not
/// appear here. Failed mutations DO appear so operators can see
/// rejected attempts (e.g. NOT_LEADER on followers, REFERENCE_IN_USE
/// when deleting an in-use endpoint).
fn show_audit(limit: Option<u32>, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetAuditLog { limit, since_unix: None }) {
        Ok(Response::AuditLog(entries)) => {
            if out.is_json() {
                out.json(&entries);
                return;
            }
            if entries.is_empty() {
                println!("No audit rows yet.");
                return;
            }
            println!("Audit log ({} entries, newest first):", entries.len());
            // Column widths chosen so a typical entry fits in 100
            // columns: 4 id, 20 timestamp, 22 caller, 22 rpc, 8
            // outcome, plus the args_hash truncated to 12 chars.
            println!(
                "  {:<5} {:<20} {:<22} {:<22} {:<10} {}",
                "#", "Timestamp (UTC)", "Caller", "RPC", "Outcome", "Args"
            );
            println!("  {}", "-".repeat(96));

            for entry in &entries {
                let ts    = &entry.ts_iso[..19.min(entry.ts_iso.len())];
                let caller = entry.caller.as_deref().unwrap_or("-");
                let outcome = colored_outcome(&entry.outcome);
                // Hash is 64 hex chars; show the first 12 so the eye
                // can still spot duplicate-payload retries without
                // wasting half the line on uniqueness.
                let hash_short = &entry.args_hash
                    [..12.min(entry.args_hash.len())];
                println!(
                    "  {:<5} {:<20} {:<22} {:<22} {:<19} {}",
                    entry.id,
                    ts,
                    truncate(caller, 22),
                    truncate(&entry.rpc, 22),
                    outcome,
                    hash_short,
                );
            }
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Color the outcome cell: green for `ok`, red for any error code.
/// Includes ANSI reset; padded internally so the surrounding
/// printf width counts the *visible* characters, not the escape
/// bytes (we use a 19-wide field that already accounts for "\x1b[31m"
/// + outcome + "\x1b[0m").
fn colored_outcome(outcome: &str) -> String {
    if outcome == "ok" {
        // 7 visible chars; pad to 8 then add escape codes.
        format!("\x1b[32m{:<8}\x1b[0m", "ok")
    } else {
        format!("\x1b[31m{:<8}\x1b[0m", outcome)
    }
}

/// Truncate a string to `max` columns, replacing the last char with
/// '…' when shortened. Avoids wrecking column alignment on long
/// `<user>@<host>` callers or rare RPC-name additions.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

/// Format a duration in seconds as a human-readable string.
fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        let m = (secs / 60.0).floor();
        let s = secs - m * 60.0;
        format!("{}m{:.0}s", m as u32, s)
    } else {
        let h = (secs / 3600.0).floor();
        let m = ((secs - h * 3600.0) / 60.0).floor();
        format!("{}h{}m", h as u32, m as u32)
    }
}

// ============================================================
// Sealed secrets (top-level `secret` command)
// ============================================================
//
// `secret add <name>` prompts for the value on stdin without
// echo (via rpassword) so it never touches shell history. The
// value is sent to the daemon over the already-encrypted RPC
// channel, where it's re-sealed into the credential store.

/// Route 'secret add|list|delete ...' in exec mode. The `delete`
/// subcommand also accepts `--dry-run` (or `-n`) for a preview.
pub fn secret(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: secret <add|list|delete> [name]");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "add"    => {
            if args.len() < 2 {
                state.out.error_coded("USAGE", "Usage: secret add <name>");
                state.exit_code = 2;
                return;
            }
            secret_add(args[1], state);
        }
        "list"   => secret_list(state),
        "delete" => {
            // Strip `--dry-run`/`-n` from the trailing args so the
            // subcommand parser only sees positional tokens. We let
            // operators put the flag in either position
            // (`secret delete --dry-run X` or `secret delete X -n`).
            let (dry_run, rest) = take_dry_run_flag(&args[1..]);
            if rest.is_empty() {
                state.out.error_coded("USAGE", "Usage: secret delete [--dry-run] <name>");
                state.exit_code = 2;
                return;
            }
            secret_delete(rest[0], dry_run, state);
        }
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown secret subcommand '{}'. Use add, list, or delete.", other),
            );
            state.exit_code = 2;
        }
    }
}

/// Prompt for a secret value (hidden) and send a PutSecret RPC.
fn secret_add(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    // Prompt twice and require both to match, so typos don't silently
    // seal the wrong value into the store.
    let value = match rpassword::prompt_password(format!("Value for '{}': ", name)) {
        Ok(v) => v,
        Err(e) => {
            out.error(format!("Could not read value: {}", e));
            state.exit_code = 1;
            return;
        }
    };
    if value.is_empty() {
        out.error("Empty value — aborting.");
        state.exit_code = 1;
        return;
    }
    let confirm = match rpassword::prompt_password("Confirm: ") {
        Ok(v) => v,
        Err(e) => {
            out.error(format!("Could not read confirmation: {}", e));
            state.exit_code = 1;
            return;
        }
    };
    if confirm != value {
        out.error("Values did not match — aborting.");
        state.exit_code = 1;
        return;
    }

    let rpc = state.rpc.as_mut().unwrap();
    match rpc.call(Request::PutSecret { name: name.to_string(), value }) {
        Ok(Response::Ok) => {
            info!("Stored secret '{}'", name);
            out.ok(format!("Secret '{}' stored.", name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Send a ListSecrets RPC and print the names.
fn secret_list(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::ListSecrets) {
        Ok(Response::Names(names)) => {
            if out.is_json() {
                out.json(&names);
                return;
            }
            if names.is_empty() {
                println!("No secrets configured.");
                return;
            }
            println!("Configured secrets ({} total):", names.len());
            for name in &names {
                println!("  {}", name);
            }
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Send a DeleteSecret RPC, or its dry-run preview.
fn secret_delete(name: &str, dry_run: bool, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();
    let req = Request::DeleteSecret { name: name.to_string() };

    if dry_run {
        match rpc.call_dry_run(req) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    match rpc.call(req) {
        Ok(Response::Ok) => {
            info!("Deleted secret '{}'", name);
            out.ok(format!("Secret '{}' deleted.", name));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// `show secrets` implementation — identical wire call to `secret list`,
/// printed in the same style as the other show handlers.
fn show_secrets(state: &mut ShellState) {
    secret_list(state);
}

// ============================================================
// Ref-field setters for endpoint and key edit modes
// ============================================================

/// `password_ref <name>` — store a ref to the sealed password by name.
/// Clears any inline plaintext password so the YAML stays clean.
pub fn set_password_ref(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: password_ref <secret-name>");
        state.exit_code = 2;
        return;
    }
    let name = args[0].to_string();
    let out = state.out;

    // Warn if the secret doesn't exist yet (best-effort RPC check).
    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Names(names)) = rpc.call(Request::ListSecrets) {
            if !names.iter().any(|n| n == &name) {
                out.info(format!("  (warning: secret '{}' does not exist yet — use 'secret add {}' first)", name, name));
            }
        }
    }

    if let Some(ref mut ep) = state.pending_endpoint {
        ep.password_ref = Some(name.clone());
        ep.password = None;
        info!("Set password_ref = '{}'", name);
        out.info(format!("  password_ref → {}", name));
    }
}

/// `ssh_key_ref <name>` — store a ref to a sealed SSH key by name.
pub fn set_ssh_key_ref(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: ssh_key_ref <secret-name>");
        state.exit_code = 2;
        return;
    }
    let name = args[0].to_string();
    let out = state.out;

    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Names(names)) = rpc.call(Request::ListSecrets) {
            if !names.iter().any(|n| n == &name) {
                out.info(format!("  (warning: secret '{}' does not exist yet — use 'secret add {}' first)", name, name));
            }
        }
    }

    if let Some(ref mut ep) = state.pending_endpoint {
        ep.ssh_key_ref = Some(name.clone());
        ep.ssh_key = None;
        info!("Set ssh_key_ref = '{}'", name);
        out.info(format!("  ssh_key_ref → {}", name));
    }
}

/// `contents_ref <name>` — store a ref to sealed PGP key material.
pub fn set_key_contents_ref(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: contents_ref <secret-name>");
        state.exit_code = 2;
        return;
    }
    let name = args[0].to_string();
    let out = state.out;

    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Names(names)) = rpc.call(Request::ListSecrets) {
            if !names.iter().any(|n| n == &name) {
                out.info(format!("  (warning: secret '{}' does not exist yet — use 'secret add {}' first)", name, name));
            }
        }
    }

    if let Some(ref mut k) = state.pending_key {
        k.contents_ref = Some(name.clone());
        k.contents = None;
        info!("Set contents_ref = '{}'", name);
        out.info(format!("  contents_ref → {}", name));
    }
}

// ============================================================
// Cluster (top-level `cluster` command, M12+)
// ============================================================
//
// Three subcommands:
//   - status            Pretty-print leader, voters, learners.
//   - token [ttl]       Mint a join token (bootstrap node only).
//   - remove <node-id>  Drop a node from the voter set; the CLI
//                       double-confirms before sending.

/// Route 'cluster status|token|remove|leave|join|bootstrap|backup ...' in exec mode.
pub fn cluster(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        state.out.error_coded("USAGE", "Usage: cluster <status|token|remove|leave|join|bootstrap|backup> [args]");
        state.exit_code = 2;
        return;
    }

    match args[0] {
        "status" => cluster_status(state),
        "token"  => {
            // Optional TTL in seconds. Daemon caps it at its max
            // (1 hour today); we just forward whatever was typed.
            let ttl = if args.len() >= 2 {
                match args[1].parse::<u32>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        state.out.error_coded("USAGE", "Usage: cluster token [ttl-seconds]");
                        state.exit_code = 2;
                        return;
                    }
                }
            } else {
                None
            };
            cluster_token(state, ttl);
        }
        "remove" => {
            // Strip `--dry-run` / `-n` so the positional parser only
            // sees the node-id. Order-insensitive: `cluster remove
            // 3 --dry-run` and `cluster remove --dry-run 3` both work.
            let (dry_run, rest) = take_dry_run_flag(&args[1..]);
            if rest.is_empty() {
                state.out.error_coded("USAGE", "Usage: cluster remove [--dry-run] <node-id>");
                state.exit_code = 2;
                return;
            }
            let node_id = match rest[0].parse::<u64>() {
                Ok(n) => n,
                Err(_) => {
                    state.out.error_coded("PARSE", "node-id must be a non-negative integer");
                    state.exit_code = 2;
                    return;
                }
            };
            cluster_remove(state, node_id, dry_run);
        }
        "leave" => cluster_leave(state),
        "join" => {
            if args.len() < 2 {
                state.out.error_coded("USAGE", "Usage: cluster join <user@host[:port]>");
                state.exit_code = 2;
                return;
            }
            cluster_join_remote(state, args[1]);
        }
        "bootstrap" => {
            if args.len() < 2 {
                // No SSH target — drop into the interactive wizard.
                // The wizard itself bails out with USAGE if we're in
                // JSON mode or stdin isn't a TTY.
                cluster_bootstrap_wizard(state);
                return;
            }
            // Arg-driven path: acquire passphrase (env or single
            // prompt) here so cluster_bootstrap_remote stays purely
            // mechanical.
            let passphrase = match acquire_bootstrap_passphrase(state, false) {
                Some(p) => p,
                None    => return,  // already error-reported + exit_code set
            };
            cluster_bootstrap_remote(state, args[1], None, None, &passphrase);
        }
        "backup" => {
            if args.len() < 2 {
                state.out.error_coded(
                    "USAGE",
                    "Usage: cluster backup <server-side absolute path .tar.gz> \
                     (e.g. /var/lib/sftpflow/backups/sftpflow-2026-04-29.tar.gz)",
                );
                state.exit_code = 2;
                return;
            }
            cluster_backup_remote(state, args[1]);
        }
        other => {
            state.out.error_coded(
                "USAGE",
                format!("Unknown cluster subcommand '{}'. Use status, token, remove, leave, join, bootstrap, or backup.", other),
            );
            state.exit_code = 2;
        }
    }
}

/// Send ClusterStatus and pretty-print the result.
fn cluster_status(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::ClusterStatus) {
        Ok(Response::ClusterStatus(status)) => {
            if out.is_json() {
                out.json(&status);
                return;
            }
            // Header block: cluster id, leader, this node, uptime,
            // responder's local log tip / state-machine tip.
            println!("Cluster:    {}", status.cluster_id);
            match status.leader_id {
                Some(id) => println!("Leader:     node_id={}", id),
                None     => println!("Leader:     <election in progress>"),
            }
            println!("This node:  {}", status.self_id);
            println!("Uptime:     {}", format_uptime(status.responder_uptime_secs));
            println!(
                "Log tip:    {}    Applied: {}",
                fmt_opt_index(status.responder_last_log_index),
                fmt_opt_index(status.responder_last_applied_index),
            );
            println!();

            // Member table. MATCHED/LAG are only populated when the
            // responder is the leader; we render "-" for both when
            // they are None so the column widths stay deterministic.
            println!(
                "  {:<8} {:<10} {:<24} {:<10} {:<8} {}",
                "NODE", "ROLE", "ADVERTISE", "MATCHED", "LAG", "LABEL",
            );
            println!(
                "  {:-<8} {:-<10} {:-<24} {:-<10} {:-<8} {:-<20}",
                "", "", "", "", "", "",
            );
            for m in &status.members {
                let role = if Some(m.node_id) == status.leader_id {
                    "leader"
                } else if m.is_voter {
                    "voter"
                } else {
                    "learner"
                };
                let self_marker = if m.node_id == status.self_id { " *" } else { "" };
                let label_str = m.label.as_deref().unwrap_or("-");
                println!(
                    "  {:<8} {:<10} {:<24} {:<10} {:<8} {}{}",
                    m.node_id,
                    role,
                    m.advertise_addr,
                    fmt_opt_index(m.matched_log_index),
                    fmt_opt_index(m.lag),
                    label_str,
                    self_marker,
                );
            }
            println!();
            println!("(* = this node)");
            // Be honest about which fields are unavailable when a
            // follower answered. Operators can `connect <leader>`
            // and re-run for the lag view.
            if !status.responder_is_leader {
                println!(
                    "(MATCHED/LAG only populated by the leader; \
                     this responder is a follower)",
                );
            }
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

// ============================================================
// cluster_status formatters
// ============================================================

/// Format a u64 log index for display, "-" when None. Centralized
/// so MATCHED/LAG/Applied/Log tip columns stay aligned.
fn fmt_opt_index(idx: Option<u64>) -> String {
    match idx {
        Some(i) => i.to_string(),
        None    => "-".to_string(),
    }
}

/// Render a wall-clock duration (in seconds) as a compact
/// human string: "37s", "12m 04s", "3h 12m", "5d 02h". Days are
/// the largest unit — operators rarely need years for daemon uptime.
fn format_uptime(total_secs: u64) -> String {
    let days  = total_secs / 86_400;
    let hours = (total_secs % 86_400) / 3_600;
    let mins  = (total_secs % 3_600) / 60;
    let secs  = total_secs % 60;
    if days > 0 {
        format!("{}d {:02}h", days, hours)
    } else if hours > 0 {
        format!("{}h {:02}m", hours, mins)
    } else if mins > 0 {
        format!("{}m {:02}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Send ClusterMintToken and print the resulting token + expiry.
fn cluster_token(state: &mut ShellState, ttl_seconds: Option<u32>) {
    if !has_rpc(state) { return; }
    let out = state.out;
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::ClusterMintToken { ttl_seconds }) {
        Ok(Response::ClusterToken(t)) => {
            info!("Minted cluster join token (expires_at_unix={})", t.expires_at_unix);
            if out.is_json() {
                out.json(&t);
                return;
            }
            out.human(|| {
                println!("Token:");
                println!("  {}", t.token);
                println!();
                println!("Expires at unix={} ({} seconds from now)",
                    t.expires_at_unix,
                    t.expires_at_unix.saturating_sub(unix_now()),
                );
                println!();
                println!("To use it manually on the joiner:");
                println!("  sftpflowd join <seed-addr> --token <token> --ca-cert-file <ca.crt>");
                println!();
                println!("Or skip the manual ceremony:");
                println!("  cluster join <user@host[:port]>   # mint+ship+remote-launch in one shot");
            });
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// `cluster leave` — graceful self-removal of the connected node.
///
/// Fetches `cluster status` first so the confirm prompt can name
/// the node by id + label (operators connect by hostname; they
/// rarely remember the node_id off the top of their head). Then
/// double-confirms and sends `ClusterLeave`.
///
/// The leaver's daemon decides the path: leader steps down via
/// change_membership directly; follower/learner forwards a
/// ClusterRemoveNode-for-self to the current leader. Either way
/// the CLI just sees Response::Ok.
fn cluster_leave(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let out = state.out;

    // Look up the connected node's id + label so the confirm
    // prompt is unambiguous. If the status call fails we still
    // let the operator proceed against whatever they're connected
    // to, with the id field shown as "?".
    let rpc = state.rpc.as_mut().unwrap();
    let (self_id_str, label_hint) = match rpc.call(Request::ClusterStatus) {
        Ok(Response::ClusterStatus(s)) => {
            let label = s.members.iter()
                .find(|m| m.node_id == s.self_id)
                .and_then(|m| m.label.clone())
                .unwrap_or_else(|| "-".to_string());
            (s.self_id.to_string(), label)
        }
        _ => ("?".to_string(), "-".to_string()),
    };

    out.info("Step the connected node out of the cluster?");
    out.info(format!("  node_id={}  label={}", self_id_str, label_hint));
    out.info(
        "If this node is the leader it will step down first; \
         otherwise it forwards the removal to the current leader.",
    );
    out.info("This is irreversible. Type the node id again to confirm:");

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        out.error("Could not read confirmation — aborting.");
        state.exit_code = 1;
        return;
    }
    let typed = input.trim();
    if typed != self_id_str {
        out.error("Confirmation did not match — aborting.");
        state.exit_code = 1;
        return;
    }

    let rpc = state.rpc.as_mut().unwrap();
    match rpc.call(Request::ClusterLeave) {
        Ok(Response::Ok) => {
            info!("cluster leave: node_id={} removed", self_id_str);
            out.ok_with(
                || {
                    println!("Node {} has left the cluster.", self_id_str);
                    println!("(daemon is still running — re-join with `cluster join` or stop it manually)");
                },
                &json!({"node_id": self_id_str, "left": true}),
            );
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Send ClusterBackup and pretty-print the resulting BackupReport.
///
/// `out_path` is server-side and absolute — the daemon refuses
/// relative paths because its CWD is unstable (often "/" under
/// systemd). The archive is left on the server's filesystem in v1;
/// the operator scps it back themselves. The printed sha256 lets
/// them verify their copy matches what the daemon wrote.
fn cluster_backup_remote(state: &mut ShellState, out_path: &str) {
    if !has_rpc(state) { return; }
    let out = state.out;

    out.info(format!("Requesting backup → {}", out_path));
    out.info("(this is the path on the *server*; scp it back when done)");

    let rpc = state.rpc.as_mut().unwrap();
    match rpc.call(Request::ClusterBackup { out_path: out_path.to_string() }) {
        Ok(Response::BackupReport(report)) => {
            if out.is_json() {
                out.json(&report);
                return;
            }
            println!();
            println!("Backup written:");
            println!("  path:        {}", report.archive_path);
            println!("  size:        {} bytes", report.archive_size);
            println!("  sha256:      {}", report.archive_sha256);
            println!("  files:       {}", report.file_count);
            if let Some(node_id) = report.node_id {
                println!("  node_id:     {}", node_id);
            }
            if let Some(cluster_id) = report.cluster_id.as_ref() {
                println!("  cluster_id:  {}", cluster_id);
            }
            println!();
            println!("To copy it back from the server:");
            println!("  scp <user>@<host>:{} ./", report.archive_path);
            println!("To verify the copy locally:");
            println!("  sha256sum <local-copy>.tar.gz");
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// Send ClusterRemoveNode after a double-confirm on stdin.
/// In dry-run mode skips the confirm and prints the daemon's
/// preview instead of mutating membership.
fn cluster_remove(state: &mut ShellState, node_id: u64, dry_run: bool) {
    if !has_rpc(state) { return; }
    let out = state.out;

    if dry_run {
        // No confirmation prompt for previews — the whole point is
        // for the operator to inspect the plan before deciding.
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call_dry_run(Request::ClusterRemoveNode { node_id }) {
            Ok(Response::DryRunReport(r)) => render_dry_run_report(out, &r),
            Err(e) => report_err(out, &e, &mut state.exit_code),
            _ => {}
        }
        return;
    }

    // The double-confirm is interactive — only meaningful in human
    // mode. JSON-mode callers are scripts; we still require the
    // confirmation but document that it must be piped on stdin.
    out.info(format!("Remove node_id={} from the cluster voter set?", node_id));
    out.info("This is irreversible. Type the node id again to confirm:");
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        out.error("Could not read confirmation — aborting.");
        state.exit_code = 1;
        return;
    }
    let typed = input.trim();
    if typed != node_id.to_string() {
        out.error("Confirmation did not match — aborting.");
        state.exit_code = 1;
        return;
    }

    let rpc = state.rpc.as_mut().unwrap();
    match rpc.call(Request::ClusterRemoveNode { node_id }) {
        Ok(Response::Ok) => {
            info!("Removed node_id={} from the cluster", node_id);
            out.ok(format!("Node {} removed.", node_id));
        }
        Err(e) => report_err(out, &e, &mut state.exit_code),
        _ => {}
    }
}

/// `cluster join <user@host[:port]>` — drive a join end-to-end.
///
/// Hides the manual three-step dance:
///   1. Mint a token here (proves we're connected to the bootstrap node).
///   2. Fetch the cluster CA cert via the new ClusterGetCa RPC.
///   3. Read the bootstrap node's advertise addr from cluster_status.
///   4. SSH into <user@host[:port]>, pipe the passphrase + CA on stdin,
///      run `sftpflowd join` over there with `nohup` so the daemon
///      stays alive after our SSH session ends.
///   5. Poll cluster_status until the new node appears in the
///      membership map, or time out.
///
/// Preconditions on the remote host:
///   - sftpflowd binary in PATH
///   - writable state-dir (default /var/lib/sftpflow)
///   - sshd accepting the operator's key
///   - SFTPFLOW_PASSPHRASE accessible to subsequent daemon
///     restarts (e.g. via systemd unit env or /etc/environment) —
///     we send it inline for *this* invocation, but the remote
///     needs a persistent source for restarts to work
fn cluster_join_remote(state: &mut ShellState, target: &str) {
    if !has_rpc(state) { return; }
    let out = state.out;

    // ---- 1. Parse user@host[:port] -----------------------------
    let (user, host, port) = match parse_ssh_target(target) {
        Ok(t) => t,
        Err(msg) => {
            out.error_coded("PARSE", msg);
            state.exit_code = 2;
            return;
        }
    };

    // ---- 2. Read passphrase from local env ---------------------
    // Sent inline via SSH stdin so the remote daemon can unlock
    // its sealed store on first boot. Also assumed to be set on
    // the remote host for daemon restarts (we don't persist it
    // there — that's the operator's job via /etc/environment,
    // a systemd EnvironmentFile, or a secrets manager).
    let passphrase = match std::env::var("SFTPFLOW_PASSPHRASE") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            match rpassword::prompt_password("Cluster passphrase (also needed on the remote host): ") {
                Ok(p) if !p.is_empty() => p,
                _ => {
                    out.error("No passphrase supplied — aborting.");
                    state.exit_code = 1;
                    return;
                }
            }
        }
    };

    // ---- 3. Mint token + verify we're on the bootstrap node ----
    let rpc = state.rpc.as_mut().unwrap();
    let token = match rpc.call(Request::ClusterMintToken { ttl_seconds: Some(600) }) {
        Ok(Response::ClusterToken(t)) => t.token,
        Err(RpcError::Proto(e)) => {
            out.error_coded(format!("E{}", e.code), format!("Could not mint join token: {}", e.message));
            out.info("  Tip: only the bootstrap node holds the token-HMAC secret.");
            out.info("       Reconnect to it via 'config' / 'connect' first.");
            state.exit_code = 1;
            return;
        }
        Err(e) => { report_rpc_err(out, &e, &mut state.exit_code); return; }
        _ => return,
    };

    // ---- 4. Fetch CA cert + bootstrap advertise addr -----------
    let ca_pem = match rpc.call(Request::ClusterGetCa) {
        Ok(Response::ClusterCaCert(pem)) => pem,
        Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
        _ => return,
    };
    let seed_advertise = match rpc.call(Request::ClusterStatus) {
        Ok(Response::ClusterStatus(s)) => {
            match s.members.iter().find(|m| m.node_id == s.self_id) {
                Some(m) => m.advertise_addr.clone(),
                None    => {
                    out.error("Could not find self in cluster status");
                    state.exit_code = 1;
                    return;
                }
            }
        }
        Err(e) => { report_err(out, &e, &mut state.exit_code); return; }
        _ => return,
    };
    let initial_member_count = match rpc.call(Request::ClusterStatus) {
        Ok(Response::ClusterStatus(s)) => s.members.len(),
        _ => 0, // we'll just verify "increased" rather than "+1 exactly"
    };

    info!(
        "cluster join: target={}@{} port={} seed_advertise={}",
        user, host, port.unwrap_or(22), seed_advertise,
    );
    out.info(format!("Joining {}@{} to cluster (seed = {})", user, host, seed_advertise));

    // ---- 5. ssh + drive remote sftpflowd join ------------------
    // Stdin payload, three lines:
    //     <passphrase>\n
    //     <CA-cert-PEM>\n
    //     ===END-CA===\n
    // (the marker lets the remote shell know where the CA ends)
    if let Err(msg) = ssh_drive_remote_join(
        user,
        host,
        port,
        &passphrase,
        &ca_pem,
        &seed_advertise,
        &token,
    ) {
        out.error_coded("REMOTE_JOIN", format!("Remote join failed: {}", msg));
        state.exit_code = 1;
        return;
    }

    // ---- 6. Poll cluster_status for the new member -------------
    out.info("Waiting for new node to appear in membership (up to 30s)...");
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let rpc = state.rpc.as_mut().unwrap();
        if let Ok(Response::ClusterStatus(s)) = rpc.call(Request::ClusterStatus) {
            if s.members.len() > initial_member_count {
                out.ok_with(
                    || println!("Joined! Cluster size is now {}.", s.members.len()),
                    &json!({"joined": true, "cluster_size": s.members.len()}),
                );
                return;
            }
        }
    }
    out.error_coded(
        "TIMEOUT",
        "Timed out after 30s. The remote join may still complete shortly — \
         re-run 'cluster status' to check, or look at /tmp/sftpflowd-join.log \
         on the remote host for diagnostics.",
    );
    state.exit_code = 1;
}

/// Parse `user@host[:port]` into its three parts. Returns user-readable
/// error strings on malformed input.
fn parse_ssh_target(target: &str) -> Result<(&str, &str, Option<u16>), String> {
    let (user, host_port) = target.split_once('@')
        .ok_or_else(|| format!("Target must be user@host[:port], got '{}'", target))?;
    if user.is_empty() {
        return Err(format!("Empty user in '{}'", target));
    }
    // Split off optional :port from the right. IPv6 literals like
    // user@[::1]:22 aren't supported in M12; ssh's user@host[:port]
    // is sufficient for the common case.
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port = port_str.parse::<u16>()
            .map_err(|_| format!("'{}' is not a valid port number", port_str))?;
        if host.is_empty() {
            return Err(format!("Empty host in '{}'", target));
        }
        Ok((user, host, Some(port)))
    } else {
        if host_port.is_empty() {
            return Err(format!("Empty host in '{}'", target));
        }
        Ok((user, host_port, None))
    }
}

/// Spawn ssh, pipe the join payload on stdin, wait for it to exit.
///
/// The remote shell runs a small heredoc-extracted script that:
///   - reads the passphrase off stdin line 1
///   - reads CA cert lines until a sentinel marker
///   - writes CA to a tmp file
///   - launches `sftpflowd join` via nohup, detaching stdio so
///     the daemon survives our SSH session closing
///   - waits ~1s and checks the daemon is still running before
///     returning success, so we surface immediate errors
fn ssh_drive_remote_join(
    user:           &str,
    host:           &str,
    port:           Option<u16>,
    passphrase:     &str,
    ca_pem:         &str,
    seed_advertise: &str,
    token:          &str,
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let remote_script = format!(r#"
        set -e
        IFS= read -r SFTPFLOW_PASSPHRASE
        export SFTPFLOW_PASSPHRASE
        # Read CA cert lines until our sentinel.
        CA_FILE="$(mktemp /tmp/sftpflow-join-ca.XXXXXX.crt)"
        while IFS= read -r line; do
            if [ "$line" = "===END-CA===" ]; then break; fi
            printf '%s\n' "$line" >> "$CA_FILE"
        done
        # nohup + redirected stdio so the daemon survives ssh exit.
        # </dev/null specifically: without it the daemon inherits the
        # ssh session's pipes and dies on EPIPE when ssh closes.
        LOG=/tmp/sftpflowd-join.log
        : > "$LOG"
        nohup sftpflowd join {seed} \
            --token {token} \
            --ca-cert-file "$CA_FILE" \
            > "$LOG" 2>&1 < /dev/null &
        DAEMON_PID=$!
        # Give it a moment to fail fast if the args are wrong.
        sleep 2
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "sftpflowd join died early; tail of $LOG:" >&2
            tail -20 "$LOG" >&2
            exit 1
        fi
        echo "sftpflowd join running (pid=$DAEMON_PID); log at $LOG"
    "#, seed = seed_advertise, token = token);

    // Pass the script as a positional argument (not `sh -s`) so
    // ssh keeps stdin available for the script's `read` commands;
    // otherwise the remote shell would slurp the whole script + CA
    // payload as one undifferentiated stream.
    let mut cmd = Command::new("ssh");
    if let Some(p) = port {
        cmd.arg("-p").arg(p.to_string());
    }
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg(format!("{}@{}", user, host));
    cmd.arg(remote_script);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let mut child = cmd.spawn()
        .map_err(|e| format!("could not spawn ssh: {}", e))?;
    {
        let mut stdin = child.stdin.take()
            .ok_or_else(|| "ssh stdin not piped".to_string())?;
        writeln!(stdin, "{}", passphrase)
            .map_err(|e| format!("writing passphrase: {}", e))?;
        for line in ca_pem.lines() {
            writeln!(stdin, "{}", line)
                .map_err(|e| format!("writing CA: {}", e))?;
        }
        writeln!(stdin, "===END-CA===")
            .map_err(|e| format!("writing sentinel: {}", e))?;
        // Drop closes stdin → remote shell sees EOF and stops reading.
    }

    let status = child.wait()
        .map_err(|e| format!("ssh wait failed: {}", e))?;
    if !status.success() {
        return Err(format!("ssh exited with status {}", status.code().unwrap_or(-1)));
    }
    Ok(())
}

// ============================================================
// cluster bootstrap — drive `sftpflowd init` over SSH
// ============================================================

/// `cluster bootstrap <user@host[:port]>` — stand up a brand new
/// single-node cluster on a remote host without the operator
/// having to SSH in manually.
///
/// Counterpart to `cluster join`. Where join requires an existing
/// connected bootstrap node (to mint tokens, fetch the CA), this
/// command runs against *no* prior cluster — there's nothing for
/// the local CLI to be connected to yet.
///
/// Steps:
///   1. Parse user@host[:port].
///   2. SSH in, pipe passphrase + (optional) label + (optional)
///      advertise on stdin, run `sftpflowd init` (one-shot), then
///      launch `sftpflowd run` via nohup so it survives our SSH
///      session ending.
///   3. Print a connection hint pointing at the new node.
///
/// `passphrase` is acquired by the caller (either env var, single
/// prompt, or wizard with confirm) so this function stays agnostic
/// of how the operator supplied it.
///
/// `label` and `advertise`, when supplied, must already have passed
/// `validate_bootstrap_label` / `validate_bootstrap_advertise` —
/// they are forwarded raw into a "$VAR" double-quoted slot in the
/// remote shell script.
///
/// Preconditions on the remote host:
///   - sftpflowd binary in PATH
///   - writable state-dir (default /var/lib/sftpflow)
///   - sshd accepting the operator's key
fn cluster_bootstrap_remote(
    state:      &mut ShellState,
    target:     &str,
    label:      Option<&str>,
    advertise:  Option<&str>,
    passphrase: &str,
) {
    let out = state.out;
    // ---- 1. Parse user@host[:port] -----------------------------
    let (user, host, port) = match parse_ssh_target(target) {
        Ok(t) => t,
        Err(msg) => {
            out.error_coded("PARSE", msg);
            state.exit_code = 2;
            return;
        }
    };

    info!(
        "cluster bootstrap: target={}@{} port={} label={:?} advertise={:?}",
        user, host, port.unwrap_or(22), label, advertise,
    );
    out.info(format!("Bootstrapping new cluster on {}@{}...", user, host));

    // ---- 2. SSH + drive remote sftpflowd init + run ------------
    if let Err(msg) = ssh_drive_remote_bootstrap(user, host, port, passphrase, label, advertise) {
        out.error_coded("REMOTE_BOOTSTRAP", format!("Remote bootstrap failed: {}", msg));
        state.exit_code = 1;
        return;
    }

    // ---- 4. Connect hint ---------------------------------------
    // The CLI talks to the daemon over SSH (NDJSON tunnel), not the
    // Raft port. So the post-bootstrap hint walks the operator
    // through pointing the CLI's `server` config at the new host.
    out.ok_with(
        || {
            println!();
            println!("Cluster bootstrapped. Daemon is running on {} (Raft on :7900).", host);
            println!("Point this CLI at it:");
            println!("  configure terminal");
            println!("  server host {}", host);
            if let Some(p) = port {
                println!("  server port {}", p);
            }
            println!("  server username {}", user);
            println!("  end");
            println!("  connect");
        },
        &json!({
            "bootstrapped": true,
            "host":      host,
            "port":      port,
            "username":  user,
            "raft_port": 7900,
            "label":     label,
            "advertise": advertise,
        }),
    );
}

/// Spawn ssh, pipe passphrase + optional label/advertise on stdin,
/// and drive `sftpflowd init` followed by a detached `sftpflowd run`.
///
/// Two-phase script:
///   1. `sftpflowd init` runs to completion (one-shot). On
///      failure we tail its log and exit non-zero — the CLI
///      surfaces that to the operator.
///   2. `nohup sftpflowd run` launches in the background with
///      stdio redirected away from ssh. We sleep ~2s, check
///      pid-alive, and if `nc` is available also confirm the
///      Raft port (7900) is listening.
fn ssh_drive_remote_bootstrap(
    user:       &str,
    host:       &str,
    port:       Option<u16>,
    passphrase: &str,
    label:      Option<&str>,
    advertise:  Option<&str>,
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Defence in depth: even though the wizard / dispatch path
    // validates these strings before calling us, a future caller
    // might forget. Refuse anything containing characters that
    // could break out of "$VAR" in the remote script.
    if let Some(s) = label {
        validate_bootstrap_label(s).map_err(|e| format!("invalid label: {}", e))?;
    }
    if let Some(s) = advertise {
        validate_bootstrap_advertise(s).map_err(|e| format!("invalid advertise: {}", e))?;
    }

    // POSIX-sh script (no bashisms) — matches the join helper's style.
    // Values flow in through stdin (passphrase + optional label +
    // optional advertise, three lines), so the script body itself
    // contains no operator-supplied substrings — there's nothing for
    // a malicious value to break out of even if validation slipped.
    // Single-quoted Rust raw string so { and } in shell ${} don't
    // collide with format!'s placeholders.
    let remote_script = r#"
        set -e
        IFS= read -r SFTPFLOW_PASSPHRASE
        export SFTPFLOW_PASSPHRASE
        IFS= read -r SFTPFLOW_LABEL || SFTPFLOW_LABEL=""
        IFS= read -r SFTPFLOW_ADVERTISE || SFTPFLOW_ADVERTISE=""

        # ---- Phase 1: sftpflowd init (one-shot) ----
        # Function so set -e applies inside; the `if ! ... ; then`
        # caller still catches the exit so we can tail the log.
        INIT_LOG=/tmp/sftpflowd-bootstrap-init.log
        : > "$INIT_LOG"
        do_init() {
            if [ -n "$SFTPFLOW_LABEL" ] && [ -n "$SFTPFLOW_ADVERTISE" ]; then
                sftpflowd init --label "$SFTPFLOW_LABEL" --advertise "$SFTPFLOW_ADVERTISE"
            elif [ -n "$SFTPFLOW_LABEL" ]; then
                sftpflowd init --label "$SFTPFLOW_LABEL"
            elif [ -n "$SFTPFLOW_ADVERTISE" ]; then
                sftpflowd init --advertise "$SFTPFLOW_ADVERTISE"
            else
                sftpflowd init
            fi
        }
        if ! do_init > "$INIT_LOG" 2>&1; then
            echo "sftpflowd init failed; tail of $INIT_LOG:" >&2
            tail -20 "$INIT_LOG" >&2
            exit 1
        fi
        echo "sftpflowd init complete"

        # ---- Phase 2: sftpflowd run (long-running, detached) ----
        # </dev/null specifically: without it the daemon inherits
        # the ssh session's pipes and dies on EPIPE when ssh closes.
        RUN_LOG=/tmp/sftpflowd.log
        : > "$RUN_LOG"
        nohup sftpflowd run > "$RUN_LOG" 2>&1 < /dev/null &
        DAEMON_PID=$!
        # Give it a moment to fail fast (port collision, bad config).
        sleep 2
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "sftpflowd run died early; tail of $RUN_LOG:" >&2
            tail -20 "$RUN_LOG" >&2
            exit 1
        fi

        # ---- Phase 3: Raft port check (best-effort) ----
        # nc isn't on every minimal install. If it's missing we skip
        # silently — pid-alive is already a strong success signal.
        if command -v nc >/dev/null 2>&1; then
            if ! nc -z localhost 7900 2>/dev/null; then
                echo "warning: pid $DAEMON_PID alive but Raft port 7900 not yet listening" >&2
            fi
        fi
        echo "sftpflowd run started (pid=$DAEMON_PID); log at $RUN_LOG"
    "#;

    // Pass the script as a positional argument (not `sh -s`) so
    // ssh keeps stdin available for the script's `read` of the
    // passphrase; otherwise the remote shell would slurp the whole
    // script + passphrase as one undifferentiated stream.
    let mut cmd = Command::new("ssh");
    if let Some(p) = port {
        cmd.arg("-p").arg(p.to_string());
    }
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg(format!("{}@{}", user, host));
    cmd.arg(remote_script);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let mut child = cmd.spawn()
        .map_err(|e| format!("could not spawn ssh: {}", e))?;
    {
        let mut stdin = child.stdin.take()
            .ok_or_else(|| "ssh stdin not piped".to_string())?;
        // Three stdin lines, in order: passphrase, label, advertise.
        // Empty string for absent label/advertise — the script's
        // `[ -n "$VAR" ]` checks treat empty as "skip".
        writeln!(stdin, "{}", passphrase)
            .map_err(|e| format!("writing passphrase: {}", e))?;
        writeln!(stdin, "{}", label.unwrap_or(""))
            .map_err(|e| format!("writing label: {}", e))?;
        writeln!(stdin, "{}", advertise.unwrap_or(""))
            .map_err(|e| format!("writing advertise: {}", e))?;
        // Drop closes stdin → remote shell sees EOF after `read`.
    }

    let status = child.wait()
        .map_err(|e| format!("ssh wait failed: {}", e))?;
    if !status.success() {
        return Err(format!("ssh exited with status {}", status.code().unwrap_or(-1)));
    }
    Ok(())
}

// ============================================================
// cluster bootstrap — interactive wizard (no-arg invocation)
// ============================================================
//
// When `cluster bootstrap` is invoked with no SSH target the CLI
// drops into this wizard instead of failing on missing args. It's
// the friendliest entry point for first-time operators who don't
// remember the exact `user@host[:port]` shape, the optional flags,
// or that the daemon needs a passphrase.
//
// The wizard is human-mode + TTY only. JSON / piped-stdin callers
// see the original USAGE error so non-interactive scripts (Ansible,
// CI) keep their previous behaviour.

/// Run the interactive `cluster bootstrap` wizard. Refuses (with a
/// USAGE error) if the caller is in JSON mode or stdin isn't a TTY,
/// since prompts only make sense for a human at a terminal.
fn cluster_bootstrap_wizard(state: &mut ShellState) {
    use std::io::IsTerminal;

    let out = state.out;

    // ---- Refuse in JSON / non-TTY mode -------------------------
    // JSON callers want machine-readable output, not prompts.
    // Non-TTY stdin (cron, piped sh) would block forever on the
    // first read_line.
    if out.is_json() {
        out.error_coded(
            "USAGE",
            "Usage: cluster bootstrap <user@host[:port]>  \
             (interactive wizard is human mode only)",
        );
        state.exit_code = 2;
        return;
    }
    if !std::io::stdin().is_terminal() {
        out.error_coded(
            "USAGE",
            "Usage: cluster bootstrap <user@host[:port]>  \
             (interactive wizard requires a TTY)",
        );
        state.exit_code = 2;
        return;
    }

    // ---- Banner ------------------------------------------------
    println!("cluster bootstrap — interactive setup");
    println!("Press Enter on optional fields to accept the default.");
    println!();

    // ---- Prompt 1: SSH target (required) -----------------------
    let ssh_target = match prompt_required(
        "SSH target (user@host[:port]): ",
        |s| parse_ssh_target(s).map(|_| ()),
    ) {
        Some(s) => s,
        None => {
            out.error("Aborted.");
            state.exit_code = 1;
            return;
        }
    };

    // ---- Prompt 2: Node label (optional) -----------------------
    // Maps to `sftpflowd init --label`. Shown in `cluster status`.
    let label = prompt_optional(
        "Node label (e.g. west-coast-1) [skip]: ",
        validate_bootstrap_label,
    );

    // ---- Prompt 3: Advertise host:port (optional) --------------
    // Maps to `sftpflowd init --advertise`. Default = remote
    // auto-detects `<hostname>:7900`.
    let advertise = prompt_optional(
        "Advertise host:port [auto-detect on remote]: ",
        validate_bootstrap_advertise,
    );

    // ---- Prompt 4: Passphrase (with confirm) -------------------
    // First-init passphrases are unrecoverable — confirm so a
    // typo doesn't silently lock the new cluster's secrets store.
    let passphrase = match acquire_bootstrap_passphrase(state, true) {
        Some(p) => p,
        None    => return,  // helper already reported + bumped exit_code
    };

    // ---- Recap ------------------------------------------------
    println!();
    println!("Ready to bootstrap:");
    println!("  ssh target:  {}", ssh_target);
    println!("  label:       {}", label.as_deref().unwrap_or("<none>"));
    println!("  advertise:   {}", advertise.as_deref().unwrap_or("<auto-detect on remote>"));
    println!();

    cluster_bootstrap_remote(
        state,
        &ssh_target,
        label.as_deref(),
        advertise.as_deref(),
        &passphrase,
    );
}

/// Acquire the bootstrap passphrase from the env var or prompt the
/// operator. With `confirm=true`, asks twice and rejects mismatches
/// — used by the wizard, where this is the operator's first time
/// typing this passphrase and a typo locks the cluster store.
///
/// Returns `None` (after error-reporting via `state.out` and bumping
/// `state.exit_code`) on EOF, mismatch, or empty input.
fn acquire_bootstrap_passphrase(state: &mut ShellState, confirm: bool) -> Option<String> {
    // Env var path: skip the prompt entirely. Useful for cron /
    // Ansible runs that pre-stage the passphrase out-of-band.
    if let Ok(p) = std::env::var("SFTPFLOW_PASSPHRASE") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    let p1 = match rpassword::prompt_password(
        "Cluster passphrase (also needed on the remote host): ",
    ) {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            state.out.error("No passphrase supplied — aborting.");
            state.exit_code = 1;
            return None;
        }
        Err(e) => {
            state.out.error(format!("Could not read passphrase: {}", e));
            state.exit_code = 1;
            return None;
        }
    };
    if confirm {
        let p2 = match rpassword::prompt_password("Confirm passphrase: ") {
            Ok(p) => p,
            Err(e) => {
                state.out.error(format!("Could not read confirmation: {}", e));
                state.exit_code = 1;
                return None;
            }
        };
        if p1 != p2 {
            state.out.error("Passphrases did not match — aborting.");
            state.exit_code = 1;
            return None;
        }
    }
    Some(p1)
}

/// Prompt the user with a one-line question; re-prompt on empty
/// input or validation failure. Returns `None` only on stdin
/// EOF / read error (operator hit Ctrl-D, terminal lost).
fn prompt_required<F>(prompt: &str, validate: F) -> Option<String>
where
    F: Fn(&str) -> Result<(), String>,
{
    use std::io::Write;
    loop {
        print!("{}", prompt);
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        if line.is_empty() {
            // True EOF — read_line returned 0 bytes.
            return None;
        }
        let s = line.trim();
        if s.is_empty() {
            eprintln!("  (this field is required)");
            continue;
        }
        match validate(s) {
            Ok(_)    => return Some(s.to_string()),
            Err(msg) => {
                eprintln!("  invalid: {}", msg);
                continue;
            }
        }
    }
}

/// Prompt the user with a one-line question; empty input means
/// "skip / accept the default" and returns `None`. A non-empty
/// answer is validated and re-prompted on failure.
fn prompt_optional<F>(prompt: &str, validate: F) -> Option<String>
where
    F: Fn(&str) -> Result<(), String>,
{
    use std::io::Write;
    loop {
        print!("{}", prompt);
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        if line.is_empty() {
            return None;  // EOF — treat as skip
        }
        let s = line.trim();
        if s.is_empty() {
            return None;  // user pressed Enter to accept default
        }
        match validate(s) {
            Ok(_)    => return Some(s.to_string()),
            Err(msg) => {
                eprintln!("  invalid: {}", msg);
                continue;
            }
        }
    }
}

// ============================================================
// Validators for wizard-collected fields
// ============================================================
//
// These run BEFORE values are written into the SSH stdin stream
// that drives the remote `sftpflowd init`. The script wraps them
// in "$VAR" double quotes, so the strict allowlists here are the
// load-bearing line of defence: anything that survives validation
// is safe to embed in that double-quoted slot.

/// Allow human-readable labels (alphanumerics, plus a handful of
/// punctuation and ASCII space) up to 64 chars. Rejects shell
/// metacharacters, quotes, control chars, and empty input.
fn validate_bootstrap_label(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("label cannot be empty (omit instead)".into());
    }
    if s.len() > 64 {
        return Err(format!(
            "label is too long ({} chars; max 64)",
            s.len(),
        ));
    }
    for ch in s.chars() {
        let ok = ch.is_ascii_alphanumeric()
            || ch == ' '
            || ch == '.'
            || ch == '-'
            || ch == '_'
            || ch == '/';
        if !ok {
            return Err(format!(
                "label contains disallowed character {:?} \
                 (allowed: A-Z, a-z, 0-9, space, '.', '-', '_', '/')",
                ch,
            ));
        }
    }
    Ok(())
}

/// Validate `host:port` for the `--advertise` flag. Host is a DNS
/// label or IP literal (alphanumerics + `.` `-` `_`), port is a
/// non-zero u16. IPv6 literals (`[::1]:7900`) are not supported —
/// matches `parse_ssh_target`'s constraint.
fn validate_bootstrap_advertise(s: &str) -> Result<(), String> {
    let (host, port) = s.rsplit_once(':')
        .ok_or_else(|| format!("'{}' must be host:port", s))?;
    if host.is_empty() {
        return Err(format!("'{}' has empty host", s));
    }
    if host.len() > 253 {
        return Err(format!("host '{}' is too long (max 253 chars)", host));
    }
    for ch in host.chars() {
        let ok = ch.is_ascii_alphanumeric()
            || ch == '.'
            || ch == '-'
            || ch == '_';
        if !ok {
            return Err(format!(
                "host '{}' contains disallowed character {:?} \
                 (allowed: A-Z, a-z, 0-9, '.', '-', '_')",
                host, ch,
            ));
        }
    }
    let port_n: u16 = port.parse()
        .map_err(|_| format!("'{}' is not a valid port number (1..=65535)", port))?;
    if port_n == 0 {
        return Err("port cannot be 0".into());
    }
    Ok(())
}

/// Seconds since the Unix epoch, saturating to 0 on clock errors.
/// Local helper so the CLI can compute "expires in N seconds" for
/// `cluster token` output without taking a chrono dependency.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ============================================================
// Tests — wizard validators
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validate_bootstrap_label ------------------------------

    #[test]
    fn label_accepts_typical_values() {
        assert!(validate_bootstrap_label("prod-1").is_ok());
        assert!(validate_bootstrap_label("west coast replica").is_ok());
        assert!(validate_bootstrap_label("us-east-2/zone-a").is_ok());
        assert!(validate_bootstrap_label("node_42").is_ok());
        assert!(validate_bootstrap_label("a.b.c").is_ok());
    }

    #[test]
    fn label_rejects_empty() {
        assert!(validate_bootstrap_label("").is_err());
    }

    #[test]
    fn label_rejects_overlong() {
        let long = "a".repeat(65);
        assert!(validate_bootstrap_label(&long).is_err());
        let max = "a".repeat(64);
        assert!(validate_bootstrap_label(&max).is_ok());
    }

    #[test]
    fn label_rejects_shell_metacharacters() {
        for bad in &[
            "evil\"label",
            "evil`whoami`",
            "evil$VAR",
            "evil\\backslash",
            "evil;rm",
            "evil|cat",
            "evil&bg",
            "evil>file",
            "evil<file",
            "evil(sub)",
            "evil'q",
        ] {
            assert!(
                validate_bootstrap_label(bad).is_err(),
                "expected '{}' to be rejected",
                bad,
            );
        }
    }

    #[test]
    fn label_rejects_control_chars_and_newlines() {
        assert!(validate_bootstrap_label("line1\nline2").is_err());
        assert!(validate_bootstrap_label("tab\there").is_err());
        assert!(validate_bootstrap_label("nul\0byte").is_err());
    }

    // ---- validate_bootstrap_advertise --------------------------

    #[test]
    fn advertise_accepts_typical_values() {
        assert!(validate_bootstrap_advertise("host.example.com:7900").is_ok());
        assert!(validate_bootstrap_advertise("10.0.0.1:7900").is_ok());
        assert!(validate_bootstrap_advertise("sftpflow-1:7900").is_ok());
        assert!(validate_bootstrap_advertise("a:1").is_ok());
        assert!(validate_bootstrap_advertise("host_underscore:65535").is_ok());
    }

    #[test]
    fn advertise_rejects_missing_port() {
        assert!(validate_bootstrap_advertise("host.example.com").is_err());
        assert!(validate_bootstrap_advertise("").is_err());
    }

    #[test]
    fn advertise_rejects_bad_port() {
        assert!(validate_bootstrap_advertise("host:0").is_err());
        assert!(validate_bootstrap_advertise("host:65536").is_err());
        assert!(validate_bootstrap_advertise("host:abc").is_err());
        assert!(validate_bootstrap_advertise("host:").is_err());
    }

    #[test]
    fn advertise_rejects_empty_host() {
        assert!(validate_bootstrap_advertise(":7900").is_err());
    }

    #[test]
    fn advertise_rejects_shell_metacharacters() {
        for bad in &[
            "evil`cmd`:7900",
            "evil$VAR:7900",
            "evil\"host:7900",
            "evil;rm:7900",
            "evil host:7900",   // space
            "[::1]:7900",       // IPv6 literal not supported
            "host:7900;rm",
        ] {
            assert!(
                validate_bootstrap_advertise(bad).is_err(),
                "expected '{}' to be rejected",
                bad,
            );
        }
    }
}
