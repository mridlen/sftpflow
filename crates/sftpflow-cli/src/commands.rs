// ============================================================
// commands.rs - Command implementations
// ============================================================
//
// Commands that read or mutate daemon state go through RPC.
// The staging pattern (pending_*) stays local — only commit
// sends the final object to the daemon via PutEndpoint/Key/Feed.
// Server connection settings are CLI-local (not managed by daemon).

use log::info;

use sftpflow_proto::{Request, Response}; // lib.rs (sftpflow-proto)

use crate::cli::{Mode, ShellState};
use crate::feed::{Endpoint, Feed, FeedPath, FtpsMode, KeyType, NextStep, NextStepAction, PgpKey, ProcessStep, Protocol, TriggerCondition}; // feed.rs
use crate::rpc::RpcError; // rpc.rs

// ============================================================
// RPC helper
// ============================================================

/// Print a standard "not connected" message. Returns true if
/// an RPC connection is available, false if not. Callers should
/// return early on false.
fn has_rpc(state: &ShellState) -> bool {
    if state.rpc.is_some() {
        true
    } else {
        println!("% Not connected to daemon. Use 'config' to set server settings, then 'connect'.");
        false
    }
}

// ============================================================
// Exec mode commands
// ============================================================

/// Print help for exec mode.
pub fn help_exec() {
    println!("Object types: endpoint, key, feed");
    println!();
    println!("  create <type> <name>         Create a new object");
    println!("  edit <type> <name>           Edit an existing object");
    println!("  delete <type> <name>         Delete an object");
    println!("  rename <type> <old> <new>    Rename (updates all references)");
    println!();
    println!("  show endpoints|keys|feeds    List all of a type");
    println!("  show secrets                 List sealed secret names");
    println!("  show <type> <name>           Show details for one object");
    println!("  show runs <feed> [limit]     Show run history for a feed");
    println!("  show version                 Show SFTPflow version");
    println!();
    println!("  secret add <name>            Add/replace a sealed secret (prompts for value)");
    println!("  secret delete <name>         Remove a sealed secret");
    println!("  secret list                  List sealed secret names");
    println!();
    println!("  cluster status               Show cluster leader / members");
    println!("  cluster token [ttl]          Mint a join token (bootstrap node only)");
    println!("  cluster bootstrap <user@host[:port]>");
    println!("                               ssh-drive sftpflowd init on a fresh host");
    println!("  cluster join <user@host[:port]>");
    println!("                               Mint+ship a token, then ssh-drive sftpflowd join");
    println!("  cluster remove <node-id>     Remove a node from the voter set");
    println!();
    println!("  run feed <name>              Manually run a feed (outside of schedule)");
    println!("  sync schedules               Reconcile feed schedules with dkron");
    println!("  connect                      Connect (or reconnect) to the daemon");
    println!("  config                       Edit server connection settings");
    println!();
    println!("  exit                         Exit SFTPflow");
    println!("  help / ?                     Show this help");
}

// ---- connect ----

/// Connect (or reconnect) to the daemon.
pub fn connect(state: &mut ShellState) {
    state.try_connect(); // cli.rs - ShellState::try_connect()
}

// ---- create <type> <name> ----

/// Route 'create endpoint|key|feed <name>'.
pub fn create(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        println!("% Usage: create <endpoint|key|feed> <name>");
        return;
    }

    match args[0] {
        "endpoint" => create_endpoint(args[1], state),
        "key"      => create_key(args[1], state),
        "feed"     => create_feed(args[1], state),
        _ => println!("% Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", args[0]),
    }
}

fn create_endpoint(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }

    {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetEndpoint { name: name.to_string() }) {
            Ok(Response::Endpoint(Some(_))) => {
                println!("% Endpoint '{}' already exists. Use 'edit endpoint {}' to modify it.", name, name);
                return;
            }
            Ok(Response::Endpoint(None)) => {}
            Err(e) => { println!("% Error: {}", e); return; }
            _ => return,
        }
    }

    info!("Creating new endpoint '{}'", name);
    println!("Creating new endpoint '{}'.", name);
    state.pending_endpoint = Some(Endpoint::new());
    state.mode = Mode::EndpointEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn create_key(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }

    {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetKey { name: name.to_string() }) {
            Ok(Response::Key(Some(_))) => {
                println!("% Key '{}' already exists. Use 'edit key {}' to modify it.", name, name);
                return;
            }
            Ok(Response::Key(None)) => {}
            Err(e) => { println!("% Error: {}", e); return; }
            _ => return,
        }
    }

    info!("Creating new key '{}'", name);
    println!("Creating new key '{}'.", name);
    state.pending_key = Some(PgpKey::new());
    state.mode = Mode::KeyEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn create_feed(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }

    {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetFeed { name: name.to_string() }) {
            Ok(Response::Feed(Some(_))) => {
                println!("% Feed '{}' already exists. Use 'edit feed {}' to modify it.", name, name);
                return;
            }
            Ok(Response::Feed(None)) => {}
            Err(e) => { println!("% Error: {}", e); return; }
            _ => return,
        }
    }

    info!("Creating new feed '{}'", name);
    println!("Creating new feed '{}'.", name);
    state.pending_feed = Some(Feed::new());
    state.mode = Mode::FeedEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

// ---- edit <type> <name> ----

/// Route 'edit endpoint|key|feed <name>'.
pub fn edit(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        println!("% Usage: edit <endpoint|key|feed> <name>");
        return;
    }

    match args[0] {
        "endpoint" => edit_endpoint(args[1], state),
        "key"      => edit_key(args[1], state),
        "feed"     => edit_feed(args[1], state),
        _ => println!("% Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", args[0]),
    }
}

fn edit_endpoint(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }

    let endpoint = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetEndpoint { name: name.to_string() }) {
            Ok(Response::Endpoint(Some(ep))) => ep,
            Ok(Response::Endpoint(None)) => {
                println!("% Endpoint '{}' does not exist. Use 'create endpoint {}' to create it.", name, name);
                return;
            }
            Err(e) => { println!("% Error: {}", e); return; }
            _ => return,
        }
    };

    info!("Editing endpoint '{}'", name);
    println!("Editing endpoint '{}'.", name);
    state.pending_endpoint = Some(endpoint);
    state.mode = Mode::EndpointEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn edit_key(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }

    let key = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetKey { name: name.to_string() }) {
            Ok(Response::Key(Some(k))) => k,
            Ok(Response::Key(None)) => {
                println!("% Key '{}' does not exist. Use 'create key {}' to create it.", name, name);
                return;
            }
            Err(e) => { println!("% Error: {}", e); return; }
            _ => return,
        }
    };

    info!("Editing key '{}'", name);
    println!("Editing key '{}'.", name);
    state.pending_key = Some(key);
    state.mode = Mode::KeyEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn edit_feed(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }

    let feed = {
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::GetFeed { name: name.to_string() }) {
            Ok(Response::Feed(Some(f))) => f,
            Ok(Response::Feed(None)) => {
                println!("% Feed '{}' does not exist. Use 'create feed {}' to create it.", name, name);
                return;
            }
            Err(e) => { println!("% Error: {}", e); return; }
            _ => return,
        }
    };

    info!("Editing feed '{}'", name);
    println!("Editing feed '{}'.", name);
    state.pending_feed = Some(feed);
    state.mode = Mode::FeedEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

// ---- delete <type> <name> ----

/// Route 'delete endpoint|key|feed <name>'.
pub fn delete(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        println!("% Usage: delete <endpoint|key|feed> <name>");
        return;
    }

    match args[0] {
        "endpoint" => delete_endpoint(args[1], state),
        "key"      => delete_key(args[1], state),
        "feed"     => delete_feed(args[1], state),
        _ => println!("% Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", args[0]),
    }
}

fn delete_endpoint(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::DeleteEndpoint { name: name.to_string() }) {
        Ok(Response::Ok) => {
            info!("Deleted endpoint '{}'", name);
            println!("Endpoint '{}' deleted.", name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

fn delete_key(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::DeleteKey { name: name.to_string() }) {
        Ok(Response::Ok) => {
            info!("Deleted key '{}'", name);
            println!("Key '{}' deleted.", name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

fn delete_feed(name: &str, state: &mut ShellState) {
    // Dkron cleanup is handled daemon-side after DeleteFeed.
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::DeleteFeed { name: name.to_string() }) {
        Ok(Response::Ok) => {
            info!("Deleted feed '{}'", name);
            println!("Feed '{}' deleted.", name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

// ---- rename <type> <old> <new> ----

/// Route 'rename endpoint|key|feed <old> <new>'.
pub fn rename(args: &[&str], state: &mut ShellState) {
    if args.len() < 3 {
        println!("% Usage: rename <endpoint|key|feed> <oldname> <newname>");
        return;
    }

    match args[0] {
        "endpoint" => rename_endpoint(args[1], args[2], state),
        "key"      => rename_key(args[1], args[2], state),
        "feed"     => rename_feed(args[1], args[2], state),
        _ => println!("% Unknown type '{}'. Use 'endpoint', 'key', or 'feed'.", args[0]),
    }
}

fn rename_endpoint(old_name: &str, new_name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::RenameEndpoint { from: old_name.to_string(), to: new_name.to_string() }) {
        Ok(Response::Ok) => {
            info!("Renamed endpoint '{}' → '{}'", old_name, new_name);
            println!("Endpoint '{}' renamed to '{}'.", old_name, new_name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

fn rename_key(old_name: &str, new_name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::RenameKey { from: old_name.to_string(), to: new_name.to_string() }) {
        Ok(Response::Ok) => {
            info!("Renamed key '{}' → '{}'", old_name, new_name);
            println!("Key '{}' renamed to '{}'.", old_name, new_name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

fn rename_feed(old_name: &str, new_name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::RenameFeed { from: old_name.to_string(), to: new_name.to_string() }) {
        Ok(Response::Ok) => {
            info!("Renamed feed '{}' → '{}'", old_name, new_name);
            println!("Feed '{}' renamed to '{}'.", old_name, new_name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// Print version info.
pub fn version() {
    println!("SFTPflow v{}", env!("CARGO_PKG_VERSION"));
}

/// Exit the shell entirely.
pub fn exit_shell(state: &mut ShellState) {
    println!("Goodbye.");
    state.running = false;
}

// ---- run feed <name> ----

/// Route 'run feed <name>'.
pub fn run(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        println!("% Usage: run feed <name>");
        return;
    }

    match args[0] {
        "feed" => run_feed(args[1], state),
        _ => println!("% Unknown run target '{}'. Usage: run feed <name>", args[0]),
    }
}

fn run_feed(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::RunFeedNow { name: name.to_string() }) {
        Ok(Response::RunResult(result)) => {
            info!("Run result for '{}': {:?}", name, result.status);
            println!("Feed '{}': {:?}", name, result.status);
            if let Some(msg) = result.message {
                println!("  {}", msg);
            }
            if result.files_transferred > 0 {
                println!("  {} file(s) transferred.", result.files_transferred);
            }
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

// ============================================================
// Scheduler sync
// ============================================================

/// Handle `sync <target>` in exec mode.
pub fn sync(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: sync schedules");
        return;
    }

    match args[0] {
        "schedules" => sync_schedules(state),
        _ => println!("% Unknown sync target '{}'. Usage: sync schedules", args[0]),
    }
}

/// Send SyncSchedules RPC and print the report.
fn sync_schedules(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::SyncSchedules) {
        Ok(Response::SyncReport(report)) => {
            info!(
                "sync schedules: created={}, updated={}, deleted={}, errors={}",
                report.created, report.updated, report.deleted, report.errors.len()
            );
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
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
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
    println!("Editing server connection settings. Type 'help' for options.");
}

/// Print help for config-edit mode.
pub fn help_config_edit() {
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
        println!("% Usage: host <address>");
        return;
    }
    if let Some(ref mut server) = state.pending_server {
        info!("Set server host = {}", args[0]);
        server.host = Some(args[0].to_string());
        println!("  host → {}", args[0]);
    }
}

/// Set the server port.
pub fn set_server_port(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: port <number>");
        return;
    }
    match args[0].parse::<u16>() {
        Ok(p) => {
            if let Some(ref mut server) = state.pending_server {
                info!("Set server port = {}", p);
                server.port = Some(p);
                println!("  port → {}", p);
            }
        }
        Err(_) => println!("% Invalid port number: '{}'", args[0]),
    }
}

/// Set the server username.
pub fn set_server_username(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: username <user>");
        return;
    }
    if let Some(ref mut server) = state.pending_server {
        info!("Set server username = {}", args[0]);
        server.username = Some(args[0].to_string());
        println!("  username → {}", args[0]);
    }
}

/// Set the dkron scheduler API URL.
pub fn set_dkron_url(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: dkron <url>  (e.g. http://dkron-server:8080)");
        return;
    }
    if let Some(ref mut server) = state.pending_server {
        info!("Set dkron_url = {}", args[0]);
        server.dkron_url = Some(args[0].to_string());
        println!("  dkron → {}", args[0]);
    }
}

/// Handle 'no <property>' in config-edit mode.
pub fn no_server_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: no <host|port|username|dkron>");
        return;
    }

    if let Some(ref mut server) = state.pending_server {
        match args[0] {
            "host"     => { server.host = None;      println!("  host cleared."); }
            "port"     => { server.port = None;      println!("  port cleared."); }
            "username" => { server.username = None;  println!("  username cleared."); }
            "dkron"    => { server.dkron_url = None; println!("  dkron cleared."); }
            _ => println!("% Unknown property: '{}'", args[0]),
        }
    }
}

/// Show the pending server connection settings.
pub fn show_pending_server(state: &ShellState) {
    match &state.pending_server {
        Some(server) => server.display(),
        None => println!("% No pending configuration."),
    }
}

/// Commit the pending server connection to disk.
pub fn commit_server(state: &mut ShellState) {
    if let Some(server) = state.pending_server.take() {
        state.config.server = server;
        match state.config.save() {
            Ok(()) => {
                info!("Committed server connection settings");
                println!("Server connection settings committed.");
            }
            Err(e) => {
                eprintln!("% Error saving config: {}", e);
                return;
            }
        }
        state.mode = Mode::Exec;
    }
}

/// Abort server config editing, discard pending changes.
pub fn abort_server(state: &mut ShellState) {
    info!("Aborted server config edit, discarding changes");
    println!("Changes discarded.");
    state.pending_server = None;
    state.mode = Mode::Exec;
}

/// Exit config-edit mode (warns if uncommitted changes).
pub fn exit_config_edit(state: &mut ShellState) {
    if state.pending_server.is_some() {
        println!("% You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
        return;
    }
    state.mode = Mode::Exec;
}

// ============================================================
// Endpoint-edit mode commands
// ============================================================

/// Print help for endpoint-edit mode.
pub fn help_endpoint_edit() {
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
        println!("% Usage: protocol <sftp|ftp|http|https>");
        return;
    }

    let proto = match args[0].to_lowercase().as_str() {
        "sftp"  => Protocol::Sftp,
        "ftp"   => Protocol::Ftp,
        "ftps"  => Protocol::Ftps,
        "http"  => Protocol::Http,
        "https" => Protocol::Https,
        _ => {
            println!("% Unknown protocol '{}'. Available: sftp, ftp, ftps, http, https", args[0]);
            return;
        }
    };

    if let Some(ref mut ep) = state.pending_endpoint {
        info!("Set protocol = {}", proto);
        ep.protocol = proto.clone();
        println!("  protocol → {}", proto);
    }
}

/// Set the host on the pending endpoint.
pub fn set_host(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: host <address>");
        return;
    }

    let value = args[0].to_string();
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.host = Some(value.clone());
        info!("Set host to '{}'", value);
        println!("  host → {}", value);
    }
}

/// Set the port on the pending endpoint.
pub fn set_port(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: port <number>");
        return;
    }

    let value: u16 = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("% Invalid port number: '{}'", args[0]);
            return;
        }
    };

    if let Some(ref mut ep) = state.pending_endpoint {
        ep.port = Some(value);
        info!("Set port to {}", value);
        println!("  port → {}", value);
    }
}

/// Set the username on the pending endpoint.
pub fn set_username(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: username <user>");
        return;
    }

    let value = args[0].to_string();
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.username = Some(value.clone());
        info!("Set username to '{}'", value);
        println!("  username → {}", value);
    }
}

/// Set the password on the pending endpoint.
pub fn set_password(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: password <pass>");
        return;
    }

    let value = args.join(" ");
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.password = Some(value);
        info!("Set password");
        println!("  password → ********");
    }
}

/// Set the SSH key path on the pending endpoint.
pub fn set_ssh_key(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: ssh_key <path>");
        return;
    }

    let value = args.join(" ");
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.ssh_key = Some(value.clone());
        info!("Set ssh_key to '{}'", value);
        println!("  ssh_key → {}", value);
    }
}

// ---- FTP/FTPS-specific setters ----

/// Set FTPS negotiation mode (explicit | implicit). Only meaningful
/// when the endpoint protocol is `ftps` — but we don't enforce that
/// here; the field is harmless on other protocols.
pub fn set_ftps_mode(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: ftps_mode <explicit|implicit>");
        return;
    }
    let mode = match args[0].to_lowercase().as_str() {
        "explicit" => FtpsMode::Explicit,
        "implicit" => FtpsMode::Implicit,
        _ => {
            println!("% Unknown ftps_mode '{}'. Available: explicit, implicit", args[0]);
            return;
        }
    };
    if let Some(ref mut ep) = state.pending_endpoint {
        info!("Set ftps_mode = {}", mode);
        println!("  ftps_mode → {}", mode);
        ep.ftps_mode = Some(mode);
    }
}

/// Set passive (true) or active (false) FTP mode.
pub fn set_passive(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: passive <yes|no>  (yes=PASV, no=active mode)");
        return;
    }
    let value = match args[0].to_lowercase().as_str() {
        "yes" | "true"  | "on"  => true,
        "no"  | "false" | "off" => false,
        _ => {
            println!("% Expected yes/no, got '{}'", args[0]);
            return;
        }
    };
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.passive = Some(value);
        info!("Set passive = {}", value);
        println!("  passive → {} ({} mode)", value, if value { "passive" } else { "active" });
    }
}

/// Set whether FTPS server certificates are validated.
pub fn set_verify_tls(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: verify_tls <yes|no>");
        return;
    }
    let value = match args[0].to_lowercase().as_str() {
        "yes" | "true"  | "on"  => true,
        "no"  | "false" | "off" => false,
        _ => {
            println!("% Expected yes/no, got '{}'", args[0]);
            return;
        }
    };
    if let Some(ref mut ep) = state.pending_endpoint {
        ep.verify_tls = Some(value);
        info!("Set verify_tls = {}", value);
        if !value {
            println!("  verify_tls → no  (WARNING: server cert will not be validated)");
        } else {
            println!("  verify_tls → yes");
        }
    }
}

/// Handle 'no <property>' in endpoint-edit mode.
pub fn no_endpoint_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: no <protocol|host|port|username|password|password_ref|ssh_key|ssh_key_ref|ftps_mode|passive|verify_tls>");
        return;
    }

    if let Some(ref mut ep) = state.pending_endpoint {
        match args[0] {
            "protocol"     => { ep.protocol = Protocol::Sftp; println!("  protocol reset to sftp (default)."); }
            "host"         => { ep.host = None;         println!("  host cleared."); }
            "port"         => { ep.port = None;         println!("  port cleared."); }
            "username"     => { ep.username = None;     println!("  username cleared."); }
            "password"     => { ep.password = None;     println!("  password cleared."); }
            "password_ref" => { ep.password_ref = None; println!("  password_ref cleared."); }
            "ssh_key"      => { ep.ssh_key = None;      println!("  ssh_key cleared."); }
            "ssh_key_ref"  => { ep.ssh_key_ref = None;  println!("  ssh_key_ref cleared."); }
            "ftps_mode"    => { ep.ftps_mode = None;    println!("  ftps_mode reset to default (explicit)."); }
            "passive"      => { ep.passive = None;      println!("  passive reset to default (yes)."); }
            "verify_tls"   => { ep.verify_tls = None;   println!("  verify_tls reset to default (yes)."); }
            _ => println!("% Unknown property: '{}'", args[0]),
        }
    }
}

/// Show the pending endpoint configuration.
pub fn show_pending_endpoint(state: &ShellState) {
    let ep_name = match &state.mode {
        Mode::EndpointEdit(name) => name.clone(),
        _ => return,
    };

    match &state.pending_endpoint {
        Some(ep) => ep.display(&ep_name),
        None => println!("% No pending configuration."),
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

    let success = {
        if !has_rpc(state) { return; }
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::PutEndpoint { name: ep_name.clone(), endpoint: ep }) {
            Ok(Response::Ok) => true,
            Err(e) => { eprintln!("% Error: {}", e); false }
            _ => false,
        }
    };

    if success {
        state.pending_endpoint = None;
        info!("Committed endpoint '{}'", ep_name);
        println!("Endpoint '{}' committed.", ep_name);
        state.mode = Mode::Exec;
    }
}

/// Abort endpoint editing, discard pending changes.
pub fn abort_endpoint(state: &mut ShellState) {
    info!("Aborted endpoint edit, discarding changes");
    println!("Changes discarded.");
    state.pending_endpoint = None;
    state.mode = Mode::Exec;
}

/// Exit endpoint-edit mode (warns if uncommitted changes).
pub fn exit_endpoint_edit(state: &mut ShellState) {
    if state.pending_endpoint.is_some() {
        println!("% You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
        return;
    }
    state.mode = Mode::Exec;
}

// ============================================================
// Key-edit mode commands
// ============================================================

/// Print help for key-edit mode.
pub fn help_key_edit() {
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
        println!("% Usage: type <public|private>");
        return;
    }

    let key_type = match args[0].to_lowercase().as_str() {
        "public"  => KeyType::Public,
        "private" => KeyType::Private,
        _ => {
            println!("% Invalid key type '{}'. Use 'public' or 'private'.", args[0]);
            return;
        }
    };

    if let Some(ref mut k) = state.pending_key {
        info!("Set key type to '{}'", key_type);
        println!("  type → {}", key_type);
        k.key_type = Some(key_type);
    }
}

/// Set the key contents via multi-line paste mode.
/// Reads from stdin until a line containing only '.' is entered.
pub fn set_key_contents(_args: &[&str], state: &mut ShellState) {
    if state.pending_key.is_none() {
        return;
    }

    println!("Paste key contents below. Enter a single '.' on its own line to finish:");

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
                eprintln!("% Read error: {}", e);
                return;
            }
        }
    }

    if lines.is_empty() {
        println!("% No content entered.");
        return;
    }

    let value = lines.join("\n");
    let line_count = lines.len();

    if let Some(ref mut k) = state.pending_key {
        k.contents = Some(value);
        info!("Set key contents ({} lines)", line_count);
        println!("  contents set ({} lines)", line_count);
    }
}

/// Load key contents from a file on disk.
pub fn load_key_file(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: load <filepath>");
        return;
    }

    let filepath = args.join(" ");
    let contents = match std::fs::read_to_string(&filepath) {
        Ok(c) => c,
        Err(e) => {
            println!("% Could not read file '{}': {}", filepath, e);
            return;
        }
    };

    if let Some(ref mut k) = state.pending_key {
        let line_count = contents.lines().count();
        k.contents = Some(contents);
        info!("Loaded key contents from '{}' ({} lines)", filepath, line_count);
        println!("  contents loaded from '{}' ({} lines)", filepath, line_count);
    }
}

/// Handle 'no <property>' in key-edit mode.
pub fn no_key_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: no <type|contents|contents_ref>");
        return;
    }

    if let Some(ref mut k) = state.pending_key {
        match args[0] {
            "type"         => { k.key_type = None;     println!("  type cleared."); }
            "contents"     => { k.contents = None;     println!("  contents cleared."); }
            "contents_ref" => { k.contents_ref = None; println!("  contents_ref cleared."); }
            _ => println!("% Unknown property: '{}'", args[0]),
        }
    }
}

/// Show the pending key configuration.
pub fn show_pending_key(state: &ShellState) {
    let key_name = match &state.mode {
        Mode::KeyEdit(name) => name.clone(),
        _ => return,
    };

    match &state.pending_key {
        Some(k) => k.display(&key_name),
        None => println!("% No pending configuration."),
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

    let success = {
        if !has_rpc(state) { return; }
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::PutKey { name: key_name.clone(), key: k }) {
            Ok(Response::Ok) => true,
            Err(e) => { eprintln!("% Error: {}", e); false }
            _ => false,
        }
    };

    if success {
        state.pending_key = None;
        info!("Committed key '{}'", key_name);
        println!("Key '{}' committed.", key_name);
        state.mode = Mode::Exec;
    }
}

/// Abort key editing, discard pending changes.
pub fn abort_key(state: &mut ShellState) {
    info!("Aborted key edit, discarding changes");
    println!("Changes discarded.");
    state.pending_key = None;
    state.mode = Mode::Exec;
}

/// Exit key-edit mode (warns if uncommitted changes).
pub fn exit_key_edit(state: &mut ShellState) {
    if state.pending_key.is_some() {
        println!("% You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
        return;
    }
    state.mode = Mode::Exec;
}

// ============================================================
// Feed-edit mode commands
// ============================================================

/// Print help for feed-edit mode.
pub fn help_feed_edit() {
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
        println!("% Usage: source <endpoint>:<path>");
        println!("% Example: source myserver:/inbound/data");
        return;
    }

    let input = args.join("");
    let feed_path = match parse_feed_path(&input) {
        Some(fp) => fp,
        None => {
            println!("% Invalid format. Use: source <endpoint>:<path>");
            return;
        }
    };

    // Warn if endpoint doesn't exist (best-effort RPC check)
    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Endpoint(None)) = rpc.call(Request::GetEndpoint { name: feed_path.endpoint.clone() }) {
            println!("  (warning: endpoint '{}' does not exist yet)", feed_path.endpoint);
        }
    }

    if let Some(ref mut feed) = state.pending_feed {
        if feed.sources.iter().any(|s| feed_paths_match(s, &feed_path)) {
            println!("% Source '{}' already exists in this feed.", feed_path);
            return;
        }
        info!("Added source '{}'", feed_path);
        println!("  source + {}", feed_path);
        feed.sources.push(feed_path);
    }
}

/// Add a destination to the pending feed.
pub fn set_destination(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: destination <endpoint>:<path>");
        println!("% Example: destination archive:/backup/landing");
        return;
    }

    let input = args.join("");
    let feed_path = match parse_feed_path(&input) {
        Some(fp) => fp,
        None => {
            println!("% Invalid format. Use: destination <endpoint>:<path>");
            return;
        }
    };

    // Warn if endpoint doesn't exist (best-effort RPC check)
    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Endpoint(None)) = rpc.call(Request::GetEndpoint { name: feed_path.endpoint.clone() }) {
            println!("  (warning: endpoint '{}' does not exist yet)", feed_path.endpoint);
        }
    }

    if let Some(ref mut feed) = state.pending_feed {
        if feed.destinations.iter().any(|d| feed_paths_match(d, &feed_path)) {
            println!("% Destination '{}' already exists in this feed.", feed_path);
            return;
        }
        info!("Added destination '{}'", feed_path);
        println!("  destination + {}", feed_path);
        feed.destinations.push(feed_path);
    }
}

/// Add a process step to the pending feed.
/// Usage: process encrypt <keyname>
///        process decrypt <keyname>
pub fn add_process(args: &[&str], state: &mut ShellState) {
    if args.len() < 2 {
        println!("% Usage: process <encrypt|decrypt> <keyname>");
        println!("% Example: process decrypt vendor-private-key");
        println!("% Example: process encrypt partner-public-key");
        return;
    }

    let action = args[0];
    let key_name = args[1].to_string();

    // Validate key exists and is the right type (best-effort RPC check)
    if let Some(ref mut rpc) = state.rpc {
        match rpc.call(Request::GetKey { name: key_name.clone() }) {
            Ok(Response::Key(Some(k))) => {
                if action == "encrypt" && k.key_type.as_ref() != Some(&KeyType::Public) {
                    println!("  (warning: key '{}' is not marked as public — encrypt requires a public key)", key_name);
                }
                if action == "decrypt" && k.key_type.as_ref() != Some(&KeyType::Private) {
                    println!("  (warning: key '{}' is not marked as private — decrypt requires a private key)", key_name);
                }
            }
            Ok(Response::Key(None)) => {
                println!("  (warning: key '{}' does not exist yet)", key_name);
            }
            _ => {}
        }
    }

    let step = match action {
        "encrypt" => ProcessStep::Encrypt { key: key_name },
        "decrypt" => ProcessStep::Decrypt { key: key_name },
        _ => {
            println!("% Unknown process action '{}'. Use 'encrypt' or 'decrypt'.", action);
            return;
        }
    };

    if let Some(ref mut feed) = state.pending_feed {
        info!("Added process step: {}", step);
        println!("  process + {}", step);
        feed.process.push(step);
    }
}

/// Add a cron schedule to the pending feed.
pub fn set_schedule(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: schedule <cron expression>");
        println!("% Example: schedule * * * * *       (every minute)");
        println!("% Example: schedule 0 */6 * * *     (every 6 hours)");
        println!("% Format: min hour day month weekday");
        return;
    }

    let cron_expr = args.join(" ");
    if let Some(ref mut feed) = state.pending_feed {
        if feed.schedules.contains(&cron_expr) {
            println!("% Schedule '{}' already exists in this feed.", cron_expr);
            return;
        }
        feed.schedules.push(cron_expr.clone());
        info!("Added schedule '{}'", cron_expr);
        println!("  schedule + {}", cron_expr);
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
        println!("% Usage: flag <name> <yes|no>");
        println!("% Available flags:");
        println!("    enabled                        Enable or disable this feed");
        println!("    delete_source_after_transfer   Delete source files after successful transfer");
        return;
    }

    let flag_name = args[0];
    let value = match parse_yes_no(args[1]) {
        Some(v) => v,
        None => {
            println!("% Invalid value '{}'. Use 'yes' or 'no'.", args[1]);
            return;
        }
    };

    if let Some(ref mut feed) = state.pending_feed {
        match flag_name {
            "enabled" => {
                feed.flags.enabled = value;
                info!("Set flag enabled = {}", if value { "yes" } else { "no" });
                println!("  enabled → {}", if value { "yes" } else { "no" });
            }
            "delete_source_after_transfer" => {
                feed.flags.delete_source_after_transfer = value;
                info!("Set flag delete_source_after_transfer = {}", if value { "yes" } else { "no" });
                println!("  delete_source_after_transfer → {}", if value { "yes" } else { "no" });
            }
            _ => {
                println!("% Unknown flag: '{}'", flag_name);
                println!("% Available flags: enabled, delete_source_after_transfer");
            }
        }
    }
}

/// Handle 'no <property> [value]' in feed-edit mode.
pub fn no_feed_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: no <source|process|destination|schedule> [value]");
        return;
    }

    if let Some(ref mut feed) = state.pending_feed {
        let property = args[0];
        let value_args = &args[1..];

        match property {
            "source" => {
                if value_args.is_empty() {
                    let count = feed.sources.len();
                    feed.sources.clear();
                    println!("  All sources removed ({} cleared).", count);
                } else {
                    let input = value_args.join("");
                    if let Some(fp) = parse_feed_path(&input) {
                        if let Some(pos) = feed.sources.iter().position(|s| feed_paths_match(s, &fp)) {
                            feed.sources.remove(pos);
                            println!("  source - {}", fp);
                        } else {
                            println!("% Source '{}' not found.", fp);
                        }
                    } else {
                        println!("% Invalid format. Use: no source <endpoint>:<path>");
                    }
                }
            }
            "process" => {
                if value_args.is_empty() {
                    let count = feed.process.len();
                    feed.process.clear();
                    println!("  All process steps removed ({} cleared).", count);
                } else {
                    let index_str = value_args[0];
                    match index_str.parse::<usize>() {
                        Ok(idx) if idx >= 1 && idx <= feed.process.len() => {
                            let removed = feed.process.remove(idx - 1);
                            println!("  process - [{}] {}", idx, removed);
                        }
                        _ => {
                            println!("% Invalid index '{}'. Use 1-{} or omit to clear all.",
                                index_str, feed.process.len());
                        }
                    }
                }
            }
            "destination" => {
                if value_args.is_empty() {
                    let count = feed.destinations.len();
                    feed.destinations.clear();
                    println!("  All destinations removed ({} cleared).", count);
                } else {
                    let input = value_args.join("");
                    if let Some(fp) = parse_feed_path(&input) {
                        if let Some(pos) = feed.destinations.iter().position(|d| feed_paths_match(d, &fp)) {
                            feed.destinations.remove(pos);
                            println!("  destination - {}", fp);
                        } else {
                            println!("% Destination '{}' not found.", fp);
                        }
                    } else {
                        println!("% Invalid format. Use: no destination <endpoint>:<path>");
                    }
                }
            }
            "nextstep" => {
                if value_args.is_empty() {
                    let count = feed.nextsteps.len();
                    feed.nextsteps.clear();
                    println!("  All next steps removed ({} cleared).", count);
                } else {
                    let index_str = value_args[0];
                    match index_str.parse::<usize>() {
                        Ok(idx) if idx >= 1 && idx <= feed.nextsteps.len() => {
                            let removed = feed.nextsteps.remove(idx - 1);
                            println!("  nextstep - [{}] {}", idx, removed.display_inline());
                        }
                        _ => {
                            println!("% Invalid index '{}'. Use 1-{} or omit to clear all.",
                                index_str, feed.nextsteps.len());
                        }
                    }
                }
            }
            "schedule" => {
                if value_args.is_empty() {
                    let count = feed.schedules.len();
                    feed.schedules.clear();
                    println!("  All schedules removed ({} cleared).", count);
                } else {
                    let expr = value_args.join(" ");
                    if let Some(pos) = feed.schedules.iter().position(|s| s == &expr) {
                        feed.schedules.remove(pos);
                        println!("  schedule - {}", expr);
                    } else {
                        println!("% Schedule '{}' not found.", expr);
                    }
                }
            }
            _ => println!("% Unknown property: '{}'", property),
        }
    }
}

/// Move a nextstep from one position to another (1-based indices).
pub fn move_nextstep(args: &[&str], state: &mut ShellState) {
    if args.len() < 3 || args[0] != "nextstep" {
        println!("% Usage: move nextstep <from> <to>");
        return;
    }

    if let Some(ref mut feed) = state.pending_feed {
        let len = feed.nextsteps.len();
        if len < 2 {
            println!("% Need at least 2 next steps to reorder.");
            return;
        }

        let from = match args[1].parse::<usize>() {
            Ok(i) if i >= 1 && i <= len => i,
            _ => {
                println!("% Invalid 'from' index '{}'. Use 1-{}.", args[1], len);
                return;
            }
        };

        let to = match args[2].parse::<usize>() {
            Ok(i) if i >= 1 && i <= len => i,
            _ => {
                println!("% Invalid 'to' index '{}'. Use 1-{}.", args[2], len);
                return;
            }
        };

        if from == to {
            println!("% Indices are the same, nothing to move.");
            return;
        }

        let ns = feed.nextsteps.remove(from - 1);
        feed.nextsteps.insert(to - 1, ns);
        info!("Moved nextstep from position {} to {}", from, to);
        println!("  Moved nextstep [{}] → [{}].", from, to);

        for (i, ns) in feed.nextsteps.iter().enumerate() {
            println!("    [{}] {}", i + 1, ns.display_inline());
        }
    }
}

/// Show the pending feed configuration.
pub fn show_pending_feed(state: &ShellState) {
    let feed_name = match &state.mode {
        Mode::FeedEdit(name) => name.clone(),
        _ => return,
    };

    match &state.pending_feed {
        Some(feed) => feed.display(&feed_name),
        None => println!("% No pending configuration."),
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

    let success = {
        if !has_rpc(state) { return; }
        let rpc = state.rpc.as_mut().unwrap();
        match rpc.call(Request::PutFeed { name: feed_name.clone(), feed }) {
            Ok(Response::Ok) => true,
            Err(e) => { eprintln!("% Error: {}", e); false }
            _ => false,
        }
    };

    if success {
        state.pending_feed = None;
        info!("Committed feed '{}'", feed_name);
        println!("Feed '{}' committed.", feed_name);
        // Dkron schedule sync is handled daemon-side after PutFeed.

        state.mode = Mode::Exec;
    }
}

/// Abort feed editing, discard pending changes.
pub fn abort_feed(state: &mut ShellState) {
    info!("Aborted feed edit, discarding changes");
    println!("Changes discarded.");
    state.pending_feed = None;
    state.mode = Mode::Exec;
}

/// Exit feed-edit mode (warns if uncommitted changes).
pub fn exit_feed_edit(state: &mut ShellState) {
    if state.pending_feed.is_some() {
        println!("% You have uncommitted changes. Use 'commit' to save or 'abort' to discard.");
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
    println!("Configuring a new next step. Type 'help' for options, 'done' to add it.");
}

/// Print help for nextstep-edit mode.
pub fn help_nextstep_edit() {
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
        println!("% Usage: type <feed|email>");
        return;
    }

    match args[0] {
        "feed" => {
            if let Some(ref mut ns) = state.pending_nextstep {
                ns.action = NextStepAction::RunFeed { feed: String::new() };
                println!("  type → feed");
            }
        }
        "email" => {
            if let Some(ref mut ns) = state.pending_nextstep {
                ns.action = NextStepAction::SendEmail { emails: Vec::new() };
                println!("  type → email");
            }
        }
        "sleep" => {
            if let Some(ref mut ns) = state.pending_nextstep {
                ns.action = NextStepAction::Sleep { seconds: 0 };
                println!("  type → sleep");
            }
        }
        _ => println!("% Unknown type '{}'. Available: feed, email, sleep", args[0]),
    }
}

/// Set the nextstep target.
pub fn set_nextstep_target(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: target <name>              (for feed type)");
        println!("        target <email1,email2,...>  (for email type)");
        println!("        target <seconds>            (for sleep type)");
        return;
    }

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
                    println!("  (warning: feed '{}' does not exist yet)", target);
                }
            }
        }
    }

    if let Some(ref mut ns) = state.pending_nextstep {
        match &mut ns.action {
            NextStepAction::RunFeed { feed } => {
                let target = args[0].to_string();
                *feed = target.clone();
                println!("  target → {}", target);
            }
            NextStepAction::SendEmail { emails } => {
                let raw = args.join(" ");
                let parsed: Vec<String> = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if parsed.is_empty() {
                    println!("% No email addresses provided.");
                    return;
                }
                *emails = parsed.clone();
                println!("  target → {}", parsed.join(", "));
            }
            NextStepAction::Sleep { seconds } => {
                match args[0].parse::<u64>() {
                    Ok(secs) => {
                        *seconds = secs;
                        println!("  target → {}s", secs);
                    }
                    Err(_) => {
                        println!("% Invalid number '{}'. Provide seconds as a whole number.", args[0]);
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
        println!("% Usage: on <success|noaction|failed>");
        return;
    }

    let condition = match parse_trigger(args[0]) {
        Some(c) => c,
        None => {
            println!("% Unknown condition '{}'. Use: success, noaction, failed", args[0]);
            return;
        }
    };

    if let Some(ref mut ns) = state.pending_nextstep {
        if ns.on.contains(&condition) {
            println!("% Condition '{}' already set.", condition);
            return;
        }
        ns.on.push(condition.clone());
        ns.on.sort();
        println!("  on + {}", condition);
    }
}

/// Handle 'no on <condition>' in nextstep-edit mode.
pub fn no_nextstep_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: no on <success|noaction|failed>");
        return;
    }

    if args[0] != "on" {
        println!("% Usage: no on <success|noaction|failed>");
        return;
    }

    if args.len() < 2 {
        if let Some(ref mut ns) = state.pending_nextstep {
            ns.on.clear();
            println!("  All conditions cleared.");
        }
        return;
    }

    let condition = match parse_trigger(args[1]) {
        Some(c) => c,
        None => {
            println!("% Unknown condition '{}'. Use: success, noaction, failed", args[1]);
            return;
        }
    };

    if let Some(ref mut ns) = state.pending_nextstep {
        if let Some(pos) = ns.on.iter().position(|c| c == &condition) {
            ns.on.remove(pos);
            println!("  on - {}", condition);
        } else {
            println!("% Condition '{}' not set.", condition);
        }
    }
}

/// Show the pending nextstep configuration.
pub fn show_pending_nextstep(state: &ShellState) {
    match &state.pending_nextstep {
        Some(ns) => {
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
        }
        None => println!("% No pending next step."),
    }
}

/// Finish building the nextstep and add it to the pending feed.
pub fn done_nextstep(state: &mut ShellState) {
    let feed_name = match &state.mode {
        Mode::NextStepEdit(name) => name.clone(),
        _ => return,
    };

    if let Some(ref ns) = state.pending_nextstep {
        match &ns.action {
            NextStepAction::RunFeed { feed } => {
                if feed.is_empty() {
                    println!("% Target feed not set. Use 'target <feedname>'.");
                    return;
                }
            }
            NextStepAction::SendEmail { emails } => {
                if emails.is_empty() {
                    println!("% No email addresses set. Use 'target <email1,email2,...>'.");
                    return;
                }
            }
            NextStepAction::Sleep { seconds } => {
                if *seconds == 0 {
                    println!("% Sleep duration not set. Use 'target <seconds>'.");
                    return;
                }
            }
        }

        if ns.on.is_empty() {
            println!("% No trigger conditions set. Use 'on <success|noaction|failed>'.");
            return;
        }
    }

    if let Some(ns) = state.pending_nextstep.take() {
        info!("Added next step: {}", ns.display_inline());
        println!("  nextstep + {}", ns.display_inline());
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

    println!("Next step discarded.");
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
        println!("Usage: show <subcommand>");
        println!("  endpoints          List all endpoints");
        println!("  endpoint <name>    Show endpoint details");
        println!("  keys               List all keys");
        println!("  key <name>         Show key details");
        println!("  feeds              List all feeds");
        println!("  feed <name>        Show feed details");
        println!("  runs <feed> [N]    Show run history for a feed (default: 25)");
        println!("  server             Show server connection settings");
        println!("  version            Show SFTPflow version");
        return;
    }

    match args[0] {
        "version"   => version(),
        "server"    => state.config.server.display(),
        "secrets"   => show_secrets(state),
        "endpoints" => show_endpoints(state),
        "endpoint"  => {
            if args.len() < 2 {
                println!("% Usage: show endpoint <name>");
                return;
            }
            show_endpoint_detail(args[1], state);
        }
        "keys"      => show_keys(state),
        "key"       => {
            if args.len() < 2 {
                println!("% Usage: show key <name>");
                return;
            }
            show_key_detail(args[1], state);
        }
        "feeds"     => show_feeds(state),
        "feed"      => {
            if args.len() < 2 {
                println!("% Usage: show feed <name>");
                return;
            }
            show_feed_detail(args[1], state);
        }
        "runs"      => {
            if args.len() < 2 {
                println!("% Usage: show runs <feed> [limit]");
                return;
            }
            let limit = args.get(2).and_then(|s| s.parse::<u32>().ok());
            show_runs(args[1], limit, state);
        }
        _ => println!("% Unknown show subcommand: '{}'", args[0]),
    }
}

/// List all configured endpoints (fetched from daemon).
fn show_endpoints(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    let names = match rpc.call(Request::ListEndpoints) {
        Ok(Response::Names(n)) => n,
        Err(e) => { println!("% Error: {}", e); return; }
        _ => return,
    };

    if names.is_empty() {
        println!("No endpoints configured.");
        return;
    }

    println!("Configured endpoints:");
    for name in &names {
        match rpc.call(Request::GetEndpoint { name: name.clone() }) {
            Ok(Response::Endpoint(Some(ep))) => {
                let host = ep.host.as_deref().unwrap_or("(no host)");
                let port = ep.port.map_or(String::new(), |p| format!(":{}", p));
                let user = ep.username.as_deref().unwrap_or("(no user)");
                println!("  {:20} {}@{}{}", name, user, host, port);
            }
            _ => println!("  {:20} (error fetching details)", name),
        }
    }
}

/// Show detail for a single endpoint (fetched from daemon).
fn show_endpoint_detail(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetEndpoint { name: name.to_string() }) {
        Ok(Response::Endpoint(Some(ep))) => ep.display(name),
        Ok(Response::Endpoint(None)) => println!("% Endpoint '{}' does not exist.", name),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// List all configured keys (fetched from daemon).
fn show_keys(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    let names = match rpc.call(Request::ListKeys) {
        Ok(Response::Names(n)) => n,
        Err(e) => { println!("% Error: {}", e); return; }
        _ => return,
    };

    if names.is_empty() {
        println!("No keys configured.");
        return;
    }

    println!("Configured keys:");
    for name in &names {
        match rpc.call(Request::GetKey { name: name.clone() }) {
            Ok(Response::Key(Some(key))) => {
                let ktype = key.key_type.as_ref().map_or("(no type)", |t| match t {
                    KeyType::Public  => "public",
                    KeyType::Private => "private",
                });
                let has_contents = if key.contents.is_some() { "loaded" } else { "empty" };
                println!("  {:20} {:10} {}", name, ktype, has_contents);
            }
            _ => println!("  {:20} (error fetching details)", name),
        }
    }
}

/// Show detail for a single key (fetched from daemon).
fn show_key_detail(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetKey { name: name.to_string() }) {
        Ok(Response::Key(Some(key))) => key.display(name),
        Ok(Response::Key(None)) => println!("% Key '{}' does not exist.", name),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// List all configured feeds (fetched from daemon via FeedSummaries).
fn show_feeds(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    let summaries = match rpc.call(Request::ListFeeds) {
        Ok(Response::FeedSummaries(s)) => s,
        Err(e) => { println!("% Error: {}", e); return; }
        _ => return,
    };

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
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetFeed { name: name.to_string() }) {
        Ok(Response::Feed(Some(feed))) => feed.display(name),
        Ok(Response::Feed(None)) => println!("% Feed '{}' does not exist.", name),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// Show run history for a feed (fetched from daemon).
fn show_runs(feed: &str, limit: Option<u32>, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::GetRunHistory { feed: feed.to_string(), limit }) {
        Ok(Response::RunHistory(entries)) => {
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
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
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

/// Route 'secret add|list|delete ...' in exec mode.
pub fn secret(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: secret <add|list|delete> [name]");
        return;
    }

    match args[0] {
        "add"    => {
            if args.len() < 2 {
                println!("% Usage: secret add <name>");
                return;
            }
            secret_add(args[1], state);
        }
        "list"   => secret_list(state),
        "delete" => {
            if args.len() < 2 {
                println!("% Usage: secret delete <name>");
                return;
            }
            secret_delete(args[1], state);
        }
        _ => println!("% Unknown secret subcommand '{}'. Use add, list, or delete.", args[0]),
    }
}

/// Prompt for a secret value (hidden) and send a PutSecret RPC.
fn secret_add(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }

    // Prompt twice and require both to match, so typos don't silently
    // seal the wrong value into the store.
    let value = match rpassword::prompt_password(format!("Value for '{}': ", name)) {
        Ok(v) => v,
        Err(e) => { println!("% Could not read value: {}", e); return; }
    };
    if value.is_empty() {
        println!("% Empty value — aborting.");
        return;
    }
    let confirm = match rpassword::prompt_password("Confirm: ") {
        Ok(v) => v,
        Err(e) => { println!("% Could not read confirmation: {}", e); return; }
    };
    if confirm != value {
        println!("% Values did not match — aborting.");
        return;
    }

    let rpc = state.rpc.as_mut().unwrap();
    match rpc.call(Request::PutSecret { name: name.to_string(), value }) {
        Ok(Response::Ok) => {
            info!("Stored secret '{}'", name);
            println!("Secret '{}' stored.", name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// Send a ListSecrets RPC and print the names.
fn secret_list(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::ListSecrets) {
        Ok(Response::Names(names)) => {
            if names.is_empty() {
                println!("No secrets configured.");
                return;
            }
            println!("Configured secrets ({} total):", names.len());
            for name in &names {
                println!("  {}", name);
            }
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// Send a DeleteSecret RPC.
fn secret_delete(name: &str, state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::DeleteSecret { name: name.to_string() }) {
        Ok(Response::Ok) => {
            info!("Deleted secret '{}'", name);
            println!("Secret '{}' deleted.", name);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
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
        println!("% Usage: password_ref <secret-name>");
        return;
    }
    let name = args[0].to_string();

    // Warn if the secret doesn't exist yet (best-effort RPC check).
    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Names(names)) = rpc.call(Request::ListSecrets) {
            if !names.iter().any(|n| n == &name) {
                println!("  (warning: secret '{}' does not exist yet — use 'secret add {}' first)", name, name);
            }
        }
    }

    if let Some(ref mut ep) = state.pending_endpoint {
        ep.password_ref = Some(name.clone());
        ep.password = None;
        info!("Set password_ref = '{}'", name);
        println!("  password_ref → {}", name);
    }
}

/// `ssh_key_ref <name>` — store a ref to a sealed SSH key by name.
pub fn set_ssh_key_ref(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: ssh_key_ref <secret-name>");
        return;
    }
    let name = args[0].to_string();

    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Names(names)) = rpc.call(Request::ListSecrets) {
            if !names.iter().any(|n| n == &name) {
                println!("  (warning: secret '{}' does not exist yet — use 'secret add {}' first)", name, name);
            }
        }
    }

    if let Some(ref mut ep) = state.pending_endpoint {
        ep.ssh_key_ref = Some(name.clone());
        ep.ssh_key = None;
        info!("Set ssh_key_ref = '{}'", name);
        println!("  ssh_key_ref → {}", name);
    }
}

/// `contents_ref <name>` — store a ref to sealed PGP key material.
pub fn set_key_contents_ref(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: contents_ref <secret-name>");
        return;
    }
    let name = args[0].to_string();

    if let Some(ref mut rpc) = state.rpc {
        if let Ok(Response::Names(names)) = rpc.call(Request::ListSecrets) {
            if !names.iter().any(|n| n == &name) {
                println!("  (warning: secret '{}' does not exist yet — use 'secret add {}' first)", name, name);
            }
        }
    }

    if let Some(ref mut k) = state.pending_key {
        k.contents_ref = Some(name.clone());
        k.contents = None;
        info!("Set contents_ref = '{}'", name);
        println!("  contents_ref → {}", name);
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

/// Route 'cluster status|token|remove|join ...' in exec mode.
pub fn cluster(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: cluster <status|token|remove|join|bootstrap> [args]");
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
                        println!("% Usage: cluster token [ttl-seconds]");
                        return;
                    }
                }
            } else {
                None
            };
            cluster_token(state, ttl);
        }
        "remove" => {
            if args.len() < 2 {
                println!("% Usage: cluster remove <node-id>");
                return;
            }
            let node_id = match args[1].parse::<u64>() {
                Ok(n) => n,
                Err(_) => {
                    println!("% node-id must be a non-negative integer");
                    return;
                }
            };
            cluster_remove(state, node_id);
        }
        "join" => {
            if args.len() < 2 {
                println!("% Usage: cluster join <user@host[:port]>");
                return;
            }
            cluster_join_remote(state, args[1]);
        }
        "bootstrap" => {
            if args.len() < 2 {
                println!("% Usage: cluster bootstrap <user@host[:port]>");
                return;
            }
            cluster_bootstrap_remote(args[1]);
        }
        _ => println!("% Unknown cluster subcommand '{}'. Use status, token, remove, join, or bootstrap.", args[0]),
    }
}

/// Send ClusterStatus and pretty-print the result.
fn cluster_status(state: &mut ShellState) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::ClusterStatus) {
        Ok(Response::ClusterStatus(status)) => {
            println!("Cluster:  {}", status.cluster_id);
            match status.leader_id {
                Some(id) => println!("Leader:   node_id={}", id),
                None     => println!("Leader:   <election in progress>"),
            }
            println!("This node: {}", status.self_id);
            println!();
            // Header + separator. Width chosen to fit a typical
            // 8-byte node_id, an IP:port advertise addr, and a
            // short label without wrapping at 80 columns.
            println!("  {:<8} {:<8} {:<24} {}", "NODE", "ROLE", "ADVERTISE", "LABEL");
            println!("  {:-<8} {:-<8} {:-<24} {:-<20}", "", "", "", "");
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
                    "  {:<8} {:<8} {:<24} {}{}",
                    m.node_id, role, m.advertise_addr, label_str, self_marker,
                );
            }
            println!();
            println!("(* = this node)");
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// Send ClusterMintToken and print the resulting token + expiry.
fn cluster_token(state: &mut ShellState, ttl_seconds: Option<u32>) {
    if !has_rpc(state) { return; }
    let rpc = state.rpc.as_mut().unwrap();

    match rpc.call(Request::ClusterMintToken { ttl_seconds }) {
        Ok(Response::ClusterToken(t)) => {
            info!("Minted cluster join token (expires_at_unix={})", t.expires_at_unix);
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
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
        _ => {}
    }
}

/// Send ClusterRemoveNode after a double-confirm on stdin.
fn cluster_remove(state: &mut ShellState, node_id: u64) {
    if !has_rpc(state) { return; }

    println!("Remove node_id={} from the cluster voter set?", node_id);
    println!("This is irreversible. Type the node id again to confirm:");
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        println!("% Could not read confirmation — aborting.");
        return;
    }
    let typed = input.trim();
    if typed != node_id.to_string() {
        println!("% Confirmation did not match — aborting.");
        return;
    }

    let rpc = state.rpc.as_mut().unwrap();
    match rpc.call(Request::ClusterRemoveNode { node_id }) {
        Ok(Response::Ok) => {
            info!("Removed node_id={} from the cluster", node_id);
            println!("Node {} removed.", node_id);
        }
        Err(RpcError::Proto(e)) => println!("% {}", e.message),
        Err(e) => println!("% Error: {}", e),
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

    // ---- 1. Parse user@host[:port] -----------------------------
    let (user, host, port) = match parse_ssh_target(target) {
        Ok(t) => t,
        Err(msg) => { println!("% {}", msg); return; }
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
                _ => { println!("% No passphrase supplied — aborting."); return; }
            }
        }
    };

    // ---- 3. Mint token + verify we're on the bootstrap node ----
    let rpc = state.rpc.as_mut().unwrap();
    let token = match rpc.call(Request::ClusterMintToken { ttl_seconds: Some(600) }) {
        Ok(Response::ClusterToken(t)) => t.token,
        Err(RpcError::Proto(e)) => {
            println!("% Could not mint join token: {}", e.message);
            println!("%   Tip: in M12 only the bootstrap node holds the token-HMAC secret.");
            println!("%        Reconnect to it via 'config' / 'connect' first.");
            return;
        }
        Err(e) => { println!("% Error minting token: {}", e); return; }
        _ => return,
    };

    // ---- 4. Fetch CA cert + bootstrap advertise addr -----------
    let ca_pem = match rpc.call(Request::ClusterGetCa) {
        Ok(Response::ClusterCaCert(pem)) => pem,
        Err(RpcError::Proto(e)) => { println!("% Could not fetch CA: {}", e.message); return; }
        Err(e) => { println!("% Error fetching CA: {}", e); return; }
        _ => return,
    };
    let seed_advertise = match rpc.call(Request::ClusterStatus) {
        Ok(Response::ClusterStatus(s)) => {
            match s.members.iter().find(|m| m.node_id == s.self_id) {
                Some(m) => m.advertise_addr.clone(),
                None    => { println!("% Could not find self in cluster status"); return; }
            }
        }
        Err(RpcError::Proto(e)) => { println!("% {}", e.message); return; }
        Err(e) => { println!("% Error: {}", e); return; }
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
    println!("Joining {}@{} to cluster (seed = {})", user, host, seed_advertise);

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
        println!("% Remote join failed: {}", msg);
        return;
    }

    // ---- 6. Poll cluster_status for the new member -------------
    println!("Waiting for new node to appear in membership (up to 30s)...");
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let rpc = state.rpc.as_mut().unwrap();
        if let Ok(Response::ClusterStatus(s)) = rpc.call(Request::ClusterStatus) {
            if s.members.len() > initial_member_count {
                println!("Joined! Cluster size is now {}.", s.members.len());
                return;
            }
        }
    }
    println!("% Timed out after 30s. The remote join may still complete shortly —");
    println!("%   re-run 'cluster status' to check, or look at /tmp/sftpflowd-join.log");
    println!("%   on the remote host for diagnostics.");
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
///   2. Read passphrase (env or prompt). The remote daemon needs
///      it to seal its secrets store; the operator must persist
///      it on the remote (e.g. /etc/environment) for restarts.
///   3. SSH in, pipe passphrase on stdin, run `sftpflowd init`
///      (one-shot), then launch `sftpflowd run` via nohup so it
///      survives our SSH session ending.
///   4. Print a connection hint pointing at the new node.
///
/// Preconditions on the remote host:
///   - sftpflowd binary in PATH
///   - writable state-dir (default /var/lib/sftpflow)
///   - sshd accepting the operator's key
fn cluster_bootstrap_remote(target: &str) {
    // ---- 1. Parse user@host[:port] -----------------------------
    let (user, host, port) = match parse_ssh_target(target) {
        Ok(t) => t,
        Err(msg) => { println!("% {}", msg); return; }
    };

    // ---- 2. Read passphrase from env or prompt -----------------
    // Sent inline via SSH stdin so the remote daemon can seal its
    // new secrets store on first init. The operator is responsible
    // for making it available to the remote daemon on subsequent
    // restarts (systemd EnvironmentFile, /etc/environment, etc.) —
    // we only supply it for *this* invocation.
    let passphrase = match std::env::var("SFTPFLOW_PASSPHRASE") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            match rpassword::prompt_password("Cluster passphrase (also needed on the remote host): ") {
                Ok(p) if !p.is_empty() => p,
                _ => { println!("% No passphrase supplied — aborting."); return; }
            }
        }
    };

    info!(
        "cluster bootstrap: target={}@{} port={}",
        user, host, port.unwrap_or(22),
    );
    println!("Bootstrapping new cluster on {}@{}...", user, host);

    // ---- 3. SSH + drive remote sftpflowd init + run ------------
    if let Err(msg) = ssh_drive_remote_bootstrap(user, host, port, &passphrase) {
        println!("% Remote bootstrap failed: {}", msg);
        return;
    }

    // ---- 4. Connect hint ---------------------------------------
    // The CLI talks to the daemon over SSH (NDJSON tunnel), not the
    // Raft port. So the post-bootstrap hint walks the operator
    // through pointing the CLI's `server` config at the new host.
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
}

/// Spawn ssh, pipe just the passphrase on stdin, and drive
/// `sftpflowd init` followed by a detached `sftpflowd run`.
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
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // POSIX-sh script (no bashisms) — matches the join helper's style.
    // Single-quoted Rust raw string so { and } in shell ${} don't
    // collide with format!'s placeholders. There are no placeholders
    // in this script (passphrase comes via stdin), so no .format()
    // call is needed.
    let remote_script = r#"
        set -e
        IFS= read -r SFTPFLOW_PASSPHRASE
        export SFTPFLOW_PASSPHRASE

        # ---- Phase 1: sftpflowd init (one-shot) ----
        INIT_LOG=/tmp/sftpflowd-bootstrap-init.log
        : > "$INIT_LOG"
        if ! sftpflowd init > "$INIT_LOG" 2>&1; then
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
        writeln!(stdin, "{}", passphrase)
            .map_err(|e| format!("writing passphrase: {}", e))?;
        // Drop closes stdin → remote shell sees EOF after `read`.
    }

    let status = child.wait()
        .map_err(|e| format!("ssh wait failed: {}", e))?;
    if !status.success() {
        return Err(format!("ssh exited with status {}", status.code().unwrap_or(-1)));
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
