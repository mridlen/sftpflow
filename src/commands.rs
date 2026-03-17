// ============================================================
// commands.rs - Command implementations
// ============================================================

use log::info;

use crate::cli::{Mode, ShellState};
use crate::feed::{Endpoint, Feed, FeedPath, KeyType, NextStep, NextStepAction, PgpKey, ProcessStep, Protocol, TriggerCondition}; // feed.rs

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
    println!("  show <type> <name>           Show details for one object");
    println!("  show version                 Show SFTPflow version");
    println!();
    println!("  run feed <name>              Manually run a feed (outside of schedule)");
    println!("  config                       Edit server connection settings");
    println!();
    println!("  exit                         Exit SFTPflow");
    println!("  help / ?                     Show this help");
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
    if state.config.endpoints.contains_key(name) {
        println!("% Endpoint '{}' already exists. Use 'edit endpoint {}' to modify it.", name, name);
        return;
    }

    info!("Creating new endpoint '{}'", name);
    println!("Creating new endpoint '{}'.", name);
    state.pending_endpoint = Some(Endpoint::new());
    state.mode = Mode::EndpointEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn create_key(name: &str, state: &mut ShellState) {
    if state.config.keys.contains_key(name) {
        println!("% Key '{}' already exists. Use 'edit key {}' to modify it.", name, name);
        return;
    }

    info!("Creating new key '{}'", name);
    println!("Creating new key '{}'.", name);
    state.pending_key = Some(PgpKey::new());
    state.mode = Mode::KeyEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn create_feed(name: &str, state: &mut ShellState) {
    if state.config.feeds.contains_key(name) {
        println!("% Feed '{}' already exists. Use 'edit feed {}' to modify it.", name, name);
        return;
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
    let endpoint = match state.config.endpoints.get(name) {
        Some(e) => e.clone(),
        None => {
            println!("% Endpoint '{}' does not exist. Use 'create endpoint {}' to create it.", name, name);
            return;
        }
    };

    info!("Editing endpoint '{}'", name);
    println!("Editing endpoint '{}'.", name);
    state.pending_endpoint = Some(endpoint);
    state.mode = Mode::EndpointEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn edit_key(name: &str, state: &mut ShellState) {
    let key = match state.config.keys.get(name) {
        Some(k) => k.clone(),
        None => {
            println!("% Key '{}' does not exist. Use 'create key {}' to create it.", name, name);
            return;
        }
    };

    info!("Editing key '{}'", name);
    println!("Editing key '{}'.", name);
    state.pending_key = Some(key);
    state.mode = Mode::KeyEdit(name.to_string());
    println!("Enter configuration commands. Type 'help' for options, 'commit' to save.");
}

fn edit_feed(name: &str, state: &mut ShellState) {
    let feed = match state.config.feeds.get(name) {
        Some(f) => f.clone(),
        None => {
            println!("% Feed '{}' does not exist. Use 'create feed {}' to create it.", name, name);
            return;
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
    if state.config.endpoints.remove(name).is_none() {
        println!("% Endpoint '{}' does not exist.", name);
        return;
    }

    match state.config.save() {
        Ok(()) => {
            info!("Deleted endpoint '{}'", name);
            println!("Endpoint '{}' deleted.", name);
        }
        Err(e) => eprintln!("% Error saving config: {}", e),
    }
}

fn delete_key(name: &str, state: &mut ShellState) {
    if state.config.keys.remove(name).is_none() {
        println!("% Key '{}' does not exist.", name);
        return;
    }

    match state.config.save() {
        Ok(()) => {
            info!("Deleted key '{}'", name);
            println!("Key '{}' deleted.", name);
        }
        Err(e) => eprintln!("% Error saving config: {}", e),
    }
}

fn delete_feed(name: &str, state: &mut ShellState) {
    if state.config.feeds.remove(name).is_none() {
        println!("% Feed '{}' does not exist.", name);
        return;
    }

    match state.config.save() {
        Ok(()) => {
            info!("Deleted feed '{}'", name);
            println!("Feed '{}' deleted.", name);
        }
        Err(e) => eprintln!("% Error saving config: {}", e),
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
    let endpoint = match state.config.endpoints.remove(old_name) {
        Some(ep) => ep,
        None => {
            println!("% Endpoint '{}' does not exist.", old_name);
            return;
        }
    };

    if state.config.endpoints.contains_key(new_name) {
        state.config.endpoints.insert(old_name.to_string(), endpoint);
        println!("% Endpoint '{}' already exists.", new_name);
        return;
    }

    state.config.endpoints.insert(new_name.to_string(), endpoint);

    // Update all feed source/destination references
    let mut ref_count = 0;
    for (_feed_name, feed) in state.config.feeds.iter_mut() {
        for src in feed.sources.iter_mut() {
            if src.endpoint == old_name {
                src.endpoint = new_name.to_string();
                ref_count += 1;
            }
        }
        for dst in feed.destinations.iter_mut() {
            if dst.endpoint == old_name {
                dst.endpoint = new_name.to_string();
                ref_count += 1;
            }
        }
    }

    match state.config.save() {
        Ok(()) => {
            info!("Renamed endpoint '{}' → '{}', updated {} feed reference(s)", old_name, new_name, ref_count);
            println!("Endpoint '{}' renamed to '{}'.", old_name, new_name);
            if ref_count > 0 {
                println!("  Updated {} feed reference(s).", ref_count);
            }
        }
        Err(e) => eprintln!("% Error saving config: {}", e),
    }
}

fn rename_key(old_name: &str, new_name: &str, state: &mut ShellState) {
    let key = match state.config.keys.remove(old_name) {
        Some(k) => k,
        None => {
            println!("% Key '{}' does not exist.", old_name);
            return;
        }
    };

    if state.config.keys.contains_key(new_name) {
        state.config.keys.insert(old_name.to_string(), key);
        println!("% Key '{}' already exists.", new_name);
        return;
    }

    state.config.keys.insert(new_name.to_string(), key);

    // Update all feed process step references
    let mut ref_count = 0;
    for (_feed_name, feed) in state.config.feeds.iter_mut() {
        for step in feed.process.iter_mut() {
            match step {
                ProcessStep::Encrypt { key } | ProcessStep::Decrypt { key } => {
                    if key == old_name {
                        *key = new_name.to_string();
                        ref_count += 1;
                    }
                }
            }
        }
    }

    match state.config.save() {
        Ok(()) => {
            info!("Renamed key '{}' → '{}', updated {} process reference(s)", old_name, new_name, ref_count);
            println!("Key '{}' renamed to '{}'.", old_name, new_name);
            if ref_count > 0 {
                println!("  Updated {} process reference(s).", ref_count);
            }
        }
        Err(e) => eprintln!("% Error saving config: {}", e),
    }
}

fn rename_feed(old_name: &str, new_name: &str, state: &mut ShellState) {
    let feed = match state.config.feeds.remove(old_name) {
        Some(f) => f,
        None => {
            println!("% Feed '{}' does not exist.", old_name);
            return;
        }
    };

    if state.config.feeds.contains_key(new_name) {
        state.config.feeds.insert(old_name.to_string(), feed);
        println!("% Feed '{}' already exists.", new_name);
        return;
    }

    state.config.feeds.insert(new_name.to_string(), feed);

    // Update nextstep references in all feeds
    let mut ref_count = 0;
    for (_feed_name, f) in state.config.feeds.iter_mut() {
        for ns in f.nextsteps.iter_mut() {
            match &mut ns.action {
                NextStepAction::RunFeed { feed } => {
                    if feed == old_name {
                        *feed = new_name.to_string();
                        ref_count += 1;
                    }
                }
                NextStepAction::SendEmail { .. } => {}  // no feed references to update
                NextStepAction::Sleep { .. } => {}     // no feed references to update
            }
        }
    }

    match state.config.save() {
        Ok(()) => {
            info!("Renamed feed '{}' → '{}'", old_name, new_name);
            println!("Feed '{}' renamed to '{}'.", old_name, new_name);
            if ref_count > 0 {
                println!("  Updated {} nextstep reference(s).", ref_count);
            }
        }
        Err(e) => eprintln!("% Error saving config: {}", e),
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
pub fn run(args: &[&str], state: &ShellState) {
    if args.len() < 2 {
        println!("% Usage: run feed <name>");
        return;
    }

    match args[0] {
        "feed" => run_feed(args[1], state),
        _ => println!("% Unknown run target '{}'. Usage: run feed <name>", args[0]),
    }
}

/// Simulate running a feed manually (interface mockup).
fn run_feed(name: &str, state: &ShellState) {
    let feed = match state.config.feeds.get(name) {
        Some(f) => f,
        None => {
            println!("% Feed '{}' does not exist.", name);
            return;
        }
    };

    if !feed.flags.enabled {
        println!("% Feed '{}' is disabled. Enable it first with: edit feed {} → flag enabled yes", name, name);
        return;
    }

    // Validate that the feed has the minimum required configuration
    if feed.sources.is_empty() {
        println!("% Feed '{}' has no sources configured.", name);
        return;
    }
    if feed.destinations.is_empty() {
        println!("% Feed '{}' has no destinations configured.", name);
        return;
    }

    // Display what would happen (mockup)
    info!("Manual run requested for feed '{}'", name);
    println!("Running feed '{}'...", name);
    println!();

    // Sources
    for src in &feed.sources {
        println!("  [source]      Fetch from {}", src);
    }

    // Process steps
    for step in &feed.process {
        println!("  [process]     {}", step);
    }

    // Destinations
    for dst in &feed.destinations {
        println!("  [destination] Deliver to {}", dst);
    }

    // Next steps
    for ns in &feed.nextsteps {
        println!("  [nextstep]    {}", ns.display_inline());
    }

    println!();
    println!("% Feed run is not yet implemented. This is a preview of what would execute.");
}

// ============================================================
// Config-edit mode commands (server connection)
// ============================================================

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
    println!("  no <property>            Clear a property (host, port, username)");
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

/// Handle 'no <property>' in config-edit mode.
pub fn no_server_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: no <host|port|username>");
        return;
    }

    if let Some(ref mut server) = state.pending_server {
        match args[0] {
            "host"     => { server.host = None;     println!("  host cleared."); }
            "port"     => { server.port = None;     println!("  port cleared."); }
            "username" => { server.username = None;  println!("  username cleared."); }
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
    println!("  protocol <proto>         Set protocol: sftp (default), ftp, http, https");
    println!("  host <address>           Set the hostname or IP address");
    println!("  port <number>            Set the port");
    println!("  username <user>          Set the username");
    println!("  password <pass>          Set the password");
    println!("  ssh_key <path>           Set the path to an SSH private key");
    println!("  no <property>            Clear a property");
    println!("  show                     Show pending configuration");
    println!("  commit                   Save changes to config file");
    println!("  abort                    Discard changes and return to exec mode");
    println!("  exit / end               Same as abort (warns if uncommitted changes)");
    println!("  help / ?                 Show this help");
}

/// Set the host on the pending endpoint.
/// Set the protocol on the pending endpoint.
pub fn set_protocol(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: protocol <sftp|ftp|http|https>");
        return;
    }

    let proto = match args[0].to_lowercase().as_str() {
        "sftp"  => Protocol::Sftp,
        "ftp"   => Protocol::Ftp,
        "http"  => Protocol::Http,
        "https" => Protocol::Https,
        _ => {
            println!("% Unknown protocol '{}'. Available: sftp, ftp, http, https", args[0]);
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

/// Handle 'no <property>' in endpoint-edit mode.
pub fn no_endpoint_command(args: &[&str], state: &mut ShellState) {
    if args.is_empty() {
        println!("% Usage: no <protocol|host|port|username|password|ssh_key>");
        return;
    }

    if let Some(ref mut ep) = state.pending_endpoint {
        match args[0] {
            "protocol" => { ep.protocol = Protocol::Sftp; println!("  protocol reset to sftp (default)."); }
            "host"     => { ep.host = None;     println!("  host cleared."); }
            "port"     => { ep.port = None;     println!("  port cleared."); }
            "username" => { ep.username = None;  println!("  username cleared."); }
            "password" => { ep.password = None;  println!("  password cleared."); }
            "ssh_key"  => { ep.ssh_key = None;   println!("  ssh_key cleared."); }
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

/// Commit the pending endpoint to disk.
pub fn commit_endpoint(state: &mut ShellState) {
    let ep_name = match &state.mode {
        Mode::EndpointEdit(name) => name.clone(),
        _ => return,
    };

    if let Some(ep) = state.pending_endpoint.take() {
        state.config.endpoints.insert(ep_name.clone(), ep);
        match state.config.save() {
            Ok(()) => {
                info!("Committed endpoint '{}'", ep_name);
                println!("Endpoint '{}' committed.", ep_name);
            }
            Err(e) => {
                eprintln!("% Error saving config: {}", e);
                return;
            }
        }
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
    println!("  load <filepath>          Load key contents from a file");
    println!("  no <property>            Clear a property (type, contents)");
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
                // Strip trailing newline for comparison
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
        println!("% Usage: no <type|contents>");
        return;
    }

    if let Some(ref mut k) = state.pending_key {
        match args[0] {
            "type"     => { k.key_type = None;  println!("  type cleared."); }
            "contents" => { k.contents = None;   println!("  contents cleared."); }
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

/// Commit the pending key to disk.
pub fn commit_key(state: &mut ShellState) {
    let key_name = match &state.mode {
        Mode::KeyEdit(name) => name.clone(),
        _ => return,
    };

    if let Some(k) = state.pending_key.take() {
        state.config.keys.insert(key_name.clone(), k);
        match state.config.save() {
            Ok(()) => {
                info!("Committed key '{}'", key_name);
                println!("Key '{}' committed.", key_name);
            }
            Err(e) => {
                eprintln!("% Error saving config: {}", e);
                return;
            }
        }
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

    // Warn if endpoint doesn't exist yet
    if !state.config.endpoints.contains_key(&feed_path.endpoint) {
        println!("  (warning: endpoint '{}' does not exist yet)", feed_path.endpoint);
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

    // Warn if endpoint doesn't exist yet
    if !state.config.endpoints.contains_key(&feed_path.endpoint) {
        println!("  (warning: endpoint '{}' does not exist yet)", feed_path.endpoint);
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

    // Validate key exists and is the right type
    let step = match action {
        "encrypt" => {
            if let Some(k) = state.config.keys.get(&key_name) {
                if k.key_type.as_ref() != Some(&KeyType::Public) {
                    println!("  (warning: key '{}' is not marked as public — encrypt requires a public key)", key_name);
                }
            } else {
                println!("  (warning: key '{}' does not exist yet)", key_name);
            }
            ProcessStep::Encrypt { key: key_name }
        }
        "decrypt" => {
            if let Some(k) = state.config.keys.get(&key_name) {
                if k.key_type.as_ref() != Some(&KeyType::Private) {
                    println!("  (warning: key '{}' is not marked as private — decrypt requires a private key)", key_name);
                }
            } else {
                println!("  (warning: key '{}' does not exist yet)", key_name);
            }
            ProcessStep::Decrypt { key: key_name }
        }
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
                    // Clear all process steps
                    let count = feed.process.len();
                    feed.process.clear();
                    println!("  All process steps removed ({} cleared).", count);
                } else {
                    // Remove by 1-based index
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

        // Show the new order
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

/// Commit the pending feed to disk.
pub fn commit_feed(state: &mut ShellState) {
    let feed_name = match &state.mode {
        Mode::FeedEdit(name) => name.clone(),
        _ => return,
    };

    if let Some(feed) = state.pending_feed.take() {
        state.config.feeds.insert(feed_name.clone(), feed);
        match state.config.save() {
            Ok(()) => {
                info!("Committed feed '{}'", feed_name);
                println!("Feed '{}' committed.", feed_name);
            }
            Err(e) => {
                eprintln!("% Error saving config: {}", e);
                return;
            }
        }
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

    if let Some(ref mut ns) = state.pending_nextstep {
        match &mut ns.action {
            NextStepAction::RunFeed { feed } => {
                let target = args[0].to_string();
                // Warn if feed doesn't exist (it might be the current feed being edited, which is ok)
                if !state.config.feeds.contains_key(&target) {
                    // Check if it matches the feed we're currently editing
                    let editing_self = match &state.mode {
                        Mode::NextStepEdit(name) => name == &target,
                        _ => false,
                    };
                    if !editing_self {
                        println!("  (warning: feed '{}' does not exist yet)", target);
                    }
                }
                *feed = target.clone();
                println!("  target → {}", target);
            }
            NextStepAction::SendEmail { emails } => {
                // Join all args in case spaces around commas, then split on commas
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
        // Clear all conditions
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

    // Validate the nextstep
    if let Some(ref ns) = state.pending_nextstep {
        // Check target is set
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

        // Check at least one condition is set
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
// Shared / show commands
// ============================================================

/// Handle 'show' subcommands in exec mode.
pub fn show(args: &[&str], state: &ShellState) {
    if args.is_empty() {
        println!("Usage: show <subcommand>");
        println!("  endpoints          List all endpoints");
        println!("  endpoint <name>    Show endpoint details");
        println!("  keys               List all keys");
        println!("  key <name>         Show key details");
        println!("  feeds              List all feeds");
        println!("  feed <name>        Show feed details");
        println!("  server             Show server connection settings");
        println!("  version            Show SFTPflow version");
        return;
    }

    match args[0] {
        "version"   => version(),
        "server"    => state.config.server.display(),
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
        _ => println!("% Unknown show subcommand: '{}'", args[0]),
    }
}

/// List all configured endpoints.
fn show_endpoints(state: &ShellState) {
    if state.config.endpoints.is_empty() {
        println!("No endpoints configured.");
        return;
    }

    println!("Configured endpoints:");
    for (name, ep) in &state.config.endpoints {
        let host = ep.host.as_deref().unwrap_or("(no host)");
        let port = ep.port.map_or(String::new(), |p| format!(":{}", p));
        let user = ep.username.as_deref().unwrap_or("(no user)");
        println!("  {:20} {}@{}{}", name, user, host, port);
    }
}

/// Show detail for a single endpoint.
fn show_endpoint_detail(name: &str, state: &ShellState) {
    match state.config.endpoints.get(name) {
        Some(ep) => ep.display(name),
        None => println!("% Endpoint '{}' does not exist.", name),
    }
}

/// List all configured keys.
fn show_keys(state: &ShellState) {
    if state.config.keys.is_empty() {
        println!("No keys configured.");
        return;
    }

    println!("Configured keys:");
    for (name, key) in &state.config.keys {
        let ktype = key.key_type.as_ref().map_or("(no type)", |t| match t {
            KeyType::Public  => "public",
            KeyType::Private => "private",
        });
        let has_contents = if key.contents.is_some() { "loaded" } else { "empty" };
        println!("  {:20} {:10} {}", name, ktype, has_contents);
    }
}

/// Show detail for a single key.
fn show_key_detail(name: &str, state: &ShellState) {
    match state.config.keys.get(name) {
        Some(key) => key.display(name),
        None => println!("% Key '{}' does not exist.", name),
    }
}

/// List all configured feeds.
fn show_feeds(state: &ShellState) {
    if state.config.feeds.is_empty() {
        println!("No feeds configured.");
        return;
    }

    println!("Configured feeds:");
    for (name, feed) in &state.config.feeds {
        let src_count = feed.sources.len();
        let proc_count = feed.process.len();
        let dst_count = feed.destinations.len();
        let sched_count = feed.schedules.len();
        // Green for enabled, red for disabled
        let colored_name = if feed.flags.enabled {
            format!("\x1b[32m{:20}\x1b[0m", name)
        } else {
            format!("\x1b[31m{:20}\x1b[0m", name)
        };
        println!("  {} {} source(s), {} process(es), {} destination(s), {} schedule(s)",
            colored_name, src_count, proc_count, dst_count, sched_count);
    }
}

/// Show detail for a single feed.
fn show_feed_detail(name: &str, state: &ShellState) {
    match state.config.feeds.get(name) {
        Some(feed) => feed.display(name),
        None => println!("% Feed '{}' does not exist.", name),
    }
}