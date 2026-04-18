// ============================================================
// cli.rs - Interactive shell loop and command dispatch
// ============================================================

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::commands; // commands.rs
use crate::feed::{Config, Endpoint, Feed, NextStep, PgpKey, ServerConnection}; // feed.rs
use crate::rpc::RpcClient; // rpc.rs

/// Shell modes, similar to Cisco IOS privilege levels.
#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    /// Top-level mode (like IOS user exec).
    Exec,
    /// Editing a specific endpoint's configuration.
    EndpointEdit(String),
    /// Editing a specific PGP key's configuration.
    KeyEdit(String),
    /// Editing a specific feed's configuration.
    FeedEdit(String),
    /// Editing a next step within a feed (feed name stored).
    NextStepEdit(String),
    /// Editing the server connection settings.
    ConfigEdit,
}

/// Shared state passed into every command handler.
pub struct ShellState {
    pub mode: Mode,
    pub running: bool,
    pub config: Config,
    /// RPC connection to the daemon.
    pub rpc: Option<RpcClient>,
    /// Socket address for direct-connect (dev) mode; None = use SSH.
    pub socket_addr: Option<String>,
    /// Staging area: uncommitted edits to the feed being configured.
    pub pending_feed: Option<Feed>,
    /// Staging area: uncommitted edits to the endpoint being configured.
    pub pending_endpoint: Option<Endpoint>,
    /// Staging area: uncommitted edits to the key being configured.
    pub pending_key: Option<PgpKey>,
    /// Staging area: next step being built in the nextstep submenu.
    pub pending_nextstep: Option<NextStep>,
    /// Staging area: uncommitted edits to the server connection.
    pub pending_server: Option<ServerConnection>,
}

impl ShellState {
    pub fn new(socket_addr: Option<String>) -> Self {
        let config = Config::load();
        let mut state = ShellState {
            mode: Mode::Exec,
            running: true,
            config,
            rpc: None,
            socket_addr,
            pending_feed: None,
            pending_endpoint: None,
            pending_key: None,
            pending_nextstep: None,
            pending_server: None,
        };
        state.try_connect();
        state
    }

    /// Attempt to connect to the daemon. Uses socket_addr (dev) or
    /// SSH via ServerConnection (prod).
    pub fn try_connect(&mut self) {
        self.rpc = None;

        let mut rpc = if let Some(ref addr) = self.socket_addr {
            match RpcClient::connect_socket(addr) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("% Could not connect to {}: {}", addr, e);
                    return;
                }
            }
        } else {
            let server = self.config.server.clone();
            match RpcClient::connect_ssh(&server) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("% Could not connect to daemon: {}", e);
                    eprintln!("% Use 'config' to set server settings, then 'connect'.");
                    return;
                }
            }
        };

        // Verify with GetServerInfo
        use sftpflow_proto::{Request, Response};
        match rpc.call(Request::GetServerInfo) {
            Ok(Response::ServerInfo(info)) => {
                println!("Connected to sftpflowd v{} ({}, up {}s)",
                    info.version, info.hostname, info.uptime_seconds);
            }
            Ok(_) => println!("Connected to daemon."),
            Err(e) => eprintln!("% Warning: server info unavailable: {}", e),
        }

        self.rpc = Some(rpc);
    }

    /// Build the prompt string based on the current mode.
    pub fn prompt(&self) -> String {
        match &self.mode {
            Mode::Exec => "sftpflow> ".to_string(),
            Mode::EndpointEdit(name) => format!("sftpflow(config-endpoint:{})# ", name),
            Mode::KeyEdit(name) => format!("sftpflow(config-key:{})# ", name),
            Mode::FeedEdit(name) => format!("sftpflow(config-feed:{})# ", name),
            Mode::NextStepEdit(name) => format!("sftpflow(config-feed:{}/nextstep)# ", name),
            Mode::ConfigEdit => "sftpflow(config-server)# ".to_string(),
        }
    }
}

/// Main entry point for the interactive shell.
pub fn run(socket_addr: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut rl = DefaultEditor::new()?;
    let mut state = ShellState::new(socket_addr);

    // Load history if available
    let history_path = history_path();
    let _ = rl.load_history(&history_path);

    // ---- REPL loop ----
    while state.running {
        let prompt = state.prompt();
        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                dispatch(&line, &mut state);
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                // Ctrl-C / Ctrl-D → exit cleanly
                println!("Goodbye.");
                break;
            }
            Err(err) => {
                eprintln!("Input error: {err}");
                break;
            }
        }
    }

    // Save history
    let _ = rl.save_history(&history_path);

    Ok(())
}

// ---- Command dispatch ----

/// Parse the input line and route to the appropriate command handler.
fn dispatch(line: &str, state: &mut ShellState) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    let cmd = parts[0];
    let args = &parts[1..];

    match &state.mode.clone() {
        Mode::Exec             => dispatch_exec(cmd, args, state),
        Mode::EndpointEdit(_)  => dispatch_endpoint_edit(cmd, args, state),
        Mode::KeyEdit(_)       => dispatch_key_edit(cmd, args, state),
        Mode::FeedEdit(_)      => dispatch_feed_edit(cmd, args, state),
        Mode::NextStepEdit(_)  => dispatch_nextstep_edit(cmd, args, state),
        Mode::ConfigEdit       => dispatch_config_edit(cmd, args, state),
    }
}

/// Dispatch commands available in exec mode.
fn dispatch_exec(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_exec(),
        "create"           => commands::create(args, state),
        "edit"             => commands::edit(args, state),
        "delete"           => commands::delete(args, state),
        "rename"           => commands::rename(args, state),
        "show"             => commands::show(args, state),
        "run"              => commands::run(args, state),
        "connect"          => commands::connect(state),
        "sync"             => commands::sync(args, state),
        "config"           => commands::enter_config(state),
        "exit" | "quit"    => commands::exit_shell(state),
        "version"          => commands::version(),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

/// Dispatch commands available in endpoint-edit mode.
fn dispatch_endpoint_edit(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_endpoint_edit(),
        "protocol"         => commands::set_protocol(args, state),
        "host"             => commands::set_host(args, state),
        "port"             => commands::set_port(args, state),
        "username"         => commands::set_username(args, state),
        "password"         => commands::set_password(args, state),
        "ssh_key"          => commands::set_ssh_key(args, state),
        "no"               => commands::no_endpoint_command(args, state),
        "show"             => commands::show_pending_endpoint(state),
        "commit"           => commands::commit_endpoint(state),
        "abort"            => commands::abort_endpoint(state),
        "exit" | "end"     => commands::exit_endpoint_edit(state),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

/// Dispatch commands available in key-edit mode.
fn dispatch_key_edit(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_key_edit(),
        "type"             => commands::set_key_type(args, state),
        "contents"         => commands::set_key_contents(args, state),
        "load"             => commands::load_key_file(args, state),
        "no"               => commands::no_key_command(args, state),
        "show"             => commands::show_pending_key(state),
        "commit"           => commands::commit_key(state),
        "abort"            => commands::abort_key(state),
        "exit" | "end"     => commands::exit_key_edit(state),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

/// Dispatch commands available in feed-edit mode.
fn dispatch_feed_edit(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_feed_edit(),
        "source"           => commands::set_source(args, state),
        "destination"      => commands::set_destination(args, state),
        "process"          => commands::add_process(args, state),
        "schedule"         => commands::set_schedule(args, state),
        "flag"             => commands::set_flag(args, state),
        "nextstep"         => commands::enter_nextstep(state),
        "move"             => commands::move_nextstep(args, state),
        "no"               => commands::no_feed_command(args, state),
        "show"             => commands::show_pending_feed(state),
        "commit"           => commands::commit_feed(state),
        "abort"            => commands::abort_feed(state),
        "exit" | "end"     => commands::exit_feed_edit(state),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

/// Dispatch commands available in nextstep-edit mode.
fn dispatch_nextstep_edit(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_nextstep_edit(),
        "type"             => commands::set_nextstep_type(args, state),
        "target"           => commands::set_nextstep_target(args, state),
        "on"               => commands::add_nextstep_condition(args, state),
        "no"               => commands::no_nextstep_command(args, state),
        "show"             => commands::show_pending_nextstep(state),
        "done"             => commands::done_nextstep(state),
        "abort"            => commands::abort_nextstep(state),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

/// Dispatch commands available in config-edit mode (server connection).
fn dispatch_config_edit(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_config_edit(),
        "host"             => commands::set_server_host(args, state),
        "port"             => commands::set_server_port(args, state),
        "username"         => commands::set_server_username(args, state),
        "dkron"            => commands::set_dkron_url(args, state),
        "no"               => commands::no_server_command(args, state),
        "show"             => commands::show_pending_server(state),
        "commit"           => commands::commit_server(state),
        "abort"            => commands::abort_server(state),
        "exit" | "end"     => commands::exit_config_edit(state),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

// ---- Helpers ----

/// Return a platform-appropriate path for command history.
fn history_path() -> String {
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
    {
        let mut path = std::path::PathBuf::from(home);
        path.push(".sftpflow_history");
        return path.to_string_lossy().to_string();
    }
    ".sftpflow_history".to_string()
}