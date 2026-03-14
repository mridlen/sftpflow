// ============================================================
// commands.rs - Command implementations
// ============================================================

use crate::cli::{Mode, ShellState};

// ---- Exec mode commands ----

/// Print help for exec mode.
pub fn help_exec() {
    println!("Available commands (exec mode):");
    println!("  configure   Enter configuration mode");
    println!("  show        Display information (e.g. 'show version')");
    println!("  version     Show SFTPflow version");
    println!("  exit        Exit SFTPflow");
    println!("  help / ?    Show this help");
}

/// Enter configuration mode.
pub fn enter_config(state: &mut ShellState) {
    state.mode = Mode::Config;
    println!("Entering configuration mode.");
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

// ---- Config mode commands ----

/// Print help for config mode.
pub fn help_config() {
    println!("Available commands (config mode):");
    println!("  show        Display information");
    println!("  exit / end  Return to exec mode");
    println!("  help / ?    Show this help");
}

/// Leave config mode, return to exec.
pub fn exit_config(state: &mut ShellState) {
    state.mode = Mode::Exec;
    println!("Exiting configuration mode.");
}

// ---- Shared commands ----

/// Handle 'show' subcommands.
pub fn show(args: &[&str], _state: &ShellState) {
    if args.is_empty() {
        println!("Usage: show <subcommand>");
        println!("  version   Show SFTPflow version");
        return;
    }

    match args[0] {
        "version" => version(),
        _ => println!("% Unknown show subcommand: '{}'", args[0]),
    }
}
