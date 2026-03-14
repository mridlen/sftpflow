// ============================================================
// cli.rs - Interactive shell loop and command dispatch
// ============================================================

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::commands; // commands.rs

/// Shell modes, similar to Cisco IOS privilege levels.
#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    /// Top-level mode (like IOS user exec).
    Exec,
    /// Configuration mode for editing flows / connections.
    Config,
}

/// Shared state passed into every command handler.
pub struct ShellState {
    pub mode: Mode,
    pub running: bool,
}

impl ShellState {
    fn new() -> Self {
        ShellState {
            mode: Mode::Exec,
            running: true,
        }
    }

    /// Build the prompt string based on the current mode.
    fn prompt(&self) -> String {
        match self.mode {
            Mode::Exec   => "sftpflow> ".to_string(),
            Mode::Config => "sftpflow(config)# ".to_string(),
        }
    }
}

/// Main entry point for the interactive shell.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut rl = DefaultEditor::new()?;
    let mut state = ShellState::new();

    // Load history if available
    let history_path = dirs_next_history_path();
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

    match state.mode {
        Mode::Exec => dispatch_exec(cmd, args, state),
        Mode::Config => dispatch_config(cmd, args, state),
    }
}

/// Dispatch commands available in exec mode.
fn dispatch_exec(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_exec(),
        "configure"        => commands::enter_config(state),
        "show"             => commands::show(args, state),
        "exit" | "quit"    => commands::exit_shell(state),
        "version"          => commands::version(),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

/// Dispatch commands available in config mode.
fn dispatch_config(cmd: &str, args: &[&str], state: &mut ShellState) {
    match cmd {
        "help" | "?"       => commands::help_config(),
        "exit" | "end"     => commands::exit_config(state),
        "show"             => commands::show(args, state),
        _ => println!("% Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

// ---- Helpers ----

/// Return a platform-appropriate path for command history.
fn dirs_next_history_path() -> String {
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
    {
        let mut path = std::path::PathBuf::from(home);
        path.push(".sftpflow_history");
        return path.to_string_lossy().to_string();
    }
    ".sftpflow_history".to_string()
}
