use std::process;

mod cli;      // cli.rs - interactive shell loop and command dispatch
mod commands; // commands.rs - command implementations

fn main() {
    println!("SFTPflow v0.1.0");
    println!("Type 'help' for a list of commands.\n");

    if let Err(e) = cli::run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
