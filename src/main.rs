use std::process;

mod cli;      // cli.rs - interactive shell loop and command dispatch
mod commands; // commands.rs - command implementations
mod feed;     // feed.rs - feed data model and YAML persistence

fn main() {
    // Initialize logging (set RUST_LOG=info to see log output)
    env_logger::init();

    println!("SFTPflow v0.1.0");
    println!("Type 'help' for a list of commands.\n");

    if let Err(e) = cli::run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
