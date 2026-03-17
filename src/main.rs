use std::process;

mod cli;      // cli.rs - interactive shell loop and command dispatch
mod commands; // commands.rs - command implementations
mod dkron;    // dkron.rs - dkron scheduler API client
mod feed;     // feed.rs - feed data model and YAML persistence

fn main() {
    // Initialize logging (set RUST_LOG=info to see log output)
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    // Non-interactive mode: sftpflow run <feed-name>
    // This is how dkron worker nodes invoke sftpflow.
    if args.len() >= 3 && args[1] == "run" {
        let feed_name = &args[2];
        let config = feed::Config::load();

        match config.feeds.get(feed_name.as_str()) {
            Some(_feed) => {
                // TODO: implement actual file transfer execution
                println!("Executing feed '{}'...", feed_name);
                eprintln!("% Feed execution is not yet implemented.");
                process::exit(0);
            }
            None => {
                eprintln!("% Feed '{}' not found in config.", feed_name);
                process::exit(1);
            }
        }
    }

    // Interactive shell
    println!("SFTPflow v0.1.1");
    println!("Type 'help' for a list of commands.\n");

    if let Err(e) = cli::run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
