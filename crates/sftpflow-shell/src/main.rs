// ============================================================
// sftpflow-shell - ForceCommand bridge
// ============================================================
//
// Connects to a local sftpflowd socket, then pumps bytes in both
// directions between that socket and the process's own stdin/stdout.
// Nothing more. The SSH daemon runs this as the `ForceCommand`
// for sftpflow users, so an incoming SSH session is transparently
// wired to the daemon.
//
// Usage:
//   sftpflow-shell                   (use the platform default address)
//   sftpflow-shell --socket <addr>   (override, same format as sftpflowd)
//
// Exit status:
//   0 - daemon closed the connection cleanly
//   1 - I/O error talking to the daemon
//   2 - bad command-line arguments

use std::io::{self, Read, Write};
use std::net::{Shutdown as TcpShutdown, TcpStream};
use std::process;
use std::thread;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use log::{error, info};

// ============================================================
// main
// ============================================================

fn main() {
    // Default logging to warn; set RUST_LOG=info (or debug) for verbose.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn"),
    )
    .init();

    let args: Vec<String> = std::env::args().collect();
    let socket_addr = match parse_socket_arg(&args) {
        Ok(Some(a)) => a,
        Ok(None)    => default_socket_addr(),
        Err(e) => {
            eprintln!("% {}", e);
            process::exit(2);
        }
    };

    info!("sftpflow-shell connecting to {}", socket_addr);
    let code = match run_bridge(&socket_addr) {
        Ok(()) => 0,
        Err(e) => {
            error!("bridge error: {}", e);
            1
        }
    };
    process::exit(code);
}

// ============================================================
// Argument helpers (mirror sftpflowd so the UX is identical)
// ============================================================

fn parse_socket_arg(args: &[String]) -> Result<Option<String>, String> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--socket" {
            if i + 1 >= args.len() {
                return Err("--socket requires an address argument".to_string());
            }
            return Ok(Some(args[i + 1].clone()));
        }
        i += 1;
    }
    Ok(None)
}

fn default_socket_addr() -> String {
    #[cfg(unix)]
    {
        "unix:/tmp/sftpflow.sock".to_string()
    }
    #[cfg(not(unix))]
    {
        "tcp:127.0.0.1:7777".to_string()
    }
}

// ============================================================
// Bridge: pick transport, then hand off to the pump loop
// ============================================================

fn run_bridge(addr: &str) -> io::Result<()> {
    let (scheme, rest) = match addr.split_once(':') {
        Some(("unix", r)) => ("unix", r),
        Some(("tcp", r))  => ("tcp", r),
        _                 => ("tcp", addr),
    };

    match scheme {
        "tcp" => bridge_tcp(rest),
        "unix" => {
            #[cfg(unix)]
            { bridge_unix(rest) }
            #[cfg(not(unix))]
            {
                let _ = rest; // silence unused on windows
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unix sockets are not supported on this platform; use tcp:",
                ))
            }
        }
        _ => unreachable!(),
    }
}

// ---- TCP ----

fn bridge_tcp(addr: &str) -> io::Result<()> {
    let stream = TcpStream::connect(addr)?;
    info!("connected via tcp to {}", addr);

    // We need three handles to the same socket:
    //   - reader: socket -> stdout
    //   - writer: stdin  -> socket
    //   - shutter: signals "no more input" to the daemon when stdin EOFs
    let reader = stream.try_clone()?;
    let writer = stream.try_clone()?;
    let shutter = stream;

    // pump() - below
    pump(reader, writer, move || {
        let _ = shutter.shutdown(TcpShutdown::Write);
    })
}

// ---- Unix domain socket ----

#[cfg(unix)]
fn bridge_unix(path: &str) -> io::Result<()> {
    let stream = UnixStream::connect(path)?;
    info!("connected via unix socket {}", path);

    let reader = stream.try_clone()?;
    let writer = stream.try_clone()?;
    let shutter = stream;

    pump(reader, writer, move || {
        let _ = shutter.shutdown(std::net::Shutdown::Write);
    })
}

// ============================================================
// pump - two threads, byte-for-byte copy, exit when the daemon
// closes the socket (stdout side ends).
// ============================================================

fn pump<R, W, S>(reader: R, writer: W, shutdown_write: S) -> io::Result<()>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    S: FnOnce() + Send + 'static,
{
    // stdin -> socket
    let stdin_thread = thread::spawn(move || {
        let mut w = writer;
        let mut stdin = io::stdin().lock();
        // Ignore the copy result: any error here means stdin EOFed or
        // the socket broke; either way we want to close the write half.
        let _ = io::copy(&mut stdin, &mut w);
        // Tell the daemon we won't send any more by closing the write
        // half. Without this, the daemon would wait forever for the
        // next request even after the user has hung up.
        shutdown_write();
    });

    // socket -> stdout
    let stdout_thread = thread::spawn(move || -> io::Result<()> {
        let mut r = reader;
        let mut stdout = io::stdout().lock();
        io::copy(&mut r, &mut stdout)?;
        Ok(())
    });

    // The socket->stdout direction is the authoritative end-of-session
    // signal: when the daemon closes the connection, we're done.
    let stdout_result = match stdout_thread.join() {
        Ok(r) => r,
        Err(_) => Err(io::Error::other("stdout pump thread panicked")),
    };

    // Best-effort: let the stdin pump wind down. If stdin is still
    // open (e.g. a user who never typed Ctrl-D), it won't finish until
    // process exit closes its FD for it — that's fine, we return here
    // and let the process terminate.
    drop(stdin_thread);

    stdout_result
}
