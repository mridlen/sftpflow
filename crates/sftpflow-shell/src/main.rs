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

    // We need handles to the same socket for both directions of
    // the pump, plus two shutdown closures so each pump direction
    // can signal the other when its side of the conversation ends.
    let reader = stream.try_clone()?;
    let writer = stream.try_clone()?;
    let shutter_w = stream.try_clone()?;
    let shutter_r = stream;

    // pump() - below
    pump(
        reader,
        writer,
        move || { let _ = shutter_w.shutdown(TcpShutdown::Write); },
        move || { let _ = shutter_r.shutdown(TcpShutdown::Both); },
    )
}

// ---- Unix domain socket ----

#[cfg(unix)]
fn bridge_unix(path: &str) -> io::Result<()> {
    let stream = UnixStream::connect(path)?;
    info!("connected via unix socket {}", path);

    let reader = stream.try_clone()?;
    let writer = stream.try_clone()?;
    let shutter_w = stream.try_clone()?;
    let shutter_r = stream;

    pump(
        reader,
        writer,
        move || { let _ = shutter_w.shutdown(std::net::Shutdown::Write); },
        move || { let _ = shutter_r.shutdown(std::net::Shutdown::Both); },
    )
}

// ============================================================
// pump - two threads, byte-for-byte copy, exit when the daemon
// closes the socket (stdout side ends).
// ============================================================

fn pump<R, W, SW, SB>(
    reader:           R,
    writer:           W,
    shutdown_write:   SW,
    shutdown_both:    SB,
) -> io::Result<()>
where
    R:  Read  + Send + 'static,
    W:  Write + Send + 'static,
    SW: FnOnce() + Send + 'static,
    SB: FnOnce() + Send + 'static,
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
        // Make sure the final reply byte hits the wire before we
        // return — without this, a small response can be lost when
        // the process exits with bytes still in the BufWriter.
        stdout.flush()?;
        Ok(())
    });

    // The socket->stdout direction is the authoritative end-of-session
    // signal: when the daemon closes the connection, we're done.
    let stdout_result = match stdout_thread.join() {
        Ok(r) => r,
        Err(_) => Err(io::Error::other("stdout pump thread panicked")),
    };

    // Tear down both directions so the stdin pump's next write
    // returns BrokenPipe and the thread can exit. Without this the
    // stdin reader would block until the OS closed our stdin FD on
    // process exit — fine in production, but surprising under
    // tests / under a parent that wraps us.
    shutdown_both();

    // Best effort: give the stdin thread a chance to observe the
    // shutdown and exit. If it's stuck on a blocking stdin read
    // that will never unblock (e.g. an interactive user who hasn't
    // typed Ctrl-D), join() would block forever — so we don't
    // wait. Process exit will reclaim the thread.
    drop(stdin_thread);

    stdout_result
}
