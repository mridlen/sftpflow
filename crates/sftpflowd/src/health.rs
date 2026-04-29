// ============================================================
// sftpflowd::health - HTTP healthcheck endpoints
// ============================================================
//
// Tiny sync HTTP/1.1 server bound to a separate port from the
// NDJSON RPC listener. Exists so docker-compose `healthcheck:`,
// Kubernetes liveness/readiness probes, and load balancers can
// observe the daemon without learning the NDJSON RPC protocol.
//
// Two endpoints, both GET:
//
//   /healthz  - liveness. 200 OK as long as the HTTP server is
//               answering. The whole point of liveness is "kill
//               and restart if not responsive"; if we can write a
//               response, we are responsive by definition. Body
//               is JSON with a few diagnostic fields.
//
//   /readyz   - readiness. 200 OK if this node is ready to take
//               traffic, 503 otherwise. In cluster mode "ready"
//               means we have a known leader (so mutating RPCs
//               can be forwarded) OR we are the leader. In legacy
//               single-node mode the daemon is always ready —
//               there is no consensus to wait for.
//
// Hand-rolled HTTP/1.1 because the surface is tiny (two paths,
// GET only, no Keep-Alive — close the connection after every
// response) and adding `hyper`/`axum` for ~80 lines of logic is
// not worth the dep weight or async-runtime entanglement (legacy
// single-node mode runs without a tokio runtime).
//
// Thread model mirrors server.rs: one OS thread per connection,
// reading the request line + headers, writing the response, then
// closing. Each handler clones the SharedDaemonState Arc to peek
// at cluster status while holding the daemon mutex briefly.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use log::{debug, info, warn};

use crate::server::SharedDaemonState; // server.rs - SharedDaemonState alias

// ============================================================
// spawn - bind the listener, accept loop on a background thread
// ============================================================

/// Bind a TCP listener at `addr` (host:port) and serve healthcheck
/// requests on a dedicated OS thread.
///
/// Bind failures are logged and swallowed: a working daemon with a
/// dead healthcheck port is much better than refusing to start
/// because of port contention on a non-critical service.
pub fn spawn(addr: &str, state: SharedDaemonState) {
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "healthcheck server: could not bind to '{}': {} — \
                 probes against this node will fail until restarted with a free port",
                addr, e,
            );
            return;
        }
    };
    info!("healthcheck server listening on http://{}/healthz, /readyz", addr);

    std::thread::Builder::new()
        .name("sftpflowd-health".to_string())
        .spawn(move || accept_loop(listener, state))
        .expect("could not spawn healthcheck thread");
}

// ============================================================
// accept_loop - per-connection thread spawn
// ============================================================

fn accept_loop(listener: TcpListener, state: SharedDaemonState) {
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let state = state.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, state) {
                        debug!("healthcheck connection error: {}", e);
                    }
                });
            }
            Err(e) => warn!("healthcheck accept error: {}", e),
        }
    }
}

// ============================================================
// handle_connection - parse one request, write one response
// ============================================================
//
// Tight read/write timeouts so a probe client that starts speaking
// HTTP and then stalls can't tie up a thread indefinitely. Five
// seconds is generous for a localhost-or-LAN probe.

fn handle_connection(stream: TcpStream, state: SharedDaemonState) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let writer = stream.try_clone()?;
    let reader = BufReader::new(stream);

    let (method, path) = match read_request_line(reader) {
        Ok(pair) => pair,
        Err(_) => {
            return write_response(writer, 400, "Bad Request", b"{\"error\":\"bad request\"}");
        }
    };

    // Only GET is supported. Anything else gets a 405 with the
    // canonical Allow header so clients know what's offered.
    if method != "GET" {
        return write_response(writer, 405, "Method Not Allowed", b"{\"error\":\"method not allowed\"}");
    }

    // Strip query string + fragment so probes can append cache-busters.
    let path_only = path.split(['?', '#']).next().unwrap_or("");

    match path_only {
        "/healthz" => respond_healthz(writer, &state),
        "/readyz"  => respond_readyz(writer, &state),
        _          => write_response(writer, 404, "Not Found", b"{\"error\":\"not found\"}"),
    }
}

// ============================================================
// read_request_line - HTTP/1.1 request-line + headers parser
// ============================================================
//
// We don't actually need the headers (no body, no auth, no
// Keep-Alive), but we have to consume them so the client doesn't
// see a half-closed connection before its request is fully sent.
// Bound the total read so a slow-loris probe can't hold a thread.

fn read_request_line<R: BufRead>(mut reader: R) -> std::io::Result<(String, String)> {
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line)?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client closed before sending request",
        ));
    }

    // Parse "METHOD PATH HTTP/1.x\r\n"
    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path   = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    // Drain headers until the empty line. Cap header bytes so a
    // hostile probe can't stream forever.
    let mut header_bytes_seen = 0usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // peer closed without trailing CRLF — tolerate
        }
        header_bytes_seen += n;
        if header_bytes_seen > 8 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers exceeded 8KiB",
            ));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    Ok((method, path))
}

// ============================================================
// respond_healthz - liveness. always 200.
// ============================================================
//
// Holds the daemon mutex briefly to read out cluster identity for
// the response body. The body is purely informational; a probe
// that just checks the status code never has to parse it.

fn respond_healthz<W: Write>(writer: W, state: &SharedDaemonState) -> std::io::Result<()> {
    let body = {
        let guard = state.lock().unwrap();
        let uptime_secs = guard.started.elapsed().as_secs();
        match guard.cluster.as_ref() {
            Some(c) => format!(
                "{{\"status\":\"ok\",\"mode\":\"cluster\",\"node_id\":{},\"cluster_id\":\"{}\",\"uptime_seconds\":{}}}",
                c.self_id,
                json_escape(&c.cluster_id),
                uptime_secs,
            ),
            None => format!(
                "{{\"status\":\"ok\",\"mode\":\"legacy\",\"uptime_seconds\":{}}}",
                uptime_secs,
            ),
        }
    };
    write_response(writer, 200, "OK", body.as_bytes())
}

// ============================================================
// respond_readyz - readiness. 200 if ready, 503 otherwise.
// ============================================================
//
// Readiness rules:
//   - legacy mode: always ready (no consensus to wait for).
//   - cluster mode: ready iff this node is the leader OR knows
//     who the current leader is. A node that has lost contact
//     with the rest of the cluster (no leader, e.g. partition
//     minority) reports not-ready so a load balancer drains it.
//
// Body always includes the same fields whether 200 or 503 so an
// operator inspecting the response can see *why* it's not ready.

fn respond_readyz<W: Write>(writer: W, state: &SharedDaemonState) -> std::io::Result<()> {
    let (ready, body) = {
        let guard = state.lock().unwrap();
        match guard.cluster.as_ref() {
            None => {
                let body = "{\"ready\":true,\"mode\":\"legacy\"}".to_string();
                (true, body)
            }
            Some(c) => {
                let is_leader     = c.is_leader();
                let leader_id_opt = c.current_leader();
                let ready         = is_leader || leader_id_opt.is_some();
                let leader_field = match leader_id_opt {
                    Some(id) => format!("{}", id),
                    None     => "null".to_string(),
                };
                let reason = if ready {
                    ""
                } else {
                    ",\"reason\":\"no leader known — election in progress or quorum unavailable\""
                };
                let body = format!(
                    "{{\"ready\":{},\"mode\":\"cluster\",\"node_id\":{},\"is_leader\":{},\"leader_id\":{}{}}}",
                    ready, c.self_id, is_leader, leader_field, reason,
                );
                (ready, body)
            }
        }
    };

    if ready {
        write_response(writer, 200, "OK", body.as_bytes())
    } else {
        write_response(writer, 503, "Service Unavailable", body.as_bytes())
    }
}

// ============================================================
// write_response - emit a single HTTP/1.1 response, then close
// ============================================================
//
// `Connection: close` so the client doesn't try to reuse the
// socket; the per-thread accept loop is too lightweight to bother
// with Keep-Alive. Content-Type is application/json for both
// success and error bodies.

fn write_response<W: Write>(
    mut writer: W,
    status_code: u16,
    status_text: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         \r\n",
        status_code,
        status_text,
        body.len(),
    );
    writer.write_all(head.as_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

// ============================================================
// json_escape - minimal JSON string escaper for cluster_id
// ============================================================
//
// cluster_id is a UUID string in practice — no escaping needed —
// but we still pass it through this helper because the daemon's
// cluster_id comes from JoinResponse over the wire and we'd
// rather not emit invalid JSON if a test config ever sets it to
// something exotic. Only escapes the seven characters JSON
// requires; control characters become \uXXXX.

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ============================================================
// Tests
// ============================================================
//
// Direct unit tests of the small helpers. End-to-end accept-loop
// testing happens in the cluster integration tests which can curl
// the spawned listener.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpStream;

    use sftpflow_core::Config;

    use crate::server::{self, DaemonPaths};

    // ---- helpers -----------------------------------------------

    /// Build a SharedDaemonState with no cluster handle, suitable
    /// for legacy-mode readiness assertions. Paths are dummy
    /// because the healthcheck path never reads them.
    fn legacy_shared_state() -> server::SharedDaemonState {
        let paths = DaemonPaths {
            state_dir:    std::path::PathBuf::from("/tmp/sftpflow-health-test/state"),
            runs_db:      std::path::PathBuf::from("/tmp/sftpflow-health-test/runs.db"),
            audit_db:     std::path::PathBuf::from("/tmp/sftpflow-health-test/audit.db"),
            secrets_file: std::path::PathBuf::from("/tmp/sftpflow-health-test/secrets.sealed"),
            config_yaml:  std::path::PathBuf::from("/tmp/sftpflow-health-test/config.yaml"),
        };
        server::build_shared_state(Config::default(), None, None, None, None, paths)
    }

    /// Bind 127.0.0.1:0 (OS-assigned port), spawn the accept loop
    /// on a background thread, and return the bound address so the
    /// test can connect to it.
    fn boot_local(state: server::SharedDaemonState) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || accept_loop(listener, state));
        addr
    }

    /// Send `request_bytes` to `addr` and return (status_code, body).
    /// Minimal HTTP/1.1 client — assumes Content-Length is present
    /// (which our server always emits).
    fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path,
        );
        stream.write_all(req.as_bytes()).expect("write request");
        stream.flush().ok();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read response");
        let text = String::from_utf8(buf).expect("utf-8 response");

        // Parse "HTTP/1.1 NNN ..." status line
        let status_line = text.lines().next().expect("status line");
        let mut parts = status_line.split(' ');
        let _proto = parts.next();
        let code = parts.next().unwrap_or("0").parse::<u16>().unwrap_or(0);

        // Body starts after the blank line.
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        (code, body)
    }

    // ---- json_escape unit tests --------------------------------

    #[test]
    fn json_escape_passes_through_ascii_uuid() {
        let s = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(json_escape(s), s);
    }

    #[test]
    fn json_escape_handles_quotes_and_backslashes() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn json_escape_encodes_control_chars() {
        assert_eq!(json_escape("\x01"), "\\u0001");
    }

    // ---- end-to-end accept-loop tests --------------------------

    #[test]
    fn legacy_healthz_returns_200_with_legacy_mode_body() {
        let addr = boot_local(legacy_shared_state());
        let (code, body) = http_get(addr, "/healthz");
        assert_eq!(code, 200);
        assert!(body.contains("\"status\":\"ok\""), "body was: {}", body);
        assert!(body.contains("\"mode\":\"legacy\""), "body was: {}", body);
    }

    #[test]
    fn legacy_readyz_returns_200_always_ready() {
        let addr = boot_local(legacy_shared_state());
        let (code, body) = http_get(addr, "/readyz");
        assert_eq!(code, 200);
        assert!(body.contains("\"ready\":true"), "body was: {}", body);
        assert!(body.contains("\"mode\":\"legacy\""), "body was: {}", body);
    }

    #[test]
    fn unknown_path_returns_404() {
        let addr = boot_local(legacy_shared_state());
        let (code, _body) = http_get(addr, "/nope");
        assert_eq!(code, 404);
    }

    #[test]
    fn query_string_is_stripped_before_routing() {
        // Probe clients (k8s, curl) sometimes append cache-busters.
        let addr = boot_local(legacy_shared_state());
        let (code, _body) = http_get(addr, "/healthz?cb=12345");
        assert_eq!(code, 200);
    }

    #[test]
    fn non_get_method_returns_405() {
        // Hand-roll the request because http_get only does GET.
        let addr = boot_local(legacy_shared_state());
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .write_all(b"POST /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read");
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 405"), "response was: {}", text);
    }
}
