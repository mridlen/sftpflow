// ============================================================
// output.rs - Human / JSON / quiet output helpers
// ============================================================
//
// Every command in commands.rs routes user-visible output through
// one of the methods on `Output` instead of calling println!/eprintln!
// directly. The two output modes are:
//
//   Human  — the default. Formatted text on stdout; errors prefixed
//            with "% " on stderr. Banner/info lines are suppressed
//            when `quiet=true`.
//
//   Json   — one JSON document per command on stdout, suitable for
//            scripts and Ansible. Errors come back as
//            {"error":{"code":..., "message":...}}; successful
//            mutations as {"ok":true}; reads as the command-specific
//            data shape.
//
// `Output` is `Copy` so commands can stash a local copy with
// `let out = state.out;` before borrowing other fields of state
// mutably, sidestepping borrow-checker conflicts.

use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

impl Default for OutputMode {
    fn default() -> Self {
        OutputMode::Human
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Output {
    pub mode:  OutputMode,
    pub quiet: bool,
}

impl Output {
    pub fn is_json(&self) -> bool {
        self.mode == OutputMode::Json
    }

    pub fn is_human(&self) -> bool {
        self.mode == OutputMode::Human
    }

    // --------------------------------------------------------------
    // info — banner / status text
    // --------------------------------------------------------------
    //
    // Suppressed in JSON mode and when --quiet is set in human mode.
    // Use for "Connected to sftpflowd…", "Configured endpoints:", etc.
    pub fn info(&self, msg: impl AsRef<str>) {
        if self.is_human() && !self.quiet {
            println!("{}", msg.as_ref());
        }
    }

    // --------------------------------------------------------------
    // human — render a complex human view via callback
    // --------------------------------------------------------------
    //
    // Runs the closure only in human mode. Use for tabular renders
    // and any block of multiple println!()s where it's not worth
    // building the strings up-front.
    pub fn human<F: FnOnce()>(&self, render: F) {
        if self.is_human() {
            render();
        }
    }

    // --------------------------------------------------------------
    // json — emit a structured value (JSON mode only)
    // --------------------------------------------------------------
    //
    // No-op in human mode. The value is serialized with serde_json
    // and printed on a single line so consumers can read one
    // command-result-per-line.
    pub fn json<T: Serialize>(&self, value: &T) {
        if self.is_json() {
            match serde_json::to_string(value) {
                Ok(s)  => println!("{}", s),
                Err(e) => self.json_encode_failed(&e.to_string()),
            }
        }
    }

    // --------------------------------------------------------------
    // error — error message, both modes
    // --------------------------------------------------------------
    //
    // Human: "% <msg>" on stderr.
    // Json:  {"error":{"message":...}} on stdout.
    //
    // Errors do NOT honor --quiet; an operator running an automated
    // script needs the failure visible regardless.
    pub fn error(&self, msg: impl AsRef<str>) {
        let m = msg.as_ref();
        match self.mode {
            OutputMode::Human => eprintln!("% {}", m),
            OutputMode::Json => {
                let v = json!({"error": {"message": m}});
                println!("{}", v);
            }
        }
    }

    // --------------------------------------------------------------
    // error_coded — error with a machine-readable code
    // --------------------------------------------------------------
    //
    // For RPC errors carrying ProtoError.code, plus a few CLI-side
    // codes ("USAGE", "PARSE", "NOT_CONNECTED", ...). The human
    // render only shows the message; JSON includes both.
    pub fn error_coded(&self, code: impl AsRef<str>, msg: impl AsRef<str>) {
        let c = code.as_ref();
        let m = msg.as_ref();
        match self.mode {
            OutputMode::Human => eprintln!("% {}", m),
            OutputMode::Json => {
                let v = json!({"error": {"code": c, "message": m}});
                println!("{}", v);
            }
        }
    }

    // --------------------------------------------------------------
    // ok — acknowledge a mutation (no body)
    // --------------------------------------------------------------
    //
    // Human: prints `human_msg` (suppressed under --quiet).
    // Json:  always `{"ok":true}`.
    pub fn ok(&self, human_msg: impl AsRef<str>) {
        match self.mode {
            OutputMode::Human => {
                if !self.quiet {
                    println!("{}", human_msg.as_ref());
                }
            }
            OutputMode::Json => {
                println!("{{\"ok\":true}}");
            }
        }
    }

    // --------------------------------------------------------------
    // ok_with — acknowledge a mutation with a structured payload
    // --------------------------------------------------------------
    //
    // Human: renders `human_render` (suppressed under --quiet).
    // Json:  `{"ok":true, "data": <data>}`.
    pub fn ok_with<T: Serialize, F: FnOnce()>(&self, human_render: F, data: &T) {
        match self.mode {
            OutputMode::Human => {
                if !self.quiet {
                    human_render();
                }
            }
            OutputMode::Json => {
                let v = json!({"ok": true, "data": data});
                println!("{}", v);
            }
        }
    }

    // --------------------------------------------------------------
    // result — emit a structured result with a custom human renderer
    // --------------------------------------------------------------
    //
    // Convenience for read commands: pick one path or the other based
    // on output mode without re-checking is_json() at each call site.
    //
    //   out.result(|| { ep.display(name); }, || json!({...}));
    //
    // The JSON closure is only evaluated in JSON mode (so building
    // the value can be lazy), and the human closure only in human
    // mode.
    pub fn result<H: FnOnce(), J: FnOnce() -> Value>(&self, human_render: H, json_value: J) {
        match self.mode {
            OutputMode::Human => human_render(),
            OutputMode::Json => {
                let v = json_value();
                println!("{}", v);
            }
        }
    }

    // --------------------------------------------------------------
    // Internal: json encode failure
    // --------------------------------------------------------------
    //
    // serde_json errors on a Serialize impl shouldn't happen for our
    // own types (they all derive Serialize), but if one ever does we
    // surface it as a synthetic JSON error rather than panicking.
    fn json_encode_failed(&self, msg: &str) {
        // Fall back to a hand-built string so we don't recursively
        // hit the same encoder bug. The message is sanitized to
        // avoid breaking the JSON: backslash + double-quote only.
        let escaped: String = msg
            .chars()
            .flat_map(|c| match c {
                '\\' => "\\\\".chars().collect::<Vec<_>>(),
                '"'  => "\\\"".chars().collect::<Vec<_>>(),
                _    => vec![c],
            })
            .collect();
        println!(
            "{{\"error\":{{\"code\":\"JSON_ENCODE\",\"message\":\"{}\"}}}}",
            escaped,
        );
    }
}
