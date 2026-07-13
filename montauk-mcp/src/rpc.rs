// Hand-rolled JSON-RPC 2.0 loop over stdio. One line in, one line out: MCP's
// stdio transport is newline-delimited JSON, not LSP-style Content-Length
// framing. stdout carries protocol messages only; all logging goes to
// stderr, so a client tailing stdout never sees anything but valid frames.

use crate::json::Value;
use std::io::{self, BufRead, Write};

pub trait Dispatcher {
    /// Handle one JSON-RPC method call. Return Err((code, message)) for a
    /// JSON-RPC error response.
    fn dispatch(&mut self, method: &str, params: Option<&Value>) -> Result<Value, (i64, String)>;
}

pub fn run(dispatcher: &mut dyn Dispatcher) {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with_io(dispatcher, stdin.lock(), stdout.lock());
}

/// The actual loop, generic over its IO so an external integration test
/// (tests/test_mcp_rpc.rs) can drive it with in-memory buffers instead of
/// real stdio.
pub fn run_with_io<R: BufRead, W: Write>(dispatcher: &mut dyn Dispatcher, input: R, mut stdout: W) {
    for line in input.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("montauk-mcp: stdin read error: {e}");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let request = match crate::json::parse(line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("montauk-mcp: malformed JSON-RPC line, dropped: {e}");
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = match request.get("method").and_then(Value::as_str) {
            Some(m) => m.to_string(),
            None => {
                eprintln!("montauk-mcp: request missing 'method', dropped");
                continue;
            }
        };
        let params = request.get("params").cloned();

        // A notification (no "id") gets no response, per JSON-RPC 2.0.
        let Some(id) = id else {
            let _ = dispatcher.dispatch(&method, params.as_ref());
            continue;
        };

        let response = match dispatcher.dispatch(&method, params.as_ref()) {
            Ok(result) => Value::obj(vec![
                ("jsonrpc", Value::String("2.0".to_string())),
                ("id", id),
                ("result", result),
            ]),
            Err((code, message)) => Value::obj(vec![
                ("jsonrpc", Value::String("2.0".to_string())),
                ("id", id),
                (
                    "error",
                    Value::obj(vec![
                        ("code", Value::Number(code as f64)),
                        ("message", Value::String(message)),
                    ]),
                ),
            ]),
        };

        let _ = writeln!(stdout, "{}", response.to_string());
        let _ = stdout.flush();
    }
}

