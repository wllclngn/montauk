// montauk-mcp's hand-rolled JSON-RPC 2.0 framing (montauk_mcp::rpc) -- one
// line in, one line out, driven here with in-memory buffers instead of real
// stdio via rpc::run_with_io.

use montauk_mcp::json::Value;
use montauk_mcp::rpc::{run_with_io, Dispatcher};
use std::io::Cursor;

struct EchoDispatcher;

impl Dispatcher for EchoDispatcher {
    fn dispatch(&mut self, method: &str, params: Option<&Value>) -> Result<Value, (i64, String)> {
        match method {
            "ping" => Ok(Value::String("pong".to_string())),
            "echo" => Ok(params.cloned().unwrap_or(Value::Null)),
            "boom" => Err((-32000, "boom happened".to_string())),
            other => Err((-32601, format!("unknown method '{other}'"))),
        }
    }
}

fn drive(input: &str) -> Vec<String> {
    let mut dispatcher = EchoDispatcher;
    let mut out = Vec::new();
    run_with_io(&mut dispatcher, Cursor::new(input.as_bytes()), &mut out);
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn responds_to_a_simple_request() {
    let responses = drive(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    assert_eq!(responses.len(), 1);
    let parsed = montauk_mcp::json::parse(&responses[0]).unwrap();
    assert_eq!(parsed.get("id").unwrap(), &Value::Number(1.0));
    assert_eq!(parsed.get("result").unwrap(), &Value::String("pong".to_string()));
}

#[test]
fn echoes_params_back_through_result() {
    let responses = drive(r#"{"jsonrpc":"2.0","id":2,"method":"echo","params":{"x":5}}"#);
    let parsed = montauk_mcp::json::parse(&responses[0]).unwrap();
    assert_eq!(parsed.get("result").unwrap().get("x").unwrap(), &Value::Number(5.0));
}

#[test]
fn maps_dispatcher_errors_to_jsonrpc_error_objects() {
    let responses = drive(r#"{"jsonrpc":"2.0","id":3,"method":"boom"}"#);
    let parsed = montauk_mcp::json::parse(&responses[0]).unwrap();
    let error = parsed.get("error").unwrap();
    assert_eq!(error.get("code").unwrap(), &Value::Number(-32000.0));
    assert_eq!(error.get("message").unwrap(), &Value::String("boom happened".to_string()));
}

#[test]
fn notifications_without_an_id_get_no_response() {
    // Per JSON-RPC 2.0: a request with no "id" is a notification -- the
    // server must not reply, even though dispatch() still runs.
    let responses = drive(r#"{"jsonrpc":"2.0","method":"ping"}"#);
    assert!(responses.is_empty());
}

#[test]
fn processes_multiple_requests_in_one_stream_in_order() {
    let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\
                 {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"unknown_method\"}\n\
                 {\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n";
    let responses = drive(input);
    assert_eq!(responses.len(), 3);
    let r1 = montauk_mcp::json::parse(&responses[0]).unwrap();
    let r2 = montauk_mcp::json::parse(&responses[1]).unwrap();
    let r3 = montauk_mcp::json::parse(&responses[2]).unwrap();
    assert_eq!(r1.get("result").unwrap(), &Value::String("pong".to_string()));
    assert!(r2.get("error").is_some());
    assert_eq!(r3.get("result").unwrap(), &Value::String("pong".to_string()));
}

#[test]
fn blank_lines_and_malformed_json_are_skipped_without_crashing() {
    let input = "\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\nnot json at all\n";
    let responses = drive(input);
    // Only the one well-formed request produces a response; the blank line
    // and the malformed line are dropped (logged to stderr, not stdout).
    assert_eq!(responses.len(), 1);
}
