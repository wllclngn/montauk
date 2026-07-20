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
fn blank_lines_are_skipped_and_malformed_json_gets_a_parse_error() {
    let input = "\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\nnot json at all\n";
    let responses = drive(input);
    // The blank line is skipped; the malformed line now earns a -32700
    // error response instead of a silent stderr-only drop.
    assert_eq!(responses.len(), 2);
    let r1 = montauk_mcp::json::parse(&responses[0]).unwrap();
    assert_eq!(r1.get("result").unwrap(), &Value::String("pong".to_string()));
    let r2 = montauk_mcp::json::parse(&responses[1]).unwrap();
    assert_eq!(r2.get("error").unwrap().get("code").unwrap(), &Value::Number(-32700.0));
}

#[test]
fn parse_error_response_carries_null_id_per_spec() {
    let responses = drive("{this is not json}\n");
    assert_eq!(responses.len(), 1);
    let parsed = montauk_mcp::json::parse(&responses[0]).unwrap();
    assert_eq!(parsed.get("jsonrpc").unwrap(), &Value::String("2.0".to_string()));
    // JSON-RPC 2.0: when the request id cannot be determined, id is null.
    assert_eq!(parsed.get("id").unwrap(), &Value::Null);
    let error = parsed.get("error").unwrap();
    assert_eq!(error.get("code").unwrap(), &Value::Number(-32700.0));
    assert_eq!(error.get("message").unwrap(), &Value::String("Parse error".to_string()));
}

#[test]
fn invalid_request_with_recoverable_id_echoes_that_id() {
    // Valid JSON, has an id, but no "method": Invalid Request, and the
    // response must carry the request's own id so the caller can match it.
    let responses = drive(r#"{"jsonrpc":"2.0","id":7}"#);
    assert_eq!(responses.len(), 1);
    let parsed = montauk_mcp::json::parse(&responses[0]).unwrap();
    assert_eq!(parsed.get("id").unwrap(), &Value::Number(7.0));
    let error = parsed.get("error").unwrap();
    assert_eq!(error.get("code").unwrap(), &Value::Number(-32600.0));
    assert_eq!(error.get("message").unwrap(), &Value::String("Invalid Request".to_string()));
}

#[test]
fn invalid_request_with_non_string_method_echoes_its_id() {
    let responses = drive(r#"{"jsonrpc":"2.0","id":"abc","method":42}"#);
    assert_eq!(responses.len(), 1);
    let parsed = montauk_mcp::json::parse(&responses[0]).unwrap();
    assert_eq!(parsed.get("id").unwrap(), &Value::String("abc".to_string()));
    assert_eq!(parsed.get("error").unwrap().get("code").unwrap(), &Value::Number(-32600.0));
}

#[test]
fn non_object_request_is_invalid_with_null_id() {
    // Well-formed JSON that isn't a request object at all: no id is
    // recoverable, so the -32600 response carries null.
    let responses = drive("42\n");
    assert_eq!(responses.len(), 1);
    let parsed = montauk_mcp::json::parse(&responses[0]).unwrap();
    assert_eq!(parsed.get("id").unwrap(), &Value::Null);
    assert_eq!(parsed.get("error").unwrap().get("code").unwrap(), &Value::Number(-32600.0));
}
