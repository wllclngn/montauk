// montauk-mcp's real tool-dispatch surface (montauk_mcp::tools::ToolServer) --
// the actual four tools an MCP client calls, as opposed to test_mcp_rpc.rs's
// framing tests (which deliberately use a trivial EchoDispatcher and never
// touch ToolServer at all) or test_mcp_json.rs's parser tests. Before this
// file, ToolServer's dispatch logic -- initialize, tools/list, tools/call
// for all four tools, argument validation, subprocess wrapping, FFI dispatch
// -- had zero test coverage.

use montauk_mcp::json::Value;
use montauk_mcp::rpc::Dispatcher;
use montauk_mcp::tools::ToolServer;
use std::path::PathBuf;
use std::sync::Once;

fn call(method: &str, params: Option<Value>) -> Result<Value, (i64, String)> {
    let mut server = ToolServer;
    server.dispatch(method, params.as_ref())
}

fn tool_call(name: &str, arguments: Value) -> Result<Value, (i64, String)> {
    call(
        "tools/call",
        Some(Value::obj(vec![
            ("name", Value::String(name.to_string())),
            ("arguments", arguments),
        ])),
    )
}

fn tool_text(result: &Value) -> &str {
    result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .expect("tool result missing content[0].text")
}

#[test]
fn initialize_reports_protocol_version_and_server_info() {
    let result = call("initialize", None).unwrap();
    assert_eq!(
        result.get("protocolVersion").unwrap(),
        &Value::String("2024-11-05".to_string())
    );
    let info = result.get("serverInfo").unwrap();
    assert_eq!(info.get("name").unwrap(), &Value::String("montauk-mcp".to_string()));
    assert!(result.get("capabilities").unwrap().get("tools").is_some());
}

#[test]
fn tools_list_names_all_four_tools() {
    let result = call("tools/list", None).unwrap();
    let tools = result.get("tools").unwrap().as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.get("name").unwrap().as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec!["montauk_snapshot", "montauk_analyze_report", "montauk_digest", "sublimation"]
    );
    // Every tool description must say what it wraps or does -- a regression
    // where a description goes empty would otherwise pass silently.
    for tool in tools {
        assert!(!tool.get("description").unwrap().as_str().unwrap().is_empty());
    }
}

#[test]
fn unknown_method_is_a_jsonrpc_method_not_found_error() {
    let err = call("no/such/method", None).unwrap_err();
    assert_eq!(err.0, -32601);
}

#[test]
fn tools_call_missing_params_is_an_error() {
    let err = call("tools/call", None).unwrap_err();
    assert_eq!(err.0, -32602);
}

#[test]
fn tools_call_unknown_tool_name_is_an_error() {
    let err = tool_call("not_a_real_tool", Value::obj(vec![])).unwrap_err();
    assert_eq!(err.0, -32601);
    assert!(err.1.contains("not_a_real_tool"));
}

// sublimation: direct FFI, no subprocess -- every op, the happy path and
// the argument-validation error paths.

#[test]
fn sublimation_sort_returns_ascending_order() {
    let args = Value::obj(vec![
        ("op", Value::String("sort".to_string())),
        (
            "values",
            Value::Array(vec![Value::Number(5.0), Value::Number(1.0), Value::Number(3.0)]),
        ),
    ]);
    let result = tool_call("sublimation", args).unwrap();
    let parsed = montauk_mcp::json::parse(tool_text(&result)).expect("sublimation sort output must parse");
    let sorted = parsed.get("result").unwrap().as_array().unwrap();
    let values: Vec<f64> = sorted.iter().map(|v| v.as_f64().unwrap()).collect();
    assert_eq!(values, vec![1.0, 3.0, 5.0]);
}

#[test]
fn sublimation_classify_names_a_disorder_class() {
    let values: Vec<Value> = (0..64).map(|i| Value::Number(i as f64)).collect();
    let args = Value::obj(vec![
        ("op", Value::String("classify".to_string())),
        ("values", Value::Array(values)),
    ]);
    let result = tool_call("sublimation", args).unwrap();
    let parsed = montauk_mcp::json::parse(tool_text(&result)).expect("sublimation classify output must parse");
    // Ascending 0..64 is the textbook "already sorted" case.
    assert_eq!(parsed.get("disorder").unwrap(), &Value::String("sorted".to_string()));
}

#[test]
fn sublimation_grep_reports_match_position() {
    let args = Value::obj(vec![
        ("op", Value::String("grep".to_string())),
        ("pattern", Value::String("wor.d".to_string())),
        ("text", Value::String("hello world".to_string())),
    ]);
    let result = tool_call("sublimation", args).unwrap();
    let parsed = montauk_mcp::json::parse(tool_text(&result)).expect("sublimation grep output must parse");
    assert_eq!(parsed.get("matched").unwrap(), &Value::Bool(true));
    assert_eq!(parsed.get("start").unwrap(), &Value::Number(6.0));
}

#[test]
fn sublimation_grep_no_match_reports_false() {
    let args = Value::obj(vec![
        ("op", Value::String("grep".to_string())),
        ("pattern", Value::String("xyz".to_string())),
        ("text", Value::String("hello world".to_string())),
    ]);
    let result = tool_call("sublimation", args).unwrap();
    let parsed = montauk_mcp::json::parse(tool_text(&result)).expect("sublimation grep output must parse");
    assert_eq!(parsed.get("matched").unwrap(), &Value::Bool(false));
}

#[test]
fn sublimation_grep_invalid_regex_is_an_error_not_false() {
    // A pattern that cannot compile (state explosion past the engine's 256
    // NFA states) must surface as a JSON-RPC error. Mapping it to
    // matched:false hands the caller a silent wrong answer, indistinguishable
    // from a genuine no-match.
    let big = "a".repeat(400);
    let args = Value::obj(vec![
        ("op", Value::String("grep".to_string())),
        ("pattern", Value::String(big)),
        ("text", Value::String("hello".to_string())),
    ]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("invalid regex"), "got: {}", err.1);
}

#[test]
fn sublimation_contains_oversize_needle_is_an_error_not_a_match() {
    // A needle past the engine's pattern cap (1023 bytes) must surface as an
    // argument error, not compile through to a silent wrong answer.
    let big = "b".repeat(1100);
    let args = Value::obj(vec![
        ("op", Value::String("contains".to_string())),
        ("pattern", Value::String(big)),
        ("text", Value::String("anything".to_string())),
    ]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("needle length"), "got: {}", err.1);
}

#[test]
fn sublimation_contains_case_insensitive() {
    let args = Value::obj(vec![
        ("op", Value::String("contains".to_string())),
        ("pattern", Value::String("WORLD".to_string())),
        ("text", Value::String("hello world".to_string())),
        ("icase", Value::Bool(true)),
    ]);
    let result = tool_call("sublimation", args).unwrap();
    let parsed = montauk_mcp::json::parse(tool_text(&result)).expect("sublimation contains output must parse");
    assert_eq!(parsed.get("matched").unwrap(), &Value::Bool(true));
}

#[test]
fn sublimation_unknown_op_is_an_error() {
    let args = Value::obj(vec![("op", Value::String("median".to_string()))]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("median"));
}

#[test]
fn sublimation_missing_op_is_an_error() {
    let err = tool_call("sublimation", Value::obj(vec![])).unwrap_err();
    assert_eq!(err.0, -32602);
}

#[test]
fn sublimation_sort_missing_values_is_an_error() {
    let args = Value::obj(vec![("op", Value::String("sort".to_string()))]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
}

#[test]
fn sublimation_grep_missing_text_is_an_error() {
    let args = Value::obj(vec![
        ("op", Value::String("grep".to_string())),
        ("pattern", Value::String("x".to_string())),
    ]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
}

// montauk_analyze_report / montauk_digest: argument validation fails before
// any subprocess is spawned, so these are safe to run with no binary on PATH.

#[test]
fn montauk_analyze_report_missing_file_is_an_error() {
    let err = tool_call("montauk_analyze_report", Value::obj(vec![])).unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("file"));
}

#[test]
fn montauk_digest_missing_dir_is_an_error() {
    let err = tool_call("montauk_digest", Value::obj(vec![])).unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("dir"));
}

// The three subprocess-wrapping tools' happy paths, against the real
// binaries built earlier in the same tree (../build/ relative to
// CARGO_MANIFEST_DIR). Skipped, not failed, if the binaries aren't there --
// same missing-binary discipline tests/harness.py's missing_bins() uses,
// since a fresh checkout with montauk-mcp built but montauk_core not yet
// built shouldn't fail this suite. All three share one PATH mutation, done
// once in one test function -- std::env::set_var is process-global, and
// Rust runs #[test] functions in parallel by default, so splitting this
// across multiple functions would race.
static PATH_SET: Once = Once::new();

fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("build")
}

fn ensure_build_dir_on_path() {
    PATH_SET.call_once(|| {
        let build = build_dir();
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![build];
        paths.extend(std::env::split_paths(&existing));
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
    });
}

#[test]
fn subprocess_backed_tools_happy_paths() {
    let build = build_dir();
    if !build.join("montauk_analyze").exists() {
        eprintln!("SKIP: montauk_analyze not built at {build:?}, skipping subprocess-backed tests");
        return;
    }
    ensure_build_dir_on_path();

    // montauk_analyze_report over the deterministic synthetic fixture
    // corpus_check.py already gates -- same file, different consumer.
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("synthetic.mtk");
    if fixture.exists() {
        let args = Value::obj(vec![("file", Value::String(fixture.to_string_lossy().into_owned()))]);
        let result = tool_call("montauk_analyze_report", args).unwrap();
        let text = tool_text(&result);
        let parsed = montauk_mcp::json::parse(text).expect("montauk_analyze --json output must parse");
        assert!(parsed.get("schema_version").is_some());
        assert!(parsed.get("reports").is_some());
    }

    // montauk_digest over a throwaway directory containing a copy of the
    // same fixture -- --digest takes a recording directory, not a file.
    if fixture.exists() {
        let digest_dir = std::env::temp_dir().join(format!("mcp_digest_test_{}", std::process::id()));
        std::fs::create_dir_all(&digest_dir).unwrap();
        std::fs::copy(&fixture, digest_dir.join("synthetic.mtk")).unwrap();
        let args = Value::obj(vec![("dir", Value::String(digest_dir.to_string_lossy().into_owned()))]);
        let result = tool_call("montauk_digest", args).unwrap();
        let text = tool_text(&result);
        let parsed = montauk_mcp::json::parse(text).expect("montauk_analyze --digest --json output must parse");
        assert!(parsed.get("schema_version").is_some());
        assert!(parsed.get("digest").is_some());
        std::fs::remove_dir_all(&digest_dir).ok();
    }

    // montauk_snapshot: a real, live one-shot system snapshot.
    if build.join("montauk").exists() {
        let result = tool_call("montauk_snapshot", Value::obj(vec![])).unwrap();
        let text = tool_text(&result);
        let parsed = montauk_mcp::json::parse(text).expect("montauk --json output must parse");
        assert!(parsed.get("cpu").is_some());
        assert!(parsed.get("memory").is_some());
    }
}
