// vector's real tool-dispatch surface (vector::tools::ToolServer) --
// the actual tools an MCP client calls, as opposed to test_mcp_rpc.rs's
// framing tests (which deliberately use a trivial EchoDispatcher and never
// touch ToolServer at all) or test_mcp_json.rs's parser tests. Before this
// file, ToolServer's dispatch logic -- initialize, tools/list, tools/call
// for every tool, argument validation, subprocess wrapping, FFI dispatch
// -- had zero test coverage.

use vector::json::Value;
use vector::rpc::Dispatcher;
use vector::tools::ToolServer;
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
fn ffi_search_size_contract_holds() {
    // The Rust SubSearch mirror and the C sublimation_search must be the
    // same size, or compile writes past the mirror's stack buffer. The C
    // side pins its half with a static_assert; this is the runtime half.
    vector::ffi::assert_search_size_matches();
}

#[test]
fn initialize_reports_protocol_version_and_server_info() {
    let result = call("initialize", None).unwrap();
    assert_eq!(
        result.get("protocolVersion").unwrap(),
        &Value::String("2024-11-05".to_string())
    );
    let info = result.get("serverInfo").unwrap();
    assert_eq!(info.get("name").unwrap(), &Value::String("vector".to_string()));
    assert!(result.get("capabilities").unwrap().get("tools").is_some());
}

#[test]
fn tools_list_names_every_tool() {
    let result = call("tools/list", None).unwrap();
    let tools = result.get("tools").unwrap().as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.get("name").unwrap().as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "montauk_snapshot",
            "montauk_anomalies",
            "montauk_similar",
            "montauk_regime",
            "montauk_analyze_report",
            "montauk_digest",
            "sublimation"
        ]
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
    let parsed = vector::json::parse(tool_text(&result)).expect("sublimation sort output must parse");
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
    let parsed = vector::json::parse(tool_text(&result)).expect("sublimation classify output must parse");
    // Ascending 0..64 is the textbook "already sorted" case.
    assert_eq!(parsed.get("disorder").unwrap(), &Value::String("sorted".to_string()));
}

#[test]
fn sublimation_find_reports_match_position() {
    let args = Value::obj(vec![
        ("op", Value::String("find".to_string())),
        ("pattern", Value::String("wor.d".to_string())),
        ("text", Value::String("hello world".to_string())),
    ]);
    let result = tool_call("sublimation", args).unwrap();
    let parsed = vector::json::parse(tool_text(&result)).expect("sublimation grep output must parse");
    assert_eq!(parsed.get("matched").unwrap(), &Value::Bool(true));
    assert_eq!(parsed.get("start").unwrap(), &Value::Number(6.0));
}

#[test]
fn sublimation_find_no_match_reports_false() {
    let args = Value::obj(vec![
        ("op", Value::String("find".to_string())),
        ("pattern", Value::String("xyz".to_string())),
        ("text", Value::String("hello world".to_string())),
    ]);
    let result = tool_call("sublimation", args).unwrap();
    let parsed = vector::json::parse(tool_text(&result)).expect("sublimation grep output must parse");
    assert_eq!(parsed.get("matched").unwrap(), &Value::Bool(false));
}

#[test]
fn sublimation_find_invalid_regex_is_an_error_not_false() {
    // A pattern that cannot compile (state explosion past the engine's 256
    // NFA states) must surface as a JSON-RPC error. Mapping it to
    // matched:false hands the caller a silent wrong answer, indistinguishable
    // from a genuine no-match.
    let big = "a".repeat(400);
    let args = Value::obj(vec![
        ("op", Value::String("find".to_string())),
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
    let parsed = vector::json::parse(tool_text(&result)).expect("sublimation contains output must parse");
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
fn sublimation_find_missing_text_is_an_error() {
    let args = Value::obj(vec![
        ("op", Value::String("find".to_string())),
        ("pattern", Value::String("x".to_string())),
    ]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
}

// sublimation stat ops run over direct FFI; only the stream-shaped verbs spawn
// the sublimation CLI. The q check for quantile fails before either path
// (binary-independent); the CLI-backed ops skip gracefully when the binary
// isn't on PATH (the mcp layer runs cargo test with no build/ on PATH).

#[test]
fn sublimation_quantile_without_q_is_an_error() {
    let args = Value::obj(vec![
        ("op", Value::String("quantile".to_string())),
        ("values", Value::Array(vec![Value::Number(1.0), Value::Number(2.0)])),
    ]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
    assert!(err.1.contains('q'), "got: {}", err.1);
}

#[test]
fn sublimation_mean_returns_a_structured_value() {
    // Direct FFI into the stats lane -- no subprocess, so this never skips.
    let args = Value::obj(vec![
        ("op", Value::String("mean".to_string())),
        ("values", Value::Array(
            vec![Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)])),
    ]);
    let r = tool_call("sublimation", args).unwrap();
    let parsed = vector::json::parse(tool_text(&r)).expect("mean output must parse");
    assert_eq!(parsed.get("mean").and_then(Value::as_f64), Some(2.0));
}

#[test]
fn sublimation_describe_returns_the_full_summary() {
    let vals: Vec<Value> = (1..=4).map(|i| Value::Number(i as f64)).collect();
    let args = Value::obj(vec![
        ("op", Value::String("describe".to_string())),
        ("values", Value::Array(vals)),
    ]);
    let r = tool_call("sublimation", args).unwrap();
    let p = vector::json::parse(tool_text(&r)).expect("describe output must parse");
    assert_eq!(p.get("count").and_then(Value::as_f64), Some(4.0));
    assert_eq!(p.get("mean").and_then(Value::as_f64), Some(2.5));
    assert_eq!(p.get("min").and_then(Value::as_f64), Some(1.0));
    assert_eq!(p.get("max").and_then(Value::as_f64), Some(4.0));
}

#[test]
fn sublimation_quantile_honors_nearest_rank() {
    let vals: Vec<Value> = (1..=4).map(|i| Value::Number(i as f64)).collect();
    let args = Value::obj(vec![
        ("op", Value::String("quantile".to_string())),
        ("q", Value::Number(0.5)),
        ("values", Value::Array(vals)),
    ]);
    let r = tool_call("sublimation", args).unwrap();
    let p = vector::json::parse(tool_text(&r)).expect("quantile output must parse");
    // Estimator index floor(0.5*4) = 2 -> the third smallest.
    assert_eq!(p.get("value").and_then(Value::as_f64), Some(3.0));
}

#[test]
fn sublimation_quantile_rejects_q_out_of_range() {
    let args = Value::obj(vec![
        ("op", Value::String("quantile".to_string())),
        ("q", Value::Number(1.5)),
        ("values", Value::Array(vec![Value::Number(1.0), Value::Number(2.0)])),
    ]);
    let err = tool_call("sublimation", args).unwrap_err();
    assert_eq!(err.0, -32602);
}

#[test]
fn sublimation_tally_returns_structured_counts() {
    // Direct FFI (sublimation_tally) -- structured, high-to-low, never skips.
    let args = Value::obj(vec![
        ("op", Value::String("tally".to_string())),
        ("text", Value::String("a\nb\na\nc\na\nb".to_string())),
    ]);
    let r = tool_call("sublimation", args).unwrap();
    let p = vector::json::parse(tool_text(&r)).expect("tally output must parse");
    let arr = p.get("tally").and_then(Value::as_array).expect("tally array");
    // a:3, b:2, c:1 -- descending by count.
    let pair = |v: &Value| {
        (v.get("token").and_then(Value::as_str).unwrap_or("").to_string(),
         v.get("count").and_then(Value::as_f64).unwrap_or(0.0) as u64)
    };
    assert_eq!(pair(&arr[0]), ("a".to_string(), 3));
    assert_eq!(pair(&arr[1]), ("b".to_string(), 2));
    assert_eq!(pair(&arr[2]), ("c".to_string(), 1));
}

#[test]
fn sublimation_characterize_zeros_below_the_minimum_n() {
    // Direct FFI (sublimation_randomness_f64) -- n < 2 is a documented zeroed
    // result (confidence 0, verdict structured), the one deterministic case
    // that doesn't depend on the battery's own internal thresholds.
    let args = Value::obj(vec![
        ("op", Value::String("characterize".to_string())),
        ("values", Value::Array(vec![Value::Number(1.0)])),
    ]);
    let r = tool_call("sublimation", args).unwrap();
    let p = vector::json::parse(tool_text(&r)).expect("characterize output must parse");
    assert_eq!(p.get("confidence").and_then(Value::as_f64), Some(0.0));
    assert_eq!(p.get("verdict").and_then(Value::as_str), Some("structured"));
    assert_eq!(p.get("lens_count").and_then(Value::as_f64), Some(0.0));
    assert_eq!(p.get("agree_count").and_then(Value::as_f64), Some(0.0));
    let lenses = p.get("lenses").and_then(Value::as_array).expect("lenses array");
    assert_eq!(lenses.len(), 8);
    for lens in lenses {
        assert_eq!(lens.get("available").and_then(Value::as_bool), Some(false));
    }
}

#[test]
fn sublimation_characterize_names_every_lens() {
    // A real-sized input, so every lens name/score/available shape is
    // exercised even though the fused verdict itself is the C battery's own
    // call (already covered by sublimation/tests/test_randomness.c).
    let vals: Vec<Value> = (0..300)
        .map(|i| Value::Number(((i * 2654435761u32 as u64) % 1000) as f64))
        .collect();
    let args = Value::obj(vec![
        ("op", Value::String("characterize".to_string())),
        ("values", Value::Array(vals)),
    ]);
    let r = tool_call("sublimation", args).unwrap();
    let p = vector::json::parse(tool_text(&r)).expect("characterize output must parse");
    let verdict = p.get("verdict").and_then(Value::as_str).expect("verdict string");
    assert!(["structured", "mixed", "consistent", "max_entropy"].contains(&verdict));
    let confidence = p.get("confidence").and_then(Value::as_f64).expect("confidence number");
    assert!((0.0..1.0).contains(&confidence));
    let lenses = p.get("lenses").and_then(Value::as_array).expect("lenses array");
    let names: Vec<&str> = lenses.iter()
        .map(|l| l.get("name").and_then(Value::as_str).expect("lens name"))
        .collect();
    assert_eq!(names, vec![
        "hook", "lis", "inversion", "distinct", "hvg", "bandt_pompe", "rqa", "spectral",
    ]);
}

#[test]
fn sublimation_characterize_missing_values_is_an_error() {
    let err = tool_call("sublimation", Value::obj(vec![
        ("op", Value::String("characterize".to_string())),
    ])).unwrap_err();
    assert_eq!(err.0, -32602);
}

#[test]
fn sublimation_count_and_distinct_over_text() {
    let count = tool_call("sublimation", Value::obj(vec![
        ("op", Value::String("count".to_string())),
        ("text", Value::String("x\ny\nx\nz".to_string())),
    ])).unwrap();
    let cp = vector::json::parse(tool_text(&count)).unwrap();
    assert_eq!(cp.get("count").and_then(Value::as_f64), Some(4.0));

    let distinct = tool_call("sublimation", Value::obj(vec![
        ("op", Value::String("distinct".to_string())),
        ("text", Value::String("x\ny\nx\nz".to_string())),
    ])).unwrap();
    let dp = vector::json::parse(tool_text(&distinct)).unwrap();
    assert_eq!(dp.get("distinct").and_then(Value::as_f64), Some(3.0));
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
// since a fresh checkout with vector built but montauk_core not yet
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
        let parsed = vector::json::parse(text).expect("montauk_analyze --json output must parse");
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
        let parsed = vector::json::parse(text).expect("montauk_analyze --digest --json output must parse");
        assert!(parsed.get("schema_version").is_some());
        assert!(parsed.get("digest").is_some());
        std::fs::remove_dir_all(&digest_dir).ok();
    }

    // montauk_snapshot: a real, live one-shot system snapshot.
    if build.join("montauk").exists() {
        let result = tool_call("montauk_snapshot", Value::obj(vec![])).unwrap();
        let text = tool_text(&result);
        let parsed = vector::json::parse(text).expect("montauk --json output must parse");
        assert!(parsed.get("cpu").is_some());
        assert!(parsed.get("memory").is_some());
    }
}

#[test]
fn montauk_anomalies_computes_the_fusion_over_the_feature_matrix() {
    // Synthetic `montauk --json`: pid 100 is a pure CPU outlier against a quiet
    // population (rss/threads normal), so the in-process fusion must rank it
    // first and name cpu as its axis. >= 8 rows so the population gate passes.
    // Exercises the real learn-lane FFI (sublimation_anomaly_fuse), no subprocess.
    let json = r#"{"processes":{
        "top":[{"pid":100,"cmd":"hog"}],
        "anomaly_features":[
          {"pid":100,"cpu_pct":98.0,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0},
          {"pid":101,"cpu_pct":0.5,"rss_kb":1000,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0},
          {"pid":102,"cpu_pct":0.4,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0},
          {"pid":103,"cpu_pct":0.3,"rss_kb":1200,"gpu_util_pct":0,"fault_delta":0,"thread_count":2,"ctxsw_delta":0},
          {"pid":104,"cpu_pct":0.6,"rss_kb":1050,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0},
          {"pid":105,"cpu_pct":0.2,"rss_kb":1300,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0},
          {"pid":106,"cpu_pct":0.5,"rss_kb":1150,"gpu_util_pct":0,"fault_delta":0,"thread_count":2,"ctxsw_delta":0},
          {"pid":107,"cpu_pct":0.4,"rss_kb":1250,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0},
          {"pid":108,"cpu_pct":0.3,"rss_kb":1080,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0}
        ]}}"#;
    let result = vector::tools::anomalies_reduce(json, 3).expect("anomalies_reduce ok");
    let inner = vector::json::parse(tool_text(&result)).expect("inner json parses");
    let anomalies = inner.get("anomalies").and_then(Value::as_array).expect("anomalies array");
    assert!(!anomalies.is_empty(), "expected ranked anomalies");
    let top = &anomalies[0];
    assert_eq!(top.get("pid").and_then(Value::as_f64), Some(100.0), "the CPU hog ranks first");
    assert_eq!(top.get("axis").and_then(Value::as_str), Some("cpu"), "dominant axis is cpu");
    assert_eq!(top.get("cmd").and_then(Value::as_str), Some("hog"), "named from the top set");
}

// THE DRIFT GUARD. vector fused five features while montauk fused six for the
// whole of v8.7.0 -- two different answers to "what is anomalous", from a tool
// whose entire value is that it agrees with montauk. Nothing failed, because
// nothing was watching the SHAPE.
//
// A montauk that publishes a feature this build does not fuse must now be a
// REFUSAL, not a narrower ranking: a plausible-looking answer computed over the
// wrong matrix is the worst way to be wrong, and the message has to name the
// field so the fix is obvious.
#[test]
fn montauk_anomalies_refuses_a_feature_matrix_wider_than_it_fuses() {
    let json = r#"{"processes":{
        "top":[{"pid":100,"cmd":"hog"}],
        "anomaly_features":[
          {"pid":100,"cpu_pct":98.0,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0,"future_axis":5.0},
          {"pid":101,"cpu_pct":0.5,"rss_kb":1000,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0,"future_axis":0.0},
          {"pid":102,"cpu_pct":0.4,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0,"future_axis":0.0},
          {"pid":103,"cpu_pct":0.3,"rss_kb":1200,"gpu_util_pct":0,"fault_delta":0,"thread_count":2,"ctxsw_delta":0,"future_axis":0.0},
          {"pid":104,"cpu_pct":0.6,"rss_kb":1050,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0,"future_axis":0.0},
          {"pid":105,"cpu_pct":0.2,"rss_kb":1300,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0,"future_axis":0.0},
          {"pid":106,"cpu_pct":0.5,"rss_kb":1150,"gpu_util_pct":0,"fault_delta":0,"thread_count":2,"ctxsw_delta":0,"future_axis":0.0},
          {"pid":107,"cpu_pct":0.4,"rss_kb":1250,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0,"future_axis":0.0},
          {"pid":108,"cpu_pct":0.3,"rss_kb":1080,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":0,"future_axis":0.0}
        ]}}"#;
    let err = vector::tools::anomalies_reduce(json, 3).expect_err("must refuse a wider matrix");
    assert!(err.1.contains("future_axis"), "the refusal names the unknown feature: {}", err.1);
}

// And the sixth feature is genuinely fused, not merely accepted: a population
// whose ONLY outlier is the context-switch axis must rank that process first
// and name ctxsw. Under the five-feature build this row was invisible.
#[test]
fn montauk_anomalies_fuses_the_context_switch_axis() {
    let json = r#"{"processes":{
        "top":[{"pid":200,"cmd":"preempted"}],
        "anomaly_features":[
          {"pid":200,"cpu_pct":1.0,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":90000},
          {"pid":201,"cpu_pct":1.1,"rss_kb":1000,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":202,"cpu_pct":0.9,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2},
          {"pid":203,"cpu_pct":1.0,"rss_kb":1200,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":4},
          {"pid":204,"cpu_pct":1.2,"rss_kb":1050,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":205,"cpu_pct":0.8,"rss_kb":1300,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2},
          {"pid":206,"cpu_pct":1.0,"rss_kb":1150,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":5},
          {"pid":207,"cpu_pct":1.1,"rss_kb":1250,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":208,"cpu_pct":0.9,"rss_kb":1080,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2}
        ]}}"#;
    let result = vector::tools::anomalies_reduce(json, 3).expect("anomalies_reduce ok");
    let inner = vector::json::parse(tool_text(&result)).expect("inner json parses");
    let anomalies = inner.get("anomalies").and_then(Value::as_array).expect("anomalies array");
    let top = &anomalies[0];
    assert_eq!(top.get("pid").and_then(Value::as_f64), Some(200.0), "the preempted process ranks first");
    assert_eq!(top.get("axis").and_then(Value::as_str), Some("ctxsw"), "dominant axis is ctxsw");
}

// EVERY RANKED PROCESS IS NAMEABLE. The ranking runs over anomaly_features
// (the whole population) while `top` holds only the displayed subset, so
// naming from `top` alone left the majority of ranked pids with cmd:"" -- a
// rank attached to what reads like a process with no command. montauk carries
// a comm on every feature row for this; `top`'s fuller cmdline still wins
// where it exists.
#[test]
fn montauk_anomalies_names_a_process_outside_the_displayed_top_set() {
    let json = r#"{"processes":{
        "top":[{"pid":200,"cmd":"/usr/lib/firefox/firefox --tab"}],
        "anomaly_features":[
          {"pid":200,"comm":"firefox","cpu_pct":1.0,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":90000},
          {"pid":201,"comm":"kworker/2:1","cpu_pct":1.1,"rss_kb":1000,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":202,"comm":"sshd","cpu_pct":0.9,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2},
          {"pid":203,"comm":"systemd","cpu_pct":1.0,"rss_kb":1200,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":4},
          {"pid":204,"comm":"dbus-daemon","cpu_pct":1.2,"rss_kb":1050,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":205,"comm":"pipewire","cpu_pct":0.8,"rss_kb":1300,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2},
          {"pid":206,"comm":"chrome","cpu_pct":1.0,"rss_kb":1150,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":5},
          {"pid":207,"comm":"bash","cpu_pct":1.1,"rss_kb":1250,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":208,"comm":"nvidia-smi","cpu_pct":0.9,"rss_kb":1080,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2}
        ]}}"#;
    let result = vector::tools::anomalies_reduce(json, 9).expect("anomalies_reduce ok");
    let inner = vector::json::parse(tool_text(&result)).expect("inner json parses");
    let anomalies = inner.get("anomalies").and_then(Value::as_array).expect("anomalies array");

    for a in anomalies {
        let pid = a.get("pid").and_then(Value::as_f64).expect("pid");
        let cmd = a.get("cmd").and_then(Value::as_str).unwrap_or("");
        assert!(!cmd.is_empty(), "pid {pid} ranked but was returned with no name");
    }
    // pid 200 is in `top`, so the richer full cmdline wins over its comm.
    let p200 = anomalies.iter().find(|a| a.get("pid").and_then(Value::as_f64) == Some(200.0)).unwrap();
    assert_eq!(p200.get("cmd").and_then(Value::as_str), Some("/usr/lib/firefox/firefox --tab"));
    // pid 206 is NOT in `top` and would have been nameless before.
    let p206 = anomalies.iter().find(|a| a.get("pid").and_then(Value::as_f64) == Some(206.0)).unwrap();
    assert_eq!(p206.get("cmd").and_then(Value::as_str), Some("chrome"));
}

// comm is IDENTITY, not a feature: it must not trip the contract check that
// refuses a feature matrix wider than this build fuses.
#[test]
fn montauk_anomalies_does_not_mistake_comm_for_a_fusion_axis() {
    let json = r#"{"processes":{
        "top":[],
        "anomaly_features":[
          {"pid":1,"comm":"a","cpu_pct":1.0,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":9},
          {"pid":2,"comm":"b","cpu_pct":1.1,"rss_kb":1000,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":3,"comm":"c","cpu_pct":0.9,"rss_kb":1100,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2},
          {"pid":4,"comm":"d","cpu_pct":1.0,"rss_kb":1200,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":4},
          {"pid":5,"comm":"e","cpu_pct":1.2,"rss_kb":1050,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":6,"comm":"f","cpu_pct":0.8,"rss_kb":1300,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2},
          {"pid":7,"comm":"g","cpu_pct":1.0,"rss_kb":1150,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":5},
          {"pid":8,"comm":"h","cpu_pct":1.1,"rss_kb":1250,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":3},
          {"pid":9,"comm":"i","cpu_pct":0.9,"rss_kb":1080,"gpu_util_pct":0,"fault_delta":0,"thread_count":1,"ctxsw_delta":2}
        ]}}"#;
    assert!(vector::tools::anomalies_reduce(json, 3).is_ok(),
            "comm names the row; it is not an axis and must not be refused as one");
}

// Build a snapshot with `rows` feature rows, of which only the first
// `top_rows` also appear in `top`. pid == index, so a pid above top_rows is one
// that the old top-only implementation would have refused outright.
fn similar_fixture(rows: usize, top_rows: usize) -> String {
    let mut top = Vec::new();
    for i in 0..top_rows {
        top.push(format!(r#"{{"pid":{i},"cmd":"displayed-{i}"}}"#));
    }
    let mut feats = Vec::new();
    for i in 0..rows {
        let f = i as f64;
        feats.push(format!(
            r#"{{"pid":{i},"comm":"proc-{i}","cpu_pct":{:.3},"rss_kb":{:.1},"gpu_util_pct":0,"fault_delta":{:.1},"thread_count":{},"ctxsw_delta":{:.1}}}"#,
            (f * 0.37) % 11.0,
            1000.0 + f * 13.0,
            f % 7.0,
            1 + (i % 5),
            f % 17.0
        ));
    }
    format!(
        r#"{{"processes":{{"top":[{}],"anomaly_features":[{}]}}}}"#,
        top.join(","),
        feats.join(",")
    )
}

// THE HAND-OFF THE TWO TOOLS EXIST TO SUPPORT. montauk_anomalies ranks the whole
// population, so montauk_similar has to accept a pid from anywhere in it. This
// read `top` alone and refused 79% of them on a real box.
#[test]
fn montauk_similar_accepts_a_pid_outside_the_displayed_top_set() {
    let json = similar_fixture(120, 10);
    let result = vector::tools::similar_reduce(&json, 97, 5).expect("pid 97 is a live process");
    let inner = vector::json::parse(tool_text(&result)).expect("inner json parses");
    assert_eq!(
        inner.get("query").and_then(|q| q.get("pid")).and_then(Value::as_f64),
        Some(97.0)
    );
    // Named from the feature row's comm, since 97 is not in `top`.
    assert_eq!(
        inner.get("query").and_then(|q| q.get("cmd")).and_then(Value::as_str),
        Some("proc-97")
    );
    let sim = inner.get("similar").and_then(Value::as_array).expect("similar array");
    assert_eq!(sim.len(), 5);
    for s in sim {
        assert!(!s.get("cmd").and_then(Value::as_str).unwrap_or("").is_empty(),
                "every neighbour is named");
    }
}

// A pid genuinely absent from the population is still an error, and the error
// still names live pids for the caller to retry with.
#[test]
fn montauk_similar_still_refuses_a_pid_that_is_not_running() {
    let json = similar_fixture(50, 10);
    let err = vector::tools::similar_reduce(&json, 999_999, 5).expect_err("pid is not live");
    assert!(err.1.contains("999999"), "the error names the pid asked for");
    assert!(err.1.contains("process population"), "and says what it searched");
}

// ABOVE THE CAP THE GRAPH IS BOUNDED, and `basis` says so rather than leaving
// the caller to assume the whole population was related. The O(n^3) solve costs
// ~50 s at n=1024, so an uncapped promise here is a hang.
#[test]
fn montauk_similar_caps_the_graph_and_states_the_bound() {
    let json = similar_fixture(900, 10);
    let result = vector::tools::similar_reduce(&json, 800, 5).expect("query is live");
    let inner = vector::json::parse(tool_text(&result)).expect("inner json parses");
    let basis = inner.get("basis").and_then(Value::as_str).expect("basis");
    assert!(basis.contains("512 of 900"), "basis reports the bound it used: {basis}");
    assert!(basis.contains("nearest to the query"), "and how the set was chosen: {basis}");
    // The query survives its own pre-filter.
    assert_eq!(
        inner.get("query").and_then(|q| q.get("pid")).and_then(Value::as_f64),
        Some(800.0)
    );
}

// Under the cap, nothing is dropped and the basis says the whole population.
#[test]
fn montauk_similar_relates_the_whole_population_when_it_fits() {
    let json = similar_fixture(200, 10);
    let result = vector::tools::similar_reduce(&json, 150, 3).expect("query is live");
    let inner = vector::json::parse(tool_text(&result)).expect("inner json parses");
    let basis = inner.get("basis").and_then(Value::as_str).expect("basis");
    assert!(basis.contains("200 of 200"), "no pre-filter below the cap: {basis}");
    assert!(basis.contains("whole population"), "and it says so: {basis}");
}

#[test]
fn montauk_anomalies_errors_when_the_feature_matrix_is_absent() {
    // No anomaly_features block -> a contract break, surfaced as an error rather
    // than a silent all-zero ranking.
    let json = r#"{"processes":{"top":[{"pid":1,"cmd":"x"}]}}"#;
    assert!(vector::tools::anomalies_reduce(json, 5).is_err());
}

// `grep` IS REJECTED BY NAME, WITH THE ALTERNATIVES. sublimation replaces grep
// rather than reimplementing it, so this surface must not promise grep's
// contract -- the op returns ONE span over the whole text, where grep returns
// one result per matching line. A bare "unknown op 'grep'" would read as "this
// server cannot match text", which is the opposite of true.
#[test]
fn sublimation_rejects_grep_by_name_and_names_the_alternatives() {
    for name in ["grep", "search", "match"] {
        let args = Value::obj(vec![
            ("op", Value::String(name.to_string())),
            ("pattern", Value::String("a".to_string())),
            ("text", Value::String("abc".to_string())),
        ]);
        let err = vector::tools::call_sublimation(&args).expect_err("must reject");
        assert!(err.1.contains("'find'"), "{name}: names find: {}", err.1);
        assert!(err.1.contains("'contains'"), "{name}: names contains: {}", err.1);
        assert!(err.1.contains("sublimation search"), "{name}: names the CLI: {}", err.1);
        assert!(!err.1.starts_with("unknown op"), "{name}: not a bare unknown: {}", err.1);
    }
}

// And `find` is honest about WHICH span it returns: one match over the whole
// text, not per line. ^ anchors to the text, so a pattern that would match
// three separate lines under grep matches once here.
#[test]
fn sublimation_find_spans_the_text_not_each_line() {
    let args = Value::obj(vec![
        ("op", Value::String("find".to_string())),
        ("pattern", Value::String("^a.*a$".to_string())),
        ("text", Value::String("alpha\nbeta\nalpaca".to_string())),
    ]);
    let out = vector::tools::call_sublimation(&args).expect("find ok");
    let v = vector::json::parse(tool_text(&out)).expect("json");
    assert_eq!(v.get("matched").and_then(Value::as_bool), Some(true));
    // The whole 17-byte text, not the 5-byte first line -- the behaviour the
    // rename exists to stop misrepresenting. grep would return three lines here.
    assert_eq!(v.get("len").and_then(Value::as_f64), Some(17.0), "one span over the text");
}
