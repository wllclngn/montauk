// montauk-mcp -- agent-facing MCP tool surface over montauk/sublimation.
// Read-only / observational only: no killing processes, no scheduler-policy
// changes, nothing mutating, in any of the four tools below.
//
// Three subprocess tools (montauk_snapshot, montauk_analyze_report,
// montauk_digest) wrap standalone one-shot processes -- nothing to link
// into, so language choice is inert there. `sublimation` is direct FFI into
// libsublimation.a instead, since an agent calling it repeatedly in a
// debugging loop would otherwise pay full process-spawn cost per call.

use montauk_mcp::{ffi, json, rpc};

use json::Value;
use std::process::Command;

struct ToolServer;

const TOOLS_LIST: &[(&str, &str)] = &[
    (
        "montauk_snapshot",
        "One-shot structured snapshot of live system state (CPU, PMU, memory, GPU, thermal, network, disk, filesystems, top processes). Read-only, wraps `montauk --json`.",
    ),
    (
        "montauk_analyze_report",
        "Run montauk_analyze's diagnostic reports over a trace file and return the structured JSON envelope. Read-only. Arguments: file (path), report (comma-separated report names, optional -- default all).",
    ),
    (
        "montauk_digest",
        "Compact specs+stability+thermal+offenders+key-metrics digest over a montauk --trace recording directory. Read-only. Arguments: dir (path), redact (bool, optional).",
    ),
    (
        "sublimation",
        "Direct call into sublimation's sort/classify/grep/contains engines -- no subprocess. Arguments: op (\"sort\"|\"classify\"|\"grep\"|\"contains\"), values (number array, for sort/classify), pattern/text (strings, for grep/contains), icase (bool, optional).",
    ),
];

fn run_subprocess(bin: &str, args: &[&str]) -> Result<String, (i64, String)> {
    let output = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| (-32000, format!("failed to spawn {bin}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err((-32000, format!("{bin} exited with {}: {stderr}", output.status)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn text_content(text: String) -> Value {
    Value::obj(vec![(
        "content",
        Value::Array(vec![Value::obj(vec![
            ("type", Value::String("text".to_string())),
            ("text", Value::String(text)),
        ])]),
    )])
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn arg_bool(args: &Value, key: &str) -> bool {
    matches!(args.get(key), Some(Value::Bool(true)))
}

fn call_montauk_snapshot() -> Result<Value, (i64, String)> {
    let out = run_subprocess("montauk", &["--json"])?;
    Ok(text_content(out))
}

fn call_montauk_analyze_report(args: &Value) -> Result<Value, (i64, String)> {
    let file = arg_str(args, "file").ok_or((-32602, "missing 'file' argument".to_string()))?;
    let mut owned_args: Vec<String> = vec![file.to_string()];
    if let Some(report) = arg_str(args, "report") {
        owned_args.push("--report".to_string());
        owned_args.push(report.to_string());
    }
    owned_args.push("--json".to_string());
    let arg_refs: Vec<&str> = owned_args.iter().map(String::as_str).collect();
    let out = run_subprocess("montauk_analyze", &arg_refs)?;
    Ok(text_content(out))
}

fn call_montauk_digest(args: &Value) -> Result<Value, (i64, String)> {
    let dir = arg_str(args, "dir").ok_or((-32602, "missing 'dir' argument".to_string()))?;
    let mut owned_args: Vec<String> = vec![dir.to_string(), "--digest".to_string()];
    if arg_bool(args, "redact") {
        owned_args.push("--redact".to_string());
    }
    owned_args.push("--json".to_string());
    let arg_refs: Vec<&str> = owned_args.iter().map(String::as_str).collect();
    let out = run_subprocess("montauk_analyze", &arg_refs)?;
    Ok(text_content(out))
}

fn values_as_f64(args: &Value) -> Result<Vec<f64>, (i64, String)> {
    let arr = args
        .get("values")
        .and_then(Value::as_array)
        .ok_or((-32602, "missing 'values' array argument".to_string()))?;
    arr.iter()
        .map(|v| v.as_f64().ok_or((-32602, "'values' must be an array of numbers".to_string())))
        .collect()
}

fn call_sublimation(args: &Value) -> Result<Value, (i64, String)> {
    let op = arg_str(args, "op").ok_or((-32602, "missing 'op' argument".to_string()))?;
    let icase = arg_bool(args, "icase");
    match op {
        "sort" => {
            let values = values_as_f64(args)?;
            let sorted = ffi::sort_f64(values);
            Ok(Value::obj(vec![(
                "result",
                Value::Array(sorted.into_iter().map(Value::Number).collect()),
            )]))
        }
        "classify" => {
            let values = values_as_f64(args)?;
            let profile = ffi::classify_f64(&values);
            let disorder = ffi::DISORDER_NAMES
                .get(profile.disorder as usize)
                .copied()
                .unwrap_or("unknown");
            Ok(Value::obj(vec![
                ("disorder", Value::String(disorder.to_string())),
                ("distinct_estimate", Value::Number(profile.distinct_estimate as f64)),
                ("inversion_ratio", Value::Number(profile.inversion_ratio as f64)),
                ("run_count", Value::Number(profile.run_count as f64)),
            ]))
        }
        "grep" => {
            let pattern = arg_str(args, "pattern").ok_or((-32602, "missing 'pattern' argument".to_string()))?;
            let text = arg_str(args, "text").ok_or((-32602, "missing 'text' argument".to_string()))?;
            match ffi::grep_find(pattern, text, icase) {
                Some((start, len)) => Ok(Value::obj(vec![
                    ("matched", Value::Bool(true)),
                    ("start", Value::Number(start as f64)),
                    ("len", Value::Number(len as f64)),
                ])),
                None => Ok(Value::obj(vec![("matched", Value::Bool(false))])),
            }
        }
        "contains" => {
            let pattern = arg_str(args, "pattern").ok_or((-32602, "missing 'pattern' argument".to_string()))?;
            let text = arg_str(args, "text").ok_or((-32602, "missing 'text' argument".to_string()))?;
            match ffi::contains_find(pattern, text, icase) {
                Some(pos) => Ok(Value::obj(vec![
                    ("matched", Value::Bool(true)),
                    ("start", Value::Number(pos as f64)),
                ])),
                None => Ok(Value::obj(vec![("matched", Value::Bool(false))])),
            }
        }
        other => Err((-32602, format!("unknown op '{other}' -- expected sort|classify|grep|contains"))),
    }
}

impl rpc::Dispatcher for ToolServer {
    fn dispatch(&mut self, method: &str, params: Option<&Value>) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(Value::obj(vec![
                ("protocolVersion", Value::String("2024-11-05".to_string())),
                (
                    "serverInfo",
                    Value::obj(vec![
                        ("name", Value::String("montauk-mcp".to_string())),
                        ("version", Value::String(env!("CARGO_PKG_VERSION").to_string())),
                    ]),
                ),
                ("capabilities", Value::obj(vec![("tools", Value::obj(vec![]))])),
            ])),
            "tools/list" => {
                let tools = TOOLS_LIST
                    .iter()
                    .map(|(name, desc)| {
                        Value::obj(vec![
                            ("name", Value::String(name.to_string())),
                            ("description", Value::String(desc.to_string())),
                            (
                                "inputSchema",
                                Value::obj(vec![
                                    ("type", Value::String("object".to_string())),
                                ]),
                            ),
                        ])
                    })
                    .collect();
                Ok(Value::obj(vec![("tools", Value::Array(tools))]))
            }
            "tools/call" => {
                let params = params.ok_or((-32602, "missing params".to_string()))?;
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or((-32602, "missing 'name'".to_string()))?;
                let empty_args = Value::obj(vec![]);
                let args = params.get("arguments").unwrap_or(&empty_args);
                match name {
                    "montauk_snapshot" => call_montauk_snapshot(),
                    "montauk_analyze_report" => call_montauk_analyze_report(args),
                    "montauk_digest" => call_montauk_digest(args),
                    "sublimation" => call_sublimation(args),
                    other => Err((-32601, format!("unknown tool '{other}'"))),
                }
            }
            other => Err((-32601, format!("unknown method '{other}'"))),
        }
    }
}

fn main() {
    if std::env::args().any(|a| a == "--version") {
        println!("montauk-mcp {} (sublimation api v{}, {})",
                  env!("CARGO_PKG_VERSION"), ffi::api_version(), ffi::version());
        return;
    }
    let mut server = ToolServer;
    rpc::run(&mut server);
}
