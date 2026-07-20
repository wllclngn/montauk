// The four-tool dispatch surface -- moved out of main.rs into the library
// so it's reachable from tests/test_mcp_tools.rs the same way ffi/json/rpc
// already are. main.rs is now a thin wrapper: parse --version, then
// rpc::run(&mut ToolServer).
//
// Three subprocess tools (montauk_snapshot, montauk_analyze_report,
// montauk_digest) wrap standalone one-shot processes -- nothing to link
// into, so language choice is inert there. `sublimation` is direct FFI into
// libsublimation.a instead, since an agent calling it repeatedly in a
// debugging loop would otherwise pay full process-spawn cost per call.

use crate::ffi;
use crate::json::Value;
use crate::rpc;
use std::process::Command;

pub struct ToolServer;

pub const TOOLS_LIST: &[(&str, &str)] = &[
    (
        "montauk_snapshot",
        "One-shot structured snapshot of live system state (CPU, PMU, memory, GPU, thermal, network, disk, filesystems, top processes). Read-only, wraps `montauk --json`.",
    ),
    (
        "montauk_anomalies",
        "What is anomalous on the system right now, ranked and explained. Fuses MAD, Mahalanobis and Half-Space Trees over the live process population (CPU, RSS, GPU) into a per-process anomaly score, and returns the top processes with the dominant feature axis and a plain-language note. Read-only, wraps `montauk --json`. Arguments: top (number, optional, how many to return, default 5).",
    ),
    (
        "montauk_similar",
        "Processes behaving like a given one, by effective-resistance (commute-time) distance over an RBF affinity graph of the live process population (CPU, RSS, GPU). Read-only, wraps `montauk --json` plus a direct FFI into sublimation's spectral core. Arguments: pid (number, required), top (number, optional, default 5).",
    ),
    (
        "montauk_regime",
        "Did the machine's load regime shift recently, and when. Samples aggregate CPU utilization over a short window and runs sublimation's Spectral Residual (direct FFI) to locate shifts, returning each flagged point with how many seconds ago it happened. Read-only, an active measurement (about 6s). Arguments: samples (number, optional, rounded to a power of two, default 64, sampled 100ms apart).",
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

fn str_array(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.to_string())).collect())
}

fn schema_prop(ty: &str) -> Value {
    Value::obj(vec![("type", Value::String(ty.to_string()))])
}

fn schema_string_enum(variants: &[&str]) -> Value {
    Value::obj(vec![
        ("type", Value::String("string".to_string())),
        ("enum", str_array(variants)),
    ])
}

fn schema_number_array() -> Value {
    Value::obj(vec![
        ("type", Value::String("array".to_string())),
        ("items", schema_prop("number")),
    ])
}

fn schema_object(properties: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let mut fields = vec![
        ("type", Value::String("object".to_string())),
        ("properties", Value::obj(properties)),
    ];
    if !required.is_empty() {
        fields.push(("required", str_array(required)));
    }
    Value::obj(fields)
}

// The real per-tool JSON Schema, keyed by name. tools/list previously
// advertised a bare {"type":"object"} for every tool regardless of what it
// actually took -- with no declared `properties`, an MCP client has nothing
// but the free-text description to learn a param's shape from, which is how
// `sublimation`'s array-typed `values` field failed to reach the server: the
// arg is real in call_sublimation/values_as_f64, just never described here.
pub fn input_schema_for(name: &str) -> Value {
    match name {
        "montauk_snapshot" => schema_object(vec![], &[]),
        "montauk_anomalies" => schema_object(vec![("top", schema_prop("number"))], &[]),
        "montauk_similar" => schema_object(
            vec![("pid", schema_prop("number")), ("top", schema_prop("number"))],
            &["pid"],
        ),
        "montauk_regime" => schema_object(vec![("samples", schema_prop("number"))], &[]),
        "montauk_analyze_report" => schema_object(
            vec![
                ("file", schema_prop("string")),
                ("report", schema_prop("string")),
            ],
            &["file"],
        ),
        "montauk_digest" => schema_object(
            vec![
                ("dir", schema_prop("string")),
                ("redact", schema_prop("boolean")),
            ],
            &["dir"],
        ),
        "sublimation" => schema_object(
            vec![
                ("op", schema_string_enum(&["sort", "classify", "grep", "contains"])),
                ("values", schema_number_array()),
                ("pattern", schema_prop("string")),
                ("text", schema_prop("string")),
                ("icase", schema_prop("boolean")),
            ],
            &["op"],
        ),
        _ => schema_object(vec![], &[]),
    }
}

pub fn run_subprocess(bin: &str, args: &[&str]) -> Result<String, (i64, String)> {
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

pub fn text_content(text: String) -> Value {
    Value::obj(vec![(
        "content",
        Value::Array(vec![Value::obj(vec![
            ("type", Value::String("text".to_string())),
            ("text", Value::String(text)),
        ])]),
    )])
}

pub fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

pub fn arg_bool(args: &Value, key: &str) -> bool {
    matches!(args.get(key), Some(Value::Bool(true)))
}

pub fn call_montauk_snapshot() -> Result<Value, (i64, String)> {
    let out = run_subprocess("montauk", &["--json"])?;
    Ok(text_content(out))
}

pub fn call_montauk_anomalies(args: &Value) -> Result<Value, (i64, String)> {
    let top_n = args
        .get("top")
        .and_then(Value::as_f64)
        .map(|f| f as usize)
        .unwrap_or(5)
        .clamp(1, 50);
    let out = run_subprocess("montauk", &["--json"])?;
    let snap = crate::json::parse(&out).map_err(|e| (-32000, format!("parse montauk --json: {e}")))?;
    let procs = snap
        .get("processes")
        .and_then(|p| p.get("top"))
        .and_then(Value::as_array)
        .ok_or((-32000, "montauk --json missing processes.top".to_string()))?;
    let mut rows: Vec<(f64, i64, String, i64, f64, f64)> = procs
        .iter()
        .map(|p| {
            (
                p.get("anomaly_score").and_then(Value::as_f64).unwrap_or(0.0),
                p.get("pid").and_then(Value::as_f64).unwrap_or(0.0) as i64,
                p.get("cmd").and_then(Value::as_str).unwrap_or("").to_string(),
                p.get("anomaly_axis").and_then(Value::as_f64).unwrap_or(-1.0) as i64,
                p.get("cpu_pct").and_then(Value::as_f64).unwrap_or(0.0),
                p.get("rss_kb").and_then(Value::as_f64).unwrap_or(0.0),
            )
        })
        .collect();
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(top_n);
    let axis_name = |a: i64| -> &'static str {
        match a {
            0 => "cpu",
            1 => "rss",
            2 => "gpu",
            _ => "none",
        }
    };
    let items: Vec<Value> = rows
        .iter()
        .map(|(score, pid, cmd, axis, cpu, rss)| {
            let an = axis_name(*axis);
            let val = match *axis {
                0 => format!("{cpu:.0}% CPU"),
                1 => format!("{:.0} MB RSS", rss / 1024.0),
                2 => "GPU activity".to_string(),
                _ => "no dominant feature".to_string(),
            };
            let note =
                format!("{an} is this process's dominant deviation from the population ({val})");
            Value::obj(vec![
                ("pid", Value::Number(*pid as f64)),
                ("cmd", Value::String(cmd.clone())),
                ("anomaly_score", Value::Number((score * 1000.0).round() / 1000.0)),
                ("axis", Value::String(an.to_string())),
                ("cpu_pct", Value::Number((cpu * 10.0).round() / 10.0)),
                ("rss_mb", Value::Number((rss / 1024.0).round())),
                ("note", Value::String(note)),
            ])
        })
        .collect();
    let count = items.len() as f64;
    let result = Value::obj(vec![
        ("anomalies", Value::Array(items)),
        ("count", Value::Number(count)),
        (
            "basis",
            Value::String(
                "fused MAD, Mahalanobis and Half-Space Trees over the live process \
                 population (cpu, rss, gpu); higher score is more anomalous"
                    .to_string(),
            ),
        ),
    ]);
    Ok(text_content(result.to_string()))
}

pub fn call_montauk_similar(args: &Value) -> Result<Value, (i64, String)> {
    let query_pid = args
        .get("pid")
        .and_then(Value::as_f64)
        .ok_or((-32602, "missing 'pid' argument".to_string()))? as i64;
    let top_n = args
        .get("top")
        .and_then(Value::as_f64)
        .map(|f| f as usize)
        .unwrap_or(5)
        .clamp(1, 50);
    let out = run_subprocess("montauk", &["--json"])?;
    let snap = crate::json::parse(&out).map_err(|e| (-32000, format!("parse montauk --json: {e}")))?;
    let procs = snap
        .get("processes")
        .and_then(|p| p.get("top"))
        .and_then(Value::as_array)
        .ok_or((-32000, "montauk --json missing processes.top".to_string()))?;
    let n = procs.len();
    if n < 3 {
        return Err((-32000, "too few processes for a similarity graph".to_string()));
    }
    let mut pids = Vec::with_capacity(n);
    let mut cmds = Vec::with_capacity(n);
    let mut feat = vec![0.0f64; n * 3];
    for (i, p) in procs.iter().enumerate() {
        pids.push(p.get("pid").and_then(Value::as_f64).unwrap_or(0.0) as i64);
        cmds.push(p.get("cmd").and_then(Value::as_str).unwrap_or("").to_string());
        feat[i * 3] = p.get("cpu_pct").and_then(Value::as_f64).unwrap_or(0.0);
        feat[i * 3 + 1] = p.get("rss_kb").and_then(Value::as_f64).unwrap_or(0.0);
        feat[i * 3 + 2] = p.get("gpu_util_pct").and_then(Value::as_f64).unwrap_or(0.0);
    }
    let qi = pids
        .iter()
        .position(|&p| p == query_pid)
        .ok_or((-32602, format!("pid {query_pid} not in the top process list")))?;
    for j in 0..3 {                                   // standardize each column
        let mean = (0..n).map(|i| feat[i * 3 + j]).sum::<f64>() / n as f64;
        let var = (0..n).map(|i| (feat[i * 3 + j] - mean).powi(2)).sum::<f64>() / n as f64;
        let sd = var.sqrt();
        for i in 0..n {
            feat[i * 3 + j] = if sd > 0.0 { (feat[i * 3 + j] - mean) / sd } else { 0.0 };
        }
    }
    let mut d2 = vec![0.0f64; n * n];                 // pairwise squared distance
    let mut nz = Vec::new();
    for i in 0..n {
        for k in (i + 1)..n {
            let s: f64 = (0..3).map(|j| (feat[i * 3 + j] - feat[k * 3 + j]).powi(2)).sum();
            d2[i * n + k] = s;
            d2[k * n + i] = s;
            if s > 0.0 {
                nz.push(s);
            }
        }
    }
    nz.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let sigma2 = if nz.is_empty() { 1.0 } else { nz[nz.len() / 2].max(1e-12) };
    // RBF affinity, zero diagonal, with a small floor so the graph stays
    // connected: on a mostly-idle population the raw RBF isolates the few active
    // outliers, and effective resistance to a disconnected node is degenerate.
    let mut w = vec![0.0f64; n * n];
    for i in 0..n {
        for k in 0..n {
            if i != k {
                w[i * n + k] = (-d2[i * n + k] / (2.0 * sigma2)).exp() + 1e-3;
            }
        }
    }
    let reff = ffi::effective_resistance(&w, n)
        .ok_or((-32000, "effective resistance failed (degenerate graph)".to_string()))?;
    let mut order: Vec<usize> = (0..n).filter(|&j| j != qi).collect();
    order.sort_by(|&a, &b| {
        reff[qi * n + a]
            .partial_cmp(&reff[qi * n + b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    order.truncate(top_n);
    let items: Vec<Value> = order
        .iter()
        .map(|&j| {
            Value::obj(vec![
                ("pid", Value::Number(pids[j] as f64)),
                ("cmd", Value::String(cmds[j].clone())),
                ("resistance", Value::Number((reff[qi * n + j] * 1000.0).round() / 1000.0)),
            ])
        })
        .collect();
    let result = Value::obj(vec![
        (
            "query",
            Value::obj(vec![
                ("pid", Value::Number(query_pid as f64)),
                ("cmd", Value::String(cmds[qi].clone())),
            ]),
        ),
        ("similar", Value::Array(items)),
        (
            "basis",
            Value::String(
                "effective-resistance (commute-time) nearest over an RBF affinity \
                 graph of the live processes (cpu, rss, gpu); lower resistance is \
                 more similar"
                    .to_string(),
            ),
        ),
    ]);
    Ok(text_content(result.to_string()))
}

// Aggregate CPU busy/total jiffies from the first line of /proc/stat. montauk's
// one-shot snapshot is instantaneous and carries no history, so a temporal "did
// anything shift" query samples this directly. Read-only.
fn read_cpu_totals() -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().next()?;
    let mut it = line.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = it.filter_map(|t| t.parse().ok()).collect();
    if vals.len() < 5 {
        return None;
    }
    let idle = vals[3] + vals[4]; // idle + iowait
    let total: u64 = vals.iter().sum();
    Some((idle, total))
}

pub fn call_montauk_regime(args: &Value) -> Result<Value, (i64, String)> {
    let req = args
        .get("samples")
        .and_then(Value::as_f64)
        .map(|f| f as usize)
        .unwrap_or(64);
    let n = req.next_power_of_two().clamp(16, 256);
    let interval = std::time::Duration::from_millis(100);
    let mut prev = read_cpu_totals().ok_or((-32000, "cannot read /proc/stat".to_string()))?;
    let mut signal = Vec::with_capacity(n);
    for _ in 0..n {
        std::thread::sleep(interval);
        let cur = read_cpu_totals().ok_or((-32000, "cannot read /proc/stat".to_string()))?;
        let dt = cur.1.saturating_sub(prev.1);
        let di = cur.0.saturating_sub(prev.0);
        let pct = if dt > 0 { (1.0 - di as f64 / dt as f64) * 100.0 } else { 0.0 };
        signal.push(pct);
        prev = cur;
    }
    let z = (n / 4).max(1);
    let (sal, flags) = ffi::spectral_residual(&signal, 3, 3.0, z)
        .ok_or((-32000, "spectral residual failed".to_string()))?;
    let mut shifts = Vec::new();
    for i in 0..n {
        if flags[i] != 0 {
            shifts.push(Value::obj(vec![
                ("seconds_ago", Value::Number(((n - 1 - i) as f64 * 0.1 * 10.0).round() / 10.0)),
                ("cpu_pct", Value::Number((signal[i] * 10.0).round() / 10.0)),
                ("saliency", Value::Number((sal[i] * 1000.0).round() / 1000.0)),
            ]));
        }
    }
    let shifted = !shifts.is_empty();
    let mean = signal.iter().sum::<f64>() / n as f64;
    let result = Value::obj(vec![
        ("shifted", Value::Bool(shifted)),
        ("shifts", Value::Array(shifts)),
        ("window_seconds", Value::Number((n as f64 * 0.1 * 10.0).round() / 10.0)),
        ("samples", Value::Number(n as f64)),
        ("mean_cpu_pct", Value::Number((mean * 10.0).round() / 10.0)),
        (
            "basis",
            Value::String(
                "Spectral Residual over the machine's aggregate CPU sampled at 100ms; \
                 a flagged point is a regime shift, seconds_ago counts back from now"
                    .to_string(),
            ),
        ),
    ]);
    Ok(text_content(result.to_string()))
}

pub fn call_montauk_analyze_report(args: &Value) -> Result<Value, (i64, String)> {
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

pub fn call_montauk_digest(args: &Value) -> Result<Value, (i64, String)> {
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

pub fn values_as_f64(args: &Value) -> Result<Vec<f64>, (i64, String)> {
    let arr = args
        .get("values")
        .and_then(Value::as_array)
        .ok_or((-32602, "missing 'values' array argument".to_string()))?;
    arr.iter()
        .map(|v| v.as_f64().ok_or((-32602, "'values' must be an array of numbers".to_string())))
        .collect()
}

pub fn call_sublimation(args: &Value) -> Result<Value, (i64, String)> {
    let op = arg_str(args, "op").ok_or((-32602, "missing 'op' argument".to_string()))?;
    let icase = arg_bool(args, "icase");
    let result = match op {
        "sort" => {
            let values = values_as_f64(args)?;
            let sorted = ffi::sort_f64(values);
            Value::obj(vec![(
                "result",
                Value::Array(sorted.into_iter().map(Value::Number).collect()),
            )])
        }
        "classify" => {
            let values = values_as_f64(args)?;
            let profile = ffi::classify_f64(&values);
            let disorder = ffi::DISORDER_NAMES
                .get(profile.disorder as usize)
                .copied()
                .unwrap_or("unknown");
            Value::obj(vec![
                ("disorder", Value::String(disorder.to_string())),
                ("distinct_estimate", Value::Number(profile.distinct_estimate as f64)),
                ("inversion_ratio", Value::Number(profile.inversion_ratio as f64)),
                ("run_count", Value::Number(profile.run_count as f64)),
            ])
        }
        "grep" => {
            let pattern = arg_str(args, "pattern").ok_or((-32602, "missing 'pattern' argument".to_string()))?;
            let text = arg_str(args, "text").ok_or((-32602, "missing 'text' argument".to_string()))?;
            // A compile failure is a JSON-RPC error, never matched:false --
            // a default that aliases a real result is the failure mode this
            // boundary exists to prevent.
            match ffi::grep_find(pattern, text, icase).map_err(|e| (-32602, e))? {
                Some((start, len)) => Value::obj(vec![
                    ("matched", Value::Bool(true)),
                    ("start", Value::Number(start as f64)),
                    ("len", Value::Number(len as f64)),
                ]),
                None => Value::obj(vec![("matched", Value::Bool(false))]),
            }
        }
        "contains" => {
            let pattern = arg_str(args, "pattern").ok_or((-32602, "missing 'pattern' argument".to_string()))?;
            let text = arg_str(args, "text").ok_or((-32602, "missing 'text' argument".to_string()))?;
            match ffi::contains_find(pattern, text, icase).map_err(|e| (-32602, e))? {
                Some(pos) => Value::obj(vec![
                    ("matched", Value::Bool(true)),
                    ("start", Value::Number(pos as f64)),
                ]),
                None => Value::obj(vec![("matched", Value::Bool(false))]),
            }
        }
        other => {
            return Err((-32602, format!("unknown op '{other}' -- expected sort|classify|grep|contains")));
        }
    };
    Ok(text_content(result.to_string()))
}

impl rpc::Dispatcher for ToolServer {
    fn dispatch(&mut self, method: &str, params: Option<&Value>) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(Value::obj(vec![
                ("protocolVersion", Value::String("2024-11-05".to_string())),
                (
                    "serverInfo",
                    Value::obj(vec![
                        ("name", Value::String("vector".to_string())),
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
                            ("inputSchema", input_schema_for(name)),
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
                    "montauk_anomalies" => call_montauk_anomalies(args),
                    "montauk_similar" => call_montauk_similar(args),
                    "montauk_regime" => call_montauk_regime(args),
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
