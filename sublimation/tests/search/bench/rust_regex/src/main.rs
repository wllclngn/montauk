// Cross-language search bench, Rust regex crate point (the gold standard: the
// engine inside ripgrep, SIMD Teddy prefilters and a lazy DFA). Works on bytes,
// so it handles every corpus. A literal pattern is escaped and fed to the same
// engine, which is exactly how fast Rust literal search is done in practice.
// Protocol: <corpusfile> <pattern> <runs> <literal|regex>
use regex::bytes::Regex;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: file pat runs literal|regex");
        std::process::exit(2);
    }
    let data = std::fs::read(&a[1]).unwrap();
    let pat = &a[2];
    let is_regex = a[4] == "regex";
    let re = if is_regex {
        Regex::new(pat).unwrap()
    } else {
        Regex::new(&regex::escape(pat)).unwrap()
    };
    let run = || re.find_iter(&data).count();
    let count = run();
    let mut dt = vec![0f64; 9];
    for r in 0..9 {
        let t0 = Instant::now();
        let _ = run();
        dt[r] = t0.elapsed().as_secs_f64();
    }
    dt.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let mb = data.len() as f64 / 1e6 / dt[4];
    let algo = if is_regex { "rust_regex_crate" } else { "rust_regex_literal" };
    println!("{{\"algo\":\"{}\",\"count\":{},\"mb_s\":{:.0}}}", algo, count, mb);
}
