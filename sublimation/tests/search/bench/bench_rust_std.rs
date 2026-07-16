// Cross-language search bench, Rust standard-library point.
// literal: str::find (Two-Way), the only fast substring search in std, and it
// needs UTF-8, so this runs on the ASCII/UTF-8 corpora only. std has no regex.
// Protocol: <corpusfile> <pattern> <runs> <literal|regex>
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: file pat runs literal|regex");
        std::process::exit(2);
    }
    let is_regex = a[4] == "regex";
    if is_regex {
        return; // std has no regex engine
    }
    let data = std::fs::read(&a[1]).unwrap();
    let s = match std::str::from_utf8(&data) {
        Ok(s) => s,
        Err(_) => return, // str::find needs valid UTF-8
    };
    let pat = &a[2];
    let run = || {
        let (mut c, mut i) = (0usize, 0usize);
        while i <= s.len() {
            match s[i..].find(pat) {
                Some(j) => {
                    c += 1;
                    i += j + 1;
                } // overlapping
                None => break,
            }
        }
        c
    };
    let count = run();
    let mut dt = vec![0f64; 9];
    for r in 0..9 {
        let t0 = Instant::now();
        let _ = run();
        dt[r] = t0.elapsed().as_secs_f64();
    }
    dt.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let mb = data.len() as f64 / 1e6 / dt[4];
    println!("{{\"algo\":\"rust_std_find\",\"count\":{},\"mb_s\":{:.0}}}", count, mb);
}
