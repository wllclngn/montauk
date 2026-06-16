// bench_rust.rs -- Benchmark: Rust slice::sort_unstable (pdqsort) +
// std-only fork-join parallel pdqsort wrapper around it.
// Protocol: argv[1]=size argv[2]=pattern argv[3]=runs [argv[4]=parallel]
// Output: JSON line(s) with ns_per_element
use std::env;
use std::thread;
use std::time::Instant;

// Median-of-three pivot selection -- swap median into arr[mid].
fn med3(arr: &mut [i64]) -> i64 {
    let n = arr.len();
    let mid = n / 2;
    if arr[mid] < arr[0] { arr.swap(0, mid); }
    if arr[n - 1] < arr[0] { arr.swap(0, n - 1); }
    if arr[n - 1] < arr[mid] { arr.swap(mid, n - 1); }
    arr[mid]
}

// Lomuto partition. Returns the index of the pivot after partitioning.
fn partition(arr: &mut [i64], pivot: i64) -> usize {
    let n = arr.len();
    let mut store = 0;
    for i in 0..n {
        if arr[i] < pivot {
            arr.swap(i, store);
            store += 1;
        }
    }
    store
}

// Fork-join parallel pdqsort wrapper. Recurses in parallel using
// std::thread::scope (stable since Rust 1.63). Below CUTOFF or beyond
// MAX_DEPTH, falls back to the standard library's sort_unstable (which
// IS pdqsort, so the leaf phase is at the same speed as serial Rust).
fn par_sort(arr: &mut [i64], depth: usize) {
    const CUTOFF: usize = 50_000;
    const MAX_DEPTH: usize = 4; // 2^4 = up to 16 worker threads

    if arr.len() < CUTOFF || depth >= MAX_DEPTH {
        arr.sort_unstable();
        return;
    }

    let pivot = med3(arr);
    let p = partition(arr, pivot);
    let (left, right) = arr.split_at_mut(p);

    thread::scope(|s| {
        s.spawn(|| par_sort(left, depth + 1));
        par_sort(right, depth + 1);
    });
}

fn fill_random(arr: &mut [i64], seed: u64) {
    let mut s = seed;
    for v in arr.iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *v = (s >> 16) as i64;
    }
}

fn fill_pattern(arr: &mut [i64], pattern: &str, seed: u64) {
    let n = arr.len();
    match pattern {
        "random" => fill_random(arr, seed),
        "sorted" => { for i in 0..n { arr[i] = i as i64; } }
        "reversed" => { for i in 0..n { arr[i] = (n - i) as i64; } }
        "nearly" => {
            for i in 0..n { arr[i] = i as i64; }
            let swaps = std::cmp::max(n / 100, 2);
            let mut s = seed;
            for _ in 0..swaps {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let i = (s >> 33) as usize % n;
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let j = (s >> 33) as usize % n;
                arr.swap(i, j);
            }
        }
        "few_unique" => {
            let mut s = seed;
            for v in arr.iter_mut() {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *v = ((s >> 33) % 5) as i64;
            }
        }
        "pipe_organ" => {
            let half = n / 2;
            for i in 0..half { arr[i] = i as i64; }
            for i in half..n { arr[i] = (n - i) as i64; }
        }
        "phased" => {
            let boundary = n * 3 / 4;
            for i in 0..boundary { arr[i] = i as i64; }
            fill_random(&mut arr[boundary..], seed);
        }
        "equal" => { for v in arr.iter_mut() { *v = 42; } }
        _ => fill_random(arr, seed),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <size> <pattern> <runs> [parallel]", args[0]);
        std::process::exit(1);
    }
    let n: usize = args[1].parse().unwrap();
    let pattern = &args[2];
    let runs: usize = args[3].parse().unwrap();
    let do_parallel = args.len() > 4 && args[4] == "parallel";

    let mut arr = vec![0i64; n];

    // ---- Serial: slice::sort_unstable (pdqsort) ----
    let mut best_ns = f64::MAX;
    fill_pattern(&mut arr, pattern, 42);
    arr.sort_unstable(); // warmup
    for r in 0..runs {
        fill_pattern(&mut arr, pattern, 42 + r as u64);
        let t0 = Instant::now();
        arr.sort_unstable();
        let elapsed = t0.elapsed().as_nanos() as f64;
        let ns_per = elapsed / n as f64;
        if ns_per < best_ns { best_ns = ns_per; }
    }
    println!("{{\"algo\":\"rust_sort_unstable\",\"size\":{},\"pattern\":\"{}\",\"ns_per_elem\":{:.2}}}",
             n, pattern, best_ns);

    // ---- Parallel: std::thread::scope fork-join wrapper around sort_unstable ----
    if do_parallel {
        let mut best_par = f64::MAX;
        fill_pattern(&mut arr, pattern, 42);
        par_sort(&mut arr, 0); // warmup
        for r in 0..runs {
            fill_pattern(&mut arr, pattern, 42 + r as u64);
            let t0 = Instant::now();
            par_sort(&mut arr, 0);
            let elapsed = t0.elapsed().as_nanos() as f64;
            let ns_per = elapsed / n as f64;
            if ns_per < best_par { best_par = ns_per; }
        }
        println!("{{\"algo\":\"rust_par_sort_unstable\",\"size\":{},\"pattern\":\"{}\",\"ns_per_elem\":{:.2}}}",
                 n, pattern, best_par);
    }
}
