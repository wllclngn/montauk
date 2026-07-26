// extern "C" bindings straight into libsublimation.a -- no subprocess, no CLI
// argv parsing. Covers the core numeric sort/classify path (sublimation.h)
// and the text engines (sublimation_text.h): the two families an agent's
// `sublimation` tool call actually needs. Every symbol here is already
// extern "C" on the C++ side too (montauk_core/montauk_analyze link the same
// static lib), so the ABI is plain C -- no name mangling, no bindgen needed.

use std::os::raw::{c_int, c_long, c_uint};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SubProfile {
    pub n: usize,
    pub run_count: usize,
    pub mono_count: usize,
    pub max_run_len: usize,
    pub max_descent_gap: i64,
    pub lis_length: usize,
    pub lds_length: usize,
    pub info_theoretic_bound: f32,
    pub interleave_k: usize,
    pub distinct_estimate: usize,
    pub inversion_ratio: f32,
    pub phase_boundary: usize,
    pub rotation_point: usize,
    pub spectral_gap: f32,
    pub spectral_gap_ratio: f32,
    pub disorder: c_int, // sub_disorder_t
}

pub const DISORDER_NAMES: [&str; 6] = [
    "sorted", "reversed", "nearly_sorted", "few_unique", "random", "phased",
];

// sublimation_search: the tri-face matcher, one compiled value type (exact,
// regex and fuzzy under a classify-dispatch front end). Opaque to Rust -- an
// 8-byte-aligned buffer sized to sizeof(sublimation_search) = 5696 bytes
// (grew from 3648 when the byte-position map moved into the compiled
// program). The size contract is enforced twice: a C static_assert in
// match.c pins 5696 so library growth breaks that build, and
// assert_search_size_matches() below checks the C library at runtime, so a
// mismatched pairing can never compile a pattern into a short buffer.
const SUB_SEARCH_MAX_PATTERN: usize = 1023;
const SUB_SEARCH_FIXED: c_uint = 1;
const SUB_SEARCH_ICASE: c_uint = 2;

#[repr(C, align(8))]
struct SubSearch {
    _data: [u64; 712], // 712 * 8 = 5696 bytes, mirrors sizeof(sublimation_search)
}

static SIZE_CHECK: std::sync::Once = std::sync::Once::new();

/// Runtime half of the size contract: the C library reports
/// sizeof(sublimation_search); the mirror must match exactly. Called before
/// the first compile; also exercised directly by the test suite.
pub fn assert_search_size_matches() {
    let c_size = unsafe { sublimation_search_sizeof() };
    let rs_size = std::mem::size_of::<SubSearch>();
    assert!(
        c_size == rs_size,
        "sublimation_search size mismatch: C {c_size} vs Rust mirror {rs_size}; \
         update SubSearch in ffi.rs"
    );
}

extern "C" {
    fn sublimation_f64(arr: *mut f64, n: usize);
    fn sublimation_classify_f64(arr: *const f64, n: usize) -> SubProfile;
    fn sublimation_api_version() -> c_int;
    fn sublimation_version() -> *const std::os::raw::c_char;

    fn sublimation_search_sizeof() -> usize;
    fn sublimation_search_compile(out: *mut SubSearch, pattern: *const u8, len: usize,
                                  flags: c_uint, k: c_int);
    fn sublimation_search_valid(s: *const SubSearch) -> c_int;
    fn sublimation_search_find(s: *const SubSearch, input: *const u8, n: usize,
                               end_out: *mut c_long) -> c_long;
    fn sublimation_self_tuning_affinity(x: *const f64, n: usize, d: usize, knn: c_uint,
                                        w: *mut f64) -> c_int;
    fn sublimation_effective_resistance(w: *const f64, n: usize, reff: *mut f64) -> c_int;
    fn sublimation_spectral_residual(signal: *const f64, n: usize, q: usize, tau: f64,
                                     z: usize, saliency: *mut f64, flags: *mut u8) -> c_int;
    fn sublimation_anomaly_fuse(x: *const f64, n: usize, d: usize,
                                scores: *mut f64, axes: *mut i8) -> c_int;
}

pub fn sort_f64(mut values: Vec<f64>) -> Vec<f64> {
    unsafe { sublimation_f64(values.as_mut_ptr(), values.len()) };
    values
}

pub fn classify_f64(values: &[f64]) -> SubProfile {
    unsafe { sublimation_classify_f64(values.as_ptr(), values.len()) }
}

// Self-tuning (local-scaling) RBF affinity over a feature matrix x (n rows by d
// columns). Standardizes columns, scales each node by the distance to its knn-th
// neighbor, and returns the n*n affinity, or None on a size mismatch or OOM. The
// local scale keeps an outlier query's neighborhood defined where a single
// global bandwidth would collapse every edge to the connectivity floor.
pub fn self_tuning_affinity(x: &[f64], n: usize, d: usize, knn: u32) -> Option<Vec<f64>> {
    if n == 0 || d == 0 || x.len() != n * d {
        return None;
    }
    let mut w = vec![0.0f64; n * n];
    let rc = unsafe { sublimation_self_tuning_affinity(x.as_ptr(), n, d, knn, w.as_mut_ptr()) };
    if rc == 0 {
        Some(w)
    } else {
        None
    }
}

// Effective resistance (Kyng-Dinic commute-time distance) over the Laplacian of
// a symmetric non-negative n*n adjacency w. Returns the n*n resistance matrix,
// or None on a size mismatch or a degenerate graph.
pub fn effective_resistance(w: &[f64], n: usize) -> Option<Vec<f64>> {
    if n == 0 || w.len() != n * n {
        return None;
    }
    let mut reff = vec![0.0f64; n * n];
    let rc = unsafe { sublimation_effective_resistance(w.as_ptr(), n, reff.as_mut_ptr()) };
    if rc == 0 {
        Some(reff)
    } else {
        None
    }
}

// Spectral Residual saliency + anomaly flags over a real signal (length a power
// of two). Returns (saliency, flags) or None on a bad length. q is the box
// filter length, tau the relative-deviation threshold, z the trailing window.
pub fn spectral_residual(signal: &[f64], q: usize, tau: f64, z: usize)
    -> Option<(Vec<f64>, Vec<u8>)> {
    let n = signal.len();
    if n == 0 || (n & (n - 1)) != 0 {
        return None;
    }
    let mut sal = vec![0.0f64; n];
    let mut fl = vec![0u8; n];
    let rc = unsafe {
        sublimation_spectral_residual(signal.as_ptr(), n, q, tau, z, sal.as_mut_ptr(),
                                      fl.as_mut_ptr())
    };
    if rc == 0 {
        Some((sal, fl))
    } else {
        None
    }
}

// Fused anomaly score + dominant axis over a row-major n*d feature matrix -- the
// same learn-lane primitive montauk's snapshot enrichment uses, so vector's
// montauk_anomalies computes the conclusion in-process rather than relaying a
// precomputed number. Returns (scores[n], axes[n]) or None on a size mismatch or
// allocation failure.
pub fn anomaly_fuse(x: &[f64], n: usize, d: usize) -> Option<(Vec<f64>, Vec<i8>)> {
    if n == 0 || d == 0 || x.len() != n * d {
        return None;
    }
    let mut scores = vec![0.0f64; n];
    let mut axes = vec![0i8; n];
    let rc = unsafe {
        sublimation_anomaly_fuse(x.as_ptr(), n, d, scores.as_mut_ptr(), axes.as_mut_ptr())
    };
    if rc == 0 {
        Some((scores, axes))
    } else {
        None
    }
}

pub fn version() -> String {
    unsafe {
        let ptr = sublimation_version();
        if ptr.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// sublimation_stats: the descriptive-statistics lane. These used to live
// inline in the CLI, so reaching them meant forking a subprocess per call;
// they are library entry points now and this tool calls them directly, the
// same way it already calls sort and the matcher.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SubDescribe {
    pub n: usize,
    pub mean: f64,
    pub stdev: f64,
    pub min: f64,
    pub q25: f64,
    pub q50: f64,
    pub q75: f64,
    pub max: f64,
}

extern "C" {
    fn sublimation_sum_f64(v: *const f64, n: usize) -> f64;
    fn sublimation_mean_f64(v: *const f64, n: usize) -> f64;
    fn sublimation_variance_f64(v: *const f64, n: usize) -> f64;
    fn sublimation_stdev_f64(v: *const f64, n: usize) -> f64;
    fn sublimation_min_f64(v: *const f64, n: usize) -> f64;
    fn sublimation_max_f64(v: *const f64, n: usize) -> f64;
    fn sublimation_quantile_f64(arr: *mut f64, n: usize, q: f64, nearest: c_int) -> f64;
    fn sublimation_describe_f64(arr: *mut f64, n: usize) -> SubDescribe;
    fn sublimation_tukey_fences_f64(arr: *mut f64, n: usize, lo: *mut f64, hi: *mut f64);
    fn sublimation_histogram_f64(v: *const f64, n: usize, nbins: usize,
                                 counts: *mut usize, out_min: *mut f64,
                                 out_width: *mut f64);
}

pub fn sum(v: &[f64]) -> f64 { unsafe { sublimation_sum_f64(v.as_ptr(), v.len()) } }
pub fn mean(v: &[f64]) -> f64 { unsafe { sublimation_mean_f64(v.as_ptr(), v.len()) } }
pub fn variance(v: &[f64]) -> f64 { unsafe { sublimation_variance_f64(v.as_ptr(), v.len()) } }
pub fn stdev(v: &[f64]) -> f64 { unsafe { sublimation_stdev_f64(v.as_ptr(), v.len()) } }
pub fn min(v: &[f64]) -> f64 { unsafe { sublimation_min_f64(v.as_ptr(), v.len()) } }
pub fn max(v: &[f64]) -> f64 { unsafe { sublimation_max_f64(v.as_ptr(), v.len()) } }

/// Sorts the caller's copy in place, as the C entry point does.
pub fn quantile(values: &mut [f64], q: f64, nearest: bool) -> f64 {
    unsafe {
        sublimation_quantile_f64(values.as_mut_ptr(), values.len(), q,
                                 if nearest { 1 } else { 0 })
    }
}

pub fn describe(values: &mut [f64]) -> SubDescribe {
    unsafe { sublimation_describe_f64(values.as_mut_ptr(), values.len()) }
}

/// Returns (lo, hi) Tukey fences; sorts the caller's copy in place.
pub fn tukey_fences(values: &mut [f64]) -> (f64, f64) {
    let (mut lo, mut hi) = (0.0f64, 0.0f64);
    unsafe {
        sublimation_tukey_fences_f64(values.as_mut_ptr(), values.len(), &mut lo, &mut hi);
    }
    (lo, hi)
}

/// Returns (counts, min, bin_width) for a fixed-bin histogram.
pub fn histogram(v: &[f64], nbins: usize) -> (Vec<usize>, f64, f64) {
    let mut counts = vec![0usize; nbins];
    let (mut mn, mut bw) = (0.0f64, 0.0f64);
    unsafe {
        sublimation_histogram_f64(v.as_ptr(), v.len(), nbins, counts.as_mut_ptr(),
                                  &mut mn, &mut bw);
    }
    (counts, mn, bw)
}

// sublimation_tally: distinct newline-separated records with counts, high to
// low, as offsets into the caller's buffer. The FFI form of the tally/distinct/
// count verbs, so vector no longer shells out for them.
#[repr(C)]
#[derive(Clone, Copy)]
struct SubTally {
    offset: usize,
    length: usize,
    count: u64,
}

extern "C" {
    fn sublimation_tally(data: *const u8, n: usize, out: *mut SubTally,
                         out_cap: usize, total: *mut u64) -> usize;
}

/// Returns (distinct_record_count, total_records, entries sorted high-to-low by
/// count then first-seen). Bounded input; two passes (size, then fill) keep it
/// allocation-exact.
pub fn tally(text: &str) -> (usize, u64, Vec<(String, u64)>) {
    let bytes = text.as_bytes();
    let mut total: u64 = 0;
    let distinct = unsafe {
        sublimation_tally(bytes.as_ptr(), bytes.len(), std::ptr::null_mut(), 0, &mut total)
    };
    if distinct == 0 {
        return (0, total, Vec::new());
    }
    let mut out = vec![SubTally { offset: 0, length: 0, count: 0 }; distinct];
    let mut total2: u64 = 0;
    unsafe {
        sublimation_tally(bytes.as_ptr(), bytes.len(), out.as_mut_ptr(), distinct, &mut total2);
    }
    let entries = out
        .iter()
        .map(|e| {
            let s = String::from_utf8_lossy(&bytes[e.offset..e.offset + e.length]).into_owned();
            (s, e.count)
        })
        .collect();
    (distinct, total, entries)
}

pub fn api_version() -> i32 {
    unsafe { sublimation_api_version() }
}

/// Returns the byte offset of the first regex match, and its length; Ok(None)
/// on a genuine no-match. A pattern that fails to compile is an ERROR, never a
/// no-match: mapping it to false would hand the caller a silent wrong answer.
pub fn grep_find(pattern: &str, text: &str, icase: bool)
    -> Result<Option<(usize, usize)>, String> {
    SIZE_CHECK.call_once(assert_search_size_matches);
    let mut s = std::mem::MaybeUninit::<SubSearch>::uninit();
    unsafe {
        let flags = if icase { SUB_SEARCH_ICASE } else { 0 };
        sublimation_search_compile(s.as_mut_ptr(), pattern.as_ptr(), pattern.len(), flags, 0);
        let s = s.assume_init();
        if sublimation_search_valid(&s) == 0 {
            return Err(format!("invalid regex '{pattern}' (compile failed)"));
        }
        let mut end: c_long = -1;
        let start = sublimation_search_find(&s, text.as_ptr(), text.len(), &mut end);
        if start < 0 {
            Ok(None)
        } else {
            Ok(Some((start as usize, (end - start as c_long) as usize)))
        }
    }
}

/// Returns the byte offset of the first substring match; Ok(None) on a
/// genuine no-match. An empty or over-limit needle is an ERROR: the BMH
/// engine compiles those to the "empty pattern" that matches at offset 0,
/// which would silently report a false positive.
pub fn contains_find(needle: &str, haystack: &str, icase: bool)
    -> Result<Option<usize>, String> {
    if needle.is_empty() || needle.len() > SUB_SEARCH_MAX_PATTERN {
        return Err(format!(
            "needle length {} out of range (1..={SUB_SEARCH_MAX_PATTERN} bytes)",
            needle.len()
        ));
    }
    SIZE_CHECK.call_once(assert_search_size_matches);
    let mut s = std::mem::MaybeUninit::<SubSearch>::uninit();
    unsafe {
        let flags = SUB_SEARCH_FIXED | if icase { SUB_SEARCH_ICASE } else { 0 };
        sublimation_search_compile(s.as_mut_ptr(), needle.as_ptr(), needle.len(), flags, 0);
        let s = s.assume_init();
        let pos = sublimation_search_find(&s, haystack.as_ptr(), haystack.len(), std::ptr::null_mut());
        if pos < 0 {
            Ok(None)
        } else {
            Ok(Some(pos as usize))
        }
    }
}
