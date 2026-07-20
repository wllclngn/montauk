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

pub const DISORDER_NAMES: [&str; 7] = [
    "sorted", "reversed", "nearly_sorted", "few_unique", "random", "phased", "spectral",
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
    // The continuation-safe entry point (anchors stay absolute past `from`).
    // Bound now so any future offset-iterating tool goes through it instead
    // of re-entering find on a shifted slice, the exact anchor trap the CLI
    // already paid for once.
    #[allow(dead_code)]
    fn sublimation_search_find_from(s: *const SubSearch, input: *const u8, n: usize,
                                    from: usize, end_out: *mut c_long) -> c_long;
    fn sublimation_effective_resistance(w: *const f64, n: usize, reff: *mut f64) -> c_int;
    fn sublimation_spectral_residual(signal: *const f64, n: usize, q: usize, tau: f64,
                                     z: usize, saliency: *mut f64, flags: *mut u8) -> c_int;
}

pub fn sort_f64(mut values: Vec<f64>) -> Vec<f64> {
    unsafe { sublimation_f64(values.as_mut_ptr(), values.len()) };
    values
}

pub fn classify_f64(values: &[f64]) -> SubProfile {
    unsafe { sublimation_classify_f64(values.as_ptr(), values.len()) }
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

pub fn version() -> String {
    unsafe {
        let ptr = sublimation_version();
        if ptr.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
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
