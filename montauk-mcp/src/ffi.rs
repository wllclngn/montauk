// extern "C" bindings straight into libsublimation.a -- no subprocess, no CLI
// argv parsing. Covers the core numeric sort/classify path (sublimation.h)
// and the text engines (sublimation_text.h): the two families an agent's
// `sublimation` tool call actually needs. Every symbol here is already
// extern "C" on the C++ side too (montauk_core/montauk_analyze link the same
// static lib), so the ABI is plain C -- no name mangling, no bindgen needed.

use std::os::raw::{c_int, c_long};

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

const NFA_MAX_STATES: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct NfaState {
    op: u8,
    ch: u8,
    class_idx: u8,
    negated: u8,
    out: i16,
    out1: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NfaClass {
    bits: [u8; 32],
}

#[repr(C)]
struct Nfa {
    states: [NfaState; NFA_MAX_STATES],
    num_states: c_int,
    classes: [NfaClass; NFA_MAX_STATES],
    num_classes: c_int,
    start: c_int,
    anchored_start: c_int,
    anchored_end: c_int,
    icase: c_int,
    valid: c_int,
}

const BMH_MAX_PATTERN: usize = 256;

#[repr(C)]
struct Bmh {
    bad_char: [c_int; 256],
    pattern: [u8; BMH_MAX_PATTERN],
    pattern_len: c_int,
    icase: c_int,
}

extern "C" {
    fn sublimation_f64(arr: *mut f64, n: usize);
    fn sublimation_classify_f64(arr: *const f64, n: usize) -> SubProfile;
    fn sublimation_api_version() -> c_int;
    fn sublimation_version() -> *const std::os::raw::c_char;

    fn sublimation_nfa_compile_ex(out: *mut Nfa, pattern: *const u8, len: usize, icase: c_int);
    fn sublimation_nfa_valid(nfa: *const Nfa) -> c_int;
    fn sublimation_nfa_find(nfa: *const Nfa, input: *const u8, n: usize, end_out: *mut c_long) -> c_long;
    // The continuation-safe entry point (anchors stay absolute past `from`).
    // Bound now so any future offset-iterating tool goes through it instead
    // of re-entering find on a shifted slice, the exact anchor trap the CLI
    // already paid for once.
    #[allow(dead_code)]
    fn sublimation_nfa_find_from(nfa: *const Nfa, input: *const u8, n: usize,
                                 from: usize, end_out: *mut c_long) -> c_long;

    fn sublimation_bmh_compile_ex(out: *mut Bmh, pattern: *const u8, len: usize, icase: c_int);
    fn sublimation_bmh_search(bmh: *const Bmh, text: *const u8, n: usize) -> c_long;
}

pub fn sort_f64(mut values: Vec<f64>) -> Vec<f64> {
    unsafe { sublimation_f64(values.as_mut_ptr(), values.len()) };
    values
}

pub fn classify_f64(values: &[f64]) -> SubProfile {
    unsafe { sublimation_classify_f64(values.as_ptr(), values.len()) }
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
    let mut nfa = std::mem::MaybeUninit::<Nfa>::uninit();
    unsafe {
        sublimation_nfa_compile_ex(
            nfa.as_mut_ptr(),
            pattern.as_ptr(),
            pattern.len(),
            icase as c_int,
        );
        let nfa = nfa.assume_init();
        if sublimation_nfa_valid(&nfa) == 0 {
            return Err(format!(
                "invalid regex '{pattern}' (compile failed; the engine caps \
                 at 256 NFA states)"
            ));
        }
        let mut end: c_long = -1;
        let start = sublimation_nfa_find(&nfa, text.as_ptr(), text.len(), &mut end);
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
    const BMH_MAX: usize = 256;
    if needle.is_empty() || needle.len() > BMH_MAX {
        return Err(format!(
            "needle length {} out of range (1..={BMH_MAX} bytes)",
            needle.len()
        ));
    }
    let mut bmh = std::mem::MaybeUninit::<Bmh>::uninit();
    unsafe {
        sublimation_bmh_compile_ex(
            bmh.as_mut_ptr(),
            needle.as_ptr(),
            needle.len(),
            icase as c_int,
        );
        let bmh = bmh.assume_init();
        let pos = sublimation_bmh_search(&bmh, haystack.as_ptr(), haystack.len());
        if pos < 0 {
            Ok(None)
        } else {
            Ok(Some(pos as usize))
        }
    }
}
