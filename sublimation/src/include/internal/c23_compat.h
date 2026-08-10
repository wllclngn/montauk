// c23_compat.h -- C23 features with pre-C23 fallbacks
//
// Supports GCC 13+ and Clang 16+ with or without full C23 mode.
#ifndef SUB_C23_COMPAT_H
#define SUB_C23_COMPAT_H

#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 202311L
#define SUB_HAVE_C23 1
#endif
#endif
#ifndef SUB_HAVE_C23
#define SUB_HAVE_C23 0
#endif

// constexpr
#if SUB_HAVE_C23
#define SUB_CONSTEXPR constexpr
#else
#define SUB_CONSTEXPR static const
#endif

// [[nodiscard]]
#if SUB_HAVE_C23 || (defined(__GNUC__) && __GNUC__ >= 10)
#define SUB_NODISCARD [[nodiscard]]
#define SUB_NODISCARD_MSG(msg) [[nodiscard(msg)]]
#else
#define SUB_NODISCARD
#define SUB_NODISCARD_MSG(msg)
#endif

// [[noreturn]]
#if SUB_HAVE_C23
#define SUB_NORETURN [[noreturn]]
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define SUB_NORETURN _Noreturn
#elif defined(__GNUC__)
#define SUB_NORETURN __attribute__((noreturn))
#else
#define SUB_NORETURN
#endif

// [[reproducible]] / [[unsequenced]] -- C23, but newer than most C23 modes
// implement, so a compiler can advertise C23 yet still lack them. Consult
// __has_c_attribute before use; fall back to the equivalent GNU hints otherwise
// (a bare -std=c23 clang warns -Wunknown-attributes on the C23 spelling). The
// __has_c_attribute test is nested, not on the same #if line, so C++ TUs that
// pull this header -- where __has_c_attribute is undefined -- never try to parse
// its argument list.
#if SUB_HAVE_C23 && defined(__has_c_attribute)
#  if __has_c_attribute(reproducible) && __has_c_attribute(unsequenced)
#    define SUB_PURE [[reproducible]]
#    define SUB_CONST [[unsequenced]]
#  endif
#endif
#ifndef SUB_PURE
#  if defined(__GNUC__)
#    define SUB_PURE __attribute__((pure))
#    define SUB_CONST __attribute__((const))
#  else
#    define SUB_PURE
#    define SUB_CONST
#  endif
#endif

// nullptr
#if !SUB_HAVE_C23 && !defined(__cplusplus)
#ifndef nullptr
#define nullptr ((void *)0)
#endif
#endif

// unreachable() -- guarded three ways.
//
// NOT IN C++, which has std::unreachable and never wanted this shim. SUB_HAVE_C23
// is false in a C++ TU (it keys off __STDC_VERSION__), so without the __cplusplus
// test the macro is defined for every C++ consumer. Where <utility> is first seen
// AFTER a sublimation header that rewrites libstdc++'s own std::unreachable
// declaration into std::__builtin_unreachable. It does not error there: it errors
// wherever something later CALLS std::unreachable and inlining is required, as
// "inlining failed in call to always_inline 'void std::__builtin_unreachable()'"
// -- on a line that names none of the code responsible. OUROBOROS paid for this
// with two #undef unreachable lines in its public headers before it was found.
//
// And guarded: gcc 13's glibc stddef.h defines unreachable() in C23 mode even
// when SUB_HAVE_C23's own detection says otherwise, so an unconditional redefine
// here dies on -Werror (confirmed on gcc 13.3 / Ubuntu 24.04). Respect an
// existing definition wherever it came from.
#if !defined(__cplusplus) && !SUB_HAVE_C23 && !defined(unreachable)
#if defined(__GNUC__)
#define unreachable() __builtin_unreachable()
#else
#define unreachable() do {} while (0)
#endif
#endif

// static_assert (C11 fallback)
#if !SUB_HAVE_C23 && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#ifndef static_assert
#define static_assert _Static_assert
#endif
#endif

// typeof, ckd_add/sub/mul and the stdc_*_ui bit helpers were removed 2026-08-10.
// All eight were unused across the whole library and all eight escaped into C++
// for the same reason unreachable() did -- SUB_HAVE_C23 is false in a C++ TU, so
// every `!SUB_HAVE_C23` fallback fires there. Guarding dead macros would have
// kept the hazard shape around to be copied; anything genuinely needed later
// comes back with the __cplusplus test the survivors above carry.

// Inline hint
#if defined(__GNUC__)
#define SUB_INLINE static inline __attribute__((always_inline))
#else
#define SUB_INLINE static inline
#endif

// Likely/unlikely branch hints
#if defined(__GNUC__)
#define sub_likely(x)   __builtin_expect(!!(x), 1)
#define sub_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define sub_likely(x)   (x)
#define sub_unlikely(x) (x)
#endif

// Prefetch
#if defined(__GNUC__)
#define sub_prefetch_r(addr) __builtin_prefetch((addr), 0, 3)
#define sub_prefetch_w(addr) __builtin_prefetch((addr), 1, 3)
#else
#define sub_prefetch_r(addr) ((void)(addr))
#define sub_prefetch_w(addr) ((void)(addr))
#endif

// restrict qualifier (C only; C++ uses compiler extension)
#ifdef __cplusplus
#define SUB_RESTRICT __restrict__
#else
#define SUB_RESTRICT restrict
#endif

// Symbol visibility for shared libraries
#if SUB_HAVE_C23
#define SUB_API [[gnu::visibility("default")]]
#elif defined(__GNUC__) || defined(__clang__)
#define SUB_API __attribute__((visibility("default")))
#else
#define SUB_API
#endif

#endif // SUB_C23_COMPAT_H
