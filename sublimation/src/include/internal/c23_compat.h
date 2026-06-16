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

// [[reproducible]] / [[unsequenced]]
#if SUB_HAVE_C23
#define SUB_PURE [[reproducible]]
#define SUB_CONST [[unsequenced]]
#elif defined(__GNUC__)
#define SUB_PURE __attribute__((pure))
#define SUB_CONST __attribute__((const))
#else
#define SUB_PURE
#define SUB_CONST
#endif

// nullptr
#if !SUB_HAVE_C23 && !defined(__cplusplus)
#ifndef nullptr
#define nullptr ((void *)0)
#endif
#endif

// unreachable()
#if !SUB_HAVE_C23
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

// typeof (C23 or GCC extension)
#if !SUB_HAVE_C23 && defined(__GNUC__)
#define typeof __typeof__
#endif

// Checked arithmetic
#if SUB_HAVE_C23 && __has_include(<stdckdint.h>)
#include <stdckdint.h>
#elif defined(__GNUC__) && __GNUC__ >= 5
#define ckd_add(r, a, b) __builtin_add_overflow((a), (b), (r))
#define ckd_sub(r, a, b) __builtin_sub_overflow((a), (b), (r))
#define ckd_mul(r, a, b) __builtin_mul_overflow((a), (b), (r))
#endif

// Bit manipulation
#if SUB_HAVE_C23 && __has_include(<stdbit.h>)
#include <stdbit.h>
#else
#define stdc_count_ones_ui(x)     ((unsigned)__builtin_popcount(x))
#define stdc_leading_zeros_ui(x)  ((x) ? (unsigned)__builtin_clz(x) : 32u)
#define stdc_trailing_zeros_ui(x) ((x) ? (unsigned)__builtin_ctz(x) : 32u)
#define stdc_has_single_bit_ui(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)
#endif

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
