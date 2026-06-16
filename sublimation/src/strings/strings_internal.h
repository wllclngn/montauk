// strings_internal.h -- internal declarations for the string-sort module
#ifndef SUB_STRINGS_INTERNAL_H
#define SUB_STRINGS_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

// Below this cluster size, MSD radix falls back to insertion sort with
// byte comparison from the current depth. Matches the user's Go reference
// (msdCutover = 15).
#define SUB_STRINGS_MSD_CUTOVER 16

// MSD radix tiebreak on a contiguous range of strings.
//
//   arr     : pointer array (permuted in-place by this call)
//   lens    : per-string length (parallel to arr); permuted alongside arr
//   indices : optional (NULL = not tracked). When non-NULL, permuted in
//             parallel so `indices[i]` tracks the original caller-supplied
//             index that ended up at sorted position i.
//   scratch : auxiliary pointer buffer of length >= (hi - lo)
//   lo, hi  : half-open range [lo, hi) within arr to sort
//   depth   : byte offset to start comparing at (inclusive)
//
// Iterative; uses a heap-allocated work stack so adversarial deep-prefix
// inputs cannot blow the C stack. NOT stable within ties.
void sub_msd_radix(
    const char **arr,
    size_t *lens,
    uint32_t *indices,
    const char **scratch,
    size_t lo,
    size_t hi,
    size_t depth);

// Big-endian load of the first 4 bytes of a string into a uint32. Strings
// shorter than 4 bytes are zero-padded so they sort before any string
// sharing the same prefix bytes. Result preserves lex order:
// pack_prefix4("ABCD", 4) == 0x41424344.
static inline uint32_t sub_pack_prefix4(const char *s, size_t len) {
    if (len >= 4) {
        uint32_t v;
        __builtin_memcpy(&v, s, 4);
        return __builtin_bswap32(v);
    }
    uint32_t v = 0;
    if (len >= 1) v |= ((uint32_t)(unsigned char)s[0]) << 24;
    if (len >= 2) v |= ((uint32_t)(unsigned char)s[1]) << 16;
    if (len >= 3) v |= ((uint32_t)(unsigned char)s[2]) <<  8;
    return v;
}

#endif // SUB_STRINGS_INTERNAL_H
