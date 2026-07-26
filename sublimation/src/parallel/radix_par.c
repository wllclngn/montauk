// radix_par.c -- parallel MSD radix instantiations (see radix_par_impl.h)
#define _POSIX_C_SOURCE 200809L
#include "internal/dfspool.h"
#include "internal/radix.h"
#include "internal/sort_internal.h"   // SUB_TYPED / SUB_CONCAT
#include <string.h>

// Float bits -> monotonic unsigned key (IEEE total order), memcpy-clean.
static inline uint64_t rp_f64key(double d) {
    uint64_t u; memcpy(&u, &d, 8);
    return u ^ ((-(int64_t)(u >> 63)) | 0x8000000000000000ull);
}
static inline uint32_t rp_f32key(float f) {
    uint32_t u; memcpy(&u, &f, 4);
    return u ^ ((uint32_t)(-(int32_t)(u >> 31)) | 0x80000000u);
}

#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#define SUB_ORDER_KEY(v) ((uint32_t)(v) ^ 0x80000000u)
#define SUB_TOPBYTE 3
#include "radix_par_impl.h"
#undef SUB_ORDER_KEY
#undef SUB_TOPBYTE
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#define SUB_ORDER_KEY(v) ((uint64_t)(v) ^ 0x8000000000000000ull)
#define SUB_TOPBYTE 7
#include "radix_par_impl.h"
#undef SUB_ORDER_KEY
#undef SUB_TOPBYTE
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#define SUB_ORDER_KEY(v) ((uint32_t)(v))
#define SUB_TOPBYTE 3
#include "radix_par_impl.h"
#undef SUB_ORDER_KEY
#undef SUB_TOPBYTE
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#define SUB_ORDER_KEY(v) ((uint64_t)(v))
#define SUB_TOPBYTE 7
#include "radix_par_impl.h"
#undef SUB_ORDER_KEY
#undef SUB_TOPBYTE
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE float
#define SUB_SUFFIX _f32
#define SUB_TYPE_IS_FLOAT
#define SUB_ORDER_KEY(v) rp_f32key(v)
#define SUB_TOPBYTE 3
#include "radix_par_impl.h"
#undef SUB_ORDER_KEY
#undef SUB_TOPBYTE
#undef SUB_TYPE_IS_FLOAT
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE double
#define SUB_SUFFIX _f64
#define SUB_TYPE_IS_FLOAT
#define SUB_ORDER_KEY(v) rp_f64key(v)
#define SUB_TOPBYTE 7
#include "radix_par_impl.h"
#undef SUB_ORDER_KEY
#undef SUB_TOPBYTE
#undef SUB_TYPE_IS_FLOAT
#undef SUB_TYPE
#undef SUB_SUFFIX
