// merge.c -- Merge primitives with R_eff-ordered merge tree
//
// Type-generic via macro template instantiation.
#include "internal/sort_internal.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

// int32_t
#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#include "merge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// int64_t
#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#include "merge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint32_t
#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#include "merge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint64_t
#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "merge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// float
#define SUB_TYPE float
#define SUB_SUFFIX _f32
#include "merge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// double
#define SUB_TYPE double
#define SUB_SUFFIX _f64
#include "merge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX
