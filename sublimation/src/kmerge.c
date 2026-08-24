// kmerge.c -- k-way merge of already-sorted runs.
//
// Type-generic via macro template instantiation, same convention as merge.c.
#include "internal/sort_internal.h"
#include "sublimation.h"
#include <stdlib.h>
#include <string.h>

#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#include "kmerge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#include "kmerge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#include "kmerge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "kmerge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE float
#define SUB_SUFFIX _f32
#include "kmerge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE double
#define SUB_SUFFIX _f64
#include "kmerge_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX
