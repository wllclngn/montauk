// search.c -- structural locator (sublimation_locate.h). Instantiates the
// sliding-window classifier locate/profile for all six key types (the same set
// the value sort and randomness battery cover) and the disorder name helper.
// The query engine is sublimation_classify; this just walks it.
#include "sublimation_locate.h"
#include "sublimation.h"
#include "include/internal/sort_internal.h"

#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#include "search_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#include "search_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#include "search_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "search_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE float
#define SUB_SUFFIX _f32
#include "search_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE double
#define SUB_SUFFIX _f64
#include "search_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

const char *sublimation_disorder_name(sub_disorder_t d) {
    switch (d) {
        case SUB_SORTED:        return "SORTED";
        case SUB_REVERSED:      return "REVERSED";
        case SUB_NEARLY_SORTED: return "NEARLY_SORTED";
        case SUB_FEW_UNIQUE:    return "FEW_UNIQUE";
        case SUB_RANDOM:        return "RANDOM";
        case SUB_PHASED:        return "PHASED";
    }
    return "?";
}
