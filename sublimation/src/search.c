// search.c -- structural locator (sublimation_search.h). Instantiates the
// sliding-window classifier locate/profile for u64/i64/f64 and the disorder
// name helper. The query engine is sublimation_classify; this just walks it.
#include "sublimation_search.h"
#include "sublimation.h"
#include "include/internal/sort_internal.h"

#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "search_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
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
        case SUB_SPECTRAL:      return "SPECTRAL";
    }
    return "?";
}
