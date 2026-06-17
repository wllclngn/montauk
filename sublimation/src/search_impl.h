// search_impl.h -- Template body for the structural locator. Included once per
// type; requires SUB_TYPE / SUB_SUFFIX. Slides sublimation_classify_<T> across
// the stream; classify is pure (reads, never writes), so each window is profiled
// in place on arr + start with no copy.

SUB_API size_t SUB_TYPED(sublimation_profile)(
    const SUB_TYPE *arr, size_t n, size_t window, size_t stride,
    sub_match_t *out, size_t out_cap) {
    if (window == 0 || stride == 0 || window > n || out_cap == 0) return 0;
    size_t count = 0;
    for (size_t start = 0; start + window <= n && count < out_cap; start += stride) {
        sub_profile_t p = SUB_TYPED(sublimation_classify)(arr + start, window);
        out[count].start = start;
        out[count].len = window;
        out[count].disorder = p.disorder;
        out[count].inversion_ratio = p.inversion_ratio;
        out[count].distinct_estimate = p.distinct_estimate;
        count++;
    }
    return count;
}

SUB_API size_t SUB_TYPED(sublimation_locate)(
    const SUB_TYPE *arr, size_t n, size_t window, size_t stride,
    sub_disorder_t target, sub_match_t *out, size_t out_cap) {
    if (window == 0 || stride == 0 || window > n || out_cap == 0) return 0;
    size_t count = 0;
    for (size_t start = 0; start + window <= n && count < out_cap; start += stride) {
        sub_profile_t p = SUB_TYPED(sublimation_classify)(arr + start, window);
        if (p.disorder == target) {
            out[count].start = start;
            out[count].len = window;
            out[count].disorder = p.disorder;
            out[count].inversion_ratio = p.inversion_ratio;
            out[count].distinct_estimate = p.distinct_estimate;
            count++;
        }
    }
    return count;
}
