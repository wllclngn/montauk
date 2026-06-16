// merge_impl.h -- Template body for merge primitives (included once per type)
//
// Requires SUB_TYPE and SUB_SUFFIX to be defined before inclusion.

// Constants defined once (not per-type) — guarded because this header
// is included 6 times via macro template instantiation.
#ifndef SUB_MERGE_CONSTANTS_DEFINED
#define SUB_MERGE_CONSTANTS_DEFINED
SUB_CONSTEXPR size_t SUB_MIN_MERGE = 32;
SUB_CONSTEXPR size_t SUB_MIN_GALLOP = 7;
#endif

typedef struct {
    size_t base;
    size_t length;
    int    power;
} SUB_TYPED(sub_run_t);

static void SUB_TYPED(binary_insertion_sort)(SUB_TYPE *arr, size_t n, uint64_t *cmp) {
    for (size_t i = 1; i < n; i++) {
        SUB_TYPE key = arr[i];
        size_t lo = 0, hi = i;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            (*cmp)++;
            if (arr[mid] > key) hi = mid;
            else lo = mid + 1;
        }
        if (lo < i) {
            memmove(arr + lo + 1, arr + lo, (i - lo) * sizeof(SUB_TYPE));
            arr[lo] = key;
        }
    }
}

static size_t SUB_TYPED(count_run_asc)(SUB_TYPE *arr, size_t n, uint64_t *cmp) {
    if (n <= 1) return n;
    size_t run = 1;
    (*cmp)++;
    if (arr[1] < arr[0]) {
        while (run < n - 1) {
            (*cmp)++;
            if (arr[run + 1] >= arr[run]) break;
            run++;
        }
        run++;
        for (size_t i = 0, j = run - 1; i < j; i++, j--) {
            SUB_TYPE tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
        }
    } else {
        while (run < n - 1) {
            (*cmp)++;
            if (arr[run + 1] < arr[run]) break;
            run++;
        }
        run++;
    }
    return run;
}

// GALLOP LEFT
static size_t SUB_TYPED(gallop_left)(SUB_TYPE key, const SUB_TYPE *base, size_t len,
                                      size_t hint, uint64_t *cmp) {
    size_t last_ofs = 0, ofs = 1;
    (*cmp)++;
    if (base[hint] < key) {
        size_t max_ofs = len - hint;
        while (ofs < max_ofs) {
            (*cmp)++;
            if (!(base[hint + ofs] < key)) break;
            last_ofs = ofs;
            ofs = (ofs << 1) + 1;
            if (ofs <= last_ofs) ofs = max_ofs;
        }
        if (ofs > max_ofs) ofs = max_ofs;
        last_ofs += hint;
        ofs += hint;
    } else {
        size_t max_ofs = hint + 1;
        while (ofs < max_ofs) {
            (*cmp)++;
            if (base[hint - ofs] < key) break;
            last_ofs = ofs;
            ofs = (ofs << 1) + 1;
            if (ofs <= last_ofs) ofs = max_ofs;
        }
        if (ofs > max_ofs) ofs = max_ofs;
        size_t tmp = last_ofs;
        last_ofs = (ofs > hint) ? 0 : hint - ofs;
        ofs = hint - tmp;
    }
    while (last_ofs < ofs) {
        size_t mid = last_ofs + ((ofs - last_ofs) >> 1);
        (*cmp)++;
        if (base[mid] < key) last_ofs = mid + 1;
        else ofs = mid;
    }
    return ofs;
}

// GALLOP RIGHT
static size_t SUB_TYPED(gallop_right)(SUB_TYPE key, const SUB_TYPE *base, size_t len,
                                       size_t hint, uint64_t *cmp) {
    size_t last_ofs = 0, ofs = 1;
    (*cmp)++;
    if (key < base[hint]) {
        size_t max_ofs = hint + 1;
        while (ofs < max_ofs) {
            (*cmp)++;
            if (!(key < base[hint - ofs])) break;
            last_ofs = ofs;
            ofs = (ofs << 1) + 1;
            if (ofs <= last_ofs) ofs = max_ofs;
        }
        if (ofs > max_ofs) ofs = max_ofs;
        size_t tmp = last_ofs;
        last_ofs = (ofs > hint) ? 0 : hint - ofs;
        ofs = hint - tmp;
    } else {
        size_t max_ofs = len - hint;
        while (ofs < max_ofs) {
            (*cmp)++;
            if (key < base[hint + ofs]) break;
            last_ofs = ofs;
            ofs = (ofs << 1) + 1;
            if (ofs <= last_ofs) ofs = max_ofs;
        }
        if (ofs > max_ofs) ofs = max_ofs;
        last_ofs += hint;
        ofs += hint;
    }
    while (last_ofs < ofs) {
        size_t mid = last_ofs + ((ofs - last_ofs) >> 1);
        (*cmp)++;
        if (key < base[mid]) ofs = mid;
        else last_ofs = mid + 1;
    }
    return ofs;
}

// MERGE LO
static void SUB_TYPED(merge_lo)(SUB_TYPE *base_arr, size_t left_len, size_t right_len,
                                 SUB_TYPE *tmp, size_t *min_gallop, uint64_t *cmp) {
    memcpy(tmp, base_arr, left_len * sizeof(SUB_TYPE));
    SUB_TYPE *c1 = tmp;
    SUB_TYPE *c2 = base_arr + left_len;
    SUB_TYPE *dest = base_arr;
    size_t lr = left_len, rr = right_len;

    while (lr > 1 && rr > 0) {
        size_t cnt1 = 0, cnt2 = 0;
        do {
            (*cmp)++;
            if (*c2 < *c1) {
                *dest++ = *c2++; rr--; cnt2++; cnt1 = 0;
                if (rr == 0) goto SUB_TYPED(done_lo);
            } else {
                *dest++ = *c1++; lr--; cnt1++; cnt2 = 0;
                if (lr == 1) goto SUB_TYPED(done_lo);
            }
        } while ((cnt1 | cnt2) < *min_gallop);

        do {
            cnt1 = SUB_TYPED(gallop_right)(*c2, c1, lr, 0, cmp);
            if (cnt1 > 0) {
                memcpy(dest, c1, cnt1 * sizeof(SUB_TYPE));
                dest += cnt1; c1 += cnt1; lr -= cnt1;
                if (lr <= 1) goto SUB_TYPED(done_lo);
            }
            *dest++ = *c2++; rr--;
            if (rr == 0) goto SUB_TYPED(done_lo);
            cnt2 = SUB_TYPED(gallop_left)(*c1, c2, rr, 0, cmp);
            if (cnt2 > 0) {
                memmove(dest, c2, cnt2 * sizeof(SUB_TYPE));
                dest += cnt2; c2 += cnt2; rr -= cnt2;
                if (rr == 0) goto SUB_TYPED(done_lo);
            }
            *dest++ = *c1++; lr--;
            if (lr == 1) goto SUB_TYPED(done_lo);
            if (cnt1 >= SUB_MIN_GALLOP || cnt2 >= SUB_MIN_GALLOP) {
                if (*min_gallop > 1) (*min_gallop)--;
            } else {
                (*min_gallop)++;
            }
        } while (cnt1 >= SUB_MIN_GALLOP || cnt2 >= SUB_MIN_GALLOP);
        (*min_gallop)++;
    }

SUB_TYPED(done_lo):
    if (lr == 1) {
        memmove(dest, c2, rr * sizeof(SUB_TYPE));
        dest[rr] = *c1;
    } else if (lr > 0) {
        memcpy(dest, c1, lr * sizeof(SUB_TYPE));
    }
}

// MERGE HI
static void SUB_TYPED(merge_hi)(SUB_TYPE *base_arr, size_t left_len, size_t right_len,
                                 SUB_TYPE *tmp, size_t *min_gallop, uint64_t *cmp) {
    memcpy(tmp, base_arr + left_len, right_len * sizeof(SUB_TYPE));
    SUB_TYPE *c1 = base_arr + left_len - 1;
    SUB_TYPE *c2 = tmp + right_len - 1;
    SUB_TYPE *dest = base_arr + left_len + right_len - 1;
    size_t lr = left_len, rr = right_len;

    while (lr > 0 && rr > 1) {
        size_t cnt1 = 0, cnt2 = 0;
        do {
            (*cmp)++;
            if (*c2 < *c1) {
                *dest-- = *c1--; lr--; cnt1++; cnt2 = 0;
                if (lr == 0) goto SUB_TYPED(done_hi);
            } else {
                *dest-- = *c2--; rr--; cnt2++; cnt1 = 0;
                if (rr == 1) goto SUB_TYPED(done_hi);
            }
        } while ((cnt1 | cnt2) < *min_gallop);

        do {
            cnt1 = lr - SUB_TYPED(gallop_right)(*c2, base_arr, lr, lr - 1, cmp);
            if (cnt1 > 0) {
                dest -= cnt1; c1 -= cnt1; lr -= cnt1;
                memmove(dest + 1, c1 + 1, cnt1 * sizeof(SUB_TYPE));
                if (lr == 0) goto SUB_TYPED(done_hi);
            }
            *dest-- = *c2--; rr--;
            if (rr == 1) goto SUB_TYPED(done_hi);
            cnt2 = rr - SUB_TYPED(gallop_left)(*c1, tmp, rr, rr - 1, cmp);
            if (cnt2 > 0) {
                dest -= cnt2; c2 -= cnt2; rr -= cnt2;
                memcpy(dest + 1, c2 + 1, cnt2 * sizeof(SUB_TYPE));
                if (rr <= 1) goto SUB_TYPED(done_hi);
            }
            *dest-- = *c1--; lr--;
            if (lr == 0) goto SUB_TYPED(done_hi);
            if (cnt1 >= SUB_MIN_GALLOP || cnt2 >= SUB_MIN_GALLOP) {
                if (*min_gallop > 1) (*min_gallop)--;
            } else {
                (*min_gallop)++;
            }
        } while (cnt1 >= SUB_MIN_GALLOP || cnt2 >= SUB_MIN_GALLOP);
        (*min_gallop)++;
    }

SUB_TYPED(done_hi):
    if (rr == 1) {
        dest -= lr; c1 -= lr;
        memmove(dest + 1, c1 + 1, lr * sizeof(SUB_TYPE));
        *dest = *c2;
    } else if (rr > 0) {
        memcpy(base_arr, tmp, rr * sizeof(SUB_TYPE));
    }
}

// MERGE PAIR
static void SUB_TYPED(merge_pair)(SUB_TYPE *arr, size_t base_idx, size_t len1, size_t len2,
                                   SUB_TYPE *tmp, size_t *min_gallop, uint64_t *cmp) {
    if (len1 == 0 || len2 == 0) return;
    SUB_TYPE *b1 = arr + base_idx;
    SUB_TYPE *b2 = arr + base_idx + len1;

    size_t k = SUB_TYPED(gallop_right)(*b2, b1, len1, 0, cmp);
    b1 += k; len1 -= k;
    if (len1 == 0) return;

    len2 = SUB_TYPED(gallop_left)(*(b1 + len1 - 1), b2, len2,
                                   len2 > 0 ? len2 - 1 : 0, cmp);
    if (len2 == 0) return;

    if (len1 <= len2) SUB_TYPED(merge_lo)(b1, len1, len2, tmp, min_gallop, cmp);
    else              SUB_TYPED(merge_hi)(b1, len1, len2, tmp, min_gallop, cmp);
}

// Union-find with path compression
static size_t SUB_TYPED(uf_find)(size_t *parent, size_t x) {
    while (parent[x] != x) {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    return x;
}

// R_EFF MERGE
typedef struct {
    size_t idx;
    double resistance;
} SUB_TYPED(sub_boundary_t);

static void SUB_TYPED(merge_reff)(SUB_TYPE *arr, SUB_TYPED(sub_run_t) *runs, size_t num_runs,
                                   SUB_TYPE *tmp, size_t *min_gallop, uint64_t *cmp) {
    if (num_runs <= 1) return;

    if (num_runs == 2) {
        SUB_TYPED(merge_pair)(arr, runs[0].base, runs[0].length,
                               runs[1].length, tmp, min_gallop, cmp);
        return;
    }

    size_t num_bounds = num_runs - 1;

    SUB_TYPED(sub_boundary_t) bounds[511];
    for (size_t i = 0; i < num_bounds; i++) {
        size_t end_i = runs[i].base + runs[i].length - 1;
        double gap = fabs((double)arr[runs[i + 1].base] - (double)arr[end_i]);
        bounds[i].idx = i;
        bounds[i].resistance = 1.0 + gap;
    }

    for (size_t i = 1; i < num_bounds; i++) {
        SUB_TYPED(sub_boundary_t) key = bounds[i];
        size_t j = i;
        while (j > 0 && bounds[j - 1].resistance > key.resistance) {
            bounds[j] = bounds[j - 1];
            j--;
        }
        bounds[j] = key;
    }

    size_t parent[512];
    size_t sbase[512], slen[512];
    for (size_t i = 0; i < num_runs; i++) {
        parent[i] = i;
        sbase[i] = runs[i].base;
        slen[i] = runs[i].length;
    }

    for (size_t b = 0; b < num_bounds; b++) {
        size_t left_root = SUB_TYPED(uf_find)(parent, bounds[b].idx);
        size_t right_root = SUB_TYPED(uf_find)(parent, bounds[b].idx + 1);
        if (left_root == right_root) continue;

        size_t lo, hi;
        if (sbase[left_root] < sbase[right_root]) {
            lo = left_root; hi = right_root;
        } else {
            lo = right_root; hi = left_root;
        }

        SUB_TYPED(merge_pair)(arr, sbase[lo], slen[lo], slen[hi], tmp, min_gallop, cmp);

        slen[lo] += slen[hi];
        parent[hi] = lo;
    }
}

// SPECTRAL MERGE
void SUB_TYPED(sub_spectral_merge)(SUB_TYPE *arr, size_t n, uint64_t *comparisons) {
    if (n < 2) return;
    if (n < SUB_MIN_MERGE) {
        SUB_TYPED(binary_insertion_sort)(arr, n, comparisons);
        return;
    }

    SUB_TYPED(sub_run_t) detected[512];
    size_t num_runs = 0;
    size_t remaining = n;
    SUB_TYPE *cur = arr;

    while (remaining > 0 && num_runs < 511) {
        size_t run_len = SUB_TYPED(count_run_asc)(cur, remaining, comparisons);
        detected[num_runs].base = (size_t)(cur - arr);
        detected[num_runs].length = run_len;
        detected[num_runs].power = 0;
        num_runs++;
        cur += run_len;
        remaining -= run_len;
    }

    if (remaining > 0) {
        if (remaining <= 64) {
            SUB_TYPED(binary_insertion_sort)(cur, remaining, comparisons);
        } else {
            SUB_TYPED(sub_spectral_merge)(cur, remaining, comparisons);
        }
        detected[num_runs].base = (size_t)(cur - arr);
        detected[num_runs].length = remaining;
        detected[num_runs].power = 0;
        num_runs++;
    }

    if (num_runs <= 1) return;

    // Phase 2: gap heuristic
    {
        size_t out = 0;
        detected[out] = detected[0];
        for (size_t i = 1; i < num_runs; i++) {
            size_t prev_end = detected[out].base + detected[out].length - 1;
            if (arr[prev_end] <= arr[detected[i].base]) {
                detected[out].length += detected[i].length;
            } else {
                out++;
                detected[out] = detected[i];
            }
        }
        num_runs = out + 1;
    }

    if (num_runs <= 1) return;

    // Phase 3: R_eff-ordered merge
    size_t min_gallop = SUB_MIN_GALLOP;
    SUB_TYPE *tmp = malloc((n / 2 + 1) * sizeof(SUB_TYPE));
    if (!tmp) {
        SUB_TYPED(binary_insertion_sort)(arr, n, comparisons);
        return;
    }

    SUB_TYPED(merge_reff)(arr, detected, num_runs, tmp, &min_gallop, comparisons);

    free(tmp);
}
