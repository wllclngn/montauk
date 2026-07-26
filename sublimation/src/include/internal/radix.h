// radix.h -- the pure-random arm of the sort (LSD radix, all types)
//
// Once the classifier / entropy detector calls a workload high-randomness,
// there is no order to exploit and the comparison model has no edge -- the
// input is sent here. A tuned LSD radix: one combined histogram scan over all
// byte-columns, then write-combining scatter passes (one cache line per bucket)
// with constant-byte skipping. Distribution-agnostic (no sampled CDF), so it
// does not degrade on skewed keys the way a learned-bucket sort does.
//
// Signed and float types map to a monotonic unsigned key (sign-bit flip for
// ints, IEEE total-order flip for floats) and back; unsigned is the identity.
#ifndef SUB_RADIX_H
#define SUB_RADIX_H

#include <stddef.h>
#include <stdint.h>

void sub_radix_sort_i32(int32_t  *arr, size_t n);
void sub_radix_sort_i64(int64_t  *arr, size_t n);
void sub_radix_sort_u32(uint32_t *arr, size_t n);
void sub_radix_sort_u64(uint64_t *arr, size_t n);
void sub_radix_sort_f32(float    *arr, size_t n);
void sub_radix_sort_f64(double   *arr, size_t n);

// Parallel radix: in-place American Flag MSD on the work-stealing engine, each
// top-byte bucket a frame. The large-random arm; workers < 2 or a small n runs
// the serial recursive radix. Floats park NaNs at the tail.
void sub_radix_sort_par_i32(int32_t  *arr, size_t n, size_t workers);
void sub_radix_sort_par_i64(int64_t  *arr, size_t n, size_t workers);
void sub_radix_sort_par_u32(uint32_t *arr, size_t n, size_t workers);
void sub_radix_sort_par_u64(uint64_t *arr, size_t n, size_t workers);
void sub_radix_sort_par_f32(float    *arr, size_t n, size_t workers);
void sub_radix_sort_par_f64(double   *arr, size_t n, size_t workers);

#endif // SUB_RADIX_H
