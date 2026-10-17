// Shortest round-trip binary64 formatting: Dragonbox, Junekey Jeon's algorithm
// ("Dragonbox: A New Floating-Point Binary-to-Decimal Conversion Algorithm",
// 2020), which supersedes Ryu (Ulf Adams) and Grisu (Florian Loitsch). This is
// sublimation's own implementation of the published algorithm for binary64
// under round-to-nearest-even, with its multiplier table derived in exact
// arithmetic by tools/genpow10.py.
//
// Dragonbox finds the shortest decimal in the rounding interval of a double,
// nearest to it when several qualify. The text around those digits follows
// std::to_chars exactly, since that is the oracle this file is held to.

#include "sublimation_fmt.h"

#include <stdint.h>
#include <string.h>

#include "text/pow10_cache.h"

typedef unsigned __int128 u128;

enum { SIG_BITS = 52, EXP_BIAS = 1023, KAPPA = 2 };

static inline int floor_log10_pow2(int e) { return (e * 315653) >> 20; }
static inline int floor_log2_pow10(int k) { return (k * 1741647) >> 19; }
static inline int floor_log10_pow2_minus_log10_4_over_3(int e) {
    return (e * 631305 - 261663) >> 21;
}

static inline u128 cache_at(int k) {
    const uint64_t *c = sub_pow10_cache[k - SUB_POW10_MIN_K];
    return ((u128)c[0] << 64) | c[1];
}

// The upper and lower 128 bits of a 64 x 128-bit product.
static inline u128 mul_upper128(uint64_t x, u128 y) {
    return (u128)x * (uint64_t)(y >> 64) + (((u128)x * (uint64_t)y) >> 64);
}
static inline u128 mul_lower128(uint64_t x, u128 y) {
    return ((u128)(x * (uint64_t)(y >> 64)) << 64) + (u128)x * (uint64_t)y;
}

// Parity and integer-ness of x * cache * 2^beta, read off the low bits.
static inline void mul_parity(uint64_t two_f, u128 cache, int beta, int *parity, int *is_int) {
    u128 r = mul_lower128(two_f, cache);
    uint64_t hi = (uint64_t)(r >> 64), lo = (uint64_t)r;
    *parity = (int)((hi >> (64 - beta)) & 1);
    *is_int = ((hi << beta) | (lo >> (64 - beta))) == 0;
}

// A power of two's interval is lopsided: Its lower neighbour is half as far
// away as its upper one.
static void shorter_interval(int e, uint64_t *sig, int *exp) {
    const int minus_k = floor_log10_pow2_minus_log10_4_over_3(e);
    const int beta = e + floor_log2_pow10(-minus_k);
    const uint64_t hi = (uint64_t)(cache_at(-minus_k) >> 64);
    uint64_t xi = (hi - (hi >> (SIG_BITS + 2))) >> (64 - SIG_BITS - 1 - beta);
    const uint64_t zi = (hi + (hi >> (SIG_BITS + 1))) >> (64 - SIG_BITS - 1 - beta);
    // The left endpoint is an integer only for e in [2, 3]; otherwise the
    // first candidate is the integer above it.
    if (!(e >= 2 && e <= 3)) ++xi;
    *sig = zi / 10;
    if (*sig * 10 >= xi) { *exp = minus_k + 1; return; }
    *sig = ((hi >> (64 - SIG_BITS - 2 - beta)) + 1) / 2;
    *exp = minus_k;
    if ((*sig & 1) && e == -77) --*sig;   // the one exact tie: round to even
    else if (*sig < xi) ++*sig;
}

// The shortest correctly rounded decimal sig * 10^exp for a finite nonzero
// double, trailing zeros possibly still on sig.
static void to_decimal(uint64_t fraction, int exp_field, uint64_t *sig, int *exp) {
    uint64_t two_fc = fraction << 1;
    int e;
    if (exp_field != 0) {
        e = exp_field - EXP_BIAS - SIG_BITS;
        // The smallest normal's lower neighbour is a subnormal one ulp away,
        // so its interval is symmetric and takes the ordinary path.
        if (fraction == 0 && exp_field > 1) { shorter_interval(e, sig, exp); return; }
        two_fc |= (uint64_t)1 << (SIG_BITS + 1);
    } else {
        e = 1 - EXP_BIAS - SIG_BITS;
    }
    // Round-to-nearest-even keeps both endpoints for an even significand.
    const int endpoints = (two_fc & 2) == 0;

    const int minus_k = floor_log10_pow2(e) - KAPPA;
    const u128 cache = cache_at(-minus_k);
    const int beta = e + floor_log2_pow10(-minus_k);
    const uint64_t deltai = (uint64_t)(cache >> 64) >> (63 - beta);
    const u128 zr = mul_upper128((two_fc | 1) << beta, cache);
    const uint64_t z = (uint64_t)(zr >> 64);
    const int z_is_int = (uint64_t)zr == 0;

    enum { BIG = 1000, SMALL = 100 };
    *sig = z / BIG;
    uint64_t r = z - BIG * *sig;
    if (r < deltai) {
        if (r == 0 && z_is_int && !endpoints) { --*sig; r = BIG; goto small_divisor; }
        *exp = minus_k + KAPPA + 1;
        return;
    }
    if (r == deltai) {
        int x_parity, x_is_int;
        mul_parity(two_fc - 1, cache, beta, &x_parity, &x_is_int);
        if (x_parity | (x_is_int & endpoints)) { *exp = minus_k + KAPPA + 1; return; }
    }

small_divisor:
    *sig *= 10;
    {
        uint64_t dist = r - (deltai / 2) + (SMALL / 2);
        const int approx_y_parity = ((dist ^ (SMALL / 2)) & 1) != 0;
        const int divisible = dist % SMALL == 0;
        dist /= SMALL;
        *sig += dist;
        if (divisible) {
            int y_parity, y_is_int;
            mul_parity(two_fc, cache, beta, &y_parity, &y_is_int);
            if (y_parity != approx_y_parity) --*sig;
            else if (y_is_int && (*sig & 1)) --*sig;   // an exact tie: to even
        }
    }
    *exp = minus_k + KAPPA;
}

static size_t put_u128(char *p, u128 v) {
    char d[40];
    size_t n = 0;
    do { d[n++] = (char)('0' + (int)(v % 10)); v /= 10; } while (v);
    for (size_t i = 0; i < n; i++) p[i] = d[n - 1 - i];
    return n;
}

int sublimation_fmt_double(char *buf, size_t cap, double v) {
    uint64_t bits;
    memcpy(&bits, &v, sizeof bits);
    const uint64_t fraction = bits & (((uint64_t)1 << SIG_BITS) - 1);
    const int exp_field = (int)((bits >> SIG_BITS) & 0x7ff);
    char out[32];
    size_t n = 0;
    if (bits >> 63) out[n++] = '-';

    if (exp_field == 0x7ff) {
        memcpy(out + n, fraction ? "nan" : "inf", 3);
        n += 3;
    } else if (exp_field == 0 && fraction == 0) {
        out[n++] = '0';
    } else {
        uint64_t sig;
        int exp;
        to_decimal(fraction, exp_field, &sig, &exp);
        while (sig % 10 == 0) { sig /= 10; ++exp; }
        char digits[40];   // put_u128's bound; a significand uses at most 17
        int nd = (int)put_u128(digits, sig);

        // std::to_chars takes whichever of fixed and scientific is shorter,
        // fixed on a tie.
        const int sci_exp = exp + nd - 1;
        const int abs_exp = sci_exp < 0 ? -sci_exp : sci_exp;
        const int sci_len = nd + (nd > 1) + 2 + (abs_exp >= 100 ? 3 : 2);
        const int fix_len = exp >= 0 ? nd + exp : (-exp < nd ? nd + 1 : 2 - exp);
        if (fix_len <= sci_len) {
            if (exp >= 0) {
                // Of the fixed strings this long, to_chars writes the one
                // nearest the value -- the double's exact integer, not the
                // shortest digits padded with zeros.
                const uint64_t m = exp_field ? fraction | ((uint64_t)1 << SIG_BITS) : fraction;
                const int e2 = (exp_field ? exp_field : 1) - EXP_BIAS - SIG_BITS;
                const u128 whole = e2 >= 0 ? (u128)m << e2 : (u128)(m >> -e2);
                n += put_u128(out + n, whole);
            } else if (-exp < nd) {
                const int point = nd + exp;
                memcpy(out + n, digits, (size_t)point);
                n += (size_t)point;
                out[n++] = '.';
                memcpy(out + n, digits + point, (size_t)(nd - point));
                n += (size_t)(nd - point);
            } else {
                out[n++] = '0';
                out[n++] = '.';
                for (int z = 0; z < -exp - nd; z++) out[n++] = '0';
                memcpy(out + n, digits, (size_t)nd);
                n += (size_t)nd;
            }
        } else {
            out[n++] = digits[0];
            if (nd > 1) {
                out[n++] = '.';
                memcpy(out + n, digits + 1, (size_t)(nd - 1));
                n += (size_t)(nd - 1);
            }
            out[n++] = 'e';
            out[n++] = sci_exp < 0 ? '-' : '+';
            if (abs_exp >= 100) out[n++] = (char)('0' + abs_exp / 100);
            out[n++] = (char)('0' + abs_exp / 10 % 10);
            out[n++] = (char)('0' + abs_exp % 10);
        }
    }
    if (n > cap) return -1;
    memcpy(buf, out, n);
    return (int)n;
}
