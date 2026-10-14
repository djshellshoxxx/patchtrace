/*
 * loops: small numeric kernels written as plain counted loops.
 *
 * Reductions, copies, scans, bit counting and two classic checksums. Optimising compilers unroll or vectorise most of
 * these (sums, copies, saturating adds, scaling) and leave the data-dependent ones alone (early-exit searches,
 * histograms, prefix sums), so the same source yields machine code that ranges from a byte loop at -O0 to SIMD blocks
 * with runtime overlap checks at -O2/-O3. Freestanding C11: no libc, so even the memcpy-like loops are our own.
 */
#include <stddef.h>
#include <stdint.h>

#define LP_MIN(a, b) ((a) < (b) ? (a) : (b))
#define LP_BLOCK 359u /* largest run of 16-bit words Fletcher-32 can add before a 32-bit sum could overflow */

/* ---- reductions --------------------------------------------------------------------------------------------- */

/* Sum of the bytes, wrapping at 2^32. */
uint32_t lp_sum_u8(const uint8_t *p, size_t n) {
    uint32_t sum = 0;
    size_t i = 0;
    while (i < n) {
        sum += p[i];
        i++;
    }
    return sum;
}

/* Sum of 32-bit values accumulated in 64 bits. */
uint64_t lp_sum_u32(const uint32_t *p, size_t n) {
    uint64_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum += p[i];
    }
    return sum;
}

/* Dot product of two int16 vectors, accumulated modulo 2^32. */
uint32_t lp_dot_i16(const int16_t *a, const int16_t *b, size_t n) {
    uint32_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc += (uint32_t)((int32_t)a[i] * (int32_t)b[i]);
    }
    return acc;
}

/* Largest element, 0 for an empty array. */
uint32_t lp_max_u32(const uint32_t *p, size_t n) {
    uint32_t best = 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] > best) {
            best = p[i];
        }
    }
    return best;
}

uint32_t lp_diff_u32(uint32_t hi, uint32_t lo) {
    return hi - lo;
}

/* Spread of the values (max - min), 0 for an empty array. */
uint32_t lp_range_u32(const uint32_t *p, size_t n) {
    uint32_t lo;
    uint32_t hi;
    if (n == 0) {
        return 0;
    }
    lo = hi = p[0];
    for (size_t i = 1; i < n; i++) {
        if (p[i] < lo) {
            lo = p[i];
        } else if (p[i] > hi) {
            hi = p[i];
        }
    }
    return lp_diff_u32(hi, lo);
}

/* Number of elements strictly above the threshold. */
size_t lp_count_above(const uint32_t *p, size_t n, uint32_t threshold) {
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] > threshold) {
            count++;
        }
    }
    return count;
}

/* Sum of every stride-th element: p[0], p[stride], p[2 * stride], ... */
uint32_t lp_sum_strided(const uint32_t *p, size_t count, size_t stride) {
    uint32_t sum = 0;
    size_t offset = 0;
    for (size_t i = 0; i < count; i++) {
        sum += p[offset];
        offset += stride;
    }
    return sum;
}

/* ---- copies and fills --------------------------------------------------------------------------------------- */

/* memcpy-like forward copy; the buffers must not overlap. */
void lp_copy_bytes(uint8_t *dst, const uint8_t *src, size_t n) {
    const uint8_t *end = src + n;
    while (src != end) {
        *dst++ = *src++;
    }
}

/* memmove-like copy: the direction is chosen from the buffer addresses. */
void lp_move_bytes(uint8_t *dst, const uint8_t *src, size_t n) {
    if ((uintptr_t)dst <= (uintptr_t)src) {
        for (size_t i = 0; i < n; i++) {
            dst[i] = src[i];
        }
    } else {
        for (size_t i = n; i > 0; i--) {
            dst[i - 1] = src[i - 1];
        }
    }
}

/* memset-like fill. */
void lp_fill_bytes(uint8_t *dst, uint8_t value, size_t n) {
    while (n != 0) {
        n--;
        dst[n] = value;
    }
}

/* Saturating byte-wise addition of src into dst. */
void lp_add_sat_u8(uint8_t *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint32_t s = (uint32_t)dst[i] + src[i];
        if (s > 255u) {
            s = 255u;
        }
        dst[i] = (uint8_t)s;
    }
}

/* dst[i] = src[i] * k (wrapping). */
void lp_scale_u32(uint32_t *dst, const uint32_t *src, size_t n, uint32_t k) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i] * k;
    }
}

/* In-place inclusive prefix sum (wrapping): p[i] becomes p[0] + ... + p[i]. */
void lp_prefix_sum_u32(uint32_t *p, size_t n) {
    for (size_t i = 1; i < n; i++) {
        p[i] += p[i - 1];
    }
}

/* Reverse a byte buffer in place. */
void lp_reverse_bytes(uint8_t *p, size_t n) {
    size_t i = 0;
    size_t j = n;
    while (i + 1 < j) {
        uint8_t t = p[i];
        p[i] = p[j - 1];
        p[j - 1] = t;
        i++;
        j--;
    }
}

/* Rotate the buffer left by k positions with the three-reversal trick. */
void lp_rotate_bytes(uint8_t *p, size_t n, size_t k) {
    if (n == 0) {
        return;
    }
    k %= n;
    lp_reverse_bytes(p, k);
    lp_reverse_bytes(p + k, n - k);
    lp_reverse_bytes(p, n);
}

/* ---- searching and comparing ------------------------------------------------------------------------------- */

/* Three-way comparison of two buffers: -1, 0 or 1 by the first differing byte. */
int32_t lp_compare_bytes(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

/* Index of the first byte equal to `value`, or n when it is absent. */
size_t lp_find_byte(const uint8_t *p, size_t n, uint8_t value) {
    size_t i = 0;
    while (i < n && p[i] != value) {
        i++;
    }
    return i;
}

/* Length of the NUL-terminated prefix, looking at no more than cap bytes. */
size_t lp_strnlen(const uint8_t *p, size_t cap) {
    size_t len = 0;
    while (len < cap && p[len] != 0) {
        len++;
    }
    return len;
}

/* Byte frequency table: counts must have room for 256 entries. */
void lp_histogram_u8(const uint8_t *p, size_t n, uint32_t *counts) {
    for (size_t i = 0; i < 256; i++) {
        counts[i] = 0;
    }
    for (size_t i = 0; i < n; i++) {
        counts[p[i]]++;
    }
}

/* ---- bit counting ------------------------------------------------------------------------------------------- */

/* Population count by clearing the lowest set bit. */
uint32_t lp_popcount32(uint32_t x) {
    uint32_t count = 0;
    for (uint32_t bit = 0; bit < 32u; bit++) {
        count += (x >> bit) & 1u;
    }
    return count;
}

/* Total number of set bits in a buffer. */
uint32_t lp_popcount_bytes(const uint8_t *p, size_t n) {
    uint32_t total = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t b = p[i];
        while (b != 0u) {
            b &= b - 1u;
            total++;
        }
    }
    return total;
}

/* Number of significant bits in x (0 for x == 0). */
uint32_t lp_bit_length(uint32_t x) {
    uint32_t bits = 0;
    while (x != 0u) {
        bits++;
        x >>= 1;
    }
    return bits;
}

/* ---- checksums ---------------------------------------------------------------------------------------------- */

/* Fold a wide ones'-complement accumulator down to 16 bits; factored out of lp_inet_checksum. */
uint32_t lp_fold16(uint64_t sum) {
    while ((sum >> 16) != 0u) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint32_t)sum;
}

/* RFC 1071 Internet checksum: ones'-complement sum of big-endian 16-bit words, odd tail byte padded with zero. */
uint16_t lp_inet_checksum(const uint8_t *p, size_t n) {
    uint64_t sum = 0;
    size_t i = 0;
    while (i + 1 < n) {
        sum += ((uint32_t)p[i] << 8) | p[i + 1];
        i += 2;
    }
    if (i < n) {
        sum += (uint32_t)p[i] << 8;
    }
    return (uint16_t)~lp_fold16(sum);
}

/* Fletcher-32 over 16-bit words, reducing the running sums once per block. */
uint32_t lp_fletcher32(const uint16_t *p, size_t n) {
    uint32_t sum1 = 0xFFFFu;
    uint32_t sum2 = 0xFFFFu;
    while (n != 0) {
        size_t block = LP_MIN(n, (size_t)LP_BLOCK);
        n -= block;
        do {
            sum1 += *p++;
            sum2 += sum1;
        } while (--block != 0);
        sum1 = (sum1 & 0xFFFFu) + (sum1 >> 16);
        sum2 = (sum2 & 0xFFFFu) + (sum2 >> 16);
    }
    sum1 = (sum1 & 0xFFFFu) + (sum1 >> 16);
    sum2 = (sum2 & 0xFFFFu) + (sum2 >> 16);
    return (sum2 << 16) | sum1;
}

/* FNV-1a, 64 bit. */
uint64_t lp_fnv1a(const uint8_t *p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ull;
    for (size_t k = 0; k < n; k++) {
        h ^= p[k];
        h *= 0x100000001B3ull;
    }
    return h;
}
