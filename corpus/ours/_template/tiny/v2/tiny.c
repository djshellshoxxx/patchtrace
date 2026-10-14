/* Freestanding example, version 2. No libc, no system headers: it must build for any target. */
#include <stdint.h>

int32_t tiny_add(int32_t a, int32_t b) { return a + b; }

int32_t tiny_clamp(int32_t v, int32_t hi) {
    if (hi < 0) {
        return 0;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

int32_t tiny_sum_to(int32_t n) {
    int32_t acc = 0;
    for (int32_t k = 1; k <= n; k++) {
        acc += k;
    }
    return acc;
}

int32_t tiny_new_only(int32_t x) { return x << 2; }
