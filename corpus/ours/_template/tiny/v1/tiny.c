/* Freestanding example, version 1. No libc, no system headers: it must build for any target. */
#include <stdint.h>

int32_t tiny_add(int32_t a, int32_t b) { return a + b; }

int32_t tiny_clamp(int32_t v, int32_t hi) {
    if (v > hi) {
        return hi;
    }
    return v;
}

int32_t tiny_sum_to(int32_t n) {
    int32_t total = 0;
    for (int32_t i = 1; i <= n; i++) {
        total += i;
    }
    return total;
}

int32_t tiny_old_only(int32_t x) { return x * 3; }
