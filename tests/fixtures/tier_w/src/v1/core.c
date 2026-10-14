/* PatchTrace Tier-W self-made test fixture, version 1. MIT licence (see repository LICENSE).
 * Freestanding C11: no CRT, no OS calls; built only to produce a real DLL + PDB pair for tests. Never run. */
#include <stddef.h>
#include <stdint.h>

uintptr_t __security_cookie = 0x2B992DDFA232u;

/* N3-style shared library helpers (the names, not the code, matter for tagging). */
__declspec(dllexport) void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

__declspec(dllexport) void *memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

/* N9-style compiler helper name. */
__attribute__((noinline)) void __security_check_cookie(uintptr_t cookie) {
    if (cookie != __security_cookie) {
        for (;;) {
        }
    }
}

/* Unchanged in version 2. */
__declspec(dllexport) __attribute__((noinline)) uint32_t checksum(const uint8_t *p, size_t n) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n; i++) {
        a = (a + p[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

/* Renamed to parse_header_ex (with one more check) in version 2. */
__declspec(dllexport) int parse_header(const uint8_t *p, size_t n, uint32_t *out) {
    if (n < 8) return -1;
    uint32_t magic = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    if (magic != 0x31545050u) return -2;
    *out = (uint32_t)p[4] | (uint32_t)p[5] << 8;
    return 0;
}

/* Comparison changes in version 2 (small edit, same function). */
__attribute__((noinline)) int clamp_index(int i, int limit) {
    if (i < 0) return 0;
    if (i >= limit) return limit - 1;
    return i;
}

/* Large rewrite in version 2 (same function, much bigger body). */
__attribute__((noinline)) int rewrite_me(const int *v, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += v[i];
    return total;
}

/* Removed in version 2. */
__attribute__((noinline)) int removed_later(int x) { return x * 7 + 3; }

/* N2-style wrapper name; a tail call that tools may report as a thunk. */
__attribute__((noinline)) int j_checksum(const uint8_t *p, size_t n) { return (int)checksum(p, n); }

/* N10-style split-piece name through an assembler label. */
int worker_cold(int x) __asm__("worker.cold.1");
__attribute__((noinline)) int worker_cold(int x) {
    int r = x;
    for (int i = 0; i < 5; i++) r = r * 31 + i;
    return r;
}

/* Identical bodies: lld-link /opt:icf folds them, giving two public names at one address. */
__attribute__((noinline)) int same_a(int x) { return x * 3 + 1; }
__attribute__((noinline)) int same_b(int x) { return x * 3 + 1; }

typedef int (*op_t)(int);
__declspec(dllexport) const op_t dispatch[] = {same_a, same_b, worker_cold, removed_later};

__declspec(dllexport) int run_all(const int *v, int n, uintptr_t cookie) {
    int acc = clamp_index(n, 16) + rewrite_me(v, n) + j_checksum((const uint8_t *)v, (size_t)n * sizeof(int));
    for (int i = 0; i < 4; i++) acc += dispatch[i](acc);
    __security_check_cookie(cookie);
    return acc;
}
