/* arena.c - bump allocator with array and table helpers (v2).
 *
 * Offsets and sizes are 32-bit throughout; the arena never grows. Every allocation is carved
 * from `base + used` after aligning, and fails (returns NULL) when it does not fit.
 */
#include "arena.h"

/* ---- byte helpers ------------------------------------------------------- */

void ar_zero(void *dst, uint32_t n) {
    uint8_t *p = (uint8_t *)dst;
    uint32_t i;
    for (i = 0; i < n; i++) {
        p[i] = 0;
    }
}

void ar_copy(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    uint32_t i;
    for (i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

uint32_t ar_str_len(const char *s) {
    uint32_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

/* Round `value` up to a multiple of `align` (a power of two). May wrap near UINT32_MAX. */
uint32_t ar_align_up(uint32_t value, uint32_t align) {
    return (value + align - 1u) & ~(align - 1u);
}

/* ---- lifecycle and accounting ------------------------------------------- */

int ar_init(ar_arena *a, void *storage, uint32_t cap) {
    if (a == NULL || storage == NULL || cap == 0) {
        return -1;
    }
    a->base = (uint8_t *)storage;
    a->cap = cap;
    a->used = 0;
    a->peak = 0;
    a->allocs = 0;
    a->failed = 0;
    return 0;
}

void ar_reset(ar_arena *a) {
    a->used = 0;
}

uint32_t ar_used(const ar_arena *a) {
    return a->used;
}

uint32_t ar_remaining(const ar_arena *a) {
    return a->cap - a->used;
}

uint32_t ar_peak(const ar_arena *a) {
    return a->peak;
}

uint32_t ar_failed(const ar_arena *a) {
    return a->failed;
}

uint32_t ar_mark(const ar_arena *a) {
    return a->used;
}

/* Roll the bump pointer back to an earlier mark; stale marks are ignored. */
void ar_release(ar_arena *a, uint32_t mark) {
    if (mark <= a->used) {
        a->used = mark;
    }
}

int ar_contains(const ar_arena *a, const void *p) {
    uintptr_t lo = (uintptr_t)a->base;
    uintptr_t hi = lo + a->used;
    uintptr_t at = (uintptr_t)p;
    return at >= lo && at < hi;
}

/* ---- allocation --------------------------------------------------------- */

/* True when a 64-bit byte count still fits the arena's 32-bit offsets. */
int ar_fits_u32(uint64_t value) {
    return value <= 0xffffffffull;
}

void *ar_alloc(ar_arena *a, uint32_t size, uint32_t align) {
    uint32_t start;
    uint32_t end;
    if (a == NULL || size == 0 || align == 0 || (align & (align - 1u)) != 0) {
        return NULL;
    }
    start = ar_align_up(a->used, align);
    end = start + size;
    if (start < a->used || end < start || end > a->cap) {
        a->failed++;
        return NULL;
    }
    a->used = end;
    if (end > a->peak) {
        a->peak = end;
    }
    a->allocs++;
    return a->base + start;
}

void *ar_alloc_zeroed(ar_arena *a, uint32_t size, uint32_t align) {
    void *p = ar_alloc(a, size, align);
    if (p != NULL) {
        ar_zero(p, size);
    }
    return p;
}

/* Allocate room for `count` elements; NULL when the byte count does not fit in 32 bits. */
void *ar_alloc_array(ar_arena *a, uint32_t count, uint32_t elem_size, uint32_t align) {
    uint64_t total = (uint64_t)count * elem_size;
    if (!ar_fits_u32(total)) {
        return NULL;
    }
    return ar_alloc(a, (uint32_t)total, align);
}

/* Like ar_alloc_array, but every element is cleared one by one. */
void *ar_alloc_array_zeroed(ar_arena *a, uint32_t count, uint32_t elem_size, uint32_t align) {
    uint8_t *p = (uint8_t *)ar_alloc_array(a, count, elem_size, align);
    uint32_t i;
    if (p == NULL) {
        return NULL;
    }
    for (i = 0; i < count; i++) {
        ar_zero(p + (size_t)i * elem_size, elem_size);
    }
    return p;
}

/* Allocate a rows x cols table of `elem_size`-byte cells. */
void *ar_alloc_table(ar_arena *a, uint32_t rows, uint32_t cols, uint32_t elem_size) {
    uint64_t cells = (uint64_t)rows * cols;
    uint64_t total;
    if (!ar_fits_u32(cells)) {
        return NULL;
    }
    total = cells * elem_size;
    if (!ar_fits_u32(total)) {
        return NULL;
    }
    return ar_alloc(a, (uint32_t)total, 8);
}

char *ar_strdup(ar_arena *a, const char *s) {
    uint32_t n = ar_str_len(s);
    char *p = (char *)ar_alloc(a, n + 1u, 1);
    if (p != NULL) {
        ar_copy(p, s, n + 1u);
    }
    return p;
}

void *ar_memdup(ar_arena *a, const void *src, uint32_t n) {
    void *p = ar_alloc(a, n, 1);
    if (p != NULL) {
        ar_copy(p, src, n);
    }
    return p;
}

/* ---- typed convenience wrappers ----------------------------------------- */

uint32_t *ar_new_u32_array(ar_arena *a, uint32_t count) {
    return (uint32_t *)ar_alloc_array(a, count, 4, 4);
}

uint16_t *ar_new_u16_array(ar_arena *a, uint32_t count) {
    return (uint16_t *)ar_alloc_array(a, count, 2, 2);
}

uint8_t *ar_new_byte_array(ar_arena *a, uint32_t count) {
    return (uint8_t *)ar_alloc_array(a, count, 1, 1);
}

void ar_array_fill_u32(uint32_t *items, uint32_t count, uint32_t value) {
    uint32_t i;
    for (i = 0; i < count; i++) {
        items[i] = value;
    }
}

uint32_t ar_array_sum_u32(const uint32_t *items, uint32_t count) {
    uint32_t sum = 0;
    uint32_t i;
    for (i = 0; i < count; i++) {
        sum += items[i];
    }
    return sum;
}
