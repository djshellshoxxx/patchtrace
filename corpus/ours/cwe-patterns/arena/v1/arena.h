/* arena.h - bump allocator over a caller-provided byte array, with array and table helpers.
 *
 * Nothing is ever freed individually: callers take a mark, allocate, and release back to the mark.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef ARENA_H
#define ARENA_H

#include <stddef.h>
#include <stdint.h>

typedef struct ar_arena {
    uint8_t *base;   /* caller-provided storage */
    uint32_t cap;    /* bytes available */
    uint32_t used;   /* bump offset */
    uint32_t peak;   /* high-water mark of `used` */
    uint32_t allocs; /* successful allocations */
    uint32_t failed; /* rejected allocations */
} ar_arena;

/* byte helpers */
void ar_zero(void *dst, uint32_t n);
void ar_copy(void *dst, const void *src, uint32_t n);
uint32_t ar_str_len(const char *s);
uint32_t ar_align_up(uint32_t value, uint32_t align);

/* lifecycle and accounting */
int ar_init(ar_arena *a, void *storage, uint32_t cap);
void ar_reset(ar_arena *a);
uint32_t ar_used(const ar_arena *a);
uint32_t ar_remaining(const ar_arena *a);
uint32_t ar_peak(const ar_arena *a);
uint32_t ar_failed(const ar_arena *a);
uint32_t ar_mark(const ar_arena *a);
void ar_release(ar_arena *a, uint32_t mark);
int ar_contains(const ar_arena *a, const void *p);

/* allocation */
uint32_t ar_total_bytes(uint32_t count, uint32_t elem_size);
void *ar_alloc(ar_arena *a, uint32_t size, uint32_t align);
void *ar_alloc_zeroed(ar_arena *a, uint32_t size, uint32_t align);
void *ar_alloc_array(ar_arena *a, uint32_t count, uint32_t elem_size, uint32_t align);
void *ar_alloc_array_zeroed(ar_arena *a, uint32_t count, uint32_t elem_size, uint32_t align);
void *ar_alloc_table(ar_arena *a, uint32_t rows, uint32_t cols, uint32_t elem_size);
char *ar_strdup(ar_arena *a, const char *s);
void *ar_memdup(ar_arena *a, const void *src, uint32_t n);

/* typed convenience wrappers */
uint32_t *ar_new_u32_array(ar_arena *a, uint32_t count);
uint16_t *ar_new_u16_array(ar_arena *a, uint32_t count);
uint8_t *ar_new_byte_array(ar_arena *a, uint32_t count);
void ar_array_fill_u32(uint32_t *items, uint32_t count, uint32_t value);
uint32_t ar_array_sum_u32(const uint32_t *items, uint32_t count);

#endif /* ARENA_H */
