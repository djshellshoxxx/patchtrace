/* PatchTrace known-answer corpus: identity-negatives/layoutshift, version 3. MIT licence.
 * Heap allocator. Prototypes are in heap.h, so definitions can appear in any order.
 */
#include "heap.h"

void hp_stats_reset(struct hp_heap *h) {
    h->peak = h->used;
    h->nallocs = 0u;
    h->nfrees = 0u;
}

/* Percentage (0..100) of the free space that is not in the largest free block. */
uint32_t hp_fragmentation(const struct hp_heap *h) {
    const struct hp_block *b;
    uint32_t total = 0u;
    uint32_t best = hp_largest_free(h);

    for (b = h->free_list; b != NULL; b = b->next_free) {
        total += b->size;
    }
    if (total == 0u) {
        return 0u;
    }
    return 100u - (uint32_t)(((uint64_t)best * 100u) / total);
}

/* Walks every block and the free list; any inconsistency is reported as HP_E_CORRUPT. */
int32_t hp_check(const struct hp_heap *h) {
    const struct hp_block *b;
    const struct hp_block *prev = NULL;
    const struct hp_block *f;
    uint32_t used = 0u;
    uint32_t nfree = 0u;
    uint32_t listed = 0u;

    if (h == NULL || h->base == NULL) {
        return HP_E_NULL;
    }
    for (b = (const struct hp_block *)h->base; b != NULL; b = hp_blk_next(h, b)) {
        if (!hp_blk_valid(h, b) || b->prev != prev) {
            return HP_E_CORRUPT;
        }
        if (b->magic == HP_MAGIC_USED) {
            used += b->size;
        } else {
            nfree++;
        }
        prev = b;
    }
    for (f = h->free_list; f != NULL; f = f->next_free) {
        if (f->magic != HP_MAGIC_FREE) {
            return HP_E_CORRUPT;
        }
        listed++;
    }
    if (used != h->used || listed != nfree) {
        return HP_E_CORRUPT;
    }
    return HP_OK;
}

uint32_t hp_usable_size(const struct hp_heap *h, const void *p) {
    const struct hp_block *b;

    if (!hp_in_heap(h, p)) {
        return 0u;
    }
    b = (const struct hp_block *)((const uint8_t *)p - HP_HDR_SIZE);
    if (!hp_blk_valid(h, b) || b->magic != HP_MAGIC_USED) {
        return 0u;
    }
    return b->size;
}

void *hp_realloc(struct hp_heap *h, void *p, uint32_t size) {
    struct hp_block *b;
    uint8_t *q;
    uint32_t i, n;

    if (p == NULL) {
        return hp_alloc(h, size);
    }
    if (size == 0u) {
        hp_free(h, p);
        return NULL;
    }
    b = (struct hp_block *)((uint8_t *)p - HP_HDR_SIZE);
    if (!hp_blk_valid(h, b) || b->magic != HP_MAGIC_USED) {
        return NULL;
    }
    if (b->size >= size) {
        return p;
    }
    q = (uint8_t *)hp_alloc(h, size);
    if (q == NULL) {
        return NULL;
    }
    n = b->size;
    for (i = 0; i < n; i++) {
        q[i] = ((const uint8_t *)p)[i];
    }
    hp_free(h, p);
    return q;
}

int32_t hp_free(struct hp_heap *h, void *p) {
    struct hp_block *b;

    if (h == NULL || p == NULL) {
        return HP_E_NULL;
    }
    if (!hp_in_heap(h, p)) {
        return HP_E_BADPTR;
    }
    b = (struct hp_block *)((uint8_t *)p - HP_HDR_SIZE);
    if (!hp_blk_valid(h, b) || b->magic != HP_MAGIC_USED) {
        return HP_E_BADPTR;
    }
    h->used -= b->size;
    h->nfrees++;
    b->magic = HP_MAGIC_FREE;
    hp_free_list_insert(h, b);
    hp_coalesce(h, b);
    return HP_OK;
}

void *hp_alloc_zero(struct hp_heap *h, uint32_t size) {
    uint8_t *p = (uint8_t *)hp_alloc(h, size);
    uint32_t i;

    if (p != NULL) {
        for (i = 0; i < size; i++) {
            p[i] = 0u;
        }
    }
    return p;
}

void *hp_alloc(struct hp_heap *h, uint32_t size) {
    struct hp_block *b;
    uint32_t need;

    if (h == NULL || size == 0u || size > h->capacity) {
        return NULL;
    }
    need = hp_align_up(size);
    b = hp_find_best_fit(h, need);
    if (b == NULL) {
        return NULL;
    }
    hp_free_list_remove(h, b);
    hp_split_block(h, b, need);
    b->magic = HP_MAGIC_USED;
    h->used += b->size;
    if (h->used > h->peak) {
        h->peak = h->used;
    }
    h->nallocs++;
    return (uint8_t *)b + HP_HDR_SIZE;
}

/* Merges a free block with free physical neighbours; returns the surviving block. */
struct hp_block *hp_coalesce(struct hp_heap *h, struct hp_block *b) {
    struct hp_block *next = hp_blk_next(h, b);
    struct hp_block *prev = b->prev;

    if (next != NULL && next->magic == HP_MAGIC_FREE) {
        hp_free_list_remove(h, next);
        b->size += HP_HDR_SIZE + next->size;
        next->magic = 0u;
        next = hp_blk_next(h, b);
        if (next != NULL) {
            next->prev = b;
        }
    }
    if (prev != NULL && prev->magic == HP_MAGIC_FREE) {
        hp_free_list_remove(h, b);
        prev->size += HP_HDR_SIZE + b->size;
        b->magic = 0u;
        next = hp_blk_next(h, prev);
        if (next != NULL) {
            next->prev = prev;
        }
        b = prev;
    }
    return b;
}

/* Carves the tail of b into a new free block when enough is left over. */
void hp_split_block(struct hp_heap *h, struct hp_block *b, uint32_t size) {
    struct hp_block *rest;
    struct hp_block *after;

    if (b->size < size + HP_HDR_SIZE + HP_MIN_SPLIT) {
        return;
    }
    rest = (struct hp_block *)((uint8_t *)b + HP_HDR_SIZE + size);
    rest->magic = HP_MAGIC_FREE;
    rest->size = b->size - size - HP_HDR_SIZE;
    rest->prev = b;
    rest->reserved = 0u;
    after = hp_blk_next(h, rest);
    if (after != NULL) {
        after->prev = rest;
    }
    b->size = size;
    hp_free_list_insert(h, rest);
}

void hp_free_list_remove(struct hp_heap *h, struct hp_block *b) {
    struct hp_block **link = &h->free_list;

    while (*link != NULL && *link != b) {
        link = &(*link)->next_free;
    }
    if (*link == b) {
        *link = b->next_free;
    }
    b->next_free = NULL;
}

/* Keeps the free list ordered by address. */
void hp_free_list_insert(struct hp_heap *h, struct hp_block *b) {
    struct hp_block *cur = h->free_list;
    struct hp_block *before = NULL;

    while (cur != NULL && (uintptr_t)cur < (uintptr_t)b) {
        before = cur;
        cur = cur->next_free;
    }
    b->next_free = cur;
    if (before == NULL) {
        h->free_list = b;
    } else {
        before->next_free = b;
    }
}

int32_t hp_init(struct hp_heap *h, void *base, uint32_t size) {
    uintptr_t start;
    uint32_t skew;
    struct hp_block *b;

    if (h == NULL || base == NULL) {
        return HP_E_NULL;
    }
    start = ((uintptr_t)base + (HP_ALIGN - 1u)) & ~(uintptr_t)(HP_ALIGN - 1u);
    skew = (uint32_t)(start - (uintptr_t)base);
    if (size < skew + HP_HDR_SIZE + HP_ALIGN) {
        return HP_E_NOMEM;
    }
    h->base = (uint8_t *)start;
    h->capacity = (size - skew) & ~(HP_ALIGN - 1u);
    b = (struct hp_block *)h->base;
    b->magic = HP_MAGIC_FREE;
    b->size = h->capacity - HP_HDR_SIZE;
    b->next_free = NULL;
    b->prev = NULL;
    b->reserved = 0u;
    h->free_list = b;
    h->used = 0u;
    h->peak = 0u;
    h->nallocs = 0u;
    h->nfrees = 0u;
    return HP_OK;
}

int32_t hp_blk_valid(const struct hp_heap *h, const struct hp_block *b) {
    if (!hp_in_heap(h, b)) {
        return 0;
    }
    if (b->magic != HP_MAGIC_USED && b->magic != HP_MAGIC_FREE) {
        return 0;
    }
    if ((b->size & (HP_ALIGN - 1u)) != 0u) {
        return 0;
    }
    return (uintptr_t)b + HP_HDR_SIZE + b->size <= (uintptr_t)h->base + h->capacity;
}

uint32_t hp_align_up(uint32_t v) {
    return (v + (HP_ALIGN - 1u)) & ~(HP_ALIGN - 1u);
}

struct hp_block *hp_find_best_fit(const struct hp_heap *h, uint32_t size) {
    struct hp_block *b;
    struct hp_block *best = NULL;

    for (b = h->free_list; b != NULL; b = b->next_free) {
        if (b->size >= size && (best == NULL || b->size < best->size)) {
            best = b;
            if (b->size == size) {
                break;
            }
        }
    }
    return best;
}

uint32_t hp_largest_free(const struct hp_heap *h) {
    const struct hp_block *b;
    uint32_t best = 0u;

    for (b = h->free_list; b != NULL; b = b->next_free) {
        if (b->size > best) {
            best = b->size;
        }
    }
    return best;
}

struct hp_block *hp_blk_next(const struct hp_heap *h, const struct hp_block *b) {
    uintptr_t next = (uintptr_t)b + HP_HDR_SIZE + b->size;

    if (next + HP_HDR_SIZE > (uintptr_t)h->base + h->capacity) {
        return NULL;
    }
    return (struct hp_block *)next;
}

int32_t hp_in_heap(const struct hp_heap *h, const void *p) {
    uintptr_t addr = (uintptr_t)p;
    uintptr_t lo;

    if (h == NULL || p == NULL) {
        return 0;
    }
    lo = (uintptr_t)h->base;
    return addr >= lo && addr < lo + h->capacity;
}

/* Scans the free list for the first block that is large enough. */
struct hp_block *hp_find_first_fit(const struct hp_heap *h, uint32_t size) {
    struct hp_block *b;

    for (b = h->free_list; b != NULL; b = b->next_free) {
        if (b->size >= size) {
            return b;
        }
    }
    return NULL;
}

/* Added in version 2, at the very top of the file: the highest-addressed block that fits. */
struct hp_block *hp_find_last_fit(const struct hp_heap *h, uint32_t size) {
    struct hp_block *b;
    struct hp_block *last = NULL;

    for (b = h->free_list; b != NULL; b = b->next_free) {
        if (b->size >= size) {
            last = b;
        }
    }
    return last;
}
