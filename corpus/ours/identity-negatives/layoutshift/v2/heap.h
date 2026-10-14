/* PatchTrace known-answer corpus: identity-negatives/layoutshift, version 2. MIT licence.
 * Freestanding C11, no libc.
 *
 * Best-fit heap allocator over a caller supplied buffer. Every block has a 32-byte header
 * (magic, payload size, link to the physically previous block); free blocks sit on an
 * address-ordered list and are coalesced eagerly when they are released.
 */
#ifndef HEAP_H
#define HEAP_H

#include <stddef.h>
#include <stdint.h>

#define HP_OK 0
#define HP_E_NULL (-1)
#define HP_E_NOMEM (-2)
#define HP_E_BADPTR (-3)
#define HP_E_CORRUPT (-4)

#define HP_ALIGN 16u
#define HP_HDR_SIZE 32u
#define HP_MIN_SPLIT 32u
#define HP_MAGIC_USED 0xA110CA7Eu
#define HP_MAGIC_FREE 0xF4EEB10Cu

struct hp_block {
    uint32_t magic;
    uint32_t size;
    struct hp_block *next_free;
    struct hp_block *prev;
    uint64_t reserved;
};

struct hp_heap {
    uint8_t *base;
    uint32_t capacity;
    uint32_t used;
    uint32_t peak;
    uint32_t nallocs;
    uint32_t nfrees;
    struct hp_block *free_list;
};

uint32_t hp_align_up(uint32_t v);
int32_t hp_in_heap(const struct hp_heap *h, const void *p);
struct hp_block *hp_blk_next(const struct hp_heap *h, const struct hp_block *b);
int32_t hp_blk_valid(const struct hp_heap *h, const struct hp_block *b);
int32_t hp_init(struct hp_heap *h, void *base, uint32_t size);
void hp_free_list_insert(struct hp_heap *h, struct hp_block *b);
void hp_free_list_remove(struct hp_heap *h, struct hp_block *b);
struct hp_block *hp_find_first_fit(const struct hp_heap *h, uint32_t size);
struct hp_block *hp_find_best_fit(const struct hp_heap *h, uint32_t size);
struct hp_block *hp_find_last_fit(const struct hp_heap *h, uint32_t size);
void hp_split_block(struct hp_heap *h, struct hp_block *b, uint32_t size);
struct hp_block *hp_coalesce(struct hp_heap *h, struct hp_block *b);
void *hp_alloc(struct hp_heap *h, uint32_t size);
void *hp_alloc_zero(struct hp_heap *h, uint32_t size);
int32_t hp_free(struct hp_heap *h, void *p);
void *hp_realloc(struct hp_heap *h, void *p, uint32_t size);
uint32_t hp_usable_size(const struct hp_heap *h, const void *p);
int32_t hp_check(const struct hp_heap *h);
uint32_t hp_largest_free(const struct hp_heap *h);
uint32_t hp_fragmentation(const struct hp_heap *h);
void hp_stats_reset(struct hp_heap *h);

#endif
