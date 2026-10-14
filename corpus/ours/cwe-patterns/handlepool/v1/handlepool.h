/* handlepool.h - fixed-size object pool with 32-bit handles, over a caller-provided byte array.
 *
 * A handle packs a 16-bit generation (high half) and a 16-bit slot index (low half). Slots carry an
 * 8-byte header followed by the object payload: [gen:2][state:2][next_free:4][payload...].
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef HANDLEPOOL_H
#define HANDLEPOOL_H

#include <stddef.h>
#include <stdint.h>

#define HP_OFF_GEN 0u
#define HP_OFF_STATE 2u
#define HP_OFF_NEXT 4u
#define HP_HDR 8u

#define HP_FREE 0u
#define HP_USED 1u
#define HP_NONE 0xffffffffu
#define HP_INVALID 0u
#define HP_MAX_SLOTS 0xfffeu

#define HP_OK 0
#define HP_ERR_ARG (-1)
#define HP_ERR_HANDLE (-2)

typedef uint32_t hp_handle;

typedef struct hp_pool {
    uint8_t *base;      /* caller-provided storage */
    uint32_t stride;    /* bytes per slot: header + payload, 8-aligned */
    uint32_t obj_size;  /* payload bytes per object */
    uint32_t nslots;    /* slots that fit in the storage */
    uint32_t free_head; /* first free slot or HP_NONE */
    uint32_t live;      /* objects currently allocated */
    uint32_t allocs;
    uint32_t frees;
} hp_pool;

typedef void (*hp_visitor)(void *ctx, hp_handle h, uint8_t *payload);

/* byte-array accessors and handle packing */
uint16_t hp_load16(const uint8_t *p);
void hp_store16(uint8_t *p, uint16_t v);
uint32_t hp_load32(const uint8_t *p);
void hp_store32(uint8_t *p, uint32_t v);
hp_handle hp_make(uint16_t gen, uint32_t index);
uint32_t hp_index_of(hp_handle h);
uint16_t hp_gen_of(hp_handle h);

/* pool management */
uint8_t *hp_slot_at(const hp_pool *p, uint32_t index);
int hp_init(hp_pool *p, uint8_t *storage, uint32_t bytes, uint32_t obj_size);
uint32_t hp_capacity(const hp_pool *p);
uint32_t hp_live(const hp_pool *p);
uint32_t hp_available(const hp_pool *p);
uint32_t hp_size(const hp_pool *p);
uint32_t hp_stat_allocs(const hp_pool *p);
uint32_t hp_stat_frees(const hp_pool *p);
void hp_release_slot(hp_pool *p, uint32_t index);
uint8_t *hp_slot_for(const hp_pool *p, hp_handle h);
uint8_t *hp_get_unchecked(const hp_pool *p, uint32_t index);

/* handle operations */
hp_handle hp_alloc(hp_pool *p);
int hp_free(hp_pool *p, hp_handle h);
int hp_is_valid(const hp_pool *p, hp_handle h);
uint8_t *hp_get(const hp_pool *p, hp_handle h);
int hp_read(const hp_pool *p, hp_handle h, uint8_t *out, uint32_t n);
int hp_write(hp_pool *p, hp_handle h, const uint8_t *src, uint32_t n);
void hp_clear(hp_pool *p);
uint32_t hp_for_each(hp_pool *p, hp_visitor visit, void *ctx);
uint32_t hp_free_list_len(const hp_pool *p);

#endif /* HANDLEPOOL_H */
