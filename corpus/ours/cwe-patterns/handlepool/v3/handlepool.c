/* handlepool.c - generational-handle object pool over a caller-provided byte array (v3).
 *
 * Free slots form a singly linked list threaded through their headers. Allocation pops the list head;
 * freeing pushes the slot back, so the most recently freed slot is the next one handed out.
 */
#include "handlepool.h"

/* ---- byte-array accessors and handle packing ---------------------------- */

uint16_t hp_load16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

void hp_store16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)(v >> 8);
}

uint32_t hp_load32(const uint8_t *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

void hp_store32(uint8_t *p, uint32_t v) {
    p[3] = (uint8_t)((v >> 24) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[0] = (uint8_t)(v & 0xffu);
}

hp_handle hp_make(uint16_t gen, uint32_t index) {
    return (index & 0xffffu) | ((uint32_t)gen << 16);
}

uint32_t hp_index_of(hp_handle h) {
    return h & 0xffffu;
}

uint16_t hp_gen_of(hp_handle h) {
    return (uint16_t)(h >> 16);
}

/* ---- pool management ---------------------------------------------------- */

uint8_t *hp_slot_at(const hp_pool *p, uint32_t index) {
    return p->base + (size_t)index * p->stride;
}

int hp_init(hp_pool *pool, uint8_t *storage, uint32_t bytes, uint32_t obj_size) {
    uint32_t n;
    if (pool == NULL || storage == NULL || obj_size == 0 || obj_size > 4096u) {
        return HP_ERR_ARG;
    }
    pool->base = storage;
    pool->obj_size = obj_size;
    pool->stride = (HP_HDR + obj_size + 7u) & ~7u;
    pool->nslots = bytes / pool->stride;
    if (pool->nslots > HP_MAX_SLOTS) {
        pool->nslots = HP_MAX_SLOTS;
    }
    pool->free_head = pool->nslots > 0 ? 0 : HP_NONE;
    pool->frees = 0;
    pool->allocs = 0;
    pool->live = 0;
    n = 0;
    while (n < pool->nslots) {
        uint8_t *slot = hp_slot_at(pool, n);
        hp_store16(slot + HP_OFF_GEN, 1);
        hp_store16(slot + HP_OFF_STATE, HP_FREE);
        hp_store32(slot + HP_OFF_NEXT, n + 1u < pool->nslots ? n + 1u : HP_NONE);
        n++;
    }
    return pool->nslots > 0 ? HP_OK : HP_ERR_ARG;
}

uint32_t hp_capacity(const hp_pool *p) {
    return p->nslots;
}

uint32_t hp_live(const hp_pool *p) {
    return p->live;
}

uint32_t hp_available(const hp_pool *p) {
    return p->nslots - p->live;
}

/* Next generation number; 0 is skipped so a live handle is never HP_INVALID. */
uint16_t hp_next_gen(uint16_t gen) {
    uint16_t next = (uint16_t)(gen + 1u);
    return next == 0 ? 1 : next;
}

/* Return a slot to the free list; the generation moves on so old handles go stale. */
void hp_release_slot(hp_pool *p, uint32_t index) {
    uint8_t *slot = hp_slot_at(p, index);
    hp_store16(slot + HP_OFF_GEN, hp_next_gen(hp_load16(slot + HP_OFF_GEN)));
    hp_store16(slot + HP_OFF_STATE, HP_FREE);
    hp_store32(slot + HP_OFF_NEXT, p->free_head);
    p->free_head = index;
    p->live--;
    p->frees++;
}

/* Resolve a handle to its slot, or NULL when the handle does not name a live object. */
uint8_t *hp_slot_for(const hp_pool *p, hp_handle h) {
    uint32_t index = hp_index_of(h);
    uint8_t *slot;
    if (h == HP_INVALID || index >= p->nslots) {
        return NULL;
    }
    slot = hp_slot_at(p, index);
    if (hp_load16(slot + HP_OFF_STATE) != HP_USED) {
        return NULL;
    }
    if (hp_load16(slot + HP_OFF_GEN) != hp_gen_of(h)) {
        return NULL;
    }
    return slot;
}

/* ---- handle operations -------------------------------------------------- */

hp_handle hp_alloc(hp_pool *p) {
    uint32_t index = p->free_head;
    uint8_t *slot;
    uint32_t i = 0;
    if (index == HP_NONE) {
        return HP_INVALID;
    }
    slot = hp_slot_at(p, index);
    p->free_head = hp_load32(slot + HP_OFF_NEXT);
    hp_store16(slot + HP_OFF_STATE, HP_USED);
    hp_store32(slot + HP_OFF_NEXT, HP_NONE);
    while (i < p->obj_size) {
        slot[HP_HDR + i] = 0;
        i++;
    }
    p->allocs++;
    p->live++;
    return hp_make(hp_load16(slot + HP_OFF_GEN), index);
}

int hp_free(hp_pool *p, hp_handle h) {
    if (hp_slot_for(p, h) == NULL) {
        return HP_ERR_HANDLE;
    }
    hp_release_slot(p, hp_index_of(h));
    return HP_OK;
}

int hp_is_valid(const hp_pool *p, hp_handle h) {
    return hp_slot_for(p, h) != NULL;
}

uint8_t *hp_get(const hp_pool *p, hp_handle h) {
    uint8_t *slot = hp_slot_for(p, h);
    if (slot == NULL) {
        return NULL;
    }
    return slot + HP_HDR;
}

int hp_read(const hp_pool *p, hp_handle h, uint8_t *out, uint32_t n) {
    const uint8_t *payload = hp_get(p, h);
    if (payload == NULL) {
        return HP_ERR_HANDLE;
    }
    if (n > p->obj_size) {
        n = p->obj_size;
    }
    for (uint32_t k = 0; k < n; k++) {
        out[k] = payload[k];
    }
    return (int)n;
}

int hp_write(hp_pool *p, hp_handle h, const uint8_t *src, uint32_t n) {
    uint8_t *payload = hp_get(p, h);
    if (payload == NULL) {
        return HP_ERR_HANDLE;
    }
    if (n > p->obj_size) {
        n = p->obj_size;
    }
    for (uint32_t k = 0; k < n; k++) {
        payload[k] = src[k];
    }
    return (int)n;
}

/* Free every live object. */
void hp_clear(hp_pool *p) {
    uint32_t i;
    for (i = 0; i < p->nslots; i++) {
        const uint8_t *slot = hp_slot_at(p, i);
        if (hp_load16(slot + HP_OFF_STATE) == HP_USED) {
            hp_release_slot(p, i);
        }
    }
}

/* Call `visit` for each live object; returns how many were visited. */
uint32_t hp_for_each(hp_pool *p, hp_visitor visit, void *ctx) {
    uint32_t count = 0;
    uint32_t i;
    for (i = 0; i < p->nslots; i++) {
        uint8_t *slot = hp_slot_at(p, i);
        if (hp_load16(slot + HP_OFF_STATE) == HP_USED) {
            visit(ctx, hp_make(hp_load16(slot + HP_OFF_GEN), i), slot + HP_HDR);
            count++;
        }
    }
    return count;
}

/* Length of the free list, with a guard against a corrupted (cyclic) list. */
uint32_t hp_free_list_len(const hp_pool *p) {
    uint32_t len;
    uint32_t index;
    for (len = 0, index = p->free_head; index != HP_NONE && len <= p->nslots; len++) {
        index = hp_load32(hp_slot_at(p, index) + HP_OFF_NEXT);
    }
    return len;
}

/* ---- counters ------------------------------------------------------------ */

uint32_t hp_size(const hp_pool *p) {
    return p->obj_size;
}

uint32_t hp_stat_allocs(const hp_pool *p) {
    return p->allocs;
}

uint32_t hp_stat_frees(const hp_pool *p) {
    return p->frees;
}
