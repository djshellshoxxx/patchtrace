/* handlepool.c - generational-handle object pool over a caller-provided byte array (v1).
 *
 * Free slots form a singly linked list threaded through their headers. Allocation pops the list head;
 * freeing pushes the slot back, so the most recently freed slot is the next one handed out.
 */
#include "handlepool.h"

/* ---- byte-array accessors and handle packing ---------------------------- */

uint16_t hp_load16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

void hp_store16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)(v >> 8);
}

uint32_t hp_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void hp_store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

hp_handle hp_make(uint16_t gen, uint32_t index) {
    return ((uint32_t)gen << 16) | (index & 0xffffu);
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

int hp_init(hp_pool *p, uint8_t *storage, uint32_t bytes, uint32_t obj_size) {
    uint32_t i;
    if (p == NULL || storage == NULL || obj_size == 0 || obj_size > 4096u) {
        return HP_ERR_ARG;
    }
    p->base = storage;
    p->obj_size = obj_size;
    p->stride = (HP_HDR + obj_size + 7u) & ~7u;
    p->nslots = bytes / p->stride;
    if (p->nslots > HP_MAX_SLOTS) {
        p->nslots = HP_MAX_SLOTS;
    }
    p->free_head = p->nslots > 0 ? 0 : HP_NONE;
    p->live = 0;
    p->allocs = 0;
    p->frees = 0;
    for (i = 0; i < p->nslots; i++) {
        uint8_t *slot = hp_slot_at(p, i);
        hp_store16(slot + HP_OFF_GEN, 1);
        hp_store16(slot + HP_OFF_STATE, HP_FREE);
        hp_store32(slot + HP_OFF_NEXT, i + 1u < p->nslots ? i + 1u : HP_NONE);
    }
    return p->nslots > 0 ? HP_OK : HP_ERR_ARG;
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

uint32_t hp_size(const hp_pool *p) {
    return p->obj_size;
}

uint32_t hp_stat_allocs(const hp_pool *p) {
    return p->allocs;
}

uint32_t hp_stat_frees(const hp_pool *p) {
    return p->frees;
}

/* Return a slot to the free list. */
void hp_release_slot(hp_pool *p, uint32_t index) {
    uint8_t *slot = hp_slot_at(p, index);
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
    return slot;
}

/* Payload of slot `index`, whatever its state (internal debugging aid). */
uint8_t *hp_get_unchecked(const hp_pool *p, uint32_t index) {
    return hp_slot_at(p, index) + HP_HDR;
}

/* ---- handle operations -------------------------------------------------- */

hp_handle hp_alloc(hp_pool *p) {
    uint32_t index = p->free_head;
    uint8_t *slot;
    uint32_t i;
    if (index == HP_NONE) {
        return HP_INVALID;
    }
    slot = hp_slot_at(p, index);
    p->free_head = hp_load32(slot + HP_OFF_NEXT);
    hp_store16(slot + HP_OFF_STATE, HP_USED);
    hp_store32(slot + HP_OFF_NEXT, HP_NONE);
    for (i = 0; i < p->obj_size; i++) {
        slot[HP_HDR + i] = 0;
    }
    p->live++;
    p->allocs++;
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
    return slot == NULL ? NULL : slot + HP_HDR;
}

int hp_read(const hp_pool *p, hp_handle h, uint8_t *out, uint32_t n) {
    const uint8_t *payload = hp_get(p, h);
    uint32_t i;
    if (payload == NULL) {
        return HP_ERR_HANDLE;
    }
    if (n > p->obj_size) {
        n = p->obj_size;
    }
    for (i = 0; i < n; i++) {
        out[i] = payload[i];
    }
    return (int)n;
}

int hp_write(hp_pool *p, hp_handle h, const uint8_t *src, uint32_t n) {
    uint8_t *payload = hp_get(p, h);
    uint32_t i;
    if (payload == NULL) {
        return HP_ERR_HANDLE;
    }
    if (n > p->obj_size) {
        n = p->obj_size;
    }
    for (i = 0; i < n; i++) {
        payload[i] = src[i];
    }
    return (int)n;
}

/* Free every live object. */
void hp_clear(hp_pool *p) {
    uint32_t i;
    for (i = 0; i < p->nslots; i++) {
        if (hp_load16(hp_slot_at(p, i) + HP_OFF_STATE) == HP_USED) {
            hp_release_slot(p, i);
        }
    }
}

/* Call `visit` for each live object; returns how many were visited. */
uint32_t hp_for_each(hp_pool *p, hp_visitor visit, void *ctx) {
    uint32_t visited = 0;
    uint32_t i;
    for (i = 0; i < p->nslots; i++) {
        uint8_t *slot = hp_slot_at(p, i);
        if (hp_load16(slot + HP_OFF_STATE) == HP_USED) {
            visit(ctx, hp_make(hp_load16(slot + HP_OFF_GEN), i), slot + HP_HDR);
            visited++;
        }
    }
    return visited;
}

/* Length of the free list, with a guard against a corrupted (cyclic) list. */
uint32_t hp_free_list_len(const hp_pool *p) {
    uint32_t len = 0;
    uint32_t index = p->free_head;
    while (index != HP_NONE && len <= p->nslots) {
        index = hp_load32(hp_slot_at(p, index) + HP_OFF_NEXT);
        len++;
    }
    return len;
}
