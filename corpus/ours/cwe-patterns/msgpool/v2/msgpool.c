/* msgpool.c - fixed-block message pool and send/dispatch layer (v2).
 *
 * Ownership rule: whoever holds a payload pointer owns the block. msg_encode() consumes the buffer
 * when it fails (it hands the block back to the pool before returning an error).
 */
#include "msgpool.h"

/* ---- byte helpers ------------------------------------------------------- */

uint32_t mp_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void mp_store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

/* ---- pool --------------------------------------------------------------- */

int mp_init(mp_pool *pool, uint8_t *storage, uint32_t bytes) {
    if (pool == NULL || storage == NULL) {
        return -1;
    }
    pool->base = storage;
    pool->nblocks = bytes / MP_BLOCK;
    pool->in_use = 0;
    pool->allocs = 0;
    mp_reset(pool);
    return pool->nblocks > 0 ? 0 : -1;
}

/* Rebuild the free list: block i points at block i + 1. */
void mp_reset(mp_pool *pool) {
    uint32_t i;
    for (i = 0; i < pool->nblocks; i++) {
        uint8_t *hdr = pool->base + (size_t)i * MP_BLOCK;
        mp_store32(hdr, MP_STATE_FREE);
        mp_store32(hdr + 4, i + 1u < pool->nblocks ? i + 1u : MP_NONE);
    }
    pool->free_head = pool->nblocks > 0 ? 0 : MP_NONE;
    pool->in_use = 0;
}

/* Block index for a payload pointer, or -1 when it does not name a block of this pool. */
int32_t mp_index_of(const mp_pool *pool, const uint8_t *payload) {
    uintptr_t lo = (uintptr_t)pool->base;
    uintptr_t at = (uintptr_t)payload;
    uintptr_t off;
    if (at < lo + MP_HDR) {
        return -1;
    }
    off = at - lo - MP_HDR;
    if (off % MP_BLOCK != 0 || off / MP_BLOCK >= pool->nblocks) {
        return -1;
    }
    return (int32_t)(off / MP_BLOCK);
}

uint8_t *mp_alloc(mp_pool *pool) {
    uint32_t index = pool->free_head;
    uint8_t *hdr;
    if (index == MP_NONE) {
        return NULL;
    }
    hdr = pool->base + (size_t)index * MP_BLOCK;
    pool->free_head = mp_load32(hdr + 4);
    mp_store32(hdr, MP_STATE_USED);
    mp_store32(hdr + 4, MP_NONE);
    pool->in_use++;
    pool->allocs++;
    return hdr + MP_HDR;
}

/* True when the block behind `payload` is currently handed out. */
int mp_is_used(const uint8_t *payload) {
    return mp_load32(payload - MP_HDR) == MP_STATE_USED;
}

/* Return a block to the pool; foreign pointers and blocks that are already free are ignored. */
void mp_release(mp_pool *pool, uint8_t *payload) {
    int32_t index = mp_index_of(pool, payload);
    uint8_t *hdr;
    if (index < 0 || !mp_is_used(payload)) {
        return;
    }
    hdr = payload - MP_HDR;
    mp_store32(hdr, MP_STATE_FREE);
    mp_store32(hdr + 4, pool->free_head);
    pool->free_head = (uint32_t)index;
    pool->in_use--;
}

/* Free-list length, stopping early if the list loops. */
uint32_t mp_free_count(const mp_pool *pool) {
    uint32_t count = 0;
    uint32_t index = pool->free_head;
    while (index != MP_NONE && count <= pool->nblocks) {
        index = mp_load32(pool->base + (size_t)index * MP_BLOCK + 4);
        count++;
    }
    return count;
}

uint32_t mp_in_use(const mp_pool *pool) {
    return pool->in_use;
}

uint32_t mp_block_count(const mp_pool *pool) {
    return pool->nblocks;
}

/* Consistency check: returns 0 when counters and the free list agree, else a bit mask of problems. */
uint32_t mp_audit(const mp_pool *pool) {
    uint32_t problems = 0;
    uint32_t free_len = mp_free_count(pool);
    if (free_len > pool->nblocks) {
        problems |= 1u; /* free list is longer than the pool: a block was released twice */
    }
    if (pool->in_use > pool->nblocks) {
        problems |= 2u; /* in-use counter underflowed */
    }
    if (free_len <= pool->nblocks && free_len + pool->in_use != pool->nblocks) {
        problems |= 4u;
    }
    return problems;
}

/* ---- messages ----------------------------------------------------------- */

uint16_t msg_checksum(const uint8_t *data, uint32_t len) {
    uint32_t sum = 0;
    uint32_t i;
    for (i = 0; i < len; i++) {
        sum = ((sum << 1) | (sum >> 15)) & 0xffffu;
        sum ^= data[i];
    }
    return (uint16_t)sum;
}

/* Fill `buf` (a pool payload) with a message. On failure the buffer is released to the pool. */
int msg_encode(mp_pool *pool, uint8_t *buf, uint8_t dest, const uint8_t *data, uint32_t len) {
    uint32_t i;
    uint16_t sum;
    if (len > MSG_MAX_DATA) {
        mp_release(pool, buf);
        return MSG_ERR_SIZE;
    }
    if (dest == MSG_DEST_RESERVED) {
        mp_release(pool, buf);
        return MSG_ERR_DEST;
    }
    buf[0] = dest;
    buf[1] = 1;
    buf[2] = (uint8_t)(len & 0xffu);
    buf[3] = (uint8_t)(len >> 8);
    for (i = 0; i < len; i++) {
        buf[MSG_HDR + i] = data[i];
    }
    sum = msg_checksum(buf + MSG_HDR, len);
    buf[4] = (uint8_t)(sum & 0xffu);
    buf[5] = (uint8_t)(sum >> 8);
    return MSG_OK;
}

int msg_verify(const uint8_t *buf) {
    uint16_t len = msg_len(buf);
    uint16_t sum = (uint16_t)(buf[4] | ((uint16_t)buf[5] << 8));
    if (len > MSG_MAX_DATA) {
        return 0;
    }
    return sum == msg_checksum(buf + MSG_HDR, len);
}

uint8_t msg_dest(const uint8_t *buf) {
    return buf[0];
}

uint16_t msg_len(const uint8_t *buf) {
    return (uint16_t)(buf[2] | ((uint16_t)buf[3] << 8));
}

const uint8_t *msg_data(const uint8_t *buf) {
    return buf + MSG_HDR;
}

/* ---- queue and senders -------------------------------------------------- */

void msg_queue_init(msg_queue *q) {
    uint32_t i;
    for (i = 0; i < MSG_QUEUE_SLOTS; i++) {
        q->slots[i] = NULL;
    }
    q->head = 0;
    q->tail = 0;
    q->count = 0;
}

int msg_queue_push(msg_queue *q, uint8_t *buf) {
    if (q->count == MSG_QUEUE_SLOTS) {
        return -1;
    }
    q->slots[q->tail] = buf;
    q->tail = (q->tail + 1u) % MSG_QUEUE_SLOTS;
    q->count++;
    return 0;
}

uint8_t *msg_queue_pop(msg_queue *q) {
    uint8_t *buf;
    if (q->count == 0) {
        return NULL;
    }
    buf = q->slots[q->head];
    q->slots[q->head] = NULL;
    q->head = (q->head + 1u) % MSG_QUEUE_SLOTS;
    q->count--;
    return buf;
}

uint32_t msg_queue_count(const msg_queue *q) {
    return q->count;
}

/* Allocate, encode and queue one message. */
int msg_send(mp_pool *pool, msg_queue *q, uint8_t dest, const uint8_t *data, uint32_t len) {
    uint8_t *buf = mp_alloc(pool);
    int rc;
    if (buf == NULL) {
        return MSG_ERR_NOMEM;
    }
    rc = msg_encode(pool, buf, dest, data, len);
    if (rc != MSG_OK) {
        return rc; /* msg_encode already handed the block back */
    }
    if (msg_queue_push(q, buf) != 0) {
        mp_release(pool, buf);
        return MSG_ERR_QUEUE;
    }
    return MSG_OK;
}

/* Answer a request: the reply goes to the sender recorded in the request. */
int msg_reply(mp_pool *pool, msg_queue *q, const uint8_t *request, const uint8_t *data, uint32_t len) {
    uint8_t *buf = mp_alloc(pool);
    int rc;
    if (buf == NULL) {
        return MSG_ERR_NOMEM;
    }
    rc = msg_encode(pool, buf, request[1], data, len);
    if (rc != MSG_OK) {
        return rc;
    }
    if (msg_queue_push(q, buf) != 0) {
        mp_release(pool, buf);
        return MSG_ERR_QUEUE;
    }
    return MSG_OK;
}

/* Hand every queued message to `handler` and release its buffer. */
int msg_dispatch(mp_pool *pool, msg_queue *q, msg_handler handler, void *ctx) {
    int handled = 0;
    uint8_t *buf;
    while ((buf = msg_queue_pop(q)) != NULL) {
        if (msg_verify(buf)) {
            handler(ctx, msg_dest(buf), msg_data(buf), msg_len(buf));
            handled++;
        }
        mp_release(pool, buf);
    }
    return handled;
}
