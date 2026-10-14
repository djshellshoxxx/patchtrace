/* ringbuf.c - fixed-slot record ring over a caller-provided byte array (v2).
 *
 * Slot layout (32 bytes): [len_lo][len_hi][payload ... up to 30 bytes].
 * Records are pushed at `head` and popped from `tail`; the ring wraps modulo `slots`.
 */
#include "ringbuf.h"

/* ---- byte helpers ----------------------------------------------------- */

void rb_copy(uint8_t *dst, const uint8_t *src, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

void rb_fill(uint8_t *dst, uint8_t value, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) {
        dst[i] = value;
    }
}

uint16_t rb_load_len(const uint8_t *slot) {
    return (uint16_t)(slot[0] | ((uint16_t)slot[1] << 8));
}

void rb_store_len(uint8_t *slot, uint16_t len) {
    slot[0] = (uint8_t)(len & 0xffu);
    slot[1] = (uint8_t)(len >> 8);
}

uint8_t *rb_slot_ptr(const rb_ring *r, uint32_t index) {
    return r->base + (size_t)index * RB_SLOT_BYTES;
}

/* ---- lifecycle and queries -------------------------------------------- */

int rb_init(rb_ring *r, uint8_t *storage, uint32_t bytes) {
    if (r == NULL || storage == NULL) {
        return RB_ERR_ARG;
    }
    r->base = storage;
    r->slots = bytes / RB_SLOT_BYTES;
    r->head = 0;
    r->tail = 0;
    r->count = 0;
    r->pushed = 0;
    r->popped = 0;
    r->dropped = 0;
    if (r->slots == 0) {
        return RB_ERR_SIZE;
    }
    return RB_OK;
}

void rb_reset(rb_ring *r) {
    r->head = 0;
    r->tail = 0;
    r->count = 0;
}

uint32_t rb_capacity(const rb_ring *r) {
    return r->slots;
}

uint32_t rb_count(const rb_ring *r) {
    return r->count;
}

int rb_is_empty(const rb_ring *r) {
    return r->count == 0;
}

int rb_is_full(const rb_ring *r) {
    return r->count == r->slots;
}

/* ---- producers and consumers ------------------------------------------ */

/* Largest payload that fits in one slot. */
uint16_t rb_payload_limit(void) {
    return 30;
}

/* True when a record of `len` bytes would be accepted right now. */
int rb_can_push(const rb_ring *r, uint16_t len) {
    return len <= rb_payload_limit() && r->count != r->slots;
}

/* Append one record. Returns RB_OK, RB_ERR_FULL, RB_ERR_SIZE or RB_ERR_ARG. */
int rb_push(rb_ring *r, const uint8_t *data, uint16_t len) {
    uint8_t *slot;
    if (r == NULL || (data == NULL && len != 0)) {
        return RB_ERR_ARG;
    }
    if (len > rb_payload_limit()) {
        r->dropped++;
        return RB_ERR_SIZE;
    }
    if (r->count == r->slots) {
        r->dropped++;
        return RB_ERR_FULL;
    }
    slot = rb_slot_ptr(r, r->head);
    rb_store_len(slot, len);
    rb_copy(slot + RB_HEADER_BYTES, data, len);
    r->head = (r->head + 1u) % r->slots;
    r->count++;
    r->pushed++;
    return RB_OK;
}

/* Remove the oldest record into `out`; returns its length or a negative error. */
int rb_pop(rb_ring *r, uint8_t *out, uint16_t out_cap) {
    const uint8_t *slot;
    uint16_t len;
    if (r == NULL || out == NULL) {
        return RB_ERR_ARG;
    }
    if (r->count == 0) {
        return RB_ERR_EMPTY;
    }
    slot = rb_slot_ptr(r, r->tail);
    len = rb_load_len(slot);
    if (len > out_cap) {
        return RB_ERR_SIZE;
    }
    rb_copy(out, slot + RB_HEADER_BYTES, len);
    r->tail = (r->tail + 1u) % r->slots;
    r->count--;
    r->popped++;
    return (int)len;
}

int rb_peek_len(const rb_ring *r) {
    if (r->count == 0) {
        return RB_ERR_EMPTY;
    }
    return (int)rb_load_len(rb_slot_ptr(r, r->tail));
}

int rb_drop(rb_ring *r) {
    if (r->count == 0) {
        return RB_ERR_EMPTY;
    }
    r->tail = (r->tail + 1u) % r->slots;
    r->count--;
    r->popped++;
    return RB_OK;
}

/* Push a NUL-terminated string (terminator not stored). */
int rb_push_str(rb_ring *r, const char *text) {
    uint16_t n = 0;
    if (text == NULL) {
        return RB_ERR_ARG;
    }
    while (text[n] != '\0') {
        n++;
    }
    return rb_push(r, (const uint8_t *)text, n);
}

/* Push a 32-bit value in little-endian byte order. */
int rb_push_u32(rb_ring *r, uint32_t value) {
    uint8_t raw[4];
    raw[0] = (uint8_t)(value & 0xffu);
    raw[1] = (uint8_t)((value >> 8) & 0xffu);
    raw[2] = (uint8_t)((value >> 16) & 0xffu);
    raw[3] = (uint8_t)((value >> 24) & 0xffu);
    return rb_push(r, raw, 4);
}

/* Pop every record into `sink`; returns the number delivered. */
int rb_drain(rb_ring *r, rb_sink sink, void *ctx) {
    uint8_t tmp[RB_SLOT_BYTES];
    int delivered = 0;
    int n;
    if (r == NULL || sink == NULL) {
        return RB_ERR_ARG;
    }
    while ((n = rb_pop(r, tmp, (uint16_t)sizeof tmp)) >= 0) {
        sink(ctx, tmp, (uint16_t)n);
        delivered++;
    }
    return delivered;
}

/* ---- inspection ------------------------------------------------------- */

uint32_t rb_pending_bytes(const rb_ring *r) {
    uint32_t total = 0;
    uint32_t i;
    for (i = 0; i < r->count; i++) {
        total += rb_load_len(rb_slot_ptr(r, (r->tail + i) % r->slots));
    }
    return total;
}

/* Fletcher-16 over every stored payload byte, oldest first. */
uint16_t rb_checksum(const rb_ring *r) {
    uint32_t sum1 = 0;
    uint32_t sum2 = 0;
    uint32_t i;
    uint32_t j;
    for (i = 0; i < r->count; i++) {
        const uint8_t *slot = rb_slot_ptr(r, (r->tail + i) % r->slots);
        uint16_t len = rb_load_len(slot);
        for (j = 0; j < len; j++) {
            sum1 = (sum1 + slot[RB_HEADER_BYTES + j]) % 255u;
            sum2 = (sum2 + sum1) % 255u;
        }
    }
    return (uint16_t)((sum2 << 8) | sum1);
}

uint32_t rb_stat_pushed(const rb_ring *r) {
    return r->pushed;
}

uint32_t rb_stat_popped(const rb_ring *r) {
    return r->popped;
}

uint32_t rb_stat_dropped(const rb_ring *r) {
    return r->dropped;
}

void rb_clear_stats(rb_ring *r) {
    r->pushed = 0;
    r->popped = 0;
    r->dropped = 0;
}
