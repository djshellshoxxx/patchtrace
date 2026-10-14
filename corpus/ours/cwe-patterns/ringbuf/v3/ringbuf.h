/* ringbuf.h - fixed-slot record ring over a caller-provided byte array.
 *
 * The ring never allocates: the caller hands in a byte array and the ring carves it into
 * 32-byte slots. Each slot holds a 2-byte little-endian length followed by the payload.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef RINGBUF_H
#define RINGBUF_H

#include <stddef.h>
#include <stdint.h>

#define RB_SLOT_BYTES 32u
#define RB_HEADER_BYTES 2u

#define RB_OK 0
#define RB_ERR_ARG (-1)
#define RB_ERR_FULL (-2)
#define RB_ERR_EMPTY (-3)
#define RB_ERR_SIZE (-4)

typedef struct rb_ring {
    uint8_t *base;   /* caller-provided storage */
    uint32_t slots;  /* whole slots that fit in the storage */
    uint32_t head;   /* next slot to write */
    uint32_t tail;   /* next slot to read */
    uint32_t count;  /* occupied slots */
    uint32_t pushed; /* lifetime counters */
    uint32_t popped;
    uint32_t dropped;
} rb_ring;

typedef void (*rb_sink)(void *ctx, const uint8_t *data, uint16_t len);

/* byte helpers */
void rb_copy(uint8_t *dst, const uint8_t *src, uint32_t n);
void rb_fill(uint8_t *dst, uint8_t value, uint32_t n);
uint16_t rb_load_len(const uint8_t *slot);
void rb_store_len(uint8_t *slot, uint16_t len);
uint8_t *rb_slot_ptr(const rb_ring *r, uint32_t index);

/* lifecycle and queries */
int rb_init(rb_ring *r, uint8_t *storage, uint32_t bytes);
void rb_reset(rb_ring *r);
uint32_t rb_capacity(const rb_ring *r);
uint32_t rb_count(const rb_ring *r);
int rb_is_empty(const rb_ring *r);
int rb_is_full(const rb_ring *r);

/* producers and consumers */
uint16_t rb_payload_limit(void);
int rb_can_push(const rb_ring *r, uint16_t len);
int rb_push(rb_ring *r, const uint8_t *data, uint16_t len);
int rb_pop(rb_ring *r, uint8_t *out, uint16_t out_cap);
int rb_peek_len(const rb_ring *r);
int rb_drop(rb_ring *r);
int rb_push_str(rb_ring *r, const char *text);
int rb_push_u32(rb_ring *r, uint32_t value);
int rb_drain(rb_ring *r, rb_sink sink, void *ctx);

/* inspection */
uint32_t rb_pending_bytes(const rb_ring *r);
uint16_t rb_checksum(const rb_ring *r);
uint32_t rb_stat_pushed(const rb_ring *r);
uint32_t rb_stat_popped(const rb_ring *r);
uint32_t rb_stat_dropped(const rb_ring *r);
void rb_clear_stats(rb_ring *r);

#endif /* RINGBUF_H */
