/* msgpool.h - fixed-block message buffer pool and a tiny send/dispatch layer, over caller-provided bytes.
 *
 * Block layout (64 bytes): [state:4][next_free:4][payload: 56 bytes]. Callers only see payload pointers.
 * Message layout inside a payload: [dest:1][src:1][len:2][checksum:2][data: up to 50 bytes].
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef MSGPOOL_H
#define MSGPOOL_H

#include <stddef.h>
#include <stdint.h>

#define MP_BLOCK 64u
#define MP_HDR 8u
#define MP_PAYLOAD (MP_BLOCK - MP_HDR)
#define MP_NONE 0xffffffffu
#define MP_STATE_FREE 0xf4ee0001u
#define MP_STATE_USED 0xa110c8edu

#define MSG_HDR 6u
#define MSG_MAX_DATA (MP_PAYLOAD - MSG_HDR)
#define MSG_DEST_RESERVED 0xffu
#define MSG_QUEUE_SLOTS 8u

#define MSG_OK 0
#define MSG_ERR_NOMEM (-1)
#define MSG_ERR_SIZE (-2)
#define MSG_ERR_DEST (-3)
#define MSG_ERR_QUEUE (-4)

typedef struct mp_pool {
    uint8_t *base;      /* caller-provided storage */
    uint32_t nblocks;   /* whole blocks that fit */
    uint32_t free_head; /* index of the first free block or MP_NONE */
    uint32_t in_use;    /* blocks handed out */
    uint32_t allocs;
} mp_pool;

typedef struct msg_queue {
    uint8_t *slots[MSG_QUEUE_SLOTS];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} msg_queue;

typedef void (*msg_handler)(void *ctx, uint8_t dest, const uint8_t *data, uint16_t len);

/* byte helpers */
uint32_t mp_load32(const uint8_t *p);
void mp_store32(uint8_t *p, uint32_t v);

/* pool */
int mp_init(mp_pool *pool, uint8_t *storage, uint32_t bytes);
void mp_reset(mp_pool *pool);
int32_t mp_index_of(const mp_pool *pool, const uint8_t *payload);
uint8_t *mp_alloc(mp_pool *pool);
void mp_release(mp_pool *pool, uint8_t *payload);
uint32_t mp_free_count(const mp_pool *pool);
uint32_t mp_in_use(const mp_pool *pool);
uint32_t mp_block_count(const mp_pool *pool);
uint32_t mp_audit(const mp_pool *pool);

/* messages */
uint16_t msg_checksum(const uint8_t *data, uint32_t len);
int msg_encode(mp_pool *pool, uint8_t *buf, uint8_t dest, const uint8_t *data, uint32_t len);
int msg_verify(const uint8_t *buf);
uint8_t msg_dest(const uint8_t *buf);
uint16_t msg_len(const uint8_t *buf);
const uint8_t *msg_data(const uint8_t *buf);
void msg_free(mp_pool *pool, uint8_t *buf);

/* queue and senders */
void msg_queue_init(msg_queue *q);
int msg_queue_push(msg_queue *q, uint8_t *buf);
uint8_t *msg_queue_pop(msg_queue *q);
uint32_t msg_queue_count(const msg_queue *q);
int msg_send(mp_pool *pool, msg_queue *q, uint8_t dest, const uint8_t *data, uint32_t len);
int msg_reply(mp_pool *pool, msg_queue *q, const uint8_t *request, const uint8_t *data, uint32_t len);
int msg_dispatch(mp_pool *pool, msg_queue *q, msg_handler handler, void *ctx);

#endif /* MSGPOOL_H */
