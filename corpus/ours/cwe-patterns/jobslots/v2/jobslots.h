/* jobslots.h - fixed-size job table with run / cancel / collect, payloads in a caller-provided byte array.
 *
 * Jobs are submitted, run by whoever drives the table, and their result is collected afterwards.
 * Callbacks and interrupt-like contexts may call back into the table while a job is running.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef JOBSLOTS_H
#define JOBSLOTS_H

#include <stddef.h>
#include <stdint.h>

#define JS_SLOTS 8u
#define JS_PAYLOAD 32u

#define JS_FREE 0u
#define JS_QUEUED 1u
#define JS_RUNNING 2u
#define JS_DONE 3u

#define JS_FLAG_LOCKED 1u
#define JS_FLAG_CANCEL 2u

#define JS_OK 0
#define JS_ERR_ARG (-1)
#define JS_ERR_FULL (-2)
#define JS_ERR_STATE (-3)
#define JS_ERR_BUSY (-4)
#define JS_ERR_CANCELLED (-5)

typedef int32_t (*js_fn)(void *ctx, uint8_t *payload, uint16_t len);

typedef struct js_job {
    uint8_t state;
    uint8_t flags;
    uint16_t len;
    uint32_t seq;
    js_fn fn;
    void *ctx;
    int32_t result;
} js_job;

typedef struct js_table {
    js_job jobs[JS_SLOTS];
    uint8_t *payloads; /* JS_SLOTS * JS_PAYLOAD bytes, caller-provided */
    uint32_t next_seq;
    uint32_t submitted;
    uint32_t completed;
    uint32_t cancelled;
} js_table;

/* helpers */
void js_copy(uint8_t *dst, const uint8_t *src, uint32_t n);
js_job *js_job_at(js_table *t, uint32_t id);
uint8_t *js_payload_ptr(js_table *t, uint32_t id);
void js_clear_slot(js_table *t, uint32_t id);
int js_find_free(const js_table *t);
uint32_t js_next_queued(const js_table *t);

/* lifecycle */
int js_init(js_table *t, uint8_t *payload_mem, uint32_t bytes);
int js_submit(js_table *t, js_fn fn, void *ctx, const uint8_t *data, uint32_t len);
int js_is_locked(js_table *t, uint32_t id);
int js_run(js_table *t, uint32_t id);
int js_run_next(js_table *t);
int js_drain(js_table *t);
int js_cancel(js_table *t, uint32_t id);
int js_collect(js_table *t, uint32_t id, int32_t *result);
uint32_t js_reap(js_table *t);

/* inspection */
uint32_t js_state(js_table *t, uint32_t id);
uint32_t js_pending(const js_table *t);
uint32_t js_free_slots(const js_table *t);
int js_is_busy(const js_table *t);
uint32_t js_stat_submitted(const js_table *t);
uint32_t js_stat_completed(const js_table *t);
uint32_t js_stat_cancelled(const js_table *t);

#endif /* JOBSLOTS_H */
