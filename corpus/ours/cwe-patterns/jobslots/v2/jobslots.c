/* jobslots.c - fixed-size job table (v2).
 *
 * A job id is the slot index plus one (0 is never a valid id). A job's callback runs inside js_run();
 * that callback, or an interrupt-like context, may call js_cancel() or js_submit() on the same table.
 */
#include "jobslots.h"

/* ---- helpers ------------------------------------------------------------ */

void js_copy(uint8_t *dst, const uint8_t *src, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

js_job *js_job_at(js_table *t, uint32_t id) {
    if (id == 0 || id > JS_SLOTS) {
        return NULL;
    }
    return &t->jobs[id - 1u];
}

uint8_t *js_payload_ptr(js_table *t, uint32_t id) {
    return t->payloads + (size_t)(id - 1u) * JS_PAYLOAD;
}

/* Return a slot to the free state. */
void js_clear_slot(js_table *t, uint32_t id) {
    js_job *job = &t->jobs[id - 1u];
    job->state = JS_FREE;
    job->flags = 0;
    job->len = 0;
    job->seq = 0;
    job->fn = NULL;
    job->ctx = NULL;
    job->result = 0;
}

/* Lowest free slot as an id, or -1. */
int js_find_free(const js_table *t) {
    uint32_t i;
    for (i = 0; i < JS_SLOTS; i++) {
        if (t->jobs[i].state == JS_FREE) {
            return (int)(i + 1u);
        }
    }
    return -1;
}

/* Id of the queued job with the smallest sequence number, or 0. */
uint32_t js_next_queued(const js_table *t) {
    uint32_t best = 0;
    uint32_t i;
    for (i = 0; i < JS_SLOTS; i++) {
        if (t->jobs[i].state == JS_QUEUED && (best == 0 || t->jobs[i].seq < t->jobs[best - 1u].seq)) {
            best = i + 1u;
        }
    }
    return best;
}

/* ---- lifecycle ---------------------------------------------------------- */

int js_init(js_table *t, uint8_t *payload_mem, uint32_t bytes) {
    uint32_t i;
    if (t == NULL || payload_mem == NULL || bytes < JS_SLOTS * JS_PAYLOAD) {
        return JS_ERR_ARG;
    }
    t->payloads = payload_mem;
    t->next_seq = 1;
    t->submitted = 0;
    t->completed = 0;
    t->cancelled = 0;
    for (i = 1; i <= JS_SLOTS; i++) {
        js_clear_slot(t, i);
    }
    return JS_OK;
}

/* Queue a job; the payload bytes are copied into the slot. Returns the job id. */
int js_submit(js_table *t, js_fn fn, void *ctx, const uint8_t *data, uint32_t len) {
    int id;
    js_job *job;
    if (fn == NULL || len > JS_PAYLOAD || (data == NULL && len != 0)) {
        return JS_ERR_ARG;
    }
    id = js_find_free(t);
    if (id < 0) {
        return JS_ERR_FULL;
    }
    job = js_job_at(t, (uint32_t)id);
    js_copy(js_payload_ptr(t, (uint32_t)id), data, len);
    job->fn = fn;
    job->ctx = ctx;
    job->len = (uint16_t)len;
    job->seq = t->next_seq++;
    job->state = JS_QUEUED;
    t->submitted++;
    return id;
}

/* True while the job's callback is executing. */
int js_is_locked(js_table *t, uint32_t id) {
    js_job *job = js_job_at(t, id);
    return job != NULL && (job->flags & JS_FLAG_LOCKED) != 0;
}

/* Run one queued job to completion. The slot is locked while the callback runs; a cancel that
 * arrives meanwhile is recorded and carried out here once the callback has returned. */
int js_run(js_table *t, uint32_t id) {
    js_job *job = js_job_at(t, id);
    int32_t result;
    if (job == NULL || job->state != JS_QUEUED) {
        return JS_ERR_STATE;
    }
    job->state = JS_RUNNING;
    job->flags |= JS_FLAG_LOCKED;
    result = job->fn(job->ctx, js_payload_ptr(t, id), job->len);
    job->flags = (uint8_t)(job->flags & ~JS_FLAG_LOCKED);
    if ((job->flags & JS_FLAG_CANCEL) != 0) {
        js_clear_slot(t, id);
        t->cancelled++;
        return JS_ERR_CANCELLED;
    }
    job->result = result;
    job->state = JS_DONE;
    t->completed++;
    return JS_OK;
}

int js_run_next(js_table *t) {
    uint32_t id = js_next_queued(t);
    if (id == 0) {
        return JS_ERR_STATE;
    }
    return js_run(t, id);
}

/* Run everything that is queued; returns the number of jobs that completed. */
int js_drain(js_table *t) {
    int done = 0;
    while (js_run_next(t) == JS_OK) {
        done++;
    }
    return done;
}

/* Abort a job. A running job cannot be freed under its runner: the request is recorded and the
 * runner releases the slot when the callback returns (JS_ERR_BUSY tells the caller it is pending). */
int js_cancel(js_table *t, uint32_t id) {
    js_job *job = js_job_at(t, id);
    if (job == NULL || job->state == JS_FREE) {
        return JS_ERR_STATE;
    }
    if (js_is_locked(t, id)) {
        job->flags |= JS_FLAG_CANCEL;
        return JS_ERR_BUSY;
    }
    js_clear_slot(t, id);
    t->cancelled++;
    return JS_OK;
}

/* Fetch the result of a finished job and free its slot. */
int js_collect(js_table *t, uint32_t id, int32_t *result) {
    js_job *job = js_job_at(t, id);
    if (job == NULL || result == NULL) {
        return JS_ERR_ARG;
    }
    if (job->state != JS_DONE) {
        return JS_ERR_STATE;
    }
    *result = job->result;
    js_clear_slot(t, id);
    return JS_OK;
}

/* Free every finished job nobody collected; returns how many. */
uint32_t js_reap(js_table *t) {
    uint32_t reaped = 0;
    uint32_t i;
    for (i = 1; i <= JS_SLOTS; i++) {
        if (t->jobs[i - 1u].state == JS_DONE) {
            js_clear_slot(t, i);
            reaped++;
        }
    }
    return reaped;
}

/* ---- inspection --------------------------------------------------------- */

uint32_t js_state(js_table *t, uint32_t id) {
    js_job *job = js_job_at(t, id);
    return job == NULL ? JS_FREE : job->state;
}

uint32_t js_pending(const js_table *t) {
    uint32_t n = 0;
    uint32_t i;
    for (i = 0; i < JS_SLOTS; i++) {
        if (t->jobs[i].state == JS_QUEUED) {
            n++;
        }
    }
    return n;
}

uint32_t js_free_slots(const js_table *t) {
    uint32_t n = 0;
    uint32_t i;
    for (i = 0; i < JS_SLOTS; i++) {
        if (t->jobs[i].state == JS_FREE) {
            n++;
        }
    }
    return n;
}

int js_is_busy(const js_table *t) {
    uint32_t i;
    for (i = 0; i < JS_SLOTS; i++) {
        if (t->jobs[i].state == JS_RUNNING) {
            return 1;
        }
    }
    return 0;
}

uint32_t js_stat_submitted(const js_table *t) {
    return t->submitted;
}

uint32_t js_stat_completed(const js_table *t) {
    return t->completed;
}

uint32_t js_stat_cancelled(const js_table *t) {
    return t->cancelled;
}
