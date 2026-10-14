/* PatchTrace known-answer corpus: identity-negatives/lookalike, version 1. MIT licence.
 * Freestanding C11, no libc.
 *
 * Scheduler support routines. Sorting, searching and priority-queue code comes in
 * ascending/descending (min-heap/max-heap) pairs built from one template, so the two halves
 * of a pair have the same control flow graph and differ in a single comparison direction.
 * The token-bucket refills for three subsystems share one shape and differ in two constants.
 */
#ifndef LOOKALIKE_H
#define LOOKALIKE_H

#include <stddef.h>
#include <stdint.h>

#define PQ_OK 0
#define PQ_E_NULL (-1)
#define PQ_E_FULL (-2)
#define PQ_E_EMPTY (-3)

struct pq_item {
    uint32_t key;
    uint32_t val;
};

struct pq {
    struct pq_item *a;
    uint32_t n;
    uint32_t cap;
};

struct bucket {
    uint32_t tokens;
    uint32_t last_tick;
};

/* Insertion sort, lower-bound search and order check on u32 arrays. */
void isort_asc(uint32_t *a, uint32_t n);
void isort_desc(uint32_t *a, uint32_t n);
uint32_t lbound_asc(const uint32_t *a, uint32_t n, uint32_t key);
uint32_t lbound_desc(const uint32_t *a, uint32_t n, uint32_t key);
int32_t sorted_asc(const uint32_t *a, uint32_t n);
int32_t sorted_desc(const uint32_t *a, uint32_t n);

/* Binary heap of (key, value) pairs, in a min flavour and a max flavour. */
void pq_init(struct pq *q, struct pq_item *storage, uint32_t cap);
void pq_siftup_min(struct pq_item *a, uint32_t i);
void pq_siftup_max(struct pq_item *a, uint32_t i);
void pq_siftdown_min(struct pq_item *a, uint32_t n, uint32_t i);
void pq_siftdown_max(struct pq_item *a, uint32_t n, uint32_t i);
int32_t pq_push_min(struct pq *q, uint32_t key, uint32_t val);
int32_t pq_push_max(struct pq *q, uint32_t key, uint32_t val);
int32_t pq_pop_min(struct pq *q, struct pq_item *out);
int32_t pq_pop_max(struct pq *q, struct pq_item *out);

/* Token buckets: refill from elapsed ticks, saturating at the bucket size. */
uint32_t tb_refill_net(struct bucket *b, uint32_t now);
uint32_t tb_refill_disk(struct bucket *b, uint32_t now);
uint32_t tb_refill_api(struct bucket *b, uint32_t now);

#endif
