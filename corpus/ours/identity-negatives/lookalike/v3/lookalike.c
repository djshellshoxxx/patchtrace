/* PatchTrace known-answer corpus: identity-negatives/lookalike, version 3. MIT licence.
 * Every asc/desc and min/max pair below is one template instantiated twice.
 */
#include "lookalike.h"

void isort_asc(uint32_t *a, uint32_t n) {
    uint32_t i, j;

    for (i = 1u; i < n; i++) {
        uint32_t v = a[i];

        for (j = i; j > 0u && a[j - 1u] > v; j--) {
            a[j] = a[j - 1u];
        }
        a[j] = v;
    }
}

void isort_desc(uint32_t *a, uint32_t n) {
    uint32_t i, j;

    for (i = 1u; i < n; i++) {
        uint32_t v = a[i];

        for (j = i; j > 0u && a[j - 1u] < v; j--) {
            a[j] = a[j - 1u];
        }
        a[j] = v;
    }
}

/* First index whose element is not strictly before key in the array's order. */
uint32_t lbound_asc(const uint32_t *a, uint32_t n, uint32_t key) {
    uint32_t lo = 0u;
    uint32_t hi = n;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;

        if (a[mid] < key) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo;
}

uint32_t lbound_desc(const uint32_t *a, uint32_t n, uint32_t key) {
    uint32_t lo = 0u;
    uint32_t hi = n;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;

        if (a[mid] >= key) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo;
}

int32_t sorted_asc(const uint32_t *a, uint32_t n) {
    uint32_t i;

    for (i = 1u; i < n; i++) {
        if (a[i - 1u] > a[i]) {
            return 0;
        }
    }
    return 1;
}

int32_t sorted_desc(const uint32_t *a, uint32_t n) {
    uint32_t i;

    for (i = 1u; i < n; i++) {
        if (a[i - 1u] < a[i]) {
            return 0;
        }
    }
    return 1;
}

void pq_init(struct pq *q, struct pq_item *storage, uint32_t cap) {
    q->a = storage;
    q->n = 0u;
    q->cap = cap;
}

void pq_siftup_min(struct pq_item *a, uint32_t i) {
    struct pq_item it = a[i];

    while (i > 0u) {
        uint32_t parent = (i - 1u) / 2u;

        if (!(it.key < a[parent].key)) {
            break;
        }
        a[i] = a[parent];
        i = parent;
    }
    a[i] = it;
}

void pq_siftup_max(struct pq_item *a, uint32_t i) {
    struct pq_item it = a[i];

    while (i > 0u) {
        uint32_t parent = (i - 1u) / 2u;

        if (!(it.key > a[parent].key)) {
            break;
        }
        a[i] = a[parent];
        i = parent;
    }
    a[i] = it;
}

void pq_siftdown_min(struct pq_item *a, uint32_t n, uint32_t i) {
    struct pq_item it = a[i];

    for (;;) {
        uint32_t c = 2u * i + 1u;

        if (c >= n) {
            break;
        }
        if (c + 1u < n && a[c + 1u].key < a[c].key) {
            c++;
        }
        if (!(a[c].key < it.key)) {
            break;
        }
        a[i] = a[c];
        i = c;
    }
    a[i] = it;
}

void pq_siftdown_max(struct pq_item *a, uint32_t n, uint32_t i) {
    struct pq_item it = a[i];

    for (;;) {
        uint32_t c = 2u * i + 1u;

        if (c >= n) {
            break;
        }
        if (c + 1u < n && a[c + 1u].key > a[c].key) {
            c++;
        }
        if (!(a[c].key > it.key)) {
            break;
        }
        a[i] = a[c];
        i = c;
    }
    a[i] = it;
}

int32_t pq_push_min(struct pq *q, uint32_t key, uint32_t val) {
    if (q == NULL || q->a == NULL) {
        return PQ_E_NULL;
    }
    if (q->n >= q->cap) {
        return PQ_E_FULL;
    }
    q->a[q->n].key = key;
    q->a[q->n].val = val;
    pq_siftup_min(q->a, q->n);
    q->n++;
    return PQ_OK;
}

int32_t pq_push_max(struct pq *q, uint32_t key, uint32_t val) {
    if (q == NULL || q->a == NULL) {
        return PQ_E_NULL;
    }
    if (q->n >= q->cap) {
        return PQ_E_FULL;
    }
    q->a[q->n].key = key;
    q->a[q->n].val = val;
    pq_siftup_max(q->a, q->n);
    q->n++;
    return PQ_OK;
}

int32_t pq_pop_min(struct pq *q, struct pq_item *out) {
    if (q == NULL || q->a == NULL || out == NULL) {
        return PQ_E_NULL;
    }
    if (q->n == 0u) {
        return PQ_E_EMPTY;
    }
    *out = q->a[0];
    q->n--;
    if (q->n > 0u) {
        q->a[0] = q->a[q->n];
        pq_siftdown_min(q->a, q->n, 0u);
    }
    return PQ_OK;
}

int32_t pq_pop_max(struct pq *q, struct pq_item *out) {
    if (q == NULL || q->a == NULL || out == NULL) {
        return PQ_E_NULL;
    }
    if (q->n == 0u) {
        return PQ_E_EMPTY;
    }
    *out = q->a[0];
    q->n--;
    if (q->n > 0u) {
        q->a[0] = q->a[q->n];
        pq_siftdown_max(q->a, q->n, 0u);
    }
    return PQ_OK;
}

/* Network: 8 tokens per tick, bucket of 256. */
uint32_t tb_refill_net(struct bucket *b, uint32_t now) {
    const uint32_t shift = 3u;
    const uint32_t cap = 256u;
    uint32_t elapsed = now - b->last_tick;

    if (elapsed == 0u) {
        return b->tokens;
    }
    b->last_tick = now;
    if (elapsed > (cap >> shift) || (elapsed << shift) > cap - b->tokens) {
        b->tokens = cap;
    } else {
        b->tokens += elapsed << shift;
    }
    return b->tokens;
}

/* Disk: 2 tokens per tick, bucket of 64. */
uint32_t tb_refill_disk(struct bucket *b, uint32_t now) {
    const uint32_t shift = 1u;
    const uint32_t cap = 96u;
    uint32_t elapsed = now - b->last_tick;

    if (elapsed == 0u) {
        return b->tokens;
    }
    b->last_tick = now;
    if (elapsed > (cap >> shift) || (elapsed << shift) > cap - b->tokens) {
        b->tokens = cap;
    } else {
        b->tokens += elapsed << shift;
    }
    return b->tokens;
}

/* API calls: 32 tokens per tick, bucket of 1024. */
uint32_t tb_refill_api(struct bucket *b, uint32_t now) {
    const uint32_t shift = 5u;
    const uint32_t cap = 1024u;
    uint32_t elapsed = now - b->last_tick;

    if (elapsed == 0u) {
        return b->tokens;
    }
    b->last_tick = now;
    if (elapsed > (cap >> shift) || (elapsed << shift) > cap - b->tokens) {
        b->tokens = cap;
    } else {
        b->tokens += elapsed << shift;
    }
    return b->tokens;
}
