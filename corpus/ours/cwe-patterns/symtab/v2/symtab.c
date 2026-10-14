/* symtab.c - string interner over a bump-allocated arena (v2).
 *
 * Nodes are allocated from the caller's byte array and never freed individually; sy_clear() drops
 * the whole table at once. When the arena is full an allocation fails and sy_alloc() returns NULL.
 */
#include "symtab.h"

/* ---- helpers ------------------------------------------------------------ */

/* 32-bit FNV-1a. */
uint32_t sy_hash(const char *name, uint16_t len) {
    uint32_t h = 2166136261u;
    uint16_t i;
    for (i = 0; i < len; i++) {
        h ^= (uint8_t)name[i];
        h *= 16777619u;
    }
    return h;
}

uint32_t sy_align8(uint32_t value) {
    return (value + (SY_ALIGN - 1u)) & ~(SY_ALIGN - 1u);
}

int sy_name_eq(const sy_node *node, const char *name, uint16_t len) {
    uint16_t i;
    if (node->len != len) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (node->name[i] != name[i]) {
            return 0;
        }
    }
    return 1;
}

/* ---- table -------------------------------------------------------------- */

int sy_init(sy_table *tab, void *storage, uint32_t bytes) {
    uintptr_t addr = (uintptr_t)storage;
    uint32_t adjust = (uint32_t)((SY_ALIGN - (addr & (SY_ALIGN - 1u))) & (SY_ALIGN - 1u));
    uint32_t i;
    if (tab == NULL || storage == NULL || bytes <= adjust) {
        return -1;
    }
    for (i = 0; i < SY_BUCKETS; i++) {
        tab->buckets[i] = NULL;
    }
    tab->base = (uint8_t *)storage + adjust;
    tab->cap = bytes - adjust;
    tab->used = 0;
    tab->count = 0;
    tab->next_id = 1;
    tab->lookups = 0;
    tab->failures = 0;
    return 0;
}

/* Bump-allocate `size` bytes, 8-aligned; NULL when the arena is exhausted. */
void *sy_alloc(sy_table *tab, uint32_t size) {
    uint32_t start = sy_align8(tab->used);
    if (start > tab->cap || size > tab->cap - start) {
        tab->failures++;
        return NULL;
    }
    tab->used = start + size;
    return tab->base + start;
}

/* Forget every symbol and reuse the storage from the start. */
void sy_clear(sy_table *tab) {
    uint32_t i;
    for (i = 0; i < SY_BUCKETS; i++) {
        tab->buckets[i] = NULL;
    }
    tab->used = 0;
    tab->count = 0;
    tab->next_id = 1;
}

sy_node *sy_find(sy_table *tab, const char *name, uint16_t len) {
    uint32_t h = sy_hash(name, len);
    sy_node *node;
    tab->lookups++;
    for (node = tab->buckets[h % SY_BUCKETS]; node != NULL; node = node->next) {
        if (node->hash == h && sy_name_eq(node, name, len)) {
            return node;
        }
    }
    return NULL;
}

/* True when fewer than 32 bytes of the arena are left. */
int sy_is_full(const sy_table *tab) {
    return tab->cap - tab->used < 32u;
}

/* Return the node for `name`, creating it on first use; NULL when the arena is exhausted. */
sy_node *sy_intern(sy_table *tab, const char *name, uint16_t len) {
    sy_node *node = sy_find(tab, name, len);
    uint32_t h;
    uint32_t bucket;
    uint32_t i;
    if (node != NULL) {
        return node;
    }
    node = (sy_node *)sy_alloc(tab, (uint32_t)offsetof(sy_node, name) + len + 1u);
    if (node == NULL) {
        return NULL;
    }
    h = sy_hash(name, len);
    bucket = h % SY_BUCKETS;
    node->hash = h;
    node->id = tab->next_id++;
    node->len = len;
    node->refs = 0;
    for (i = 0; i < len; i++) {
        node->name[i] = name[i];
    }
    node->name[len] = '\0';
    node->next = tab->buckets[bucket];
    tab->buckets[bucket] = node;
    tab->count++;
    return node;
}

sy_node *sy_intern_cstr(sy_table *tab, const char *text) {
    uint16_t len = 0;
    while (text[len] != '\0' && len < 0xffffu) {
        len++;
    }
    return sy_intern(tab, text, len);
}

/* ---- references and lookup by id ---------------------------------------- */

/* Take a reference on an existing symbol; returns the new count, or 0 for an unknown name. */
uint32_t sy_ref(sy_table *tab, const char *name, uint16_t len) {
    sy_node *node = sy_find(tab, name, len);
    if (node == NULL) {
        return 0;
    }
    node->refs++;
    return node->refs;
}

int sy_unref(sy_table *tab, const char *name, uint16_t len) {
    sy_node *node = sy_find(tab, name, len);
    if (node == NULL) {
        return -1;
    }
    if (node->refs > 0) {
        node->refs--;
    }
    return (int)node->refs;
}

uint32_t sy_id_of(sy_table *tab, const char *name, uint16_t len) {
    sy_node *node = sy_find(tab, name, len);
    if (node == NULL) {
        return 0;
    }
    return node->id;
}

const char *sy_name_of(const sy_table *tab, uint32_t id, uint16_t *len) {
    uint32_t b;
    const sy_node *node;
    for (b = 0; b < SY_BUCKETS; b++) {
        for (node = tab->buckets[b]; node != NULL; node = node->next) {
            if (node->id == id) {
                if (len != NULL) {
                    *len = node->len;
                }
                return node->name;
            }
        }
    }
    return NULL;
}

/* ---- inspection --------------------------------------------------------- */

uint32_t sy_count(const sy_table *tab) {
    return tab->count;
}

uint32_t sy_used(const sy_table *tab) {
    return tab->used;
}

uint32_t sy_free_bytes(const sy_table *tab) {
    return tab->cap - tab->used;
}

uint32_t sy_stat_lookups(const sy_table *tab) {
    return tab->lookups;
}

uint32_t sy_stat_failures(const sy_table *tab) {
    return tab->failures;
}

/* Write the id of every symbol (bucket order) into `out`; returns how many were written. */
uint32_t sy_dump_ids(const sy_table *tab, uint32_t *out, uint32_t cap) {
    uint32_t n = 0;
    uint32_t b;
    const sy_node *node;
    for (b = 0; b < SY_BUCKETS; b++) {
        for (node = tab->buckets[b]; node != NULL; node = node->next) {
            if (n < cap) {
                out[n++] = node->id;
            }
        }
    }
    return n;
}

uint16_t sy_longest(const sy_table *tab) {
    uint16_t best = 0;
    uint32_t b;
    const sy_node *node;
    for (b = 0; b < SY_BUCKETS; b++) {
        for (node = tab->buckets[b]; node != NULL; node = node->next) {
            if (node->len > best) {
                best = node->len;
            }
        }
    }
    return best;
}

uint32_t sy_total_refs(const sy_table *tab) {
    uint32_t total = 0;
    uint32_t b;
    const sy_node *node;
    for (b = 0; b < SY_BUCKETS; b++) {
        for (node = tab->buckets[b]; node != NULL; node = node->next) {
            total += node->refs;
        }
    }
    return total;
}

uint32_t sy_bucket_len(const sy_table *tab, uint32_t bucket) {
    uint32_t n = 0;
    const sy_node *node;
    if (bucket >= SY_BUCKETS) {
        return 0;
    }
    for (node = tab->buckets[bucket]; node != NULL; node = node->next) {
        n++;
    }
    return n;
}
