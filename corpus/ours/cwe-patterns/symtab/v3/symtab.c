/* symtab.c - string interner over a bump-allocated arena (v3).
 *
 * Nodes are allocated from the caller's byte array and never freed individually; sy_clear() drops
 * the whole table at once. When the arena is full an allocation fails and sy_alloc() returns NULL.
 */
#include "symtab.h"

/* ---- helpers ------------------------------------------------------------ */

/* 32-bit FNV-1a. */
uint32_t sy_hash(const char *name, uint16_t len) {
    uint32_t h = 2166136261u;
    uint16_t i = 0;
    while (i < len) {
        h ^= (uint8_t)name[i];
        h *= 16777619u;
        i++;
    }
    return h;
}

uint32_t sy_align8(uint32_t value) {
    uint32_t mask = SY_ALIGN - 1u;
    return (value + mask) & ~mask;
}

int sy_name_eq(const sy_node *node, const char *name, uint16_t len) {
    uint16_t k;
    if (node->len != len) {
        return 0;
    }
    for (k = 0; k < len; k++) {
        if (node->name[k] != name[k]) {
            return 0;
        }
    }
    return 1;
}

/* ---- table -------------------------------------------------------------- */

int sy_init(sy_table *tab, void *storage, uint32_t bytes) {
    uintptr_t addr = (uintptr_t)storage;
    uint32_t adjust = (uint32_t)((SY_ALIGN - (addr & (SY_ALIGN - 1u))) & (SY_ALIGN - 1u));
    uint32_t i = 0;
    if (tab == NULL || storage == NULL || bytes <= adjust) {
        return -1;
    }
    tab->failures = 0;
    tab->lookups = 0;
    tab->next_id = 1;
    tab->count = 0;
    tab->used = 0;
    tab->cap = bytes - adjust;
    tab->base = (uint8_t *)storage + adjust;
    while (i < SY_BUCKETS) {
        tab->buckets[i] = NULL;
        i++;
    }
    return 0;
}

/* Bump-allocate `size` bytes, 8-aligned; NULL when the arena is exhausted. */
void *sy_alloc(sy_table *tab, uint32_t size) {
    uint32_t offset = sy_align8(tab->used);
    if (offset > tab->cap || size > tab->cap - offset) {
        tab->failures++;
        return NULL;
    }
    tab->used = offset + size;
    return tab->base + offset;
}

/* Forget every symbol and reuse the storage from the start. */
void sy_clear(sy_table *tab) {
    uint32_t i = 0;
    tab->next_id = 1;
    tab->count = 0;
    tab->used = 0;
    while (i < SY_BUCKETS) {
        tab->buckets[i] = NULL;
        i++;
    }
}

sy_node *sy_find(sy_table *tab, const char *name, uint16_t len) {
    uint32_t h = sy_hash(name, len);
    sy_node *node = tab->buckets[h % SY_BUCKETS];
    tab->lookups++;
    while (node != NULL) {
        if (node->hash == h && sy_name_eq(node, name, len)) {
            return node;
        }
        node = node->next;
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
    node->refs = 0;
    node->len = len;
    node->id = tab->next_id++;
    node->hash = h;
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
    uint16_t len;
    for (len = 0; text[len] != '\0' && len < 0xffffu; len++) {
        /* measure */
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
    if (node->refs != 0) {
        node->refs--;
    }
    return (int)node->refs;
}

uint32_t sy_id_of(sy_table *tab, const char *name, uint16_t len) {
    sy_node *node = sy_find(tab, name, len);
    return node == NULL ? 0 : node->id;
}

const char *sy_name_of(const sy_table *tab, uint32_t id, uint16_t *len) {
    uint32_t bucket;
    const sy_node *cur;
    for (bucket = 0; bucket < SY_BUCKETS; bucket++) {
        for (cur = tab->buckets[bucket]; cur != NULL; cur = cur->next) {
            if (cur->id == id) {
                if (len != NULL) {
                    *len = cur->len;
                }
                return cur->name;
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
    uint32_t sum = 0;
    uint32_t b;
    const sy_node *node;
    for (b = 0; b < SY_BUCKETS; b++) {
        for (node = tab->buckets[b]; node != NULL; node = node->next) {
            sum += node->refs;
        }
    }
    return sum;
}

uint32_t sy_bucket_len(const sy_table *tab, uint32_t bucket) {
    uint32_t n = 0;
    const sy_node *node;
    if (bucket >= SY_BUCKETS) {
        return 0;
    }
    node = tab->buckets[bucket];
    while (node != NULL) {
        n++;
        node = node->next;
    }
    return n;
}
