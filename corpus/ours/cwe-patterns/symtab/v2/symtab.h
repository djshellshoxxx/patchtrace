/* symtab.h - string interner with chained hash buckets; every node is carved from a caller-provided
 * byte array by a tiny bump allocator, so the table never allocates anywhere else.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef SYMTAB_H
#define SYMTAB_H

#include <stddef.h>
#include <stdint.h>

#define SY_BUCKETS 16u
#define SY_ALIGN 8u

typedef struct sy_node {
    struct sy_node *next;
    uint32_t hash;
    uint32_t id;
    uint16_t len;
    uint16_t refs;
    char name[];
} sy_node;

typedef struct sy_table {
    sy_node *buckets[SY_BUCKETS];
    uint8_t *base;     /* aligned start of the caller's storage */
    uint32_t cap;      /* usable bytes */
    uint32_t used;     /* bump offset */
    uint32_t count;    /* interned symbols */
    uint32_t next_id;  /* ids start at 1 */
    uint32_t lookups;
    uint32_t failures; /* allocation attempts that did not fit */
} sy_table;

/* helpers */
uint32_t sy_hash(const char *name, uint16_t len);
uint32_t sy_align8(uint32_t value);
int sy_name_eq(const sy_node *node, const char *name, uint16_t len);

/* table */
int sy_init(sy_table *tab, void *storage, uint32_t bytes);
void *sy_alloc(sy_table *tab, uint32_t size);
void sy_clear(sy_table *tab);
sy_node *sy_find(sy_table *tab, const char *name, uint16_t len);
int sy_is_full(const sy_table *tab);
sy_node *sy_intern(sy_table *tab, const char *name, uint16_t len);
sy_node *sy_intern_cstr(sy_table *tab, const char *text);

/* references and lookup by id */
uint32_t sy_ref(sy_table *tab, const char *name, uint16_t len);
int sy_unref(sy_table *tab, const char *name, uint16_t len);
uint32_t sy_id_of(sy_table *tab, const char *name, uint16_t len);
const char *sy_name_of(const sy_table *tab, uint32_t id, uint16_t *len);

/* inspection */
uint32_t sy_count(const sy_table *tab);
uint32_t sy_used(const sy_table *tab);
uint32_t sy_free_bytes(const sy_table *tab);
uint32_t sy_stat_lookups(const sy_table *tab);
uint32_t sy_stat_failures(const sy_table *tab);
uint32_t sy_dump_ids(const sy_table *tab, uint32_t *out, uint32_t cap);
uint16_t sy_longest(const sy_table *tab);
uint32_t sy_total_refs(const sy_table *tab);
uint32_t sy_bucket_len(const sy_table *tab, uint32_t bucket);

#endif /* SYMTAB_H */
