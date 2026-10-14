/* namefield.h - table of fixed-width named records stored in a caller-provided byte array.
 *
 * Each record is 24 bytes: id, flags, the stored name length, and a 16-byte NUL-terminated name field
 * at the end of the record. The table keeps records packed: removal moves the last record into the hole.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef NAMEFIELD_H
#define NAMEFIELD_H

#include <stddef.h>
#include <stdint.h>

#define NF_NAME_BYTES 16u
#define NF_RECORD_BYTES 24u

#define NF_OK 0
#define NF_ERR_ARG (-1)
#define NF_ERR_LEN (-2)
#define NF_ERR_FULL (-3)
#define NF_ERR_RANGE (-4)
#define NF_ERR_DUP (-5)

#define NF_FLAG_ACTIVE 1u
#define NF_FLAG_LOCKED 2u
#define NF_FLAG_HIDDEN 4u

typedef struct nf_record {
    uint32_t id;
    uint16_t flags;
    uint16_t name_len;
    char name[NF_NAME_BYTES];
} nf_record;

typedef struct nf_table {
    uint8_t *base; /* 4-aligned start of the caller's storage */
    uint32_t cap;  /* records that fit */
    uint32_t count;
} nf_table;

/* helpers */
uint32_t nf_len(const char *s);
void nf_copy(char *dst, const char *src, uint32_t n);
int nf_streq(const char *a, uint32_t alen, const char *b, uint32_t blen);
void nf_swap(nf_record *a, nf_record *b);

/* table */
int nf_init(nf_table *tab, void *storage, uint32_t bytes);
void nf_clear(nf_table *tab);
nf_record *nf_at(const nf_table *tab, uint32_t idx);
nf_record *nf_get(const nf_table *tab, uint32_t idx);
nf_record *nf_last(const nf_table *tab);
uint32_t nf_count(const nf_table *tab);
uint32_t nf_capacity(const nf_table *tab);

/* records */
int nf_set_name(nf_record *rec, const char *src, uint32_t len);
int nf_add(nf_table *tab, uint32_t id, const char *name, uint32_t len);
int nf_find_id(const nf_table *tab, uint32_t id);
int nf_find_name(const nf_table *tab, const char *name, uint32_t len);
int nf_rename(nf_table *tab, uint32_t idx, const char *name, uint32_t len);
int nf_remove(nf_table *tab, uint32_t idx);
void nf_sort_by_id(nf_table *tab);

/* flags and totals */
void nf_flag_set(nf_record *rec, uint16_t flag);
void nf_flag_clear(nf_record *rec, uint16_t flag);
int nf_flag_test(const nf_record *rec, uint16_t flag);
uint32_t nf_total_name_bytes(const nf_table *tab);
uint32_t nf_checksum(const nf_table *tab);

#endif /* NAMEFIELD_H */
