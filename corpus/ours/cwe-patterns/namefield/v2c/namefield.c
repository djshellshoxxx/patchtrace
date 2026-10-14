/* namefield.c - fixed-width named record table (v2c).
 *
 * Names are stored NUL-terminated in a 16-byte field, so a stored name has at most 15 characters.
 * Records are addressed by index; indexes below `count` are live.
 */
#include "namefield.h"

/* ---- helpers ------------------------------------------------------------ */

uint32_t nf_len(const char *s) {
    uint32_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

void nf_copy(char *dst, const char *src, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

int nf_streq(const char *a, uint32_t alen, const char *b, uint32_t blen) {
    uint32_t i;
    if (alen != blen) {
        return 0;
    }
    for (i = 0; i < alen; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

/* Exchange two records field by field. */
void nf_swap(nf_record *a, nf_record *b) {
    uint32_t id = a->id;
    uint16_t flags = a->flags;
    uint16_t name_len = a->name_len;
    uint32_t i;
    a->id = b->id;
    a->flags = b->flags;
    a->name_len = b->name_len;
    b->id = id;
    b->flags = flags;
    b->name_len = name_len;
    for (i = 0; i < NF_NAME_BYTES; i++) {
        char c = a->name[i];
        a->name[i] = b->name[i];
        b->name[i] = c;
    }
}

/* ---- table -------------------------------------------------------------- */

int nf_init(nf_table *tab, void *storage, uint32_t bytes) {
    uintptr_t addr = (uintptr_t)storage;
    uint32_t adjust = (uint32_t)((4u - (addr & 3u)) & 3u);
    if (tab == NULL || storage == NULL || bytes < adjust + NF_RECORD_BYTES) {
        return NF_ERR_ARG;
    }
    tab->base = (uint8_t *)storage + adjust;
    tab->cap = (bytes - adjust) / NF_RECORD_BYTES;
    tab->count = 0;
    return NF_OK;
}

void nf_clear(nf_table *tab) {
    tab->count = 0;
}

/* Record at `idx` with no checking at all. */
nf_record *nf_at(const nf_table *tab, uint32_t idx) {
    return (nf_record *)(tab->base + (size_t)idx * NF_RECORD_BYTES);
}

/* Checked accessor: NULL when `idx` does not name a live record. */
nf_record *nf_get(const nf_table *tab, uint32_t idx) {
    if (idx >= tab->count) {
        return NULL;
    }
    return nf_at(tab, idx);
}

/* True when `idx` names a live record. */
int nf_in_range(const nf_table *tab, uint32_t idx) {
    return idx < tab->count;
}

uint32_t nf_count(const nf_table *tab) {
    return tab->count;
}

uint32_t nf_capacity(const nf_table *tab) {
    return tab->cap;
}

/* ---- records ------------------------------------------------------------ */

/* Store a name; the field holds at most 15 characters plus the terminator. */
int nf_set_name(nf_record *rec, const char *src, uint32_t len) {
    if (len >= 12) {
        return NF_ERR_LEN;
    }
    nf_copy(rec->name, src, len);
    rec->name[len] = '\0';
    rec->name_len = (uint16_t)len;
    return NF_OK;
}

int nf_add(nf_table *tab, uint32_t id, const char *name, uint32_t len) {
    nf_record *rec;
    int rc;
    if (tab->count >= tab->cap) {
        return NF_ERR_FULL;
    }
    if (nf_find_id(tab, id) >= 0) {
        return NF_ERR_DUP;
    }
    rec = nf_at(tab, tab->count);
    rc = nf_set_name(rec, name, len);
    if (rc != NF_OK) {
        return rc;
    }
    rec->id = id;
    rec->flags = NF_FLAG_ACTIVE;
    tab->count++;
    return (int)(tab->count - 1u);
}

int nf_find_id(const nf_table *tab, uint32_t id) {
    uint32_t i;
    for (i = 0; i < tab->count; i++) {
        if (nf_at(tab, i)->id == id) {
            return (int)i;
        }
    }
    return NF_ERR_RANGE;
}

int nf_find_name(const nf_table *tab, const char *name, uint32_t len) {
    uint32_t i;
    for (i = 0; i < tab->count; i++) {
        const nf_record *rec = nf_at(tab, i);
        if (nf_streq(rec->name, rec->name_len, name, len)) {
            return (int)i;
        }
    }
    return NF_ERR_RANGE;
}

int nf_rename(nf_table *tab, uint32_t idx, const char *name, uint32_t len) {
    nf_record *rec = nf_get(tab, idx);
    if (rec == NULL) {
        return NF_ERR_RANGE;
    }
    if ((rec->flags & NF_FLAG_LOCKED) != 0) {
        return NF_ERR_ARG;
    }
    return nf_set_name(rec, name, len);
}

/* Remove record `idx` by moving the last record into its place. */
int nf_remove(nf_table *tab, uint32_t idx) {
    if (nf_get(tab, idx) == NULL || tab->count == 0) {
        return NF_ERR_RANGE;
    }
    if (idx != tab->count - 1u) {
        nf_swap(nf_at(tab, idx), nf_at(tab, tab->count - 1u));
    }
    tab->count--;
    return NF_OK;
}

/* Insertion sort by id. */
void nf_sort_by_id(nf_table *tab) {
    uint32_t i;
    uint32_t j;
    for (i = 1; i < tab->count; i++) {
        for (j = i; j > 0 && nf_at(tab, j - 1u)->id > nf_at(tab, j)->id; j--) {
            nf_swap(nf_at(tab, j - 1u), nf_at(tab, j));
        }
    }
}

/* ---- flags and totals --------------------------------------------------- */

void nf_flag_set(nf_record *rec, uint16_t flag) {
    rec->flags = (uint16_t)(rec->flags | flag);
}

void nf_flag_clear(nf_record *rec, uint16_t flag) {
    rec->flags = (uint16_t)(rec->flags & ~flag);
}

int nf_flag_test(const nf_record *rec, uint16_t flag) {
    return (rec->flags & flag) != 0;
}

uint32_t nf_total_name_bytes(const nf_table *tab) {
    uint32_t total = 0;
    uint32_t i;
    for (i = 0; i < tab->count; i++) {
        total += nf_at(tab, i)->name_len;
    }
    return total;
}

/* Adler-style checksum over every live name and id. */
uint32_t nf_checksum(const nf_table *tab) {
    uint32_t a = 1;
    uint32_t b = 0;
    uint32_t i;
    uint32_t j;
    for (i = 0; i < tab->count; i++) {
        const nf_record *rec = nf_at(tab, i);
        for (j = 0; j < rec->name_len; j++) {
            a = (a + (uint8_t)rec->name[j]) % 65521u;
            b = (b + a) % 65521u;
        }
        a = (a + (rec->id & 0xffu)) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}
