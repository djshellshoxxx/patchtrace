/* namefield.c - fixed-width named record table (v3).
 *
 * Names are stored NUL-terminated in a 16-byte field, so a stored name has at most 15 characters.
 * Records are addressed by index; indexes below `count` are live.
 */
#include "namefield.h"

/* ---- helpers ------------------------------------------------------------ */

uint32_t nf_len(const char *s) {
    const char *p = s;
    while (*p != '\0') {
        p++;
    }
    return (uint32_t)(p - s);
}

void nf_copy(char *dst, const char *src, uint32_t n) {
    while (n > 0) {
        *dst++ = *src++;
        n--;
    }
}

int nf_streq(const char *a, uint32_t alen, const char *b, uint32_t blen) {
    uint32_t k;
    if (alen != blen) {
        return 0;
    }
    for (k = 0; k < alen; k++) {
        if (a[k] != b[k]) {
            return 0;
        }
    }
    return 1;
}

/* Exchange two records field by field. */
void nf_swap(nf_record *a, nf_record *b) {
    uint16_t name_len = a->name_len;
    uint16_t flags = a->flags;
    uint32_t id = a->id;
    uint32_t i = 0;
    a->name_len = b->name_len;
    a->flags = b->flags;
    a->id = b->id;
    b->name_len = name_len;
    b->flags = flags;
    b->id = id;
    while (i < NF_NAME_BYTES) {
        char c = a->name[i];
        a->name[i] = b->name[i];
        b->name[i] = c;
        i++;
    }
}

/* ---- flags -------------------------------------------------------------- */

void nf_flag_set(nf_record *rec, uint16_t flag) {
    rec->flags = (uint16_t)(rec->flags | flag);
}

void nf_flag_clear(nf_record *rec, uint16_t flag) {
    rec->flags = (uint16_t)(rec->flags & ~flag);
}

int nf_flag_test(const nf_record *rec, uint16_t flag) {
    return (rec->flags & flag) != 0;
}

/* ---- table -------------------------------------------------------------- */

int nf_init(nf_table *tab, void *storage, uint32_t bytes) {
    uintptr_t addr = (uintptr_t)storage;
    uint32_t adjust = (uint32_t)((4u - (addr & 3u)) & 3u);
    if (tab == NULL || storage == NULL || bytes < adjust + NF_RECORD_BYTES) {
        return NF_ERR_ARG;
    }
    tab->count = 0;
    tab->cap = (bytes - adjust) / NF_RECORD_BYTES;
    tab->base = (uint8_t *)storage + adjust;
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
    if (len >= 16) {
        return NF_ERR_LEN;
    }
    nf_copy(rec->name, src, len);
    rec->name[len] = '\0';
    rec->name_len = (uint16_t)len;
    return NF_OK;
}

int nf_add(nf_table *tab, uint32_t id, const char *name, uint32_t len) {
    nf_record *slot;
    int status;
    if (tab->count >= tab->cap) {
        return NF_ERR_FULL;
    }
    if (nf_find_id(tab, id) >= 0) {
        return NF_ERR_DUP;
    }
    slot = nf_at(tab, tab->count);
    status = nf_set_name(slot, name, len);
    if (status != NF_OK) {
        return status;
    }
    slot->id = id;
    slot->flags = NF_FLAG_ACTIVE;
    tab->count++;
    return (int)(tab->count - 1u);
}

int nf_find_id(const nf_table *tab, uint32_t id) {
    uint32_t k;
    for (k = 0; k < tab->count; k++) {
        if (nf_at(tab, k)->id == id) {
            return (int)k;
        }
    }
    return NF_ERR_RANGE;
}

int nf_find_name(const nf_table *tab, const char *name, uint32_t len) {
    uint32_t k = 0;
    while (k < tab->count) {
        const nf_record *rec = nf_at(tab, k);
        if (nf_streq(rec->name, rec->name_len, name, len)) {
            return (int)k;
        }
        k++;
    }
    return NF_ERR_RANGE;
}

int nf_rename(nf_table *tab, uint32_t idx, const char *name, uint32_t len) {
    nf_record *target = nf_get(tab, idx);
    if (target == NULL) {
        return NF_ERR_RANGE;
    }
    if ((target->flags & NF_FLAG_LOCKED) != 0) {
        return NF_ERR_ARG;
    }
    return nf_set_name(target, name, len);
}

/* Remove record `idx` by moving the last record into its place. */
int nf_remove(nf_table *tab, uint32_t idx) {
    uint32_t last;
    if (nf_get(tab, idx) == NULL || tab->count == 0) {
        return NF_ERR_RANGE;
    }
    last = tab->count - 1u;
    if (idx != last) {
        nf_swap(nf_at(tab, idx), nf_at(tab, last));
    }
    tab->count = last;
    return NF_OK;
}

/* Insertion sort by id. */
void nf_sort_by_id(nf_table *tab) {
    uint32_t i;
    uint32_t j;
    for (i = 1; i < tab->count; i++) {
        j = i;
        while (j > 0 && nf_at(tab, j - 1u)->id > nf_at(tab, j)->id) {
            nf_swap(nf_at(tab, j - 1u), nf_at(tab, j));
            j--;
        }
    }
}

/* ---- totals ------------------------------------------------------------- */

uint32_t nf_total_name_bytes(const nf_table *tab) {
    uint32_t sum = 0;
    uint32_t k;
    for (k = 0; k < tab->count; k++) {
        sum += nf_at(tab, k)->name_len;
    }
    return sum;
}

/* Adler-style checksum over every live name and id. */
uint32_t nf_checksum(const nf_table *tab) {
    uint32_t s1 = 1;
    uint32_t s2 = 0;
    uint32_t i;
    uint32_t j;
    for (i = 0; i < tab->count; i++) {
        const nf_record *rec = nf_at(tab, i);
        for (j = 0; j < rec->name_len; j++) {
            s1 = (s1 + (uint8_t)rec->name[j]) % 65521u;
            s2 = (s2 + s1) % 65521u;
        }
        s1 = (s1 + (rec->id & 0xffu)) % 65521u;
        s2 = (s2 + s1) % 65521u;
    }
    return (s2 << 16) | s1;
}
