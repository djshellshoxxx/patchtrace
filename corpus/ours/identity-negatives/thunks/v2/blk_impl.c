/* PatchTrace known-answer corpus: identity-negatives/thunks, version 2. MIT licence.
 * Implementation layer: sector copies, a four-line direct-mapped write-back cache.
 */
#include "blkdev.h"

void blk_copy(uint8_t *dst, const uint8_t *src, uint32_t n) {
    uint32_t i;

    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

/* Uncached read: straight from the backing store. */
int32_t blk_read_sync(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count) {
    uint32_t i;
    uint8_t *out = (uint8_t *)dst;

    if (d == NULL || dst == NULL) {
        return BLK_E_NULL;
    }
    if (lba >= d->sectors || count > d->sectors - lba) {
        return BLK_E_RANGE;
    }
    for (i = 0; i < count; i++) {
        blk_copy(out + (size_t)i * BLK_SECTOR, d->store + (lba + i) * BLK_SECTOR, BLK_SECTOR);
    }
    d->reads += count;
    return BLK_OK;
}

/* Cached read: a miss evicts (and writes back) whatever owns the line. */
int32_t blk_read_cached(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count) {
    uint32_t i;
    uint8_t *out = (uint8_t *)dst;

    if (d == NULL || dst == NULL) {
        return BLK_E_NULL;
    }
    if (lba >= d->sectors || count > d->sectors - lba) {
        return BLK_E_RANGE;
    }
    for (i = 0; i < count; i++) {
        uint64_t cur = lba + i;
        struct blk_line *ln = &d->cache[cur % BLK_CACHE_LINES];

        if (!ln->valid || ln->lba != cur) {
            if (ln->valid && ln->dirty) {
                blk_copy(d->store + ln->lba * BLK_SECTOR, ln->data, BLK_SECTOR);
                ln->dirty = 0;
            }
            blk_copy(ln->data, d->store + cur * BLK_SECTOR, BLK_SECTOR);
            ln->lba = cur;
            ln->valid = 1;
        }
        blk_copy(out + (size_t)i * BLK_SECTOR, ln->data, BLK_SECTOR);
    }
    d->reads += count;
    return BLK_OK;
}

/* Write-through: update the store and drop any cached copy. */
int32_t blk_write_sync(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count) {
    uint32_t i;
    const uint8_t *in = (const uint8_t *)src;

    if (d == NULL || src == NULL) {
        return BLK_E_NULL;
    }
    if (d->flags & BLK_F_READONLY) {
        return BLK_E_RO;
    }
    if (lba + count > d->sectors) {
        return BLK_E_RANGE;
    }
    for (i = 0; i < count; i++) {
        struct blk_line *ln = &d->cache[(lba + i) % BLK_CACHE_LINES];

        if (ln->valid && ln->lba == lba + i) {
            ln->valid = 0;
            ln->dirty = 0;
        }
        blk_copy(d->store + (lba + i) * BLK_SECTOR, in + (size_t)i * BLK_SECTOR, BLK_SECTOR);
    }
    d->writes += count;
    return BLK_OK;
}

/* Write-back: the data stays in the cache line until it is evicted or flushed. */
int32_t blk_write_cached(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count) {
    uint32_t i;
    const uint8_t *in = (const uint8_t *)src;

    if (d == NULL || src == NULL) {
        return BLK_E_NULL;
    }
    if (d->flags & BLK_F_READONLY) {
        return BLK_E_RO;
    }
    if (lba >= d->sectors || count > d->sectors - lba) {
        return BLK_E_RANGE;
    }
    for (i = 0; i < count; i++) {
        uint64_t cur = lba + i;
        struct blk_line *ln = &d->cache[cur % BLK_CACHE_LINES];

        if (ln->valid && ln->dirty && ln->lba != cur) {
            blk_copy(d->store + ln->lba * BLK_SECTOR, ln->data, BLK_SECTOR);
        }
        blk_copy(ln->data, in + (size_t)i * BLK_SECTOR, BLK_SECTOR);
        ln->lba = cur;
        ln->valid = 1;
        ln->dirty = 1;
    }
    d->writes += count;
    return BLK_OK;
}

int32_t blk_flush_all(struct blk_dev *d) {
    uint32_t i;

    if (d == NULL) {
        return BLK_E_NULL;
    }
    for (i = 0; i < BLK_CACHE_LINES; i++) {
        struct blk_line *ln = &d->cache[i];

        if (ln->valid && ln->dirty) {
            blk_copy(d->store + ln->lba * BLK_SECTOR, ln->data, BLK_SECTOR);
            ln->dirty = 0;
        }
    }
    return BLK_OK;
}

/* Write-through devices have nothing to flush. */
int32_t blk_flush_none(struct blk_dev *d) {
    if (d == NULL) {
        return BLK_E_NULL;
    }
    return BLK_OK;
}

int32_t blk_trim(struct blk_dev *d, uint64_t lba, uint64_t count) {
    uint64_t i;
    uint32_t b;

    if (d == NULL) {
        return BLK_E_NULL;
    }
    if (d->flags & BLK_F_READONLY) {
        return BLK_E_RO;
    }
    if (lba >= d->sectors || count > d->sectors - lba) {
        return BLK_E_RANGE;
    }
    for (i = 0; i < count; i++) {
        struct blk_line *ln = &d->cache[(lba + i) % BLK_CACHE_LINES];

        if (ln->valid && ln->lba == lba + i) {
            ln->valid = 0;
            ln->dirty = 0;
        }
        for (b = 0; b < BLK_SECTOR; b++) {
            d->store[(lba + i) * BLK_SECTOR + b] = 0;
        }
    }
    return BLK_OK;
}

void blk_stats_reset(struct blk_dev *d) {
    if (d == NULL) {
        return;
    }
    d->reads = 0;
    d->writes = 0;
}
