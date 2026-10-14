/* PatchTrace known-answer corpus: identity-negatives/thunks, version 2. MIT licence.
 * Public entry points. Everything here is a forwarder of some kind.
 */
#include "blkdev.h"

/* Replaceable hook, the moral equivalent of an import address table slot. */
int32_t (*blk_hook_read)(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count) = blk_read_sync;

/* Plain forwarders: the compiler reduces each of these to one jump. */
int32_t blk_read(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count) {
    return blk_read_sync(d, lba, dst, count);
}

int32_t blk_write(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count) {
    return blk_write_cached(d, lba, src, count);
}

int32_t blk_flush(struct blk_dev *d) {
    return blk_flush_all(d);
}

/* Single-sector helpers: forwarders that supply a constant argument. */
int32_t blk_read_one(struct blk_dev *d, uint64_t lba, void *dst) {
    return blk_read_cached(d, lba, dst, 1u);
}

int32_t blk_write_one(struct blk_dev *d, uint64_t lba, const void *src) {
    return blk_write_cached(d, lba, src, 1u);
}

/* Legacy entry points take the buffer first. */
int32_t blk_read_legacy(void *dst, struct blk_dev *d, uint64_t lba, uint32_t count) {
    return blk_read_cached(d, lba, dst, count);
}

int32_t blk_write_legacy(const void *src, struct blk_dev *d, uint64_t lba, uint32_t count) {
    return blk_write_cached(d, lba, src, count);
}

/* Guarded forwarders: one null test, then the jump. */
int32_t blk_read_checked(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count) {
    if (d == NULL) {
        return BLK_E_NULL;
    }
    return blk_read_cached(d, lba, dst, count);
}

int32_t blk_write_checked(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count) {
    if (d == NULL) {
        return BLK_E_NULL;
    }
    return blk_write_cached(d, lba, src, count);
}

/* Container adaptors: the blk_dev is embedded, so the pointer is adjusted first. */
int32_t ramdisk_read(struct ramdisk *r, uint64_t lba, void *dst, uint32_t count) {
    return blk_read_sync(&r->dev, lba, dst, count);
}

int32_t ramdisk_write(struct ramdisk *r, uint64_t lba, const void *src, uint32_t count) {
    return blk_write_sync(&r->dev, lba, src, count);
}

int32_t ramdisk_flush(struct ramdisk *r) {
    return blk_flush_none(&r->dev);
}

int32_t loopdev_read(struct loopdev *l, uint64_t lba, void *dst, uint32_t count) {
    return blk_read_cached(&l->dev, lba, dst, count);
}

int32_t loopdev_write(struct loopdev *l, uint64_t lba, const void *src, uint32_t count) {
    return blk_write_cached(&l->dev, lba, src, count);
}

int32_t loopdev_flush(struct loopdev *l) {
    return blk_flush_all(&l->dev);
}

/* Dynamic dispatch through the ops table: load the slot, jump through it. */
int32_t blk_ops_read(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count) {
    return d->ops->read(d, lba, dst, count);
}

int32_t blk_ops_write(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count) {
    return d->ops->write(d, lba, src, count);
}

int32_t blk_ops_flush(struct blk_dev *d) {
    return d->ops->flush(d);
}

/* Import-stub style: jump through a global function pointer. */
int32_t blk_read_hooked(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count) {
    return blk_hook_read(d, lba, dst, count);
}
