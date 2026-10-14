/* PatchTrace known-answer corpus: identity-negatives/thunks, version 2. MIT licence.
 * Freestanding C11, no libc.
 *
 * Block-device layer of a small storage stack. blk_impl.c holds the real work and
 * blk_thunks.c the public entry points: most of them only forward to an
 * implementation function (jump thunks), some adjust a pointer or reorder the
 * arguments first (trampolines), some go through a function pointer.
 */
#ifndef BLKDEV_H
#define BLKDEV_H

#include <stddef.h>
#include <stdint.h>

#define BLK_OK 0
#define BLK_E_NULL (-1)
#define BLK_E_RANGE (-2)
#define BLK_E_RO (-3)

#define BLK_SECTOR 512u
#define BLK_CACHE_LINES 4u
#define BLK_F_READONLY 0x1u

struct blk_dev;

struct blk_ops {
    int32_t (*read)(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);
    int32_t (*write)(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count);
    int32_t (*flush)(struct blk_dev *d);
};

struct blk_line {
    uint64_t lba;
    uint32_t valid;
    uint32_t dirty;
    uint8_t data[BLK_SECTOR];
};

struct blk_dev {
    const struct blk_ops *ops;
    uint8_t *store;
    uint64_t sectors;
    uint32_t flags;
    uint32_t reads;
    uint32_t writes;
    struct blk_line cache[BLK_CACHE_LINES];
};

/* Devices that embed a blk_dev at a non-zero offset. */
struct ramdisk {
    uint32_t tag;
    struct blk_dev dev;
};

struct loopdev {
    uint32_t tag;
    uint32_t backing_id;
    struct blk_dev dev;
    struct blk_dev shadow;
};

extern int32_t (*blk_hook_read)(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);

/* Implementation, blk_impl.c. */
void blk_copy(uint8_t *dst, const uint8_t *src, uint32_t n);
int32_t blk_read_sync(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);
int32_t blk_read_cached(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);
int32_t blk_write_sync(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count);
int32_t blk_write_cached(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count);
int32_t blk_flush_all(struct blk_dev *d);
int32_t blk_flush_none(struct blk_dev *d);
int32_t blk_trim(struct blk_dev *d, uint64_t lba, uint64_t count);
void blk_stats_reset(struct blk_dev *d);

/* Public entry points, blk_thunks.c. */
int32_t blk_read(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);
int32_t blk_write(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count);
int32_t blk_flush(struct blk_dev *d);
int32_t blk_read_one(struct blk_dev *d, uint64_t lba, void *dst);
int32_t blk_write_one(struct blk_dev *d, uint64_t lba, const void *src);
int32_t blk_read_legacy(void *dst, struct blk_dev *d, uint64_t lba, uint32_t count);
int32_t blk_write_legacy(const void *src, struct blk_dev *d, uint64_t lba, uint32_t count);
int32_t blk_read_checked(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);
int32_t blk_write_checked(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count);
int32_t ramdisk_read(struct ramdisk *r, uint64_t lba, void *dst, uint32_t count);
int32_t ramdisk_write(struct ramdisk *r, uint64_t lba, const void *src, uint32_t count);
int32_t ramdisk_flush(struct ramdisk *r);
int32_t loopdev_read(struct loopdev *l, uint64_t lba, void *dst, uint32_t count);
int32_t loopdev_write(struct loopdev *l, uint64_t lba, const void *src, uint32_t count);
int32_t loopdev_flush(struct loopdev *l);
int32_t blk_ops_read(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);
int32_t blk_ops_write(struct blk_dev *d, uint64_t lba, const void *src, uint32_t count);
int32_t blk_ops_flush(struct blk_dev *d);
int32_t blk_read_hooked(struct blk_dev *d, uint64_t lba, void *dst, uint32_t count);

#endif
