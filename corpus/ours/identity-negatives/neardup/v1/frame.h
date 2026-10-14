/* PatchTrace known-answer corpus: identity-negatives/neardup, version 1. MIT licence.
 * Freestanding C11, no libc.
 *
 * Telemetry frame decoder for a small sensor hub. A frame is an 8-byte header
 * followed by a 24-byte body: ten 10-bit analogue inputs (left aligned in
 * little-endian 16-bit cells) and four bytes of status flags.
 */
#ifndef FRAME_H
#define FRAME_H

#include <stddef.h>
#include <stdint.h>

#define FR_OK 0
#define FR_E_NULL (-1)
#define FR_E_SHORT (-2)
#define FR_E_RANGE (-3)
#define FR_E_MAGIC (-4)
#define FR_E_CRC (-5)

#define FR_MAGIC 0xA55Au
#define FR_HDR_LEN 8u
#define FR_BODY_LEN 24u
#define FR_AIN_COUNT 10u

#define FR_CFG_MIN 1u
#define FR_CFG_MAX 4095u

struct fr_view {
    const uint8_t *data;
    uint32_t len;
};

struct fr_frame {
    uint32_t ain[FR_AIN_COUNT];
    uint32_t status;
};

struct fr_cfg {
    uint32_t gain;
    uint32_t offset;
    uint32_t low;
    uint32_t high;
    uint32_t hyst;
    uint32_t dwell;
    uint32_t dirty;
};

uint32_t fr_rd_u16(const uint8_t *p);
uint32_t fr_rd_u32(const uint8_t *p);
uint8_t fr_crc8(const uint8_t *p, uint32_t n);
void fr_view_init(struct fr_view *v, const uint8_t *data, uint32_t len);
int32_t fr_check_header(const struct fr_view *v);

/* One decoder per analogue input: the bodies differ only in the cell offset. */
int32_t fr_dec_ain0(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain1(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain2(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain3(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain4(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain5(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain6(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain7(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain8(const struct fr_view *v, uint32_t *out);
int32_t fr_dec_ain9(const struct fr_view *v, uint32_t *out);

/* One setter per configuration field: the bodies differ only in the member. */
int32_t fr_cfg_set_gain(struct fr_cfg *c, uint32_t v);
int32_t fr_cfg_set_offset(struct fr_cfg *c, uint32_t v);
int32_t fr_cfg_set_low(struct fr_cfg *c, uint32_t v);
int32_t fr_cfg_set_high(struct fr_cfg *c, uint32_t v);
int32_t fr_cfg_set_hyst(struct fr_cfg *c, uint32_t v);
int32_t fr_cfg_set_dwell(struct fr_cfg *c, uint32_t v);

int32_t fr_decode_all(const struct fr_view *v, struct fr_frame *f);
void fr_cfg_reset(struct fr_cfg *c);
uint32_t fr_cfg_checksum(const struct fr_cfg *c);

#endif
