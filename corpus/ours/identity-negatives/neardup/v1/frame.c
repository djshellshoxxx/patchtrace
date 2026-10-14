/* PatchTrace known-answer corpus: identity-negatives/neardup, version 1. MIT licence.
 * Frame helpers, one decoder per analogue input, one setter per config field.
 */
#include "frame.h"

uint32_t fr_rd_u16(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

uint32_t fr_rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* CRC-8, polynomial 0x07, initial value 0xFF, no reflection. */
uint8_t fr_crc8(const uint8_t *p, uint32_t n) {
    uint32_t crc = 0xFFu;
    uint32_t i, bit;

    for (i = 0; i < n; i++) {
        crc ^= p[i];
        for (bit = 0; bit < 8u; bit++) {
            if (crc & 0x80u) {
                crc = ((crc << 1) ^ 0x07u) & 0xFFu;
            } else {
                crc = (crc << 1) & 0xFFu;
            }
        }
    }
    return (uint8_t)crc;
}

void fr_view_init(struct fr_view *v, const uint8_t *data, uint32_t len) {
    if (v == NULL) {
        return;
    }
    v->data = data;
    v->len = (data == NULL) ? 0u : len;
}

/* Header: magic(2) version(1) flags(1) body_len(2) crc8(1) pad(1). */
int32_t fr_check_header(const struct fr_view *v) {
    uint32_t body_len;

    if (v == NULL || v->data == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN) {
        return FR_E_SHORT;
    }
    if (fr_rd_u16(v->data) != FR_MAGIC) {
        return FR_E_MAGIC;
    }
    body_len = fr_rd_u16(v->data + 4u);
    if (v->len < FR_HDR_LEN + body_len) {
        return FR_E_SHORT;
    }
    if (fr_crc8(v->data, 6u) != v->data[6]) {
        return FR_E_CRC;
    }
    return FR_OK;
}

int32_t fr_dec_ain0(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 0u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain1(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 2u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain2(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 4u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain3(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 6u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain4(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 8u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain5(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 10u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain6(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 12u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain7(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 14u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain8(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 16u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_dec_ain9(const struct fr_view *v, uint32_t *out) {
    uint32_t raw;

    if (v == NULL || out == NULL) {
        return FR_E_NULL;
    }
    if (v->len < FR_HDR_LEN + FR_BODY_LEN) {
        return FR_E_SHORT;
    }
    raw = (fr_rd_u16(v->data + FR_HDR_LEN + 18u) >> 2) & 0x3FFu;
    if (raw > 1000u) {
        return FR_E_RANGE;
    }
    *out = raw;
    return FR_OK;
}

int32_t fr_cfg_set_gain(struct fr_cfg *c, uint32_t v) {
    if (c == NULL) {
        return FR_E_NULL;
    }
    if (v < FR_CFG_MIN || v > FR_CFG_MAX) {
        return FR_E_RANGE;
    }
    c->gain = v;
    c->dirty++;
    return FR_OK;
}

int32_t fr_cfg_set_offset(struct fr_cfg *c, uint32_t v) {
    if (c == NULL) {
        return FR_E_NULL;
    }
    if (v < FR_CFG_MIN || v > FR_CFG_MAX) {
        return FR_E_RANGE;
    }
    c->offset = v;
    c->dirty++;
    return FR_OK;
}

int32_t fr_cfg_set_low(struct fr_cfg *c, uint32_t v) {
    if (c == NULL) {
        return FR_E_NULL;
    }
    if (v < FR_CFG_MIN || v > FR_CFG_MAX) {
        return FR_E_RANGE;
    }
    c->low = v;
    c->dirty++;
    return FR_OK;
}

int32_t fr_cfg_set_high(struct fr_cfg *c, uint32_t v) {
    if (c == NULL) {
        return FR_E_NULL;
    }
    if (v < FR_CFG_MIN || v > FR_CFG_MAX) {
        return FR_E_RANGE;
    }
    c->high = v;
    c->dirty++;
    return FR_OK;
}

int32_t fr_cfg_set_hyst(struct fr_cfg *c, uint32_t v) {
    if (c == NULL) {
        return FR_E_NULL;
    }
    if (v < FR_CFG_MIN || v > FR_CFG_MAX) {
        return FR_E_RANGE;
    }
    c->hyst = v;
    c->dirty++;
    return FR_OK;
}

int32_t fr_cfg_set_dwell(struct fr_cfg *c, uint32_t v) {
    if (c == NULL) {
        return FR_E_NULL;
    }
    if (v < FR_CFG_MIN || v > FR_CFG_MAX) {
        return FR_E_RANGE;
    }
    c->dwell = v;
    c->dirty++;
    return FR_OK;
}
