/* PatchTrace known-answer corpus: identity-negatives/neardup, version 2. MIT licence.
 * Public entry points. They live in their own translation unit on purpose, so the compiler
 * cannot fold the per-input decoders into them.
 */
#include "frame.h"

/* Decode every input; bit k of f->status is set when input k was rejected. */
int32_t fr_decode_all(const struct fr_view *v, struct fr_frame *f) {
    int32_t rc;

    if (f == NULL) {
        return FR_E_NULL;
    }
    rc = fr_check_header(v);
    if (rc != FR_OK) {
        return rc;
    }
    f->status = 0u;
    f->status |= (uint32_t)(fr_dec_ain0(v, &f->ain[0]) != FR_OK) << 0;
    f->status |= (uint32_t)(fr_dec_ain1(v, &f->ain[1]) != FR_OK) << 1;
    f->status |= (uint32_t)(fr_dec_ain2(v, &f->ain[2]) != FR_OK) << 2;
    f->status |= (uint32_t)(fr_dec_ain3(v, &f->ain[3]) != FR_OK) << 3;
    f->status |= (uint32_t)(fr_dec_ain4(v, &f->ain[4]) != FR_OK) << 4;
    f->status |= (uint32_t)(fr_dec_ain5(v, &f->ain[5]) != FR_OK) << 5;
    f->status |= (uint32_t)(fr_dec_ain6(v, &f->ain[6]) != FR_OK) << 6;
    f->status |= (uint32_t)(fr_dec_ain7(v, &f->ain[7]) != FR_OK) << 7;
    f->status |= (uint32_t)(fr_dec_ain8(v, &f->ain[8]) != FR_OK) << 8;
    f->status |= (uint32_t)(fr_dec_ain9(v, &f->ain[9]) != FR_OK) << 9;
    return (f->status != 0u) ? FR_E_RANGE : FR_OK;
}

void fr_cfg_reset(struct fr_cfg *c) {
    if (c == NULL) {
        return;
    }
    c->gain = 256u;
    c->offset = 8u;
    c->low = 100u;
    c->high = 3900u;
    c->hyst = 8u;
    c->dwell = 50u;
    c->dirty = 0u;
}

uint32_t fr_cfg_checksum(const struct fr_cfg *c) {
    uint32_t h = 2166136261u;

    h = (h ^ c->gain) * 16777619u;
    h = (h ^ c->offset) * 16777619u;
    h = (h ^ c->low) * 16777619u;
    h = (h ^ c->high) * 16777619u;
    h = (h ^ c->hyst) * 16777619u;
    h = (h ^ c->dwell) * 16777619u;
    return h;
}
