/* PatchTrace known-answer corpus: identity-negatives/inlinesplit, version 4. MIT licence.
 * Leaf helpers. They live in their own translation unit so that the compiler cannot fold them into
 * pk_decode; only the refactorings below are free to change how pk_decode is compiled.
 */
#include "pkt.h"

uint32_t pk_be16(const uint8_t *p) {
    return ((uint32_t)p[0] << 8) | (uint32_t)p[1];
}

uint32_t pk_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void pk_put_be16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

void pk_put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* CRC-16/CCITT-FALSE: polynomial 0x1021, initial value 0xFFFF. */
uint16_t pk_crc16(const uint8_t *p, uint32_t n) {
    uint32_t crc = 0xFFFFu;
    uint32_t i, bit;

    for (i = 0; i < n; i++) {
        crc ^= (uint32_t)p[i] << 8;
        for (bit = 0; bit < 8u; bit++) {
            if (crc & 0x8000u) {
                crc = ((crc << 1) ^ 0x1021u) & 0xFFFFu;
            } else {
                crc = (crc << 1) & 0xFFFFu;
            }
        }
    }
    return (uint16_t)crc;
}

void pk_reset(struct pkt *p) {
    uint32_t i;

    p->version = 0u;
    p->type = 0u;
    p->flags = 0u;
    p->ack = 0u;
    p->urgent = 0u;
    p->compressed = 0u;
    p->length = 0u;
    p->crc = 0u;
    p->seq = 0u;
    p->nopts = 0u;
    for (i = 0; i < PK_MAX_OPTS; i++) {
        p->opts[i].kind = 0u;
        p->opts[i].len = 0u;
        p->opts[i].value = 0u;
    }
    p->payload = NULL;
    p->payload_len = 0u;
}
