/* PatchTrace known-answer corpus: identity-negatives/inlinesplit, version 4. MIT licence.
 * Packet decoder.
 */
#include "pkt.h"

/* The one deliberate static inline: the compiler folds it into its callers. */
static inline uint32_t pk_min_u32(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}

/* Version 3: the former pk_check_version and pk_check_flags in one function. */
int32_t pk_check_header_bits(uint32_t version, uint32_t flags) {
    if (version != PK_VERSION && version != 1u) {
        return PK_E_VERSION;
    }
    if ((flags & PK_F_RESERVED) != 0u) {
        return PK_E_FLAGS;
    }
    if ((flags & PK_F_URG) != 0u && (flags & PK_F_ACK) == 0u) {
        return PK_E_FLAGS;
    }
    return PK_OK;
}

/* The option walk, split out of pk_decode in version 2. */
int32_t pk_decode_options(const uint8_t *buf, uint32_t pos, uint32_t end, struct pkt *p) {
    while (pos < end) {
        uint32_t kind = buf[pos];
        uint32_t olen = (pos + 1u < end) ? buf[pos + 1u] : 0u;

        if (olen < 2u || pos + olen > end || p->nopts >= PK_MAX_OPTS) {
            return PK_E_OPTION;
        }
        p->opts[p->nopts].kind = (uint8_t)kind;
        p->opts[p->nopts].len = (uint8_t)olen;
        p->opts[p->nopts].value = (olen >= 4u) ? (uint16_t)pk_be16(buf + pos + 2u) : 0u;
        p->nopts++;
        pos += olen;
    }
    return PK_OK;
}

/* Validates the header, locates the options and the payload and checks the CRC. */
int32_t pk_decode(const uint8_t *buf, uint32_t len, struct pkt *p) {
    uint32_t opt_len, pay_len, end, total, flags;
    int32_t rc;

    if (buf == NULL || p == NULL || len < PK_HDR_LEN + 2u) {
        return PK_E_SHORT;
    }
    pk_reset(p);
    p->version = buf[0];
    p->type = buf[1];
    rc = pk_check_header_bits(buf[0], buf[2]);
    if (rc != PK_OK) {
        return rc;
    }
    flags = buf[2];
    p->flags = (uint8_t)flags;
    p->ack = (flags & PK_F_ACK) ? 1u : 0u;
    p->urgent = (flags & PK_F_URG) ? 1u : 0u;
    p->compressed = (flags & PK_F_ZIP) ? 1u : 0u;
    opt_len = buf[3];
    pay_len = pk_be16(buf + 4);
    p->seq = pk_be32(buf + 6);
    total = PK_HDR_LEN + opt_len + pay_len + 2u;
    if (total > len) {
        return PK_E_LENGTH;
    }
    p->length = (uint16_t)pk_min_u32(total, 0xFFFFu);
    end = PK_HDR_LEN + opt_len;
    rc = pk_decode_options(buf, PK_HDR_LEN, end, p);
    if (rc != PK_OK) {
        return rc;
    }
    p->payload = buf + end;
    p->payload_len = pay_len;
    p->crc = (uint16_t)pk_be16(buf + total - 2u);
    if (pk_crc16(buf, total - 2u) != p->crc) {
        return PK_E_CRC;
    }
    return PK_OK;
}

int32_t pk_peek_length(const uint8_t *buf, uint32_t len) {
    uint32_t total;

    if (buf == NULL || len < PK_HDR_LEN) {
        return PK_E_SHORT;
    }
    total = PK_HDR_LEN + (uint32_t)buf[3] + pk_be16(buf + 4) + 2u;
    return (int32_t)pk_min_u32(total, 0x7FFFFFFFu);
}

int32_t pk_encode_header(const struct pkt *p, uint8_t *out, uint32_t cap) {
    uint32_t opt_len = 0u;
    uint32_t i;

    if (p == NULL || out == NULL || cap < PK_HDR_LEN) {
        return PK_E_SHORT;
    }
    for (i = 0; i < p->nopts && i < PK_MAX_OPTS; i++) {
        opt_len += p->opts[i].len;
    }
    out[0] = p->version;
    out[1] = p->type;
    out[2] = p->flags;
    out[3] = (uint8_t)opt_len;
    pk_put_be16(out + 4, p->payload_len);
    pk_put_be32(out + 6, p->seq);
    return (int32_t)PK_HDR_LEN;
}

const struct pk_opt *pk_opt_find(const struct pkt *p, uint32_t kind) {
    uint32_t i;

    for (i = 0; i < p->nopts && i < PK_MAX_OPTS; i++) {
        if (p->opts[i].kind == kind) {
            return &p->opts[i];
        }
    }
    return NULL;
}

uint32_t pk_seq_next(uint32_t seq) {
    return (seq == 0xFFFFFFFFu) ? 1u : seq + 1u;
}

int32_t pk_seq_before(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) < 0;
}
