/* tlvparse.c - TLV record parser over a caller-provided byte array (v2c).
 *
 * The cursor walks the buffer one record at a time; accessors then read the value bytes
 * the cursor handed out. No allocation, no libc.
 */
#include "tlvparse.h"

/* ---- decoding helpers --------------------------------------------------- */

uint16_t tlv_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t tlv_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ---- cursor ------------------------------------------------------------- */

int tlv_init(tlv_cursor *cur, const uint8_t *buf, uint32_t len) {
    if (cur == NULL || (buf == NULL && len != 0)) {
        return TLV_ERR_ARG;
    }
    cur->buf = buf;
    cur->len = len;
    cur->pos = 0;
    cur->records = 0;
    return TLV_OK;
}

void tlv_rewind(tlv_cursor *cur) {
    cur->pos = 0;
    cur->records = 0;
}

uint32_t tlv_remaining(const tlv_cursor *cur) {
    return cur->pos < cur->len ? cur->len - cur->pos : 0;
}

int tlv_at_end(const tlv_cursor *cur) {
    return cur->pos >= cur->len;
}

/* Type byte of the next record without consuming it. */
int tlv_peek_type(const tlv_cursor *cur) {
    if (cur->pos >= cur->len) {
        return TLV_ERR_END;
    }
    return cur->buf[cur->pos];
}

/* True when a record body of `length` bytes fits after the 3-byte header at the cursor. */
int tlv_record_fits(const tlv_cursor *cur, uint32_t length) {
    return length <= 256u && tlv_remaining(cur) >= 3u && length <= tlv_remaining(cur) - 3u;
}

/* Return the next record. The value pointer aims into the caller's buffer. */
int tlv_next(tlv_cursor *cur, tlv_item *item) {
    const uint8_t *p;
    uint16_t length;
    if (cur == NULL || item == NULL) {
        return TLV_ERR_ARG;
    }
    if (cur->pos >= cur->len) {
        return TLV_ERR_END;
    }
    if (tlv_remaining(cur) < 3u) {
        return TLV_ERR_TRUNC;
    }
    p = cur->buf + cur->pos;
    length = tlv_be16(p + 1);
    if (!tlv_record_fits(cur, length)) {
        return TLV_ERR_TRUNC;
    }
    item->type = p[0];
    item->length = length;
    item->value = p + 3;
    cur->pos += 3u + length;
    cur->records++;
    return TLV_OK;
}

/* Like tlv_next but insists on a particular record type. */
int tlv_expect(tlv_cursor *cur, uint8_t type, tlv_item *item) {
    int rc = tlv_next(cur, item);
    if (rc != TLV_OK) {
        return rc;
    }
    if (item->type != type) {
        return TLV_ERR_TYPE;
    }
    return TLV_OK;
}

/* Search forward from the cursor position without moving the cursor. */
int tlv_find(const tlv_cursor *cur, uint8_t type, tlv_item *item) {
    tlv_cursor scan = *cur;
    int rc;
    while ((rc = tlv_next(&scan, item)) == TLV_OK) {
        if (item->type == type) {
            return TLV_OK;
        }
    }
    return rc;
}

/* ---- whole-buffer operations ------------------------------------------- */

int tlv_count(const uint8_t *buf, uint32_t len) {
    tlv_cursor cur;
    tlv_item item;
    int rc;
    if (tlv_init(&cur, buf, len) != TLV_OK) {
        return TLV_ERR_ARG;
    }
    while ((rc = tlv_next(&cur, &item)) == TLV_OK) {
        /* counting only */
    }
    if (rc != TLV_ERR_END) {
        return rc;
    }
    return (int)cur.records;
}

int tlv_validate(const uint8_t *buf, uint32_t len) {
    tlv_cursor cur;
    tlv_item item;
    int rc;
    if (tlv_init(&cur, buf, len) != TLV_OK) {
        return TLV_ERR_ARG;
    }
    while ((rc = tlv_next(&cur, &item)) == TLV_OK) {
        /* structure check only */
    }
    if (rc != TLV_ERR_END) {
        return rc;
    }
    return cur.pos == cur.len ? TLV_OK : TLV_ERR_TRUNC;
}

/* Call `visit` for each record; a non-zero return from the callback stops the walk. */
int tlv_walk(tlv_cursor *cur, tlv_visitor visit, void *ctx) {
    tlv_item item;
    int visited = 0;
    int rc;
    if (cur == NULL || visit == NULL) {
        return TLV_ERR_ARG;
    }
    while ((rc = tlv_next(cur, &item)) == TLV_OK) {
        if (visit(ctx, &item) != 0) {
            return visited;
        }
        visited++;
    }
    return rc == TLV_ERR_END ? visited : rc;
}

/* ---- value accessors ---------------------------------------------------- */

int tlv_value_u8(const tlv_item *item, uint8_t *out) {
    if (item->length != 1) {
        return TLV_ERR_ARG;
    }
    *out = item->value[0];
    return TLV_OK;
}

int tlv_value_u16(const tlv_item *item, uint16_t *out) {
    if (item->length != 2) {
        return TLV_ERR_ARG;
    }
    *out = tlv_be16(item->value);
    return TLV_OK;
}

int tlv_value_u32(const tlv_item *item, uint32_t *out) {
    if (item->length != 4) {
        return TLV_ERR_ARG;
    }
    *out = tlv_be32(item->value);
    return TLV_OK;
}

/* Copy at most `cap` value bytes; returns the number copied. */
uint16_t tlv_copy_value(const tlv_item *item, uint8_t *dst, uint16_t cap) {
    uint16_t n = item->length < cap ? item->length : cap;
    uint16_t i;
    for (i = 0; i < n; i++) {
        dst[i] = item->value[i];
    }
    return n;
}

uint16_t tlv_checksum_value(const tlv_item *item) {
    uint16_t sum = 0;
    uint16_t i;
    for (i = 0; i < item->length; i++) {
        sum = (uint16_t)(sum + item->value[i]);
    }
    return sum;
}

int tlv_is_printable(const tlv_item *item) {
    uint16_t i;
    for (i = 0; i < item->length; i++) {
        if (item->value[i] < 0x20u || item->value[i] > 0x7eu) {
            return 0;
        }
    }
    return 1;
}

/* ---- type table --------------------------------------------------------- */

const char *tlv_type_name(uint8_t type) {
    switch (type) {
    case TLV_TYPE_NAME:
        return "name";
    case TLV_TYPE_VERSION:
        return "version";
    case TLV_TYPE_FLAGS:
        return "flags";
    case TLV_TYPE_PAYLOAD:
        return "payload";
    case TLV_TYPE_DIGEST:
        return "digest";
    case TLV_TYPE_STAMP:
        return "timestamp";
    case TLV_TYPE_PAD:
        return "padding";
    default:
        return "unknown";
    }
}

int tlv_type_is_known(uint8_t type) {
    switch (type) {
    case TLV_TYPE_NAME:
    case TLV_TYPE_VERSION:
    case TLV_TYPE_FLAGS:
    case TLV_TYPE_PAYLOAD:
    case TLV_TYPE_DIGEST:
    case TLV_TYPE_STAMP:
    case TLV_TYPE_PAD:
        return 1;
    default:
        return 0;
    }
}
