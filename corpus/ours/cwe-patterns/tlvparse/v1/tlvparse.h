/* tlvparse.h - type-length-value record parser over a caller-provided byte array.
 *
 * Wire format, repeated until the buffer ends:
 *   [type : 1 byte][length : 2 bytes, big endian][value : `length` bytes]
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef TLVPARSE_H
#define TLVPARSE_H

#include <stddef.h>
#include <stdint.h>

#define TLV_OK 0
#define TLV_ERR_ARG (-1)
#define TLV_ERR_END (-2)   /* clean end of input */
#define TLV_ERR_TRUNC (-3) /* a record runs past the end of the buffer */
#define TLV_ERR_TYPE (-4)  /* unexpected record type */

#define TLV_TYPE_NAME 0x01u
#define TLV_TYPE_VERSION 0x02u
#define TLV_TYPE_FLAGS 0x03u
#define TLV_TYPE_PAYLOAD 0x04u
#define TLV_TYPE_DIGEST 0x05u
#define TLV_TYPE_STAMP 0x06u
#define TLV_TYPE_PAD 0x7fu

typedef struct tlv_cursor {
    const uint8_t *buf;
    uint32_t len;
    uint32_t pos;
    uint32_t records; /* records returned so far */
} tlv_cursor;

typedef struct tlv_item {
    uint8_t type;
    uint16_t length;
    const uint8_t *value;
} tlv_item;

typedef int (*tlv_visitor)(void *ctx, const tlv_item *item);

/* decoding helpers */
uint16_t tlv_be16(const uint8_t *p);
uint32_t tlv_be32(const uint8_t *p);

/* cursor */
int tlv_init(tlv_cursor *cur, const uint8_t *buf, uint32_t len);
void tlv_rewind(tlv_cursor *cur);
uint32_t tlv_remaining(const tlv_cursor *cur);
int tlv_at_end(const tlv_cursor *cur);
int tlv_peek_type(const tlv_cursor *cur);
int tlv_next(tlv_cursor *cur, tlv_item *item);
void tlv_skip_raw(tlv_cursor *cur, uint32_t n);
int tlv_expect(tlv_cursor *cur, uint8_t type, tlv_item *item);
int tlv_find(const tlv_cursor *cur, uint8_t type, tlv_item *item);

/* whole-buffer operations */
int tlv_count(const uint8_t *buf, uint32_t len);
int tlv_validate(const uint8_t *buf, uint32_t len);
int tlv_walk(tlv_cursor *cur, tlv_visitor visit, void *ctx);

/* value accessors */
int tlv_value_u8(const tlv_item *item, uint8_t *out);
int tlv_value_u16(const tlv_item *item, uint16_t *out);
int tlv_value_u32(const tlv_item *item, uint32_t *out);
uint16_t tlv_copy_value(const tlv_item *item, uint8_t *dst, uint16_t cap);
uint16_t tlv_checksum_value(const tlv_item *item);
int tlv_is_printable(const tlv_item *item);

/* type table */
const char *tlv_type_name(uint8_t type);
int tlv_type_is_known(uint8_t type);

#endif /* TLVPARSE_H */
