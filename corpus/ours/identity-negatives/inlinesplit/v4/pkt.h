/* PatchTrace known-answer corpus: identity-negatives/inlinesplit, version 4. MIT licence.
 * Freestanding C11, no libc.
 *
 * Decoder for a small link-layer packet: a 10-byte header, a list of type-length-value
 * options, the payload and a trailing CRC-16. Version 4 folds the single-use helper
 * pk_parse_flags into pk_decode by hand.
 */
#ifndef PKT_H
#define PKT_H

#include <stddef.h>
#include <stdint.h>

#define PK_OK 0
#define PK_E_SHORT (-1)
#define PK_E_VERSION (-2)
#define PK_E_FLAGS (-3)
#define PK_E_OPTION (-4)
#define PK_E_LENGTH (-5)
#define PK_E_CRC (-6)

#define PK_HDR_LEN 10u
#define PK_MAX_OPTS 4u
#define PK_VERSION 2u

#define PK_F_ACK 0x01u
#define PK_F_URG 0x02u
#define PK_F_ZIP 0x04u
#define PK_F_RESERVED 0xF8u

struct pk_opt {
    uint8_t kind;
    uint8_t len;
    uint16_t value;
};

struct pkt {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint8_t ack;
    uint8_t urgent;
    uint8_t compressed;
    uint16_t length;
    uint16_t crc;
    uint32_t seq;
    uint32_t nopts;
    struct pk_opt opts[PK_MAX_OPTS];
    const uint8_t *payload;
    uint32_t payload_len;
};

/* Header: version(1) type(1) flags(1) opt_len(1) payload_len(2, big endian) seq(4, big endian). */
uint32_t pk_be16(const uint8_t *p);
uint32_t pk_be32(const uint8_t *p);
void pk_put_be16(uint8_t *p, uint32_t v);
void pk_put_be32(uint8_t *p, uint32_t v);
uint16_t pk_crc16(const uint8_t *p, uint32_t n);

int32_t pk_check_header_bits(uint32_t version, uint32_t flags);
void pk_reset(struct pkt *p);

int32_t pk_decode_options(const uint8_t *buf, uint32_t pos, uint32_t end, struct pkt *p);
int32_t pk_decode(const uint8_t *buf, uint32_t len, struct pkt *p);
int32_t pk_peek_length(const uint8_t *buf, uint32_t len);
int32_t pk_encode_header(const struct pkt *p, uint8_t *out, uint32_t cap);
const struct pk_opt *pk_opt_find(const struct pkt *p, uint32_t kind);
uint32_t pk_seq_next(uint32_t seq);
int32_t pk_seq_before(uint32_t a, uint32_t b);

#endif
