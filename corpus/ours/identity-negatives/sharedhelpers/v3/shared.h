/* PatchTrace known-answer corpus: identity-negatives/sharedhelpers, version 3. MIT licence.
 * Freestanding C11, no libc.
 *
 * A small statically linked support library (util.c) used by three unrelated parsers:
 * network fields (netparse.c), configuration values (cfgparse.c) and protocol headers
 * (protoparse.c). The parsers never call each other, they only share the helpers.
 */
#ifndef SHARED_H
#define SHARED_H

#include <stddef.h>
#include <stdint.h>

#define UT_OK 0
#define UT_E_EMPTY (-1)
#define UT_E_DIGIT (-2)
#define UT_E_RANGE (-3)

#define NET_E_FORMAT (-10)
#define NET_E_PORT (-11)
#define NET_E_OCTET (-12)
#define CFG_E_VALUE (-20)
#define PRO_E_HEADER (-30)
#define PRO_E_VERSION (-31)

/* util.c: the shared helpers */
int32_t ut_digit_value(int32_t c);
int32_t ut_parse_u32(const char *s, uint32_t len, uint32_t *out);
uint32_t ut_skip_ws(const char *s, uint32_t len);
int32_t ut_eq_nocase(const char *a, const char *b, uint32_t n);
int32_t ut_find_char(const char *s, uint32_t len, char c);

/* netparse.c */
int32_t net_parse_port(const char *s, uint32_t len, uint16_t *port);
int32_t net_parse_mtu(const char *s, uint32_t len, uint16_t *mtu);
int32_t net_parse_vlan(const char *s, uint32_t len, uint16_t *vid, uint8_t *pcp);
int32_t net_parse_ipv4(const char *s, uint32_t len, uint8_t out[4]);
int32_t net_parse_prefix_len(const char *s, uint32_t len, uint8_t *prefix);

/* cfgparse.c */
int32_t cfg_read_timeout_ms(const char *s, uint32_t len, uint32_t *ms);
int32_t cfg_read_retries(const char *s, uint32_t len, uint32_t *n);
int32_t cfg_read_bufsize(const char *s, uint32_t len, uint32_t *bytes);
int32_t cfg_read_loglevel(const char *s, uint32_t len, uint32_t *level);
int32_t cfg_read_bool(const char *s, uint32_t len, uint32_t *flag);

/* protoparse.c */
int32_t pro_content_length(const char *hdr, uint32_t len, uint32_t *out);
int32_t pro_status_code(const char *line, uint32_t len, uint32_t *code);
int32_t pro_version_triplet(const char *s, uint32_t len, uint32_t out[3]);
int32_t pro_chunk_size(const char *s, uint32_t len, uint32_t *size);

#endif
