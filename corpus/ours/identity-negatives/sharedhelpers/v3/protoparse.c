/* PatchTrace known-answer corpus: identity-negatives/sharedhelpers, version 3. MIT licence.
 * Protocol header scanners. They use the shared helpers from util.c and nothing else.
 */
#include "shared.h"

/* "Content-Length: 1234" */
int32_t pro_content_length(const char *hdr, uint32_t len, uint32_t *out) {
    int32_t colon = ut_find_char(hdr, len, ':');
    uint32_t pos;
    int32_t used;

    if (colon < 0 || len < 16u || !ut_eq_nocase(hdr, "content-length", 14u)) {
        return PRO_E_HEADER;
    }
    pos = (uint32_t)colon + 1u;
    pos += ut_skip_ws(hdr + pos, len - pos);
    used = ut_parse_u32(hdr + pos, len - pos, out);
    if (used < 0) {
        return used;
    }
    if ((uint32_t)used != len - pos) {
        return PRO_E_HEADER;
    }
    return UT_OK;
}

/* "HTTP/1.1 404 Not Found" -> 404 */
int32_t pro_status_code(const char *line, uint32_t len, uint32_t *code) {
    int32_t sp = ut_find_char(line, len, ' ');
    uint32_t v;
    int32_t used;

    if (sp < 0 || len < 12u || !ut_eq_nocase(line, "http/", 5u) || (uint32_t)sp + 4u > len) {
        return PRO_E_HEADER;
    }
    used = ut_parse_u32(line + sp + 1, 3u, &v);
    if (used != 3 || v < 100u || v > 599u) {
        return PRO_E_HEADER;
    }
    *code = v;
    return UT_OK;
}

/* "1.2.3" -> {1, 2, 3} */
int32_t pro_version_triplet(const char *s, uint32_t len, uint32_t out[3]) {
    uint32_t pos = 0u;
    uint32_t k;

    for (k = 0; k < 3u; k++) {
        int32_t used;

        if (pos >= len) {
            return PRO_E_VERSION;
        }
        used = ut_parse_u32(s + pos, len - pos, &out[k]);
        if (used < 0) {
            return PRO_E_VERSION;
        }
        pos += (uint32_t)used;
        if (k < 2u) {
            if (pos >= len || s[pos] != '.') {
                return PRO_E_VERSION;
            }
            pos++;
        }
    }
    return (pos == len) ? UT_OK : PRO_E_VERSION;
}

/* Chunk header of a chunked transfer: hexadecimal size without prefix. */
int32_t pro_chunk_size(const char *s, uint32_t len, uint32_t *size) {
    uint32_t i;
    uint32_t v = 0u;

    for (i = 0; i < len; i++) {
        int32_t d = ut_digit_value((unsigned char)s[i]);

        if (d < 0 || d > 15) {
            break;
        }
        if (v > 0x0FFFFFFFu) {
            return PRO_E_HEADER;
        }
        v = (v << 4) | (uint32_t)d;
    }
    if (i == 0u) {
        return PRO_E_HEADER;
    }
    *size = v;
    return (int32_t)i;
}
