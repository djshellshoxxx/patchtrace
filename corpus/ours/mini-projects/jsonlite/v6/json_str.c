/* SPDX-License-Identifier: MIT */
/*
 * json_str.c - string handling: hex digits, UTF-8 encoding and validation,
 * escape decoding and escape-aware comparison.
 *
 * These helpers used to live in json_util.c. They moved here when the lexer,
 * the accessors and the key lookup all started to depend on them.
 */
#include "json.h"

/* Value of a hexadecimal digit, or -1 when c is not one. */
int json_hex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Read exactly four hex digits (the XXXX of a \uXXXX escape). */
json_status json_hex4(const char *s, size_t n, uint32_t *out) {
    uint32_t value = 0;
    size_t i;

    if (n < 4) {
        return JSON_ERR_STRING;
    }
    for (i = 0; i < 4; i++) {
        int digit = json_hex_digit(s[i]);

        if (digit < 0) {
            return JSON_ERR_STRING;
        }
        value = (value << 4) | (uint32_t)digit;
    }
    *out = value;
    return JSON_OK;
}

/*
 * Encode one code point as UTF-8 into out[0..cap). Returns the number of bytes
 * written (1..4), or 0 when the code point is not a scalar value (surrogate or
 * above U+10FFFF) or the encoding does not fit in cap bytes.
 */
size_t json_utf8_encode(uint32_t cp, char *out, size_t cap) {
    if (cp < 0x80) {
        /* U+0000..U+007F: one byte */
        if (cap < 1) {
            return 0;
        }
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        /* U+0080..U+07FF: two bytes */
        if (cap < 2) {
            return 0;
        }
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        /* U+0800..U+FFFF: three bytes, but never a surrogate */
        if (cap < 3 || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return 0;
        }
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    /* U+10000..U+10FFFF: four bytes */
    if (cap < 4 || cp > 0x10FFFF) {
        return 0;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/*
 * Length of the well-formed UTF-8 sequence at s[0..n), or 0 when it is
 * malformed: truncated, a stray continuation byte, overlong, a surrogate, or
 * beyond U+10FFFF.
 */
size_t json_utf8_seq_len(const char *s, size_t n) {
    unsigned char lead;
    unsigned char second;

    if (n == 0) {
        return 0;
    }
    lead = (unsigned char)s[0];
    if (lead < 0x80) {
        return 1;
    }
    if (lead < 0xC2) {
        return 0;
    }
    if (lead < 0xE0) {
        return (n >= 2 && ((unsigned char)s[1] & 0xC0) == 0x80) ? 2 : 0;
    }
    if (lead < 0xF0) {
        if (n < 3) {
            return 0;
        }
        second = (unsigned char)s[1];
        if ((second & 0xC0) != 0x80 || ((unsigned char)s[2] & 0xC0) != 0x80) {
            return 0;
        }
        if ((lead == 0xE0 && second < 0xA0) || (lead == 0xED && second >= 0xA0)) {
            return 0;
        }
        return 3;
    }
    if (lead < 0xF5) {
        if (n < 4) {
            return 0;
        }
        second = (unsigned char)s[1];
        if ((second & 0xC0) != 0x80 || ((unsigned char)s[2] & 0xC0) != 0x80 || ((unsigned char)s[3] & 0xC0) != 0x80) {
            return 0;
        }
        if ((lead == 0xF0 && second < 0x90) || (lead == 0xF4 && second >= 0x90)) {
            return 0;
        }
        return 4;
    }
    return 0;
}

/*
 * Decode the escape sequence at src[0..n), which starts with the backslash.
 * The decoded bytes go to out[0..cap); *used receives the number of source
 * bytes consumed and *written the number of bytes produced.
 */
json_status json_decode_escape(const char *src, size_t n, char *out, size_t cap, size_t *used, size_t *written) {
    char c;

    if (n < 2) {
        return JSON_ERR_STRING;
    }
    c = src[1];
    switch (c) {
    case '"':
    case '\\':
    case '/':
        break;
    case 'b':
        c = '\b';
        break;
    case 'f':
        c = '\f';
        break;
    case 'n':
        c = '\n';
        break;
    case 'r':
        c = '\r';
        break;
    case 't':
        c = '\t';
        break;
    case 'u': {
        uint32_t cp;
        uint32_t lo;
        size_t w;

        if (json_hex4(src + 2, n - 2, &cp) != JSON_OK) {
            return JSON_ERR_STRING;
        }
        *used = 6;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (n >= 12 && src[6] == '\\' && src[7] == 'u' && json_hex4(src + 8, n - 8, &lo) == JSON_OK &&
                lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                *used = 12;
            } else {
                cp = 0xFFFD;
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        w = json_utf8_encode(cp, out, cap);
        if (w == 0) {
            return JSON_ERR_NOMEM;
        }
        *written = w;
        return JSON_OK;
    }
    default:
        return JSON_ERR_STRING;
    }
    if (cap < 1) {
        return JSON_ERR_NOMEM;
    }
    out[0] = c;
    *used = 2;
    *written = 1;
    return JSON_OK;
}

/*
 * Decode the escapes of a string token (the text between the quotes) into
 * out. Stores at most cap bytes and reports the decoded length in *outlen.
 */
json_status json_unescape(const char *src, size_t n, char *out, size_t cap, size_t *outlen) {
    size_t i = 0;
    size_t o = 0;

    while (i < n) {
        if (src[i] == '\\') {
            size_t used = 0;
            size_t written = 0;
            json_status st = json_decode_escape(src + i, n - i, out + o, cap - o, &used, &written);

            if (st != JSON_OK) {
                return st;
            }
            i += used;
            o += written;
        } else {
            if (o >= cap) {
                return JSON_ERR_NOMEM;
            }
            out[o++] = src[i++];
        }
    }
    if (outlen != NULL) {
        *outlen = o;
    }
    return JSON_OK;
}

/*
 * Compare string text as written in the document (raw[0..rawlen), with
 * escapes when `escaped` is set) against the plain bytes s[0..len).
 */
int json_text_eq(const char *raw, size_t rawlen, int escaped, const char *s, size_t len) {
    size_t i = 0;
    size_t o = 0;

    if (!escaped) {
        return rawlen == len && json_bytes_eq(raw, s, len);
    }
    while (i < rawlen) {
        if (raw[i] == '\\') {
            char tmp[4];
            size_t used = 0;
            size_t written = 0;

            if (json_decode_escape(raw + i, rawlen - i, tmp, sizeof tmp, &used, &written) != JSON_OK) {
                return 0;
            }
            if (written > len - o || !json_bytes_eq(tmp, s + o, written)) {
                return 0;
            }
            i += used;
            o += written;
        } else {
            if (o >= len || s[o] != raw[i]) {
                return 0;
            }
            i++;
            o++;
        }
    }
    return o == len;
}

/* Does the key of an object member equal key[0..keylen) once escapes are decoded? */
int json_key_eq(const json_doc *doc, const json_node *m, const char *key, size_t keylen) {
    return json_text_eq(doc->src + m->key_off, m->key_len, (m->flags & JSON_F_KEY_ESCAPED) != 0, key, keylen);
}
