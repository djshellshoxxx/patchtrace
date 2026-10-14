/* PatchTrace known-answer corpus: identity-negatives/sharedhelpers, version 3. MIT licence.
 * Shared support library. Every parser in this project calls into it.
 */
#include "shared.h"

/* 0..35 for [0-9a-zA-Z], -1 for anything else. */
int32_t ut_digit_value(int32_t c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Unsigned integer, decimal or 0x-prefixed hexadecimal.
 * Returns the number of characters consumed, or a negative UT_E_* code. */
int32_t ut_parse_u32(const char *s, uint32_t len, uint32_t *out) {
    uint32_t pos = 0u;
    uint32_t radix = 10u;
    uint32_t acc = 0u;
    uint32_t ndig = 0u;

    if (s == NULL || out == NULL || len == 0u) {
        return UT_E_EMPTY;
    }
    if (len > 2u && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        radix = 16u;
        pos = 2u;
    }
    for (; pos < len; pos++) {
        int32_t dv = ut_digit_value((unsigned char)s[pos]);

        if (dv < 0 || (uint32_t)dv >= radix) {
            break;
        }
        if (acc > (0xFFFFFFFFu - (uint32_t)dv) / radix) {
            return UT_E_RANGE;
        }
        acc = acc * radix + (uint32_t)dv;
        ndig++;
    }
    if (ndig == 0u) {
        return UT_E_DIGIT;
    }
    *out = acc;
    return (int32_t)pos;
}

/* Index of the first character that is not blank. */
uint32_t ut_skip_ws(const char *s, uint32_t len) {
    uint32_t i = 0u;

    while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
        i++;
    }
    return i;
}

/* ASCII case-insensitive equality of the first n characters. */
int32_t ut_eq_nocase(const char *a, const char *b, uint32_t n) {
    uint32_t i;

    for (i = 0; i < n; i++) {
        uint8_t ca = (uint8_t)a[i];
        uint8_t cb = (uint8_t)b[i];

        if (ca >= 'A' && ca <= 'Z') {
            ca = (uint8_t)(ca + 32u);
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (uint8_t)(cb + 32u);
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

int32_t ut_find_char(const char *s, uint32_t len, char c) {
    uint32_t i;

    for (i = 0; i < len; i++) {
        if (s[i] == c) {
            return (int32_t)i;
        }
    }
    return -1;
}
