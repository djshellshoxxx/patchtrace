/* PatchTrace known-answer corpus: identity-negatives/sharedhelpers, version 1. MIT licence.
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
    uint32_t i = 0u;
    uint32_t base = 10u;
    uint32_t value = 0u;
    uint32_t digits = 0u;

    if (s == NULL || out == NULL || len == 0u) {
        return UT_E_EMPTY;
    }
    if (len > 2u && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16u;
        i = 2u;
    }
    for (; i < len; i++) {
        int32_t d = ut_digit_value((unsigned char)s[i]);

        if (d < 0 || (uint32_t)d >= base) {
            break;
        }
        value = value * base + (uint32_t)d;
        digits++;
    }
    if (digits == 0u) {
        return UT_E_DIGIT;
    }
    *out = value;
    return (int32_t)i;
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
        if ((uint8_t)(a[i] | 0x20) != (uint8_t)(b[i] | 0x20)) {
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
