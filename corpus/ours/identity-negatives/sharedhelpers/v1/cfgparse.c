/* PatchTrace known-answer corpus: identity-negatives/sharedhelpers, version 1. MIT licence.
 * Configuration value readers. They use the shared helpers from util.c and nothing else.
 */
#include "shared.h"

/* "250", "250ms" or "2s". */
int32_t cfg_read_timeout_ms(const char *s, uint32_t len, uint32_t *ms) {
    uint32_t pos = ut_skip_ws(s, len);
    uint32_t v, unit;
    int32_t used = ut_parse_u32(s + pos, len - pos, &v);

    if (used < 0) {
        return used;
    }
    pos += (uint32_t)used;
    unit = len - pos;
    if (unit == 0u || (unit == 2u && ut_eq_nocase(s + pos, "ms", 2u))) {
        *ms = v;
    } else if (unit == 1u && ut_eq_nocase(s + pos, "s", 1u)) {
        *ms = v * 1000u;
    } else {
        return CFG_E_VALUE;
    }
    return UT_OK;
}

int32_t cfg_read_retries(const char *s, uint32_t len, uint32_t *n) {
    uint32_t pos = ut_skip_ws(s, len);
    uint32_t v;
    int32_t used = ut_parse_u32(s + pos, len - pos, &v);

    if (used < 0) {
        return used;
    }
    if (v > 10u) {
        return CFG_E_VALUE;
    }
    *n = v;
    return UT_OK;
}

/* Buffer size with an optional k or m suffix. */
int32_t cfg_read_bufsize(const char *s, uint32_t len, uint32_t *bytes) {
    uint32_t pos = ut_skip_ws(s, len);
    uint32_t v;
    uint32_t shift = 0u;
    int32_t used = ut_parse_u32(s + pos, len - pos, &v);

    if (used < 0) {
        return used;
    }
    pos += (uint32_t)used;
    if (pos < len) {
        if (pos + 1u != len) {
            return CFG_E_VALUE;
        }
        if (ut_eq_nocase(s + pos, "k", 1u)) {
            shift = 10u;
        } else if (ut_eq_nocase(s + pos, "m", 1u)) {
            shift = 20u;
        } else {
            return CFG_E_VALUE;
        }
    }
    if (shift != 0u && v > (0xFFFFFFFFu >> shift)) {
        return CFG_E_VALUE;
    }
    *bytes = v << shift;
    return UT_OK;
}

/* debug / info / warn / error, or the numbers 0..3. */
int32_t cfg_read_loglevel(const char *s, uint32_t len, uint32_t *level) {
    uint32_t pos = ut_skip_ws(s, len);
    const char *p = s + pos;
    uint32_t n = len - pos;

    if (n == 5u && ut_eq_nocase(p, "debug", 5u)) {
        *level = 0u;
    } else if (n == 4u && ut_eq_nocase(p, "info", 4u)) {
        *level = 1u;
    } else if (n == 4u && ut_eq_nocase(p, "warn", 4u)) {
        *level = 2u;
    } else if (n == 5u && ut_eq_nocase(p, "error", 5u)) {
        *level = 3u;
    } else {
        uint32_t v;
        int32_t used = ut_parse_u32(p, n, &v);

        if (used < 0 || (uint32_t)used != n || v > 3u) {
            return CFG_E_VALUE;
        }
        *level = v;
    }
    return UT_OK;
}

int32_t cfg_read_bool(const char *s, uint32_t len, uint32_t *flag) {
    uint32_t pos = ut_skip_ws(s, len);
    const char *p = s + pos;
    uint32_t n = len - pos;

    if ((n == 4u && ut_eq_nocase(p, "true", 4u)) || (n == 3u && ut_eq_nocase(p, "yes", 3u)) ||
        (n == 2u && ut_eq_nocase(p, "on", 2u)) || (n == 1u && p[0] == '1')) {
        *flag = 1u;
        return UT_OK;
    }
    if ((n == 5u && ut_eq_nocase(p, "false", 5u)) || (n == 2u && ut_eq_nocase(p, "no", 2u)) ||
        (n == 3u && ut_eq_nocase(p, "off", 3u)) || (n == 1u && p[0] == '0')) {
        *flag = 0u;
        return UT_OK;
    }
    return CFG_E_VALUE;
}
