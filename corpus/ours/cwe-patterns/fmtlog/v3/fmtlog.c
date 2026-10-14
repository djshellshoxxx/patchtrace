/* fmtlog.c - pstring formatter and line logger (v3).
 *
 * lf_format() renders a pstring format with C varargs into a bounded character buffer and always
 * terminates it. The logger keeps rendered lines back to back in the caller's byte array.
 */
#include "fmtlog.h"

/* ---- pstrings ----------------------------------------------------------- */

uint32_t lf_str_len(const uint8_t *ps) {
    return ps[0];
}

const uint8_t *lf_str_data(const uint8_t *ps) {
    return ps + 1;
}

/* Build a pstring from a C string (at most 255 characters); returns the bytes written or -1. */
int lf_pack(uint8_t *dst, uint32_t cap, const char *text) {
    uint32_t len = 0;
    uint32_t k = 0;
    while (text[len] != '\0') {
        len++;
    }
    if (len > 255u || len + 1u > cap) {
        return LF_ERR_RANGE;
    }
    dst[0] = (uint8_t)len;
    while (k < len) {
        dst[1u + k] = (uint8_t)text[k];
        k++;
    }
    return (int)(len + 1u);
}

char lf_hex_digit(uint32_t v) {
    if (v < 10u) {
        return (char)('0' + v);
    }
    return (char)('a' + (v - 10u));
}

/* ---- formatter ---------------------------------------------------------- */

/* Store one character if it fits; always leave room for the terminator. */
void lf_put(lf_sink *s, char c) {
    if (s->len + 1u >= s->cap) {
        s->dropped++;
        return;
    }
    s->out[s->len++] = c;
}

void lf_emit_ps(lf_sink *s, const uint8_t *ps) {
    uint32_t n;
    uint32_t i;
    if (ps == NULL) {
        const char *none = "(null)";
        for (i = 0; none[i] != '\0'; i++) {
            lf_put(s, none[i]);
        }
        return;
    }
    n = lf_str_len(ps);
    for (i = 0; i < n; i++) {
        lf_put(s, (char)lf_str_data(ps)[i]);
    }
}

void lf_emit_u32(lf_sink *s, uint32_t value, uint32_t base) {
    char digits[32];
    uint32_t count = 0;
    if (value == 0) {
        lf_put(s, '0');
        return;
    }
    while (value != 0) {
        digits[count++] = lf_hex_digit(value % base);
        value /= base;
    }
    while (count > 0) {
        lf_put(s, digits[--count]);
    }
}

void lf_emit_i32(lf_sink *s, int32_t value) {
    uint32_t magnitude = (uint32_t)value;
    if (value < 0) {
        lf_put(s, '-');
        magnitude = (uint32_t)0 - magnitude;
    }
    lf_emit_u32(s, magnitude, 10);
}

/* Render `fmt` with the arguments in `ap`; returns the number of characters stored. */
int lf_vformat(char *out, uint32_t cap, const uint8_t *fmt, va_list ap) {
    lf_sink dst;
    uint32_t n;
    uint32_t i;
    if (out == NULL || cap == 0 || fmt == NULL) {
        return LF_ERR_ARG;
    }
    dst.dropped = 0;
    dst.len = 0;
    dst.cap = cap;
    dst.out = out;
    n = lf_str_len(fmt);
    for (i = 0; i < n; i++) {
        char ch = (char)lf_str_data(fmt)[i];
        if (ch != '%') {
            lf_put(&dst, ch);
            continue;
        }
        i++;
        if (i >= n) {
            break;
        }
        ch = (char)lf_str_data(fmt)[i];
        switch (ch) {
        case '%':
            lf_put(&dst, '%');
            break;
        case 's':
            lf_emit_ps(&dst, va_arg(ap, const uint8_t *));
            break;
        case 'c':
            lf_put(&dst, (char)va_arg(ap, int));
            break;
        case 'x':
            lf_emit_u32(&dst, va_arg(ap, uint32_t), 16);
            break;
        case 'u':
            lf_emit_u32(&dst, va_arg(ap, uint32_t), 10);
            break;
        case 'd':
            lf_emit_i32(&dst, va_arg(ap, int32_t));
            break;
        default:
            lf_put(&dst, '%');
            lf_put(&dst, ch);
            break;
        }
    }
    dst.out[dst.len] = '\0';
    return (int)dst.len;
}

int lf_format(char *out, uint32_t cap, const uint8_t *fmt, ...) {
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = lf_vformat(out, cap, fmt, ap);
    va_end(ap);
    return n;
}

/* ---- logger ------------------------------------------------------------- */

int lf_log_init(lf_log *log, uint8_t *storage, uint32_t bytes) {
    if (log == NULL || storage == NULL || bytes < 4) {
        return LF_ERR_ARG;
    }
    log->dropped = 0;
    log->lines = 0;
    log->used = 0;
    log->cap = bytes;
    log->buf = storage;
    return LF_OK;
}

/* ---- counters ----------------------------------------------------------- */

uint32_t lf_log_count(const lf_log *log) {
    return log->lines;
}

uint32_t lf_log_bytes(const lf_log *log) {
    return log->used;
}

uint32_t lf_stat_dropped(const lf_log *log) {
    return log->dropped;
}

/* Store one rendered line; text longer than 255 characters is cut. */
int lf_log_append(lf_log *log, uint8_t level, const char *text, uint32_t len) {
    uint32_t at;
    uint32_t k;
    if (len > 255u) {
        len = 255u;
    }
    if (log->used + 2u + len > log->cap) {
        log->dropped++;
        return LF_ERR_FULL;
    }
    at = log->used;
    log->buf[at] = level;
    log->buf[at + 1u] = (uint8_t)len;
    for (k = 0; k < len; k++) {
        log->buf[at + 2u + k] = (uint8_t)text[k];
    }
    log->used += 2u + len;
    log->lines++;
    return LF_OK;
}

/* Number of conversion directives in a format (a "%%" pair is not a directive). */
uint32_t lf_count_directives(const uint8_t *fmt) {
    uint32_t n = lf_str_len(fmt);
    uint32_t count = 0;
    uint32_t i;
    for (i = 0; i + 1u < n; i++) {
        if (lf_str_data(fmt)[i] == '%') {
            if (lf_str_data(fmt)[i + 1u] != '%') {
                count++;
            }
            i++;
        }
    }
    return count;
}

/* Log an event message received from a peer. The message is data, never a format: it is
 * rendered through a constant "%s" format so its own '%' characters stay literal. */
int lf_log_event(lf_log *log, uint8_t level, const uint8_t *msg) {
    const uint8_t plain[] = {2, '%', 's'};
    char line[LF_LINE_MAX];
    int n;
    if (log == NULL || msg == NULL) {
        return LF_ERR_ARG;
    }
    n = lf_format(line, sizeof line, plain, msg);
    if (n < 0) {
        return n;
    }
    return lf_log_append(log, level, line, (uint32_t)n);
}

/* Log a line built from the caller's own format string. */
int lf_log_fmt(lf_log *log, uint8_t level, const uint8_t *fmt, ...) {
    char line[LF_LINE_MAX];
    va_list ap;
    int n;
    if (log == NULL || fmt == NULL) {
        return LF_ERR_ARG;
    }
    va_start(ap, fmt);
    n = lf_vformat(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return n;
    }
    return lf_log_append(log, level, line, (uint32_t)n);
}

/* Log "<label>: <value>". */
int lf_log_u32(lf_log *log, uint8_t level, const uint8_t *label, uint32_t value) {
    const uint8_t fmt[] = {6, '%', 's', ':', ' ', '%', 'u'};
    return lf_log_fmt(log, level, fmt, label, value);
}

/* Copy line `index` (0 = oldest) into `out` as a C string; returns its length. */
int lf_log_read(const lf_log *log, uint32_t index, uint8_t *level, char *out, uint32_t cap) {
    uint32_t pos = 0;
    uint32_t line;
    uint32_t size;
    for (line = 0; line < log->lines; line++) {
        size = log->buf[pos + 1u];
        if (line == index) {
            uint32_t k;
            if (size + 1u > cap) {
                return LF_ERR_RANGE;
            }
            *level = log->buf[pos];
            for (k = 0; k < size; k++) {
                out[k] = (char)log->buf[pos + 2u + k];
            }
            out[size] = '\0';
            return (int)size;
        }
        pos += 2u + size;
    }
    return LF_ERR_RANGE;
}

void lf_log_clear(lf_log *log) {
    log->lines = 0;
    log->used = 0;
}

const char *lf_level_name(uint8_t level) {
    switch (level) {
    case LF_ERROR:
        return "error";
    case LF_WARN:
        return "warn";
    case LF_INFO:
        return "info";
    case LF_DEBUG:
        return "debug";
    default:
        return "?";
    }
}
