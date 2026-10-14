/* fmtlog.c - pstring formatter and line logger (v1).
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
    uint32_t n = 0;
    while (text[n] != '\0') {
        n++;
    }
    if (n > 255u || n + 1u > cap) {
        return LF_ERR_RANGE;
    }
    dst[0] = (uint8_t)n;
    for (uint32_t i = 0; i < n; i++) {
        dst[1u + i] = (uint8_t)text[i];
    }
    return (int)(n + 1u);
}

char lf_hex_digit(uint32_t v) {
    return (char)(v < 10u ? '0' + v : 'a' + (v - 10u));
}

/* ---- formatter ---------------------------------------------------------- */

/* Store one character if it fits; always leave room for the terminator. */
void lf_put(lf_sink *s, char c) {
    if (s->len + 1u < s->cap) {
        s->out[s->len++] = c;
    } else {
        s->dropped++;
    }
}

void lf_emit_ps(lf_sink *s, const uint8_t *ps) {
    uint32_t n;
    uint32_t i;
    if (ps == NULL) {
        lf_put(s, '(');
        lf_put(s, 'n');
        lf_put(s, 'u');
        lf_put(s, 'l');
        lf_put(s, 'l');
        lf_put(s, ')');
        return;
    }
    n = lf_str_len(ps);
    for (i = 0; i < n; i++) {
        lf_put(s, (char)lf_str_data(ps)[i]);
    }
}

void lf_emit_u32(lf_sink *s, uint32_t value, uint32_t base) {
    char digits[32];
    uint32_t n = 0;
    if (value == 0) {
        lf_put(s, '0');
        return;
    }
    while (value != 0) {
        digits[n++] = lf_hex_digit(value % base);
        value /= base;
    }
    while (n > 0) {
        lf_put(s, digits[--n]);
    }
}

void lf_emit_i32(lf_sink *s, int32_t value) {
    if (value < 0) {
        lf_put(s, '-');
        lf_emit_u32(s, (uint32_t)0 - (uint32_t)value, 10);
    } else {
        lf_emit_u32(s, (uint32_t)value, 10);
    }
}

/* Render `fmt` with the arguments in `ap`; returns the number of characters stored. */
int lf_vformat(char *out, uint32_t cap, const uint8_t *fmt, va_list ap) {
    lf_sink sink;
    uint32_t n;
    uint32_t i;
    if (out == NULL || cap == 0 || fmt == NULL) {
        return LF_ERR_ARG;
    }
    sink.out = out;
    sink.cap = cap;
    sink.len = 0;
    sink.dropped = 0;
    n = lf_str_len(fmt);
    for (i = 0; i < n; i++) {
        char c = (char)lf_str_data(fmt)[i];
        if (c != '%') {
            lf_put(&sink, c);
            continue;
        }
        i++;
        if (i >= n) {
            break;
        }
        c = (char)lf_str_data(fmt)[i];
        switch (c) {
        case 'd':
            lf_emit_i32(&sink, va_arg(ap, int32_t));
            break;
        case 'u':
            lf_emit_u32(&sink, va_arg(ap, uint32_t), 10);
            break;
        case 'x':
            lf_emit_u32(&sink, va_arg(ap, uint32_t), 16);
            break;
        case 'c':
            lf_put(&sink, (char)va_arg(ap, int));
            break;
        case 's':
            lf_emit_ps(&sink, va_arg(ap, const uint8_t *));
            break;
        case '%':
            lf_put(&sink, '%');
            break;
        default:
            lf_put(&sink, '%');
            lf_put(&sink, c);
            break;
        }
    }
    sink.out[sink.len] = '\0';
    return (int)sink.len;
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
    log->buf = storage;
    log->cap = bytes;
    log->used = 0;
    log->lines = 0;
    log->dropped = 0;
    return LF_OK;
}

/* Store one rendered line; text longer than 255 characters is cut. */
int lf_log_append(lf_log *log, uint8_t level, const char *text, uint32_t len) {
    uint32_t i;
    if (len > 255u) {
        len = 255u;
    }
    if (log->used + 2u + len > log->cap) {
        log->dropped++;
        return LF_ERR_FULL;
    }
    log->buf[log->used] = level;
    log->buf[log->used + 1u] = (uint8_t)len;
    for (i = 0; i < len; i++) {
        log->buf[log->used + 2u + i] = (uint8_t)text[i];
    }
    log->used += 2u + len;
    log->lines++;
    return LF_OK;
}

/* Log an event message received from a peer. */
int lf_log_event(lf_log *log, uint8_t level, const uint8_t *msg) {
    char line[LF_LINE_MAX];
    int n;
    if (log == NULL || msg == NULL) {
        return LF_ERR_ARG;
    }
    n = lf_format(line, sizeof line, msg);
    if (n < 0) {
        return n;
    }
    return lf_log_append(log, level, line, (uint32_t)n);
}

/* Older name for lf_log_event(). */
int lf_log_msg(lf_log *log, uint8_t level, const uint8_t *msg) {
    return lf_log_event(log, level, msg);
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

uint32_t lf_log_count(const lf_log *log) {
    return log->lines;
}

/* Copy line `index` (0 = oldest) into `out` as a C string; returns its length. */
int lf_log_read(const lf_log *log, uint32_t index, uint8_t *level, char *out, uint32_t cap) {
    uint32_t pos = 0;
    uint32_t i;
    uint32_t len;
    for (i = 0; i < log->lines; i++) {
        len = log->buf[pos + 1u];
        if (i == index) {
            uint32_t j;
            if (len + 1u > cap) {
                return LF_ERR_RANGE;
            }
            *level = log->buf[pos];
            for (j = 0; j < len; j++) {
                out[j] = (char)log->buf[pos + 2u + j];
            }
            out[len] = '\0';
            return (int)len;
        }
        pos += 2u + len;
    }
    return LF_ERR_RANGE;
}

void lf_log_clear(lf_log *log) {
    log->used = 0;
    log->lines = 0;
}

uint32_t lf_log_bytes(const lf_log *log) {
    return log->used;
}

uint32_t lf_stat_dropped(const lf_log *log) {
    return log->dropped;
}

const char *lf_level_name(uint8_t level) {
    switch (level) {
    case LF_DEBUG:
        return "debug";
    case LF_INFO:
        return "info";
    case LF_WARN:
        return "warn";
    case LF_ERROR:
        return "error";
    default:
        return "?";
    }
}
