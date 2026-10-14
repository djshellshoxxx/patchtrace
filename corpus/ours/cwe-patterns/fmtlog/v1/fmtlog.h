/* fmtlog.h - length-prefixed strings, a small printf-style formatter and a line logger.
 *
 * A "pstring" is one length byte followed by that many characters (no terminator). Format strings are
 * pstrings; the directives are %d %u %x %c %s (a pstring argument) and %%.
 * The logger stores lines as [level][len][text] in a caller-provided byte array.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef FMTLOG_H
#define FMTLOG_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define LF_LINE_MAX 128u

#define LF_OK 0
#define LF_ERR_ARG (-1)
#define LF_ERR_FULL (-2)
#define LF_ERR_RANGE (-3)

#define LF_DEBUG 0u
#define LF_INFO 1u
#define LF_WARN 2u
#define LF_ERROR 3u

typedef struct lf_sink {
    char *out;
    uint32_t cap;     /* bytes available, including the terminator */
    uint32_t len;     /* characters stored so far */
    uint32_t dropped; /* characters that did not fit */
} lf_sink;

typedef struct lf_log {
    uint8_t *buf;     /* caller-provided storage */
    uint32_t cap;
    uint32_t used;
    uint32_t lines;
    uint32_t dropped; /* lines that did not fit */
} lf_log;

/* pstrings */
uint32_t lf_str_len(const uint8_t *ps);
const uint8_t *lf_str_data(const uint8_t *ps);
int lf_pack(uint8_t *dst, uint32_t cap, const char *text);
char lf_hex_digit(uint32_t v);

/* formatter */
void lf_put(lf_sink *s, char c);
void lf_emit_ps(lf_sink *s, const uint8_t *ps);
void lf_emit_u32(lf_sink *s, uint32_t value, uint32_t base);
void lf_emit_i32(lf_sink *s, int32_t value);
int lf_vformat(char *out, uint32_t cap, const uint8_t *fmt, va_list ap);
int lf_format(char *out, uint32_t cap, const uint8_t *fmt, ...);

/* logger */
int lf_log_init(lf_log *log, uint8_t *storage, uint32_t bytes);
int lf_log_append(lf_log *log, uint8_t level, const char *text, uint32_t len);
int lf_log_event(lf_log *log, uint8_t level, const uint8_t *msg);
int lf_log_msg(lf_log *log, uint8_t level, const uint8_t *msg);
int lf_log_fmt(lf_log *log, uint8_t level, const uint8_t *fmt, ...);
int lf_log_u32(lf_log *log, uint8_t level, const uint8_t *label, uint32_t value);
uint32_t lf_log_count(const lf_log *log);
int lf_log_read(const lf_log *log, uint32_t index, uint8_t *level, char *out, uint32_t cap);
void lf_log_clear(lf_log *log);
uint32_t lf_log_bytes(const lf_log *log);
uint32_t lf_stat_dropped(const lf_log *log);
const char *lf_level_name(uint8_t level);

#endif /* FMTLOG_H */
