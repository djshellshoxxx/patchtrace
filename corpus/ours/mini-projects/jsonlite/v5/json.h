/* SPDX-License-Identifier: MIT */
/*
 * jsonlite - a small JSON tokenizer and recursive-descent parser that works
 * entirely over caller-owned buffers.
 *
 *   - Nothing is allocated. The node pool is an array the caller supplies.
 *   - Nothing is copied while parsing. Strings and numbers stay in the source
 *     text; nodes only record offsets into it.
 *   - Output goes to a caller buffer as well (json_writer).
 *   - No C library. This header needs <stddef.h>, <stdint.h>, <stdbool.h>.
 *
 * This is the public header. The tokenizer and parser internals are declared
 * in json_internal.h.
 *
 * Typical use:
 *
 *     json_node pool[128];
 *     json_doc doc;
 *     json_doc_init(&doc, text, text_len, pool, 128);
 *     if (json_parse(&doc) == JSON_OK) {
 *         const json_node *port = json_member(&doc, json_root(&doc), "port", 4);
 *         int64_t value;
 *         if (port != NULL && json_get_int(&doc, port, &value) == JSON_OK) {
 *             ...
 *         }
 *     }
 */
#ifndef JSONLITE_H
#define JSONLITE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* "No node" marker used by every index field of a json_node. */
#define JSON_NIL 0xFFFFFFFFu

/*
 * Containers nested deeper than this are rejected with JSON_ERR_DEPTH. Kept at
 * or below JSON_WRITER_MAX_DEPTH so that every document that parses can also
 * be written back with json_write_node.
 */
#define JSON_DEFAULT_MAX_DEPTH 64u

/* Nesting levels a json_writer can track (one bit each). */
#define JSON_WRITER_MAX_DEPTH 64u

/* json_options.flags */
#define JSON_OPT_COMMENTS 0x01u   /* treat // line and slash-star block comments as whitespace */

/* ------------------------------------------------------------------------ */
/* Status codes. Zero is success; every failure is negative.                 */
/* ------------------------------------------------------------------------ */
typedef enum json_status {
    JSON_OK = 0,
    JSON_ERR_SYNTAX = -1,    /* unexpected character or token */
    JSON_ERR_EOF = -2,       /* input ended inside a value */
    JSON_ERR_NOMEM = -3,     /* node pool or output buffer too small */
    JSON_ERR_STRING = -4,    /* malformed string or escape sequence */
    JSON_ERR_NUMBER = -5,    /* malformed number */
    JSON_ERR_RANGE = -6,     /* value does not fit the requested type */
    JSON_ERR_TRAILING = -7,  /* extra text after the top-level value */
    JSON_ERR_ARG = -8,       /* bad argument (NULL, wrong node type, ...) */
    JSON_ERR_DEPTH = -9,     /* containers nested too deeply */
    JSON_ERR_UTF8 = -10      /* invalid UTF-8 in the input */
} json_status;

/* ------------------------------------------------------------------------ */
/* Document tree                                                             */
/* ------------------------------------------------------------------------ */
typedef enum json_type {
    JSON_NULL = 0,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

#define JSON_F_ESCAPED     0x01u   /* string value contains escapes */
#define JSON_F_KEY_ESCAPED 0x02u   /* the member key contains escapes */
#define JSON_F_INTEGER     0x04u   /* number is an exact integer (ival) */

/*
 * One parsed value. Containers link their children through child/next;
 * object members are value nodes that also carry their key text.
 */
typedef struct json_node {
    uint8_t type;            /* json_type */
    uint8_t flags;           /* JSON_F_* */
    uint16_t reserved;
    uint32_t parent;         /* JSON_NIL for the root */
    uint32_t next;           /* next sibling, or JSON_NIL */
    uint32_t child;          /* first child, or JSON_NIL */
    uint32_t last;           /* last child, or JSON_NIL (append is O(1)) */
    uint32_t count;          /* number of children */
    uint32_t off;            /* value text start in the source */
    uint32_t len;            /* value text length */
    uint32_t key_off;        /* member key text start */
    uint32_t key_len;        /* member key text length */
    int64_t ival;            /* integer value, or the decimal mantissa */
    int32_t exp10;           /* decimal exponent applied to ival */
    int32_t reserved2;
} json_node;

typedef struct json_doc {
    const char *src;
    size_t len;
    json_node *nodes;        /* caller-owned pool */
    uint32_t cap;            /* pool capacity in nodes */
    uint32_t used;           /* nodes handed out so far */
    uint32_t root;           /* index of the top-level value */
    json_status status;      /* result of the last json_parse */
    size_t err_pos;          /* byte offset of the last error */
    uint32_t max_depth;      /* nesting limit, JSON_DEFAULT_MAX_DEPTH unless changed */
} json_doc;

/* Parser settings for json_parse_ex; json_options_default fills in the defaults. */
typedef struct json_options {
    uint32_t max_depth;      /* containers nested deeper than this fail with JSON_ERR_DEPTH */
    uint32_t flags;          /* JSON_OPT_* */
} json_options;

/*
 * Serializer state. first_bits has one bit per open container (bit depth-1);
 * a set bit means "no element written yet, so no comma is needed".
 */
typedef struct json_writer {
    char *buf;
    size_t cap;
    size_t len;
    json_status err;         /* first failure; later calls become no-ops */
    uint32_t depth;
    uint32_t after_key;      /* a member key was just written */
    uint64_t first_bits;
    uint32_t max_depth;      /* nesting limit, JSON_WRITER_MAX_DEPTH */
} json_writer;

typedef struct json_stats {
    uint32_t nodes;
    uint32_t objects;
    uint32_t arrays;
    uint32_t strings;
    uint32_t numbers;
    uint32_t literals;       /* true, false, null */
    uint32_t max_depth;
    size_t string_bytes;
} json_stats;

/* ------------------------------------------------------------------------ */
/* json_parse.c - setup and parsing                                          */
/* ------------------------------------------------------------------------ */
void json_doc_init(json_doc *doc, const char *src, size_t len, json_node *nodes, uint32_t cap);
const char *json_error_string(json_status st);
void json_options_default(json_options *opt);
json_status json_parse_ex(json_doc *doc, const json_options *opt);
json_status json_parse(json_doc *doc);
void json_doc_error_position(const json_doc *doc, uint32_t *line, uint32_t *col);

/* ------------------------------------------------------------------------ */
/* json_str.c - hex, UTF-8, escapes                                          */
/* ------------------------------------------------------------------------ */
int json_hex_digit(char c);
json_status json_hex4(const char *s, size_t n, uint32_t *out);
size_t json_utf8_encode(uint32_t cp, char *out, size_t cap);
size_t json_utf8_seq_len(const char *s, size_t n);
json_status json_decode_escape(const char *src, size_t n, char *out, size_t cap, size_t *used, size_t *written);
json_status json_unescape(const char *src, size_t n, char *out, size_t cap, size_t *outlen);
int json_text_eq(const char *raw, size_t rawlen, int escaped, const char *s, size_t len);
int json_key_eq(const json_doc *doc, const json_node *m, const char *key, size_t keylen);

/* ------------------------------------------------------------------------ */
/* json_util.c - numbers and tree access                                     */
/* ------------------------------------------------------------------------ */
json_status json_parse_int(const char *s, size_t n, int64_t *out);
json_status json_number_value(const char *s, size_t n, int64_t *mant, int32_t *exp10, uint32_t *flags);
int json_mem_eq(const char *a, const char *b, size_t n);

const json_node *json_root(const json_doc *doc);
const json_node *json_member(const json_doc *doc, const json_node *obj, const char *key, size_t keylen);
const json_node *json_element(const json_doc *doc, const json_node *arr, uint32_t index);
int json_path_next(const char *path, size_t plen, size_t *pos, const char **seg, size_t *seglen, bool *is_index,
                   uint32_t *index);
const json_node *json_get_path(const json_doc *doc, const json_node *start, const char *path, size_t plen);
uint32_t json_length(const json_node *n);
json_status json_get_int(const json_doc *doc, const json_node *n, int64_t *out);
json_status json_get_bool(const json_node *n, bool *out);
json_status json_get_string(const json_doc *doc, const json_node *n, char *out, size_t cap, size_t *outlen);
int json_str_eq(const json_doc *doc, const json_node *n, const char *s, size_t len);

uint32_t json_node_depth(const json_doc *doc, const json_node *n);
uint32_t json_u32_digits(uint32_t v);
void json_u32_write(char *out, uint32_t v, uint32_t ndigits);
size_t json_node_path(const json_doc *doc, const json_node *n, char *out, size_t cap);
void json_doc_stats(const json_doc *doc, json_stats *st);

/* ------------------------------------------------------------------------ */
/* json_write.c - serializer                                                 */
/* ------------------------------------------------------------------------ */
void json_w_init(json_writer *w, char *buf, size_t cap);
json_status json_w_putc(json_writer *w, char c);
json_status json_w_puts(json_writer *w, const char *s, size_t n);
json_status json_w_comma(json_writer *w);
json_status json_w_begin(json_writer *w, char open);
json_status json_w_end(json_writer *w, char close);
json_status json_w_begin_object(json_writer *w);
json_status json_w_end_object(json_writer *w);
json_status json_w_begin_array(json_writer *w);
json_status json_w_end_array(json_writer *w);
json_status json_w_escaped(json_writer *w, const char *s, size_t n);
json_status json_w_key(json_writer *w, const char *key, size_t n);
json_status json_w_key_raw(json_writer *w, const char *key, size_t n);
json_status json_w_string(json_writer *w, const char *s, size_t n);
json_status json_w_raw_string(json_writer *w, const char *s, size_t n);
json_status json_w_null(json_writer *w);
json_status json_w_bool(json_writer *w, bool v);
json_status json_w_int(json_writer *w, int64_t v);
json_status json_w_number_text(json_writer *w, const char *s, size_t n);
size_t json_w_length(const json_writer *w);
json_status json_w_finish(json_writer *w);
json_status json_write_node(json_writer *w, const json_doc *doc, const json_node *n);

#endif /* JSONLITE_H */
