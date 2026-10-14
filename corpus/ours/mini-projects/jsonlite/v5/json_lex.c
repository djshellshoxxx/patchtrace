/* SPDX-License-Identifier: MIT */
/*
 * json_lex.c - the jsonlite tokenizer.
 *
 * The lexer is a plain cursor over the caller's text. It never allocates and
 * never copies: a token is a byte range [start, end) of the source, and the
 * parser reads values straight out of that range later.
 */
#include "json_internal.h"

/* Reset a lexer to the start of a buffer. */
void json_lex_init(json_lexer *lx, const char *src, size_t len) {
    lx->src = src;
    lx->len = len;
    lx->pos = 0;
    lx->err = JSON_OK;
    lx->flags = 0;
}

/* Remember a lexical error and hand it back, so callers can `return json_lex_fail(...)`. */
json_status json_lex_fail(json_lexer *lx, json_status st) {
    if (lx->err == JSON_OK) {
        lx->err = st;
    }
    return st;
}

/* The four whitespace characters JSON allows between tokens. */
int json_is_ws(char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

int json_is_digit(char c) {
    return c >= '0' && c <= '9';
}

/*
 * Skip one comment if the cursor is on one (// to the end of the line, or a
 * block comment). Returns 1 when a comment was consumed, 0 otherwise. An
 * unterminated block comment records JSON_ERR_EOF.
 */
int json_lex_comment(json_lexer *lx) {
    size_t i = lx->pos;

    if (i + 1 >= lx->len || lx->src[i] != '/') {
        return 0;
    }
    if (lx->src[i + 1] == '/') {
        i += 2;
        while (i < lx->len && lx->src[i] != '\n') {
            i++;
        }
        lx->pos = i;
        return 1;
    }
    if (lx->src[i + 1] == '*') {
        i += 2;
        while (i + 1 < lx->len && !(lx->src[i] == '*' && lx->src[i + 1] == '/')) {
            i++;
        }
        if (i + 1 >= lx->len) {
            lx->pos = lx->len;
            json_lex_fail(lx, JSON_ERR_EOF);
            return 0;
        }
        lx->pos = i + 2;
        return 1;
    }
    return 0;
}

/* Advance the cursor over insignificant whitespace (and comments, when enabled). */
void json_lex_skip_ws(json_lexer *lx) {
    for (;;) {
        while (lx->pos < lx->len && json_is_ws(lx->src[lx->pos])) {
            lx->pos++;
        }
        if (!(lx->flags & JSON_OPT_COMMENTS) || !json_lex_comment(lx)) {
            return;
        }
    }
}

/* First index at or after i that is not a decimal digit. */
size_t json_lex_digits(const json_lexer *lx, size_t i) {
    while (i < lx->len && json_is_digit(lx->src[i])) {
        i++;
    }
    return i;
}

/* Match the exact keyword word[0..n) at the cursor (true, false or null). */
json_status json_lex_literal(json_lexer *lx, json_tok *t, const char *word, size_t n, json_tok_kind kind) {
    size_t k;

    if (lx->len - lx->pos < n) {
        return json_lex_fail(lx, JSON_ERR_SYNTAX);
    }
    for (k = 0; k < n; k++) {
        if (lx->src[lx->pos + k] != word[k]) {
            return json_lex_fail(lx, JSON_ERR_SYNTAX);
        }
    }
    t->kind = kind;
    t->start = lx->pos;
    t->end = lx->pos + n;
    t->flags = 0;
    lx->pos += n;
    return JSON_OK;
}

/*
 * Scan a number: -?(0|[1-9]digits*)(.digits+)?([eE][+-]?digits+)?
 * Only the extent and the shape flags are recorded here; the value itself is
 * converted by the parser (json_number_value).
 */
json_status json_lex_number(json_lexer *lx, json_tok *t) {
    size_t i = lx->pos;
    size_t first;
    size_t mark;
    uint32_t flags = 0;

    t->start = i;
    if (i < lx->len && lx->src[i] == '-') {
        flags |= JSON_TF_NEGATIVE;
        i++;
    }
    first = i;
    i = json_lex_digits(lx, i);
    if (i == first) {
        return json_lex_fail(lx, JSON_ERR_NUMBER);
    }
    if (lx->src[first] == '0' && i - first > 1) {
        return json_lex_fail(lx, JSON_ERR_NUMBER);
    }
    if (i < lx->len && lx->src[i] == '.') {
        flags |= JSON_TF_FRACTION;
        mark = i + 1;
        i = json_lex_digits(lx, mark);
        if (i == mark) {
            return json_lex_fail(lx, JSON_ERR_NUMBER);
        }
    }
    if (i < lx->len && (lx->src[i] == 'e' || lx->src[i] == 'E')) {
        flags |= JSON_TF_EXPONENT;
        i++;
        if (i < lx->len && (lx->src[i] == '+' || lx->src[i] == '-')) {
            i++;
        }
        mark = i;
        i = json_lex_digits(lx, mark);
        if (i == mark) {
            return json_lex_fail(lx, JSON_ERR_NUMBER);
        }
    }
    t->kind = JSON_TOK_NUMBER;
    t->end = i;
    t->flags = flags;
    lx->pos = i;
    return JSON_OK;
}

/*
 * Validate the escape sequence whose first character (the one after the
 * backslash) is at *pos. On success *pos is left on the last character of the
 * escape, so the caller's normal "step to the next character" lands after it.
 */
json_status json_lex_escape(json_lexer *lx, size_t *pos) {
    size_t i = *pos;
    size_t k;

    if (i >= lx->len) {
        return json_lex_fail(lx, JSON_ERR_EOF);
    }
    switch (lx->src[i]) {
    case '"':
    case '\\':
    case '/':
    case 'b':
    case 'f':
    case 'n':
    case 'r':
    case 't':
        break;
    case 'u':
        if (lx->len - i < 5) {
            return json_lex_fail(lx, JSON_ERR_EOF);
        }
        for (k = 1; k <= 4; k++) {
            if (json_hex_digit(lx->src[i + k]) < 0) {
                return json_lex_fail(lx, JSON_ERR_STRING);
            }
        }
        i += 4;
        break;
    default:
        return json_lex_fail(lx, JSON_ERR_STRING);
    }
    *pos = i;
    return JSON_OK;
}

/*
 * Byte classes for string scanning: JSON_SC_PLAIN bytes can be skipped without
 * a second look, the other classes need individual handling.
 */
const unsigned char json_str_class[256] = {
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  /* 0x00 */
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  /* 0x10 */
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x20 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x30 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x40 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,  /* 0x50 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x60 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x70 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0x80 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0x90 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0xA0 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0xB0 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0xC0 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0xD0 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  /* 0xE0 */
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4   /* 0xF0 */
};

/* Assemble eight bytes into a word (byte 0 lowest); the compiler turns this into one load. */
uint64_t json_load64(const unsigned char *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/*
 * Nonzero when any of the eight bytes in w needs individual handling inside a
 * string: below 0x20, a quote, a backslash, or 0x80 and above. Uses the usual
 * "has byte less than n" and "has zero byte" tricks, so it is exact about
 * whether such a byte exists, though not about where.
 */
uint64_t json_str_special(uint64_t w) {
    const uint64_t ones = 0x0101010101010101ull;
    const uint64_t highs = 0x8080808080808080ull;
    uint64_t quote = w ^ (ones * 0x22u);
    uint64_t slash = w ^ (ones * 0x5Cu);

    return ((w - ones * 0x20u) & ~w & highs) | ((quote - ones) & ~quote & highs) | ((slash - ones) & ~slash & highs) |
           (w & highs);
}

/*
 * Scan a string. On entry the cursor is on the opening quote. The token covers
 * the text between the quotes; escapes are validated here but decoded later.
 * Runs of plain bytes are skipped eight at a time, then by table lookup.
 */
json_status json_lex_string(json_lexer *lx, json_tok *t) {
    const unsigned char *s = (const unsigned char *)lx->src;
    size_t n = lx->len;
    size_t i = lx->pos + 1;
    uint32_t flags = 0;

    t->start = i;
    for (;;) {
        while (i + 8 <= n && json_str_special(json_load64(s + i)) == 0) {
            i += 8;
        }
        while (i < n && json_str_class[s[i]] == JSON_SC_PLAIN) {
            i++;
        }
        if (i >= n) {
            break;
        }
        switch (json_str_class[s[i]]) {
        case JSON_SC_QUOTE:
            t->kind = JSON_TOK_STRING;
            t->end = i;
            t->flags = flags;
            lx->pos = i + 1;
            return JSON_OK;
        case JSON_SC_BACKSLASH: {
            json_status st;

            flags |= JSON_TF_ESCAPED;
            i++;
            st = json_lex_escape(lx, &i);
            if (st != JSON_OK) {
                return st;
            }
            i++;
            break;
        }
        case JSON_SC_CONTROL:
            return json_lex_fail(lx, JSON_ERR_STRING);
        default: {
            size_t seq = json_utf8_seq_len(lx->src + i, n - i);

            if (seq == 0) {
                return json_lex_fail(lx, JSON_ERR_UTF8);
            }
            i += seq;
            break;
        }
        }
    }
    return json_lex_fail(lx, JSON_ERR_EOF);
}

/* Emit a one-character punctuation token and step over it. */
json_status json_lex_punct(json_lexer *lx, json_tok *t, json_tok_kind kind) {
    t->kind = kind;
    t->start = lx->pos;
    t->end = lx->pos + 1;
    t->flags = 0;
    lx->pos++;
    return JSON_OK;
}

/* Produce the next token. End of input is a normal JSON_TOK_EOF token. */
json_status json_lex_next(json_lexer *lx, json_tok *t) {
    char c;

    json_lex_skip_ws(lx);
    if (lx->err != JSON_OK) {
        return lx->err;
    }
    t->start = lx->pos;
    t->end = lx->pos;
    t->flags = 0;
    if (lx->pos >= lx->len) {
        t->kind = JSON_TOK_EOF;
        return JSON_OK;
    }
    c = lx->src[lx->pos];
    switch (c) {
    case '{':
        return json_lex_punct(lx, t, JSON_TOK_LBRACE);
    case '}':
        return json_lex_punct(lx, t, JSON_TOK_RBRACE);
    case '[':
        return json_lex_punct(lx, t, JSON_TOK_LBRACKET);
    case ']':
        return json_lex_punct(lx, t, JSON_TOK_RBRACKET);
    case ':':
        return json_lex_punct(lx, t, JSON_TOK_COLON);
    case ',':
        return json_lex_punct(lx, t, JSON_TOK_COMMA);
    case '"':
        return json_lex_string(lx, t);
    case 't':
        return json_lex_literal(lx, t, "true", 4, JSON_TOK_TRUE);
    case 'f':
        return json_lex_literal(lx, t, "false", 5, JSON_TOK_FALSE);
    case 'n':
        return json_lex_literal(lx, t, "null", 4, JSON_TOK_NULL);
    default:
        break;
    }
    if (c == '-' || json_is_digit(c)) {
        return json_lex_number(lx, t);
    }
    return json_lex_fail(lx, JSON_ERR_SYNTAX);
}

/* Printable token names for diagnostics. */
const char *json_tok_name(json_tok_kind kind) {
    switch (kind) {
    case JSON_TOK_EOF:      return "end of input";
    case JSON_TOK_LBRACE:   return "'{'";
    case JSON_TOK_RBRACE:   return "'}'";
    case JSON_TOK_LBRACKET: return "'['";
    case JSON_TOK_RBRACKET: return "']'";
    case JSON_TOK_COLON:    return "':'";
    case JSON_TOK_COMMA:    return "','";
    case JSON_TOK_STRING:   return "string";
    case JSON_TOK_NUMBER:   return "number";
    case JSON_TOK_TRUE:     return "true";
    case JSON_TOK_FALSE:    return "false";
    case JSON_TOK_NULL:     return "null";
    case JSON_TOK_ERROR:    return "error";
    }
    return "?";
}

/* Convert a byte offset into a 1-based line and column (for error messages). */
void json_offset_position(const char *src, size_t len, size_t pos, uint32_t *line, uint32_t *col) {
    uint32_t l = 1;
    uint32_t c = 1;
    size_t i;

    if (pos > len) {
        pos = len;
    }
    for (i = 0; i < pos; i++) {
        if (src[i] == '\n') {
            l++;
            c = 1;
        } else {
            c++;
        }
    }
    *line = l;
    *col = c;
}
