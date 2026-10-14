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

/* Advance the cursor over insignificant whitespace. */
void json_lex_skip_ws(json_lexer *lx) {
    while (lx->pos < lx->len && json_is_ws(lx->src[lx->pos])) {
        lx->pos++;
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
 * Scan a string. On entry the cursor is on the opening quote. The token covers
 * the text between the quotes; escapes are validated here but decoded later.
 */
json_status json_lex_string(json_lexer *lx, json_tok *t) {
    size_t i = lx->pos + 1;
    uint32_t flags = 0;

    t->start = i;
    while (i < lx->len) {
        unsigned char c = (unsigned char)lx->src[i];

        if (c == '"') {
            t->kind = JSON_TOK_STRING;
            t->end = i;
            t->flags = flags;
            lx->pos = i + 1;
            return JSON_OK;
        }
        if (c < 0x20) {
            return json_lex_fail(lx, JSON_ERR_STRING);
        }
        if (c >= 0x80) {
            size_t seq = json_utf8_seq_len(lx->src + i, lx->len - i);

            if (seq == 0) {
                return json_lex_fail(lx, JSON_ERR_UTF8);
            }
            i += seq;
            continue;
        }
        if (c == '\\') {
            json_status st;

            flags |= JSON_TF_ESCAPED;
            i++;
            st = json_lex_escape(lx, &i);
            if (st != JSON_OK) {
                return st;
            }
        }
        i++;
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
