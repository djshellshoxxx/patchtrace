/* SPDX-License-Identifier: MIT */
/*
 * json_internal.h - tokenizer and parser internals.
 *
 * Nothing here is part of the supported interface; it is shared between
 * json_lex.c and json_parse.c only.
 */
#ifndef JSONLITE_INTERNAL_H
#define JSONLITE_INTERNAL_H

#include "json.h"

/* ------------------------------------------------------------------------ */
/* Tokens                                                                    */
/* ------------------------------------------------------------------------ */
typedef enum json_tok_kind {
    JSON_TOK_EOF = 0,
    JSON_TOK_LBRACE,
    JSON_TOK_RBRACE,
    JSON_TOK_LBRACKET,
    JSON_TOK_RBRACKET,
    JSON_TOK_COLON,
    JSON_TOK_COMMA,
    JSON_TOK_STRING,
    JSON_TOK_NUMBER,
    JSON_TOK_TRUE,
    JSON_TOK_FALSE,
    JSON_TOK_NULL,
    JSON_TOK_ERROR
} json_tok_kind;

#define JSON_TF_ESCAPED  0x01u   /* string token contains a backslash escape */
#define JSON_TF_NEGATIVE 0x02u   /* number token starts with '-' */
#define JSON_TF_FRACTION 0x04u   /* number token has a '.' part */
#define JSON_TF_EXPONENT 0x08u   /* number token has an exponent */

typedef struct json_tok {
    json_tok_kind kind;
    size_t start;            /* first byte of the token (strings: after the quote) */
    size_t end;              /* one past the last byte (strings: the closing quote) */
    uint32_t flags;          /* JSON_TF_* */
} json_tok;

typedef struct json_lexer {
    const char *src;
    size_t len;
    size_t pos;
    json_status err;         /* first lexical error, or JSON_OK */
} json_lexer;

typedef struct json_parser {
    json_lexer lx;
    json_tok tok;            /* one token of lookahead */
    json_doc *doc;
    uint32_t depth;          /* containers currently open */
} json_parser;

/* ------------------------------------------------------------------------ */
/* json_lex.c - tokenizer                                                    */
/* ------------------------------------------------------------------------ */
void json_lex_init(json_lexer *lx, const char *src, size_t len);
json_status json_lex_fail(json_lexer *lx, json_status st);
int json_is_ws(char c);
int json_is_digit(char c);
void json_lex_skip_ws(json_lexer *lx);
size_t json_lex_digits(const json_lexer *lx, size_t i);
json_status json_lex_literal(json_lexer *lx, json_tok *t, const char *word, size_t n, json_tok_kind kind);
json_status json_lex_number(json_lexer *lx, json_tok *t);
json_status json_lex_escape(json_lexer *lx, size_t *pos);
json_status json_lex_string(json_lexer *lx, json_tok *t);
json_status json_lex_punct(json_lexer *lx, json_tok *t, json_tok_kind kind);
json_status json_lex_next(json_lexer *lx, json_tok *t);
const char *json_tok_name(json_tok_kind kind);
void json_offset_position(const char *src, size_t len, size_t pos, uint32_t *line, uint32_t *col);

/* ------------------------------------------------------------------------ */
/* json_parse.c - recursive-descent parser                                   */
/* ------------------------------------------------------------------------ */
void json_parser_init(json_parser *p, json_doc *doc);
json_status json_parser_advance(json_parser *p);
json_status json_node_alloc(json_doc *doc, json_type type, uint32_t *out);
void json_node_append(json_doc *doc, uint32_t parent, uint32_t child);
json_status json_fill_scalar(json_parser *p, uint32_t idx);
json_status json_close_container(json_parser *p, uint32_t idx);
json_status json_parse_value(json_parser *p, uint32_t *out);
json_status json_parse_array(json_parser *p, uint32_t *out);
json_status json_parse_member(json_parser *p, uint32_t obj);
json_status json_parse_object(json_parser *p, uint32_t *out);

#endif /* JSONLITE_INTERNAL_H */
