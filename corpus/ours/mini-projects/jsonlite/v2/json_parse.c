/* SPDX-License-Identifier: MIT */
/*
 * json_parse.c - recursive-descent parser building a flat node tree.
 *
 * The parser keeps exactly one token of lookahead in p->tok. Every
 * json_parse_* function consumes the tokens of its production and leaves the
 * first token after it in p->tok.
 */
#include "json.h"

/* Prepare a document over a source buffer and a caller-supplied node pool. */
void json_doc_init(json_doc *doc, const char *src, size_t len, json_node *nodes, uint32_t cap) {
    doc->src = src;
    doc->len = len;
    doc->nodes = nodes;
    if (cap >= JSON_NIL) {
        cap = JSON_NIL - 1;
    }
    doc->cap = cap;
    doc->used = 0;
    doc->root = JSON_NIL;
    doc->status = JSON_OK;
    doc->err_pos = 0;
    doc->max_depth = JSON_DEFAULT_MAX_DEPTH;
}

/* Human-readable text for a status code. */
const char *json_error_string(json_status st) {
    switch (st) {
    case JSON_OK:
        return "ok";
    case JSON_ERR_SYNTAX:
        return "syntax error";
    case JSON_ERR_EOF:
        return "unexpected end of input";
    case JSON_ERR_NOMEM:
        return "out of memory";
    case JSON_ERR_STRING:
        return "malformed string";
    case JSON_ERR_NUMBER:
        return "malformed number";
    case JSON_ERR_RANGE:
        return "value out of range";
    case JSON_ERR_TRAILING:
        return "trailing characters";
    case JSON_ERR_ARG:
        return "invalid argument";
    case JSON_ERR_DEPTH:
        return "nesting too deep";
    }
    return "unknown error";
}

void json_parser_init(json_parser *p, json_doc *doc) {
    json_lex_init(&p->lx, doc->src, doc->len);
    p->doc = doc;
    p->depth = 0;
    p->tok.kind = JSON_TOK_EOF;
    p->tok.start = 0;
    p->tok.end = 0;
    p->tok.flags = 0;
}

/* Replace the lookahead token with the next one. */
json_status json_advance(json_parser *p) {
    json_status st = json_lex_next(&p->lx, &p->tok);

    if (st != JSON_OK) {
        p->tok.kind = JSON_TOK_ERROR;
    }
    return st;
}

/* Take the next free node from the pool and reset it. */
json_status json_node_alloc(json_doc *doc, json_type type, uint32_t *out) {
    json_node *n;

    if (doc->used >= doc->cap) {
        return JSON_ERR_NOMEM;
    }
    *out = doc->used;
    n = &doc->nodes[doc->used++];
    n->type = (uint8_t)type;
    n->flags = 0;
    n->reserved = 0;
    n->parent = JSON_NIL;
    n->next = JSON_NIL;
    n->child = JSON_NIL;
    n->last = JSON_NIL;
    n->count = 0;
    n->off = 0;
    n->len = 0;
    n->key_off = 0;
    n->key_len = 0;
    n->ival = 0;
    n->exp10 = 0;
    n->reserved2 = 0;
    return JSON_OK;
}

/* Link child as the last child of parent. */
void json_node_append(json_doc *doc, uint32_t parent, uint32_t child) {
    json_node *pn = &doc->nodes[parent];
    json_node *cn = &doc->nodes[child];

    cn->parent = parent;
    if (pn->last == JSON_NIL) {
        pn->child = child;
    } else {
        doc->nodes[pn->last].next = child;
    }
    pn->last = child;
    pn->count++;
}

/* Record the lookahead token's text on a scalar node and convert numbers. */
json_status json_fill_scalar(json_parser *p, uint32_t idx) {
    json_node *n = &p->doc->nodes[idx];
    const json_tok *t = &p->tok;
    const char *text = p->doc->src + t->start;
    uint32_t nflags = 0;
    json_status st;

    n->off = (uint32_t)t->start;
    n->len = (uint32_t)(t->end - t->start);
    switch (n->type) {
    case JSON_STRING:
        if (t->flags & JSON_TF_ESCAPED) {
            n->flags |= JSON_F_ESCAPED;
        }
        break;
    case JSON_BOOL:
        n->ival = (t->kind == JSON_TOK_TRUE) ? 1 : 0;
        break;
    case JSON_NUMBER:
        if (t->flags & (JSON_TF_FRACTION | JSON_TF_EXPONENT)) {
            st = json_number_value(text, n->len, &n->ival, &n->exp10, &nflags);
        } else {
            st = json_parse_int(text, n->len, &n->ival);
            nflags = JSON_F_INTEGER;
        }
        if (st != JSON_OK) {
            return st;
        }
        n->flags |= (uint8_t)nflags;
        break;
    default:
        break;
    }
    return JSON_OK;
}

/* Close an array or object: record its extent and step past the bracket. */
json_status json_close_container(json_parser *p, uint32_t idx) {
    json_node *n = &p->doc->nodes[idx];

    n->len = (uint32_t)(p->tok.end - n->off);
    return json_advance(p);
}

/* value = object | array | string | number | true | false | null */
json_status json_parse_value(json_parser *p, uint32_t *out) {
    json_status st;
    json_type type;
    uint32_t idx;

    switch (p->tok.kind) {
    case JSON_TOK_LBRACE:
    case JSON_TOK_LBRACKET:
        if (p->depth >= p->doc->max_depth) {
            return JSON_ERR_DEPTH;
        }
        p->depth++;
        if (p->tok.kind == JSON_TOK_LBRACE) {
            st = json_parse_object(p, out);
        } else {
            st = json_parse_array(p, out);
        }
        p->depth--;
        return st;
    case JSON_TOK_STRING:
        type = JSON_STRING;
        break;
    case JSON_TOK_NUMBER:
        type = JSON_NUMBER;
        break;
    case JSON_TOK_TRUE:
    case JSON_TOK_FALSE:
        type = JSON_BOOL;
        break;
    case JSON_TOK_NULL:
        type = JSON_NULL;
        break;
    case JSON_TOK_EOF:
        return JSON_ERR_EOF;
    default:
        return JSON_ERR_SYNTAX;
    }
    st = json_node_alloc(p->doc, type, &idx);
    if (st != JSON_OK) {
        return st;
    }
    st = json_fill_scalar(p, idx);
    if (st != JSON_OK) {
        return st;
    }
    *out = idx;
    return json_advance(p);
}

/* array = '[' [ value { ',' value } ] ']' */
json_status json_parse_array(json_parser *p, uint32_t *out) {
    json_status st;
    uint32_t arr;
    uint32_t item;

    st = json_node_alloc(p->doc, JSON_ARRAY, &arr);
    if (st != JSON_OK) {
        return st;
    }
    p->doc->nodes[arr].off = (uint32_t)p->tok.start;
    st = json_advance(p);
    if (st != JSON_OK) {
        return st;
    }
    while (p->tok.kind != JSON_TOK_RBRACKET) {
        st = json_parse_value(p, &item);
        if (st != JSON_OK) {
            return st;
        }
        json_node_append(p->doc, arr, item);
        if (p->tok.kind == JSON_TOK_COMMA) {
            st = json_advance(p);
            if (st != JSON_OK) {
                return st;
            }
            if (p->tok.kind == JSON_TOK_RBRACKET) {
                return JSON_ERR_SYNTAX;
            }
        } else if (p->tok.kind != JSON_TOK_RBRACKET) {
            return p->tok.kind == JSON_TOK_EOF ? JSON_ERR_EOF : JSON_ERR_SYNTAX;
        }
    }
    *out = arr;
    return json_close_container(p, arr);
}

/* member = string ':' value ; the value node carries the key text. */
json_status json_parse_member(json_parser *p, uint32_t obj) {
    json_status st;
    uint32_t key_off;
    uint32_t key_len;
    uint8_t key_flags = 0;
    uint32_t val;

    if (p->tok.kind != JSON_TOK_STRING) {
        return p->tok.kind == JSON_TOK_EOF ? JSON_ERR_EOF : JSON_ERR_SYNTAX;
    }
    key_off = (uint32_t)p->tok.start;
    key_len = (uint32_t)(p->tok.end - p->tok.start);
    if (p->tok.flags & JSON_TF_ESCAPED) {
        key_flags = JSON_F_KEY_ESCAPED;
    }
    st = json_advance(p);
    if (st != JSON_OK) {
        return st;
    }
    if (p->tok.kind != JSON_TOK_COLON) {
        return p->tok.kind == JSON_TOK_EOF ? JSON_ERR_EOF : JSON_ERR_SYNTAX;
    }
    st = json_advance(p);
    if (st != JSON_OK) {
        return st;
    }
    st = json_parse_value(p, &val);
    if (st != JSON_OK) {
        return st;
    }
    p->doc->nodes[val].key_off = key_off;
    p->doc->nodes[val].key_len = key_len;
    p->doc->nodes[val].flags |= key_flags;
    json_node_append(p->doc, obj, val);
    return JSON_OK;
}

/* object = '{' [ member { ',' member } ] '}' */
json_status json_parse_object(json_parser *p, uint32_t *out) {
    json_status st;
    uint32_t obj;

    st = json_node_alloc(p->doc, JSON_OBJECT, &obj);
    if (st != JSON_OK) {
        return st;
    }
    p->doc->nodes[obj].off = (uint32_t)p->tok.start;
    st = json_advance(p);
    if (st != JSON_OK) {
        return st;
    }
    while (p->tok.kind != JSON_TOK_RBRACE) {
        st = json_parse_member(p, obj);
        if (st != JSON_OK) {
            return st;
        }
        if (p->tok.kind == JSON_TOK_COMMA) {
            st = json_advance(p);
            if (st != JSON_OK) {
                return st;
            }
            if (p->tok.kind == JSON_TOK_RBRACE) {
                return JSON_ERR_SYNTAX;
            }
        } else if (p->tok.kind != JSON_TOK_RBRACE) {
            return p->tok.kind == JSON_TOK_EOF ? JSON_ERR_EOF : JSON_ERR_SYNTAX;
        }
    }
    *out = obj;
    return json_close_container(p, obj);
}

/* Parse the whole document. On failure doc->status and doc->err_pos say why and where. */
json_status json_parse(json_doc *doc) {
    json_parser p;
    json_status st;
    uint32_t root = JSON_NIL;

    if (doc == NULL || doc->nodes == NULL || (doc->src == NULL && doc->len != 0)) {
        return JSON_ERR_ARG;
    }
    if (doc->len >= 0xFFFFFFFFu) {
        return JSON_ERR_RANGE;
    }
    doc->used = 0;
    doc->root = JSON_NIL;
    doc->status = JSON_OK;
    doc->err_pos = 0;
    json_parser_init(&p, doc);
    st = json_advance(&p);
    if (st == JSON_OK) {
        st = json_parse_value(&p, &root);
    }
    if (st == JSON_OK && p.tok.kind != JSON_TOK_EOF) {
        st = JSON_ERR_TRAILING;
    }
    if (st != JSON_OK) {
        doc->status = st;
        doc->err_pos = (p.tok.kind == JSON_TOK_ERROR) ? p.lx.pos : p.tok.start;
        return st;
    }
    doc->root = root;
    return JSON_OK;
}

/* Line and column of the last parse error. */
void json_doc_error_position(const json_doc *doc, uint32_t *line, uint32_t *col) {
    json_offset_position(doc->src, doc->len, doc->err_pos, line, col);
}
