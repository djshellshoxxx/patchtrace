/* SPDX-License-Identifier: MIT */
/*
 * json_util.c - string and number helpers plus read access to a parsed tree.
 */
#include "json.h"

/* ---- characters ---------------------------------------------------------- */

int json_is_hex(char c) {
    return json_is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* Value of a hexadecimal digit, or -1 when c is not one. */
int json_hex_val(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Read exactly four hex digits (the XXXX of a \uXXXX escape). */
json_status json_hex4(const char *s, size_t n, uint32_t *out) {
    uint32_t value = 0;
    size_t i;

    if (n < 4) {
        return JSON_ERR_STRING;
    }
    for (i = 0; i < 4; i++) {
        int digit = json_hex_val(s[i]);

        if (digit < 0) {
            return JSON_ERR_STRING;
        }
        value = (value << 4) | (uint32_t)digit;
    }
    *out = value;
    return JSON_OK;
}

/* Encode one code point as UTF-8 into out; returns the number of bytes written (1..4). */
size_t json_utf8_encode(uint32_t cp, char *out) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/*
 * Decode the escapes of a string token (the text between the quotes) into
 * out. Stores at most cap bytes and reports the decoded length in *outlen.
 */
json_status json_unescape(const char *src, size_t n, char *out, size_t cap, size_t *outlen) {
    size_t i = 0;
    size_t o = 0;

    while (i < n) {
        char c = src[i++];

        if (c == '\\') {
            if (i >= n) {
                return JSON_ERR_STRING;
            }
            c = src[i++];
            switch (c) {
            case '"':
            case '\\':
            case '/':
                break;
            case 'b':
                c = '\b';
                break;
            case 'f':
                c = '\f';
                break;
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            case 'u': {
                uint32_t cp;

                if (json_hex4(src + i, n - i, &cp) != JSON_OK) {
                    return JSON_ERR_STRING;
                }
                i += 4;
                if (o >= cap) {
                    return JSON_ERR_NOMEM;
                }
                o += json_utf8_encode(cp, out + o);
                continue;
            }
            default:
                return JSON_ERR_STRING;
            }
        }
        if (o >= cap) {
            return JSON_ERR_NOMEM;
        }
        out[o++] = c;
    }
    if (outlen != NULL) {
        *outlen = o;
    }
    return JSON_OK;
}

/* ---- numbers ------------------------------------------------------------- */

/* Parse an optionally signed run of decimal digits that fills the whole range. */
json_status json_parse_int(const char *s, size_t n, int64_t *out) {
    size_t i = 0;
    bool neg = false;
    int64_t acc = 0;

    if (n == 0) {
        return JSON_ERR_NUMBER;
    }
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
    if (i >= n) {
        return JSON_ERR_NUMBER;
    }
    for (; i < n; i++) {
        if (!json_is_digit(s[i])) {
            return JSON_ERR_NUMBER;
        }
        acc = acc * 10 + (s[i] - '0');
    }
    *out = neg ? -acc : acc;
    return JSON_OK;
}

/*
 * Convert a number with a fraction or exponent into mantissa * 10^exp10.
 * "12.5e2" becomes mant=125, exp10=1. No floating point is involved.
 */
json_status json_number_value(const char *s, size_t n, int64_t *mant, int32_t *exp10, uint32_t *flags) {
    size_t i = 0;
    bool neg = false;
    bool seen_dot = false;
    bool eneg = false;
    int64_t acc = 0;
    int32_t scale = 0;
    int32_t e = 0;

    if (i < n && s[i] == '-') {
        neg = true;
        i++;
    }
    for (; i < n; i++) {
        char c = s[i];

        if (c == '.') {
            seen_dot = true;
            continue;
        }
        if (c == 'e' || c == 'E') {
            break;
        }
        if (!json_is_digit(c)) {
            return JSON_ERR_NUMBER;
        }
        acc = acc * 10 + (c - '0');
        if (seen_dot) {
            scale--;
        }
    }
    if (i < n) {
        i++;
        if (i < n && (s[i] == '+' || s[i] == '-')) {
            eneg = (s[i] == '-');
            i++;
        }
        for (; i < n; i++) {
            if (!json_is_digit(s[i])) {
                return JSON_ERR_NUMBER;
            }
            e = e * 10 + (s[i] - '0');
        }
        if (eneg) {
            e = -e;
        }
    }
    *mant = neg ? -acc : acc;
    *exp10 = scale + e;
    *flags = 0;
    return JSON_OK;
}

/* Byte-wise equality of two buffers. */
int json_mem_eq(const char *a, const char *b, size_t n) {
    size_t i;

    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

/* ---- tree access --------------------------------------------------------- */

const json_node *json_root(const json_doc *doc) {
    if (doc->root == JSON_NIL) {
        return NULL;
    }
    return &doc->nodes[doc->root];
}

/* Find the member of an object whose key equals key[0..keylen) (compared as written). */
const json_node *json_member(const json_doc *doc, const json_node *obj, const char *key, size_t keylen) {
    uint32_t i;

    if (obj == NULL || obj->type != JSON_OBJECT) {
        return NULL;
    }
    for (i = obj->child; i != JSON_NIL; i = doc->nodes[i].next) {
        const json_node *m = &doc->nodes[i];

        if (m->key_len == keylen && json_mem_eq(doc->src + m->key_off, key, keylen)) {
            return m;
        }
    }
    return NULL;
}

/* The index-th element of an array (zero based), or NULL. */
const json_node *json_element(const json_doc *doc, const json_node *arr, uint32_t index) {
    uint32_t i;

    if (arr == NULL || arr->type != JSON_ARRAY || index >= arr->count) {
        return NULL;
    }
    i = arr->child;
    while (index > 0 && i != JSON_NIL) {
        i = doc->nodes[i].next;
        index--;
    }
    return i == JSON_NIL ? NULL : &doc->nodes[i];
}

/*
 * Split off the next segment of a path such as "servers[2].host".
 * Returns 1 and fills either seg and seglen (a member name) or index (an
 * element index, with is_index set), 0 at the end of the path, -1 when malformed.
 */
int json_path_next(const char *path, size_t plen, size_t *pos, const char **seg, size_t *seglen, bool *is_index,
                   uint32_t *index) {
    size_t i = *pos;

    if (i < plen && path[i] == '.') {
        i++;
    }
    if (i >= plen) {
        *pos = i;
        return 0;
    }
    if (path[i] == '[') {
        int64_t v;
        size_t start = i + 1;

        i = start;
        while (i < plen && path[i] != ']') {
            i++;
        }
        if (i >= plen || json_parse_int(path + start, i - start, &v) != JSON_OK || v < 0 || v > 0x7FFFFFFF) {
            return -1;
        }
        *is_index = true;
        *index = (uint32_t)v;
        *pos = i + 1;
        return 1;
    }
    *seg = path + i;
    while (i < plen && path[i] != '.' && path[i] != '[') {
        i++;
    }
    *seglen = (size_t)(path + i - *seg);
    *is_index = false;
    *pos = i;
    return 1;
}

/* Follow a dotted path from start; NULL when any step is missing or the path is malformed. */
const json_node *json_get_path(const json_doc *doc, const json_node *start, const char *path, size_t plen) {
    const json_node *cur = start;
    size_t pos = 0;
    const char *seg = path;
    size_t seglen = 0;
    bool is_index = false;
    uint32_t index = 0;
    int step = 1;

    if (plen > 0 && path[0] == '$') {
        pos = 1;
    }
    while (cur != NULL) {
        step = json_path_next(path, plen, &pos, &seg, &seglen, &is_index, &index);
        if (step <= 0) {
            break;
        }
        cur = is_index ? json_element(doc, cur, index) : json_member(doc, cur, seg, seglen);
    }
    return step < 0 ? NULL : cur;
}

/* Number of children of a container, or the raw byte length of a string. */
uint32_t json_length(const json_node *n) {
    if (n == NULL) {
        return 0;
    }
    if (n->type == JSON_ARRAY || n->type == JSON_OBJECT) {
        return n->count;
    }
    if (n->type == JSON_STRING) {
        return n->len;
    }
    return 0;
}

json_status json_get_int(const json_doc *doc, const json_node *n, int64_t *out) {
    (void)doc;
    if (n == NULL || n->type != JSON_NUMBER) {
        return JSON_ERR_ARG;
    }
    if (!(n->flags & JSON_F_INTEGER)) {
        return JSON_ERR_RANGE;
    }
    *out = n->ival;
    return JSON_OK;
}

json_status json_get_bool(const json_node *n, bool *out) {
    if (n == NULL || n->type != JSON_BOOL) {
        return JSON_ERR_ARG;
    }
    *out = n->ival != 0;
    return JSON_OK;
}

/* Copy a string value into out, decoding escapes. A NUL is stored when there is room. */
json_status json_get_string(const json_doc *doc, const json_node *n, char *out, size_t cap, size_t *outlen) {
    json_status st;
    size_t o = 0;

    if (n == NULL || n->type != JSON_STRING) {
        return JSON_ERR_ARG;
    }
    if (n->flags & JSON_F_ESCAPED) {
        st = json_unescape(doc->src + n->off, n->len, out, cap, &o);
        if (st != JSON_OK) {
            return st;
        }
    } else {
        if (n->len > cap) {
            return JSON_ERR_NOMEM;
        }
        for (o = 0; o < n->len; o++) {
            out[o] = doc->src[n->off + o];
        }
    }
    if (o < cap) {
        out[o] = '\0';
    }
    if (outlen != NULL) {
        *outlen = o;
    }
    return JSON_OK;
}

/* Does a string node hold exactly s[0..len)? Compares the text as written. */
int json_str_eq(const json_doc *doc, const json_node *n, const char *s, size_t len) {
    if (n == NULL || n->type != JSON_STRING) {
        return 0;
    }
    return n->len == len && json_mem_eq(doc->src + n->off, s, len);
}

/* ---- paths and statistics ------------------------------------------------ */

/* Distance from the root (the root is at depth 1). */
uint32_t json_node_depth(const json_doc *doc, const json_node *n) {
    uint32_t depth = 0;

    while (n != NULL) {
        depth++;
        n = n->parent == JSON_NIL ? NULL : &doc->nodes[n->parent];
    }
    return depth;
}

/* Number of decimal digits of v. */
uint32_t json_u32_digits(uint32_t v) {
    uint32_t n = 1;

    while (v >= 10) {
        v /= 10;
        n++;
    }
    return n;
}

/* Write v as exactly ndigits decimal digits (ndigits from json_u32_digits). */
void json_u32_write(char *out, uint32_t v, uint32_t ndigits) {
    while (ndigits > 0) {
        ndigits--;
        out[ndigits] = (char)('0' + v % 10);
        v /= 10;
    }
}

/*
 * Build a path such as "$.servers[2].host" for a node. Returns the full length
 * of the path; the text is stored (NUL-terminated) as far as cap allows.
 */
size_t json_node_path(const json_doc *doc, const json_node *n, char *out, size_t cap) {
    size_t total = 1;
    size_t end;
    const json_node *cur;

    /* first pass: how long is the whole path? */
    for (cur = n; cur != NULL && cur->parent != JSON_NIL; cur = &doc->nodes[cur->parent]) {
        const json_node *par = &doc->nodes[cur->parent];

        if (par->type == JSON_OBJECT) {
            total += 1 + cur->key_len;
        } else {
            uint32_t index = 0;
            uint32_t k;

            for (k = par->child; k != JSON_NIL && &doc->nodes[k] != cur; k = doc->nodes[k].next) {
                index++;
            }
            total += 2 + json_u32_digits(index);
        }
    }
    /* second pass: fill from the back so no scratch space is needed */
    end = total;
    for (cur = n; cur != NULL && cur->parent != JSON_NIL; cur = &doc->nodes[cur->parent]) {
        const json_node *par = &doc->nodes[cur->parent];
        size_t seg;
        size_t at;
        size_t k;

        if (par->type == JSON_OBJECT) {
            seg = 1 + cur->key_len;
            end -= seg;
            at = end;
            if (at < cap) {
                out[at] = '.';
            }
            for (k = 0; k < cur->key_len; k++) {
                if (at + 1 + k < cap) {
                    out[at + 1 + k] = doc->src[cur->key_off + k];
                }
            }
        } else {
            uint32_t index = 0;
            uint32_t digits;
            uint32_t j;
            char tmp[12];

            for (j = par->child; j != JSON_NIL && &doc->nodes[j] != cur; j = doc->nodes[j].next) {
                index++;
            }
            digits = json_u32_digits(index);
            seg = 2 + digits;
            end -= seg;
            at = end;
            json_u32_write(tmp, index, digits);
            if (at < cap) {
                out[at] = '[';
            }
            for (k = 0; k < digits; k++) {
                if (at + 1 + k < cap) {
                    out[at + 1 + k] = tmp[k];
                }
            }
            if (at + 1 + digits < cap) {
                out[at + 1 + digits] = ']';
            }
        }
    }
    if (cap > 0) {
        out[0] = '$';
        out[total < cap ? total : cap - 1] = '\0';
    }
    return total;
}

/* Count nodes by kind and find the deepest nesting. */
void json_doc_stats(const json_doc *doc, json_stats *st) {
    uint32_t i;

    st->nodes = doc->used;
    st->objects = 0;
    st->arrays = 0;
    st->strings = 0;
    st->numbers = 0;
    st->literals = 0;
    st->max_depth = 0;
    st->string_bytes = 0;
    for (i = 0; i < doc->used; i++) {
        const json_node *n = &doc->nodes[i];
        uint32_t depth = json_node_depth(doc, n);

        if (depth > st->max_depth) {
            st->max_depth = depth;
        }
        switch (n->type) {
        case JSON_OBJECT:
            st->objects++;
            break;
        case JSON_ARRAY:
            st->arrays++;
            break;
        case JSON_STRING:
            st->strings++;
            st->string_bytes += n->len;
            break;
        case JSON_NUMBER:
            st->numbers++;
            break;
        default:
            st->literals++;
            break;
        }
    }
}
