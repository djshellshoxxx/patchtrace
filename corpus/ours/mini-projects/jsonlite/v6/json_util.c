/* SPDX-License-Identifier: MIT */
/*
 * json_util.c - read access to a parsed tree, paths, and number parsing.
 * String and UTF-8 handling lives in json_str.c.
 *
 * Layout: tree access first (what most callers use), then paths, then the
 * number helpers the parser needs.
 */
#include "json_internal.h"

/* ---- tree access --------------------------------------------------------- */

const json_node *json_root(const json_doc *doc) {
    if (doc == NULL || doc->root == JSON_NIL) {
        return NULL;
    }
    return &doc->nodes[doc->root];
}

/* Find the member of an object whose key equals key[0..keylen) once escapes are decoded. */
const json_node *json_obj_get(const json_doc *doc, const json_node *obj, const char *key, size_t keylen) {
    uint32_t i;

    if (obj == NULL || obj->type != JSON_OBJECT) {
        return NULL;
    }
    for (i = obj->child; i != JSON_NIL; i = doc->nodes[i].next) {
        const json_node *m = &doc->nodes[i];

        if (json_key_eq(doc, m, key, keylen)) {
            return m;
        }
    }
    return NULL;
}

/* The index-th element of an array (zero based), or NULL. */
const json_node *json_arr_get(const json_doc *doc, const json_node *arr, uint32_t index) {
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

/* Number of children of a container, or the raw byte length of a string. */
uint32_t json_length(const json_node *n) {
    if (n == NULL) {
        return 0;
    }
    switch (n->type) {
    case JSON_ARRAY:
    case JSON_OBJECT:
        return n->count;
    case JSON_STRING:
        return n->len;
    default:
        return 0;
    }
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
    *out = (n->ival != 0);
    return JSON_OK;
}

/* Copy a string value into out, decoding escapes. A NUL is stored when there is room. */
json_status json_get_string(const json_doc *doc, const json_node *n, char *out, size_t cap, size_t *outlen) {
    json_status st;
    size_t o = 0;

    if (doc == NULL || n == NULL || n->type != JSON_STRING || (out == NULL && cap > 0)) {
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

/* Does a string node hold exactly s[0..len) once escapes are decoded? */
int json_str_eq(const json_doc *doc, const json_node *n, const char *s, size_t len) {
    if (n == NULL || n->type != JSON_STRING) {
        return 0;
    }
    return json_text_eq(doc->src + n->off, n->len, (n->flags & JSON_F_ESCAPED) != 0, s, len);
}

/* ---- paths --------------------------------------------------------------- */

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
        cur = is_index ? json_arr_get(doc, cur, index) : json_obj_get(doc, cur, seg, seglen);
    }
    return step < 0 ? NULL : cur;
}

/* Write v in decimal at out (room for ten digits); returns the number of digits written. */
uint32_t json_u32_format(char *out, uint32_t v) {
    char tmp[10];
    uint32_t n = 0;
    uint32_t i;

    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    for (i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    return n;
}

/* Position of child among the children of par (zero based). */
uint32_t json_child_index(const json_doc *doc, const json_node *par, const json_node *child) {
    uint32_t index = 0;
    uint32_t k;

    for (k = par->child; k != JSON_NIL && &doc->nodes[k] != child; k = doc->nodes[k].next) {
        index++;
    }
    return index;
}

/*
 * Build a path such as "$.servers[2].host" for a node. Returns the full length
 * of the path; the text is stored (NUL-terminated) as far as cap allows.
 */
size_t json_node_path(const json_doc *doc, const json_node *n, char *out, size_t cap) {
    size_t total = 1;
    size_t end;
    const json_node *cur;
    char tmp[12];

    /* first pass: how long is the whole path? */
    for (cur = n; cur != NULL && cur->parent != JSON_NIL; cur = &doc->nodes[cur->parent]) {
        const json_node *par = &doc->nodes[cur->parent];

        if (par->type == JSON_OBJECT) {
            total += 1 + cur->key_len;
        } else {
            total += 2 + json_u32_format(tmp, json_child_index(doc, par, cur));
        }
    }
    /* second pass: fill from the back so no scratch space is needed */
    end = total;
    for (cur = n; cur != NULL && cur->parent != JSON_NIL; cur = &doc->nodes[cur->parent]) {
        const json_node *par = &doc->nodes[cur->parent];
        size_t at;
        size_t k;

        if (par->type == JSON_OBJECT) {
            end -= 1 + cur->key_len;
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
            uint32_t digits = json_u32_format(tmp, json_child_index(doc, par, cur));

            end -= 2 + digits;
            at = end;
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

/* ---- numbers ------------------------------------------------------------- */

/* Parse an optionally signed run of decimal digits that fills the whole range. */
json_status json_parse_int(const char *s, size_t n, int64_t *out) {
    size_t i = 0;
    bool neg = false;
    uint64_t acc = 0;
    uint64_t limit;

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
    limit = neg ? 9223372036854775808ull : 9223372036854775807ull;
    for (; i < n; i++) {
        uint64_t digit;

        if (!json_is_digit(s[i])) {
            return JSON_ERR_NUMBER;
        }
        digit = (uint64_t)(s[i] - '0');
        if (acc > (limit - digit) / 10) {
            return JSON_ERR_RANGE;
        }
        acc = acc * 10 + digit;
    }
    if (neg) {
        *out = acc == 9223372036854775808ull ? INT64_MIN : -(int64_t)acc;
    } else {
        *out = (int64_t)acc;
    }
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
        if (acc > (INT64_MAX - (c - '0')) / 10) {
            return JSON_ERR_RANGE;
        }
        acc = acc * 10 + (c - '0');
        if (seen_dot) {
            if (scale <= -100000) {
                return JSON_ERR_RANGE;
            }
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
            if (e > 99999) {
                return JSON_ERR_RANGE;
            }
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
int json_bytes_eq(const char *a, const char *b, size_t n) {
    size_t i;

    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}
