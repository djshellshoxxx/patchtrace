/* SPDX-License-Identifier: MIT */
/*
 * json_write.c - minimal JSON serializer writing into a caller-supplied buffer.
 *
 * The first failure is sticky in w->err and turns every later call into a
 * no-op, so a long sequence of calls can be checked once with json_w_finish().
 */
#include "json.h"

/* Attach a writer to an output buffer. */
void json_w_init(json_writer *w, char *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = JSON_OK;
    w->depth = 0;
    w->first_bits = 0;
    w->after_key = 0;
}

/* Append one byte. */
json_status json_w_putc(json_writer *w, char c) {
    if (w->err != JSON_OK) {
        return w->err;
    }
    if (w->len >= w->cap) {
        w->err = JSON_ERR_NOMEM;
        return w->err;
    }
    w->buf[w->len++] = c;
    return JSON_OK;
}

/* Append n bytes verbatim. */
json_status json_w_puts(json_writer *w, const char *s, size_t n) {
    size_t i;

    if (w->err != JSON_OK) {
        return w->err;
    }
    if (n > w->cap - w->len) {
        w->err = JSON_ERR_NOMEM;
        return w->err;
    }
    for (i = 0; i < n; i++) {
        w->buf[w->len + i] = s[i];
    }
    w->len += n;
    return JSON_OK;
}

/* Emit the separator that must come before the next element of the current container. */
json_status json_w_comma(json_writer *w) {
    uint32_t bit;

    if (w->after_key) {
        w->after_key = 0;
        return JSON_OK;
    }
    if (w->depth == 0) {
        return JSON_OK;
    }
    bit = 1u << (w->depth - 1);
    if (w->first_bits & bit) {
        w->first_bits &= ~bit;
        return JSON_OK;
    }
    return json_w_putc(w, ',');
}

/* Open a container ('{' or '[') as the next element of the current one. */
json_status json_w_begin(json_writer *w, char open) {
    json_status st;

    if (w->depth >= 32) {
        if (w->err == JSON_OK) {
            w->err = JSON_ERR_DEPTH;
        }
        return w->err;
    }
    st = json_w_comma(w);
    if (st != JSON_OK) {
        return st;
    }
    st = json_w_putc(w, open);
    if (st != JSON_OK) {
        return st;
    }
    w->depth++;
    w->first_bits |= 1u << (w->depth - 1);
    return JSON_OK;
}

/* Close the innermost container. */
json_status json_w_end(json_writer *w, char close) {
    if (w->depth == 0) {
        w->err = JSON_ERR_ARG;
        return w->err;
    }
    w->first_bits &= ~(1u << (w->depth - 1));
    w->depth--;
    return json_w_putc(w, close);
}

json_status json_w_begin_object(json_writer *w) {
    return json_w_begin(w, '{');
}

json_status json_w_end_object(json_writer *w) {
    return json_w_end(w, '}');
}

json_status json_w_begin_array(json_writer *w) {
    return json_w_begin(w, '[');
}

json_status json_w_end_array(json_writer *w) {
    return json_w_end(w, ']');
}

/* Append s[0..n) as the body of a JSON string, escaping what JSON requires. */
json_status json_w_escaped(json_writer *w, const char *s, size_t n) {
    const char *hexdigits = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        size_t need;
        char *dst;

        if (w->err != JSON_OK) {
            return w->err;
        }
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') {
            need = 2;
        } else {
            need = c < 0x20 ? 6 : 1;
        }
        if (w->cap - w->len < need) {
            w->err = JSON_ERR_NOMEM;
            return w->err;
        }
        dst = w->buf + w->len;
        if (c == '"' || c == '\\') {
            dst[0] = '\\';
            dst[1] = (char)c;
            w->len += 2;
        } else if (c == '\n') {
            dst[0] = '\\';
            dst[1] = 'n';
            w->len += 2;
        } else if (c == '\r') {
            dst[0] = '\\';
            dst[1] = 'r';
            w->len += 2;
        } else if (c == '\t') {
            dst[0] = '\\';
            dst[1] = 't';
            w->len += 2;
        } else if (c < 0x20) {
            dst[0] = '\\';
            dst[1] = 'u';
            dst[2] = '0';
            dst[3] = '0';
            dst[4] = hexdigits[c >> 4];
            dst[5] = hexdigits[c & 15];
            w->len += 6;
        } else {
            dst[0] = (char)c;
            w->len += 1;
        }
    }
    return JSON_OK;
}

/* Write an object member key (escaped) followed by the colon. */
json_status json_w_key(json_writer *w, const char *key, size_t n) {
    json_status st = json_w_comma(w);

    if (st == JSON_OK) {
        st = json_w_putc(w, '"');
    }
    if (st == JSON_OK) {
        st = json_w_escaped(w, key, n);
    }
    if (st == JSON_OK) {
        st = json_w_puts(w, "\":", 2);
    }
    w->after_key = 1;
    return st;
}

/* Like json_w_key, but key[0..n) is already escaped (it came out of a parsed document). */
json_status json_w_key_raw(json_writer *w, const char *key, size_t n) {
    json_status st = json_w_comma(w);

    if (st == JSON_OK) {
        st = json_w_putc(w, '"');
    }
    if (st == JSON_OK) {
        st = json_w_puts(w, key, n);
    }
    if (st == JSON_OK) {
        st = json_w_puts(w, "\":", 2);
    }
    w->after_key = 1;
    return st;
}

/* Write a string value, escaping it. */
json_status json_w_string(json_writer *w, const char *s, size_t n) {
    json_status st = json_w_comma(w);

    if (st == JSON_OK) {
        st = json_w_putc(w, '"');
    }
    if (st == JSON_OK) {
        st = json_w_escaped(w, s, n);
    }
    if (st == JSON_OK) {
        st = json_w_putc(w, '"');
    }
    return st;
}

/* Write a string value whose text is already escaped. */
json_status json_w_raw_string(json_writer *w, const char *s, size_t n) {
    json_status st = json_w_comma(w);

    if (st == JSON_OK) {
        st = json_w_putc(w, '"');
    }
    if (st == JSON_OK) {
        st = json_w_puts(w, s, n);
    }
    if (st == JSON_OK) {
        st = json_w_putc(w, '"');
    }
    return st;
}

json_status json_w_null(json_writer *w) {
    json_status st = json_w_comma(w);

    return st == JSON_OK ? json_w_puts(w, "null", 4) : st;
}

json_status json_w_bool(json_writer *w, bool v) {
    json_status st = json_w_comma(w);

    if (st != JSON_OK) {
        return st;
    }
    return v ? json_w_puts(w, "true", 4) : json_w_puts(w, "false", 5);
}

/* Write a signed 64-bit integer in decimal. */
json_status json_w_int(json_writer *w, int64_t v) {
    char tmp[24];
    size_t pos = sizeof tmp;
    uint64_t mag = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    json_status st = json_w_comma(w);

    if (st != JSON_OK) {
        return st;
    }
    do {
        tmp[--pos] = (char)('0' + mag % 10);
        mag /= 10;
    } while (mag != 0);
    if (v < 0) {
        tmp[--pos] = '-';
    }
    return json_w_puts(w, tmp + pos, sizeof tmp - pos);
}

/* Write number text that was already validated (for example from a parsed node). */
json_status json_w_number_text(json_writer *w, const char *s, size_t n) {
    json_status st = json_w_comma(w);

    return st == JSON_OK ? json_w_puts(w, s, n) : st;
}

size_t json_w_length(const json_writer *w) {
    return w->len;
}

/* NUL-terminate when there is room and report the first error, if any. */
json_status json_w_finish(json_writer *w) {
    if (w->err == JSON_OK && w->depth != 0) {
        w->err = JSON_ERR_ARG;
    }
    if (w->err == JSON_OK && w->len < w->cap) {
        w->buf[w->len] = '\0';
    }
    return w->err;
}

/* Re-serialize a parsed value. Strings, keys and numbers are copied as written. */
json_status json_write_node(json_writer *w, const json_doc *doc, const json_node *n) {
    json_status st;
    uint32_t i;
    const char *text;

    if (n == NULL) {
        return JSON_ERR_ARG;
    }
    text = doc->src + n->off;
    switch (n->type) {
    case JSON_NULL:
        return json_w_null(w);
    case JSON_BOOL:
        return json_w_bool(w, n->ival != 0);
    case JSON_NUMBER:
        return json_w_number_text(w, text, n->len);
    case JSON_STRING:
        return json_w_raw_string(w, text, n->len);
    case JSON_ARRAY:
        st = json_w_begin_array(w);
        for (i = n->child; st == JSON_OK && i != JSON_NIL; i = doc->nodes[i].next) {
            st = json_write_node(w, doc, &doc->nodes[i]);
        }
        return st == JSON_OK ? json_w_end_array(w) : st;
    case JSON_OBJECT:
        st = json_w_begin_object(w);
        for (i = n->child; st == JSON_OK && i != JSON_NIL; i = doc->nodes[i].next) {
            const json_node *m = &doc->nodes[i];

            st = json_w_key_raw(w, doc->src + m->key_off, m->key_len);
            if (st == JSON_OK) {
                st = json_write_node(w, doc, m);
            }
        }
        return st == JSON_OK ? json_w_end_object(w) : st;
    }
    return JSON_ERR_ARG;
}
