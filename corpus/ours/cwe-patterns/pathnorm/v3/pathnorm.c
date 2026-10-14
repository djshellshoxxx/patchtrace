/* pathnorm.c - path joining, normalisation and containment checks (v3).
 *
 * pn_resolve() is the entry point used by request handlers: it joins a trusted root with a
 * client-supplied relative path, normalises the result, and verifies it still lies under the root.
 */
#include "pathnorm.h"

/* ---- character and string helpers --------------------------------------- */

int pn_is_sep(char c) {
    return c == '\\' || c == '/';
}

char pn_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

uint32_t pn_len(const char *s) {
    const char *end = s;
    while (*end != '\0') {
        end++;
    }
    return (uint32_t)(end - s);
}

int pn_eq(const char *a, const char *b) {
    uint32_t k = 0;
    while (a[k] != '\0' && a[k] == b[k]) {
        k++;
    }
    return a[k] == b[k];
}

/* Bounded copy; returns the length or PN_ERR_SPACE when the NUL does not fit. */
int pn_copy(char *dst, uint32_t cap, const char *src) {
    uint32_t n = pn_len(src);
    uint32_t i = 0;
    if (n + 1u > cap) {
        return PN_ERR_SPACE;
    }
    while (i <= n) {
        dst[i] = src[i];
        i++;
    }
    return (int)n;
}

int pn_has_prefix(const char *s, const char *prefix) {
    uint32_t i;
    for (i = 0; prefix[i] != '\0'; i++) {
        if (s[i] != prefix[i]) {
            return 0;
        }
    }
    return 1;
}

/* ---- segments ----------------------------------------------------------- */

/* Find the next non-empty segment at or after `pos`; returns the position after it or PN_END. */
uint32_t pn_next_segment(const char *path, uint32_t pos, uint32_t *start, uint32_t *len) {
    uint32_t p = pos;
    while (pn_is_sep(path[p])) {
        p++;
    }
    if (path[p] == '\0') {
        return PN_END;
    }
    *start = p;
    while (path[p] != '\0' && !pn_is_sep(path[p])) {
        p++;
    }
    *len = p - *start;
    return p;
}

/* True for the segment "..". */
int pn_segment_is_dotdot(const char *s, uint32_t len) {
    return len == 2 && s[0] == '.' && s[1] == '.';
}

/* ---- normalisation and resolution --------------------------------------- */

/* Rewrite `in` as an absolute path: single '/' separators, no "." segments, ".." resolved against the
 * preceding segment, no trailing '/'. A ".." that would climb above the top is an error. */
int pn_normalize(const char *in, char *out, uint32_t cap) {
    uint32_t starts[16];
    uint32_t depth = 0;
    uint32_t pos = 0;
    uint32_t o = 0;
    uint32_t start = 0;
    uint32_t seg = 0;
    uint32_t k;
    if (cap < 2) {
        return PN_ERR_SPACE;
    }
    for (;;) {
        pos = pn_next_segment(in, pos, &start, &seg);
        if (pos == PN_END) {
            break;
        }
        if (seg == 1 && in[start] == '.') {
            continue;
        }
        if (pn_segment_is_dotdot(in + start, seg)) {
            if (depth == 0) {
                return PN_ERR_ESCAPE;
            }
            depth--;
            o = starts[depth];
            continue;
        }
        if (depth == 16) {
            return PN_ERR_DEPTH;
        }
        if (o + 1u + seg + 1u > cap) {
            return PN_ERR_SPACE;
        }
        starts[depth++] = o;
        out[o++] = '/';
        for (k = 0; k < seg; k++) {
            out[o++] = in[start + k];
        }
    }
    if (o == 0) {
        out[o++] = '/';
    }
    out[o] = '\0';
    return (int)o;
}

/* base + "/" + rel with exactly one separator between them. */
int pn_join(const char *base, const char *rel, char *out, uint32_t cap) {
    uint32_t base_len = pn_len(base);
    uint32_t w = 0;
    uint32_t i;
    if (base_len + 2u > cap) {
        return PN_ERR_SPACE;
    }
    for (i = 0; i < base_len; i++) {
        out[w++] = base[i];
    }
    if (base_len > 0 && !pn_is_sep(base[base_len - 1u])) {
        out[w++] = '/';
    }
    while (pn_is_sep(*rel)) {
        rel++;
    }
    while (*rel != '\0') {
        if (w + 1u >= cap) {
            return PN_ERR_SPACE;
        }
        out[w++] = *rel++;
    }
    out[w] = '\0';
    return (int)w;
}

/* True when `path` lies inside `root` (both already normalised): a whole-segment prefix, so that
 * "/srv/data-old/x" is not under "/srv/data". */
int pn_is_under(const char *root, const char *path) {
    uint32_t n = pn_len(root);
    if (!pn_has_prefix(path, root)) {
        return 0;
    }
    if (n > 0 && pn_is_sep(root[n - 1u])) {
        return 1;
    }
    return path[n] == '\0' || pn_is_sep(path[n]);
}

/* Join, normalise and confine: the result is copied to `out` only when it stays under `root`. */
int pn_resolve(const char *root, const char *rel, char *out, uint32_t cap) {
    char joined[PN_MAX];
    char norm[PN_MAX];
    int n;
    if (root == NULL || rel == NULL || out == NULL) {
        return PN_ERR_ARG;
    }
    n = pn_join(root, rel, joined, sizeof joined);
    if (n < 0) {
        return n;
    }
    n = pn_normalize(joined, norm, sizeof norm);
    if (n < 0) {
        return n;
    }
    if (!pn_is_under(root, norm)) {
        return PN_ERR_ESCAPE;
    }
    return pn_copy(out, cap, norm);
}

uint32_t pn_depth(const char *path) {
    uint32_t pos = 0;
    uint32_t start = 0;
    uint32_t len = 0;
    uint32_t count = 0;
    while ((pos = pn_next_segment(path, pos, &start, &len)) != PN_END) {
        count++;
    }
    return count;
}

int pn_is_absolute(const char *path) {
    return pn_is_sep(path[0]);
}

/* ---- name parts --------------------------------------------------------- */

int pn_basename(const char *path, char *out, uint32_t cap) {
    uint32_t pos = 0;
    uint32_t start = 0;
    uint32_t len = 0;
    uint32_t tail_start = 0;
    uint32_t tail_len = 0;
    uint32_t i;
    while ((pos = pn_next_segment(path, pos, &start, &len)) != PN_END) {
        tail_start = start;
        tail_len = len;
    }
    if (tail_len + 1u > cap) {
        return PN_ERR_SPACE;
    }
    for (i = 0; i < tail_len; i++) {
        out[i] = path[tail_start + i];
    }
    out[tail_len] = '\0';
    return (int)tail_len;
}

/* Everything before the last segment; "/" for top-level absolute paths and "." for bare names. */
int pn_dirname(const char *path, char *out, uint32_t cap) {
    uint32_t pos = 0;
    uint32_t start = 0;
    uint32_t len = 0;
    uint32_t cut = 0;
    while ((pos = pn_next_segment(path, pos, &start, &len)) != PN_END) {
        cut = start;
    }
    while (cut > 0 && pn_is_sep(path[cut - 1u])) {
        cut--;
    }
    if (cut == 0) {
        return pn_copy(out, cap, pn_is_absolute(path) ? "/" : ".");
    }
    if (cut + 1u > cap) {
        return PN_ERR_SPACE;
    }
    for (pos = 0; pos < cut; pos++) {
        out[pos] = path[pos];
    }
    out[cut] = '\0';
    return (int)cut;
}

/* Text after the last '.' of the final segment, or NULL when there is none. */
const char *pn_extension(const char *path) {
    const char *ext = NULL;
    uint32_t i;
    for (i = 0; path[i] != '\0'; i++) {
        if (pn_is_sep(path[i])) {
            ext = NULL;
        } else if (path[i] == '.' && i > 0 && !pn_is_sep(path[i - 1u])) {
            ext = path + i + 1u;
        }
    }
    return ext;
}

/* Case-insensitive extension test, e.g. pn_has_ext("a/B.TXT", "txt"). */
int pn_has_ext(const char *path, const char *want) {
    const char *have = pn_extension(path);
    uint32_t i = 0;
    if (have == NULL) {
        return 0;
    }
    while (have[i] != '\0' && want[i] != '\0') {
        if (pn_lower(have[i]) != pn_lower(want[i])) {
            return 0;
        }
        i++;
    }
    return have[i] == want[i];
}

int pn_is_hidden(const char *path) {
    char name[PN_MAX];
    if (pn_basename(path, name, sizeof name) > 0) {
        return name[0] == '.';
    }
    return 0;
}
