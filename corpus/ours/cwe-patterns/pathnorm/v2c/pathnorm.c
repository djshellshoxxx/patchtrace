/* pathnorm.c - path joining, normalisation and containment checks (v2c).
 *
 * pn_resolve() is the entry point used by request handlers: it joins a trusted root with a
 * client-supplied relative path, normalises the result, and verifies it still lies under the root.
 */
#include "pathnorm.h"

/* ---- character and string helpers --------------------------------------- */

int pn_is_sep(char c) {
    return c == '/' || c == '\\';
}

char pn_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

uint32_t pn_len(const char *s) {
    uint32_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

int pn_eq(const char *a, const char *b) {
    uint32_t i = 0;
    while (a[i] != '\0' && a[i] == b[i]) {
        i++;
    }
    return a[i] == b[i];
}

/* Bounded copy; returns the length or PN_ERR_SPACE when the NUL does not fit. */
int pn_copy(char *dst, uint32_t cap, const char *src) {
    uint32_t n = pn_len(src);
    uint32_t i;
    if (n + 1u > cap) {
        return PN_ERR_SPACE;
    }
    for (i = 0; i <= n; i++) {
        dst[i] = src[i];
    }
    return (int)n;
}

int pn_has_prefix(const char *s, const char *prefix) {
    uint32_t i = 0;
    while (prefix[i] != '\0') {
        if (s[i] != prefix[i]) {
            return 0;
        }
        i++;
    }
    return 1;
}

/* ---- segments ----------------------------------------------------------- */

/* Find the next non-empty segment at or after `pos`; returns the position after it or PN_END. */
uint32_t pn_next_segment(const char *path, uint32_t pos, uint32_t *start, uint32_t *len) {
    uint32_t i = pos;
    while (pn_is_sep(path[i])) {
        i++;
    }
    if (path[i] == '\0') {
        return PN_END;
    }
    *start = i;
    while (path[i] != '\0' && !pn_is_sep(path[i])) {
        i++;
    }
    *len = i - *start;
    return i;
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

/* True for the segment "..". */
int pn_segment_is_dotdot(const char *s, uint32_t len) {
    return len == 2 && s[0] == '.' && s[1] == '.';
}

/* ---- normalisation and resolution --------------------------------------- */

/* Rewrite `in` as an absolute path: single '/' separators, no "." segments, ".." resolved against the
 * preceding segment, no trailing '/'. A ".." that would climb above the top is an error. */
int pn_normalize(const char *in, char *out, uint32_t cap) {
    uint32_t starts[8];
    uint32_t depth = 0;
    uint32_t pos = 0;
    uint32_t w = 0;
    uint32_t start = 0;
    uint32_t seg = 0;
    uint32_t i;
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
            w = starts[depth];
            continue;
        }
        if (depth == 8) {
            return PN_ERR_DEPTH;
        }
        if (w + 1u + seg + 1u > cap) {
            return PN_ERR_SPACE;
        }
        starts[depth++] = w;
        out[w++] = '/';
        for (i = 0; i < seg; i++) {
            out[w++] = in[start + i];
        }
    }
    if (w == 0) {
        out[w++] = '/';
    }
    out[w] = '\0';
    return (int)w;
}

/* base + "/" + rel with exactly one separator between them. */
int pn_join(const char *base, const char *rel, char *out, uint32_t cap) {
    uint32_t n = pn_len(base);
    uint32_t w = 0;
    uint32_t i = 0;
    if (n + 2u > cap) {
        return PN_ERR_SPACE;
    }
    for (i = 0; i < n; i++) {
        out[w++] = base[i];
    }
    if (n > 0 && !pn_is_sep(base[n - 1u])) {
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

/* ---- name parts --------------------------------------------------------- */

int pn_basename(const char *path, char *out, uint32_t cap) {
    uint32_t pos = 0;
    uint32_t start = 0;
    uint32_t len = 0;
    uint32_t last_start = 0;
    uint32_t last_len = 0;
    uint32_t i;
    while ((pos = pn_next_segment(path, pos, &start, &len)) != PN_END) {
        last_start = start;
        last_len = len;
    }
    if (last_len + 1u > cap) {
        return PN_ERR_SPACE;
    }
    for (i = 0; i < last_len; i++) {
        out[i] = path[last_start + i];
    }
    out[last_len] = '\0';
    return (int)last_len;
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
    const char *dot = NULL;
    uint32_t i;
    for (i = 0; path[i] != '\0'; i++) {
        if (pn_is_sep(path[i])) {
            dot = NULL;
        } else if (path[i] == '.' && i > 0 && !pn_is_sep(path[i - 1u])) {
            dot = path + i + 1u;
        }
    }
    return dot;
}

/* Case-insensitive extension test, e.g. pn_has_ext("a/B.TXT", "txt"). */
int pn_has_ext(const char *path, const char *ext) {
    const char *found = pn_extension(path);
    uint32_t i = 0;
    if (found == NULL) {
        return 0;
    }
    while (found[i] != '\0' && ext[i] != '\0') {
        if (pn_lower(found[i]) != pn_lower(ext[i])) {
            return 0;
        }
        i++;
    }
    return found[i] == ext[i];
}

int pn_is_hidden(const char *path) {
    char name[PN_MAX];
    if (pn_basename(path, name, sizeof name) <= 0) {
        return 0;
    }
    return name[0] == '.';
}
