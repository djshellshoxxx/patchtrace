/* pathnorm.h - path joining, normalisation and containment checks on caller-provided buffers.
 *
 * Both '/' and '\\' separate segments; results always use '/'. Intended use: resolve a client-supplied
 * relative path against a trusted root directory and refuse anything that leaves the root.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef PATHNORM_H
#define PATHNORM_H

#include <stddef.h>
#include <stdint.h>

#define PN_MAX 128u
#define PN_END 0xffffffffu

#define PN_OK 0
#define PN_ERR_SPACE (-1)
#define PN_ERR_ESCAPE (-2)
#define PN_ERR_DEPTH (-3)
#define PN_ERR_ARG (-4)

/* character and string helpers */
int pn_is_sep(char c);
char pn_lower(char c);
uint32_t pn_len(const char *s);
int pn_eq(const char *a, const char *b);
int pn_copy(char *dst, uint32_t cap, const char *src);
int pn_has_prefix(const char *s, const char *prefix);

/* segments */
uint32_t pn_next_segment(const char *path, uint32_t pos, uint32_t *start, uint32_t *len);
uint32_t pn_depth(const char *path);
int pn_is_absolute(const char *path);
int pn_segment_is_dotdot(const char *s, uint32_t len);

/* normalisation and resolution */
int pn_normalize(const char *in, char *out, uint32_t cap);
int pn_join(const char *base, const char *rel, char *out, uint32_t cap);
int pn_is_under(const char *root, const char *path);
int pn_resolve(const char *root, const char *rel, char *out, uint32_t cap);

/* name parts */
int pn_basename(const char *path, char *out, uint32_t cap);
int pn_dirname(const char *path, char *out, uint32_t cap);
const char *pn_extension(const char *path);
int pn_has_ext(const char *path, const char *ext);
int pn_is_hidden(const char *path);

#endif /* PATHNORM_H */
