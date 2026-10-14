/* authcfg.h - role-protected key/value configuration store over a caller-provided byte array.
 *
 * Entries are 24 bytes: [key : 16, NUL padded][value : 4, little endian][flags : 2][pad : 2].
 * Sessions are created by presenting a secret that was provisioned for a role.
 * Freestanding C11: no libc, no OS calls.
 */
#ifndef AUTHCFG_H
#define AUTHCFG_H

#include <stddef.h>
#include <stdint.h>

#define AC_MAX_SESSIONS 4u
#define AC_KEY_BYTES 16u
#define AC_ENTRY_BYTES 24u
#define AC_OFF_VALUE 16u
#define AC_OFF_FLAGS 20u
#define AC_FLAG_PROTECTED 1u

#define AC_ROLE_NONE 0u
#define AC_ROLE_USER 1u
#define AC_ROLE_OPERATOR 2u
#define AC_ROLE_ADMIN 3u

#define AC_OK 0
#define AC_ERR_ARG (-1)
#define AC_ERR_DENIED (-2)
#define AC_ERR_NOTFOUND (-3)
#define AC_ERR_FULL (-4)
#define AC_ERR_PROTECTED (-5)

typedef struct ac_session {
    uint32_t id;
    uint8_t role;
    uint8_t active;
    uint16_t uses;
} ac_session;

typedef struct ac_store {
    uint8_t *base;          /* caller-provided entry table */
    uint32_t cap;           /* entries that fit */
    uint32_t count;         /* entries in use */
    uint32_t writes;        /* successful writes */
    uint32_t denied;        /* rejected requests */
    uint32_t failed_logins;
    uint32_t next_id;
    uint32_t hashes[4];     /* credential hash per role, 0 = not provisioned */
    ac_session sessions[AC_MAX_SESSIONS];
} ac_store;

/* helpers */
uint32_t ac_hash(const char *s);
uint32_t ac_load32(const uint8_t *p);
void ac_store32(uint8_t *p, uint32_t v);
int ac_key_pack(uint8_t *dst, const char *key);
uint8_t *ac_entry_at(const ac_store *store, uint32_t index);
uint32_t ac_entry_flags(const ac_store *store, uint32_t index);

/* setup and sessions */
int ac_init(ac_store *store, uint8_t *storage, uint32_t bytes);
int ac_provision(ac_store *store, uint32_t role, const char *secret);
uint32_t ac_login(ac_store *store, const char *secret);
void ac_logout(ac_store *store, uint32_t sid);
int ac_session_index(const ac_store *store, uint32_t sid);
uint32_t ac_role_of(const ac_store *store, uint32_t sid);
int ac_authorize(const ac_store *store, uint32_t sid, uint32_t min_role);

/* entries */
int ac_find(const ac_store *store, const char *key);
int ac_put(ac_store *store, const char *key, uint32_t value);
int ac_get(ac_store *store, uint32_t sid, const char *key, uint32_t *out);
void ac_note_denied(ac_store *store);
int ac_set(ac_store *store, uint32_t sid, const char *key, uint32_t value);
int ac_delete(ac_store *store, uint32_t sid, const char *key);
int ac_protect(ac_store *store, uint32_t sid, const char *key);
int ac_factory_reset(ac_store *store, uint32_t sid);

/* counters */
uint32_t ac_count(const ac_store *store);
uint32_t ac_stat_denied(const ac_store *store);
uint32_t ac_stat_writes(const ac_store *store);

#endif /* AUTHCFG_H */
