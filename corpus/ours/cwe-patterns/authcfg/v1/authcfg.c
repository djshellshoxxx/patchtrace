/* authcfg.c - role-protected configuration store (v1).
 *
 * Reads need at least the user role, writes and deletes need the operator role, and protecting
 * an entry or wiping the store needs the admin role. Protected entries can only be changed by admins.
 */
#include "authcfg.h"

/* ---- helpers ------------------------------------------------------------ */

/* 32-bit FNV-1a of a NUL-terminated string. */
uint32_t ac_hash(const char *s) {
    uint32_t h = 2166136261u;
    while (*s != '\0') {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

uint32_t ac_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void ac_store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

/* Copy a key into a 16-byte NUL-padded field; returns 0 for empty or over-long keys. */
int ac_key_pack(uint8_t *dst, const char *key) {
    uint32_t i = 0;
    if (key == NULL || key[0] == '\0') {
        return 0;
    }
    while (key[i] != '\0') {
        if (i >= AC_KEY_BYTES - 1u) {
            return 0;
        }
        dst[i] = (uint8_t)key[i];
        i++;
    }
    while (i < AC_KEY_BYTES) {
        dst[i] = 0;
        i++;
    }
    return 1;
}

uint8_t *ac_entry_at(const ac_store *store, uint32_t index) {
    return store->base + (size_t)index * AC_ENTRY_BYTES;
}

uint32_t ac_entry_flags(const ac_store *store, uint32_t index) {
    const uint8_t *e = ac_entry_at(store, index);
    return (uint32_t)e[AC_OFF_FLAGS] | ((uint32_t)e[AC_OFF_FLAGS + 1u] << 8);
}

/* ---- setup and sessions ------------------------------------------------- */

int ac_init(ac_store *store, uint8_t *storage, uint32_t bytes) {
    uint32_t i;
    if (store == NULL || storage == NULL) {
        return AC_ERR_ARG;
    }
    store->base = storage;
    store->cap = bytes / AC_ENTRY_BYTES;
    store->count = 0;
    store->writes = 0;
    store->denied = 0;
    store->failed_logins = 0;
    store->next_id = 1;
    for (i = 0; i < 4; i++) {
        store->hashes[i] = 0;
    }
    for (i = 0; i < AC_MAX_SESSIONS; i++) {
        store->sessions[i].id = 0;
        store->sessions[i].role = AC_ROLE_NONE;
        store->sessions[i].active = 0;
        store->sessions[i].uses = 0;
    }
    return store->cap > 0 ? AC_OK : AC_ERR_ARG;
}

/* Install the credential for a role (done at provisioning time, before any session exists). */
int ac_provision(ac_store *store, uint32_t role, const char *secret) {
    if (role < AC_ROLE_USER || role > AC_ROLE_ADMIN || secret == NULL || secret[0] == '\0') {
        return AC_ERR_ARG;
    }
    store->hashes[role] = ac_hash(secret);
    return AC_OK;
}

/* Open a session at the highest role whose credential matches; returns the session id or 0. */
uint32_t ac_login(ac_store *store, const char *secret) {
    uint32_t h;
    uint32_t role = AC_ROLE_NONE;
    uint32_t r;
    uint32_t i;
    if (secret == NULL) {
        return 0;
    }
    h = ac_hash(secret);
    for (r = AC_ROLE_USER; r <= AC_ROLE_ADMIN; r++) {
        if (store->hashes[r] != 0 && store->hashes[r] == h) {
            role = r;
        }
    }
    if (role == AC_ROLE_NONE) {
        store->failed_logins++;
        return 0;
    }
    for (i = 0; i < AC_MAX_SESSIONS; i++) {
        if (!store->sessions[i].active) {
            store->sessions[i].id = store->next_id++;
            store->sessions[i].role = (uint8_t)role;
            store->sessions[i].active = 1;
            store->sessions[i].uses = 0;
            return store->sessions[i].id;
        }
    }
    return 0;
}

void ac_logout(ac_store *store, uint32_t sid) {
    int index = ac_session_index(store, sid);
    if (index >= 0) {
        store->sessions[index].active = 0;
        store->sessions[index].role = AC_ROLE_NONE;
    }
}

int ac_session_index(const ac_store *store, uint32_t sid) {
    uint32_t i;
    if (sid == 0) {
        return -1;
    }
    for (i = 0; i < AC_MAX_SESSIONS; i++) {
        if (store->sessions[i].active && store->sessions[i].id == sid) {
            return (int)i;
        }
    }
    return -1;
}

uint32_t ac_role_of(const ac_store *store, uint32_t sid) {
    int index = ac_session_index(store, sid);
    return index < 0 ? AC_ROLE_NONE : store->sessions[index].role;
}

int ac_authorize(const ac_store *store, uint32_t sid, uint32_t min_role) {
    return ac_role_of(store, sid) >= min_role;
}

/* ---- entries ------------------------------------------------------------ */

/* Index of `key`, AC_ERR_ARG for a malformed key or AC_ERR_NOTFOUND. */
int ac_find(const ac_store *store, const char *key) {
    uint8_t packed[AC_KEY_BYTES];
    uint32_t i;
    uint32_t j;
    if (!ac_key_pack(packed, key)) {
        return AC_ERR_ARG;
    }
    for (i = 0; i < store->count; i++) {
        const uint8_t *e = ac_entry_at(store, i);
        for (j = 0; j < AC_KEY_BYTES && e[j] == packed[j]; j++) {
            /* compare */
        }
        if (j == AC_KEY_BYTES) {
            return (int)i;
        }
    }
    return AC_ERR_NOTFOUND;
}

/* Insert or update without any permission check; callers decide who may write. */
int ac_put(ac_store *store, const char *key, uint32_t value) {
    int idx = ac_find(store, key);
    uint8_t *e;
    if (idx == AC_ERR_ARG) {
        return AC_ERR_ARG;
    }
    if (idx == AC_ERR_NOTFOUND) {
        if (store->count >= store->cap) {
            return AC_ERR_FULL;
        }
        e = ac_entry_at(store, store->count);
        ac_key_pack(e, key);
        ac_store32(e + AC_OFF_FLAGS, 0);
        store->count++;
    } else {
        e = ac_entry_at(store, (uint32_t)idx);
    }
    ac_store32(e + AC_OFF_VALUE, value);
    store->writes++;
    return AC_OK;
}

int ac_get(ac_store *store, uint32_t sid, const char *key, uint32_t *out) {
    int idx;
    if (out == NULL) {
        return AC_ERR_ARG;
    }
    if (!ac_authorize(store, sid, AC_ROLE_USER)) {
        store->denied++;
        return AC_ERR_DENIED;
    }
    idx = ac_find(store, key);
    if (idx < 0) {
        return idx;
    }
    *out = ac_load32(ac_entry_at(store, (uint32_t)idx) + AC_OFF_VALUE);
    return AC_OK;
}

/* Write a value. Protected entries can only be changed by an admin. */
int ac_set(ac_store *store, uint32_t sid, const char *key, uint32_t value) {
    int idx = ac_find(store, key);
    if (idx >= 0 && (ac_entry_flags(store, (uint32_t)idx) & AC_FLAG_PROTECTED) != 0 &&
        ac_role_of(store, sid) < AC_ROLE_ADMIN) {
        store->denied++;
        return AC_ERR_PROTECTED;
    }
    return ac_put(store, key, value);
}

int ac_delete(ac_store *store, uint32_t sid, const char *key) {
    int idx;
    uint32_t last;
    uint32_t j;
    if (!ac_authorize(store, sid, AC_ROLE_OPERATOR)) {
        store->denied++;
        return AC_ERR_DENIED;
    }
    idx = ac_find(store, key);
    if (idx < 0) {
        return idx;
    }
    if ((ac_entry_flags(store, (uint32_t)idx) & AC_FLAG_PROTECTED) != 0 && ac_role_of(store, sid) < AC_ROLE_ADMIN) {
        store->denied++;
        return AC_ERR_PROTECTED;
    }
    last = store->count - 1u;
    for (j = 0; j < AC_ENTRY_BYTES; j++) {
        ac_entry_at(store, (uint32_t)idx)[j] = ac_entry_at(store, last)[j];
    }
    store->count = last;
    return AC_OK;
}

int ac_protect(ac_store *store, uint32_t sid, const char *key) {
    int idx;
    if (!ac_authorize(store, sid, AC_ROLE_ADMIN)) {
        store->denied++;
        return AC_ERR_DENIED;
    }
    idx = ac_find(store, key);
    if (idx < 0) {
        return idx;
    }
    ac_store32(ac_entry_at(store, (uint32_t)idx) + AC_OFF_FLAGS, AC_FLAG_PROTECTED);
    return AC_OK;
}

/* Drop every entry, protected or not. */
int ac_factory_reset(ac_store *store, uint32_t sid) {
    (void)sid;
    store->count = 0;
    store->writes = 0;
    return AC_OK;
}

/* Development hook: write a value without a session. */
int ac_debug_set(ac_store *store, const char *key, uint32_t value) {
    return ac_put(store, key, value);
}

/* ---- counters ----------------------------------------------------------- */

uint32_t ac_count(const ac_store *store) {
    return store->count;
}

uint32_t ac_stat_denied(const ac_store *store) {
    return store->denied;
}

uint32_t ac_stat_writes(const ac_store *store) {
    return store->writes;
}
