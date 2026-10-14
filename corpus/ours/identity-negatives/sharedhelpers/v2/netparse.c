/* PatchTrace known-answer corpus: identity-negatives/sharedhelpers, version 2. MIT licence.
 * Network field parsers. They use the shared helpers from util.c and nothing else.
 */
#include "shared.h"

int32_t net_parse_port(const char *s, uint32_t len, uint16_t *port) {
    uint32_t v;
    int32_t used;

    if (port == NULL) {
        return NET_E_FORMAT;
    }
    used = ut_parse_u32(s, len, &v);
    if (used < 0) {
        return used;
    }
    if ((uint32_t)used != len || v == 0u || v > 65535u) {
        return NET_E_PORT;
    }
    *port = (uint16_t)v;
    return UT_OK;
}

int32_t net_parse_mtu(const char *s, uint32_t len, uint16_t *mtu) {
    uint32_t v;
    int32_t used;

    if (mtu == NULL) {
        return NET_E_FORMAT;
    }
    used = ut_parse_u32(s, len, &v);
    if (used < 0) {
        return used;
    }
    if ((uint32_t)used != len || v < 576u || v > 9000u) {
        return NET_E_FORMAT;
    }
    *mtu = (uint16_t)v;
    return UT_OK;
}

/* "100" or "100/5": VLAN id with an optional priority code point. */
int32_t net_parse_vlan(const char *s, uint32_t len, uint16_t *vid, uint8_t *pcp) {
    uint32_t id, prio = 0u;
    int32_t slash, used;

    if (vid == NULL || pcp == NULL) {
        return NET_E_FORMAT;
    }
    slash = ut_find_char(s, len, '/');
    used = ut_parse_u32(s, (slash < 0) ? len : (uint32_t)slash, &id);
    if (used < 0) {
        return used;
    }
    if (slash >= 0) {
        uint32_t rest = len - (uint32_t)slash - 1u;

        used = ut_parse_u32(s + slash + 1, rest, &prio);
        if (used < 0 || (uint32_t)used != rest || prio > 7u) {
            return NET_E_FORMAT;
        }
    }
    if (id == 0u || id > 4094u) {
        return NET_E_FORMAT;
    }
    *vid = (uint16_t)id;
    *pcp = (uint8_t)prio;
    return UT_OK;
}

int32_t net_parse_ipv4(const char *s, uint32_t len, uint8_t out[4]) {
    uint32_t pos = 0u;
    uint32_t k;

    for (k = 0; k < 4u; k++) {
        uint32_t v;
        int32_t dot = ut_find_char(s + pos, len - pos, '.');
        uint32_t part = (dot < 0) ? len - pos : (uint32_t)dot;
        int32_t used;

        if ((k < 3u && dot < 0) || (k == 3u && dot >= 0) || part == 0u) {
            return NET_E_FORMAT;
        }
        used = ut_parse_u32(s + pos, part, &v);
        if (used < 0 || (uint32_t)used != part) {
            return NET_E_FORMAT;
        }
        if (v > 255u) {
            return NET_E_OCTET;
        }
        out[k] = (uint8_t)v;
        pos += part + 1u;
    }
    return UT_OK;
}

/* "/24" or "24": CIDR prefix length. */
int32_t net_parse_prefix_len(const char *s, uint32_t len, uint8_t *prefix) {
    uint32_t v;
    uint32_t skip = (len > 0u && s[0] == '/') ? 1u : 0u;
    int32_t used = ut_parse_u32(s + skip, len - skip, &v);

    if (used < 0) {
        return used;
    }
    if ((uint32_t)used + skip != len || v > 32u) {
        return NET_E_FORMAT;
    }
    *prefix = (uint8_t)v;
    return UT_OK;
}
