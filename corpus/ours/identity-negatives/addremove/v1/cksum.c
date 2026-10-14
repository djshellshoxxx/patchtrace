/* PatchTrace known-answer corpus: identity-negatives/addremove, version 1. MIT licence.
 * Algorithms and registry.
 */
#include "cksum.h"

/* The standard check string "123456789". Not const, so the self-test cannot be folded away. */
uint8_t ck_test_vector[9] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};

/* Longitudinal parity: XOR of all bytes. */
uint32_t ck_xor8(const uint8_t *p, uint32_t n) {
    uint32_t x = 0u;
    uint32_t i;

    for (i = 0; i < n; i++) {
        x ^= p[i];
    }
    return x;
}

uint32_t ck_sum16(const uint8_t *p, uint32_t n) {
    uint32_t s = 0u;
    uint32_t i;

    for (i = 0; i < n; i++) {
        s = (s + p[i]) & 0xFFFFu;
    }
    return s;
}

uint32_t ck_fletcher16(const uint8_t *p, uint32_t n) {
    uint32_t a = 0u;
    uint32_t b = 0u;
    uint32_t i;

    for (i = 0; i < n; i++) {
        a = (a + p[i]) % 255u;
        b = (b + a) % 255u;
    }
    return (b << 8) | a;
}

uint32_t ck_adler32(const uint8_t *p, uint32_t n) {
    uint32_t a = 1u;
    uint32_t b = 0u;
    uint32_t i;

    for (i = 0; i < n; i++) {
        a = (a + p[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

/* CRC-16/CCITT-FALSE: polynomial 0x1021, init 0xFFFF, MSB first, no final xor. */
uint32_t ck_crc16_ccitt(const uint8_t *p, uint32_t n) {
    uint32_t crc = 0xFFFFu;
    uint32_t i, bit;

    for (i = 0; i < n; i++) {
        crc ^= (uint32_t)p[i] << 8;
        for (bit = 0; bit < 8u; bit++) {
            crc = (crc & 0x8000u) ? (((crc << 1) ^ 0x1021u) & 0xFFFFu) : ((crc << 1) & 0xFFFFu);
        }
    }
    return crc;
}

/* CRC-32/IEEE: reflected polynomial 0xEDB88320, init and final xor 0xFFFFFFFF. */
uint32_t ck_crc32_ieee(const uint8_t *p, uint32_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    uint32_t i, bit;

    for (i = 0; i < n; i++) {
        crc ^= p[i];
        for (bit = 0; bit < 8u; bit++) {
            crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
        }
    }
    return ~crc;
}

/* Bernstein hash, h * 33 + c. */
uint32_t ck_djb2(const uint8_t *p, uint32_t n) {
    uint32_t h = 5381u;
    uint32_t i;

    for (i = 0; i < n; i++) {
        h = ((h << 5) + h) + p[i];
    }
    return h;
}

uint32_t ck_fnv1a32(const uint8_t *p, uint32_t n) {
    uint32_t h = 2166136261u;
    uint32_t i;

    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

/* RFC 1071 one's complement sum. */
uint32_t ck_inet16(const uint8_t *p, uint32_t n) {
    uint32_t sum = 0u;
    uint32_t i;

    for (i = 0; i + 1u < n; i += 2u) {
        sum += ((uint32_t)p[i] << 8) | p[i + 1u];
    }
    if (i < n) {
        sum += (uint32_t)p[i] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (~sum) & 0xFFFFu;
}

int32_t ck_compute(uint32_t algo, const uint8_t *p, uint32_t n, uint32_t *out) {
    if (p == NULL || out == NULL) {
        return CK_E_NULL;
    }
    switch (algo) {
    case CK_PARITY:
        *out = ck_xor8(p, n);
        break;
    case CK_SUM16:
        *out = ck_sum16(p, n);
        break;
    case CK_FLETCHER:
        *out = ck_fletcher16(p, n);
        break;
    case CK_ADLER32:
        *out = ck_adler32(p, n);
        break;
    case CK_CRC16:
        *out = ck_crc16_ccitt(p, n);
        break;
    case CK_CRC32:
        *out = ck_crc32_ieee(p, n);
        break;
    case CK_STRHASH:
        *out = ck_djb2(p, n);
        break;
    case CK_FNV1A:
        *out = ck_fnv1a32(p, n);
        break;
    case CK_INET16:
        *out = ck_inet16(p, n);
        break;
    default:
        return CK_E_ALGO;
    }
    return CK_OK;
}

uint32_t ck_width_bits(uint32_t algo) {
    switch (algo) {
    case CK_PARITY:
        return 8u;
    case CK_SUM16:
    case CK_FLETCHER:
    case CK_CRC16:
    case CK_INET16:
        return 16u;
    case CK_ADLER32:
    case CK_CRC32:
    case CK_STRHASH:
    case CK_FNV1A:
        return 32u;
    default:
        return 0u;
    }
}

int32_t ck_verify(uint32_t algo, const uint8_t *p, uint32_t n, uint32_t expect) {
    uint32_t got;
    int32_t rc = ck_compute(algo, p, n, &got);

    if (rc != CK_OK) {
        return rc;
    }
    return (got == expect) ? CK_OK : CK_E_MISMATCH;
}

int32_t ck_is_crc(uint32_t algo) {
    return algo == CK_CRC16 || algo == CK_CRC32;
}

/* Known-answer test on the "123456789" vector; returns the number of failures. */
int32_t ck_selftest(void) {
    int32_t failures = 0;

    failures += ck_xor8(ck_test_vector, 9u) != 0x31u;
    failures += ck_sum16(ck_test_vector, 9u) != 0x1DDu;
    failures += ck_fletcher16(ck_test_vector, 9u) != 0x1EDEu;
    failures += ck_adler32(ck_test_vector, 9u) != 0x091E01DEu;
    failures += ck_crc16_ccitt(ck_test_vector, 9u) != 0x29B1u;
    failures += ck_crc32_ieee(ck_test_vector, 9u) != 0xCBF43926u;
    failures += ck_djb2(ck_test_vector, 9u) != 0x35CDBB82u;
    failures += ck_fnv1a32(ck_test_vector, 9u) != 0xBB86B11Cu;
    failures += ck_inet16(ck_test_vector, 9u) != 0xF62Au;
    return failures;
}
