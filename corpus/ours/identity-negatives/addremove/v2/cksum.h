/* PatchTrace known-answer corpus: identity-negatives/addremove, version 2. MIT licence.
 * Freestanding C11, no libc.
 *
 * Registry of checksum and hash algorithms used by a storage format. Every algorithm is a
 * function of the same shape (initialise, one loop over the bytes, finish), and the registry
 * addresses them by a small numeric id that is stored on disk.
 */
#ifndef CKSUM_H
#define CKSUM_H

#include <stddef.h>
#include <stdint.h>

#define CK_OK 0
#define CK_E_NULL (-1)
#define CK_E_ALGO (-2)
#define CK_E_MISMATCH (-3)

/* On-disk ids: stable across releases, whatever function implements them. */
enum ck_algo {
    CK_PARITY = 1,
    CK_SUM16 = 2,
    CK_FLETCHER = 3,
    CK_ADLER32 = 4,
    CK_CRC16 = 5,
    CK_CRC32 = 6,
    CK_STRHASH = 7,
    CK_FNV1A = 8,
    CK_INET16 = 9
};

extern uint8_t ck_test_vector[9];

uint32_t ck_xor8(const uint8_t *p, uint32_t n);
uint32_t ck_sum16(const uint8_t *p, uint32_t n);
uint32_t ck_fletcher16(const uint8_t *p, uint32_t n);
uint32_t ck_adler32(const uint8_t *p, uint32_t n);
uint32_t ck_crc16_modbus(const uint8_t *p, uint32_t n);
uint32_t ck_crc32_ieee(const uint8_t *p, uint32_t n);
uint32_t ck_sdbm(const uint8_t *p, uint32_t n);
uint32_t ck_fnv1a32(const uint8_t *p, uint32_t n);
uint32_t ck_inet16(const uint8_t *p, uint32_t n);

int32_t ck_compute(uint32_t algo, const uint8_t *p, uint32_t n, uint32_t *out);
uint32_t ck_width_bits(uint32_t algo);
int32_t ck_verify(uint32_t algo, const uint8_t *p, uint32_t n, uint32_t expect);
int32_t ck_is_crc(uint32_t algo);
int32_t ck_selftest(void);

#endif
