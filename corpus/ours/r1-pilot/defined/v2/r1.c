/* SPDX-License-Identifier: MIT
 * PatchTrace-authored static-analysis fixtures. Never execute the built image.
 * Domains and candidate source-truth ledger: ../README.md.
 */
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define R1_NOINLINE __declspec(noinline)
#else
#define R1_NOINLINE __attribute__((noinline))
#endif

typedef uint32_t (*r1_operation)(uint32_t value);
typedef uint8_t *(*r1_allocator)(size_t bytes, void *context);

typedef struct r1_operations {
    r1_operation primary;
    r1_operation secondary;
} r1_operations;

typedef struct r1_record {
    uint32_t requested;
    uint32_t granted;
} r1_record;

_Static_assert(UINT8_MAX == 255u, "requires exact eight-bit byte values");
_Static_assert(UINT32_MAX == 0xffffffffu, "requires exact 32-bit arithmetic");
_Static_assert(sizeof(uint32_t) == 4u, "fixture field offset assumes four bytes");
_Static_assert(offsetof(r1_record, requested) == 0u, "first field offset");
_Static_assert(offsetof(r1_record, granted) == 4u, "second field offset");
_Static_assert(sizeof(size_t) >= sizeof(uint32_t), "allocator sizes fit size_t");
_Static_assert((0x40000000u * 4u) == 0u, "unsigned multiplication wraps");
_Static_assert(((uint32_t)-1) == UINT32_MAX, "signed-to-unsigned is modulo 2^32");

uint32_t R1_NOINLINE r1_integer_constant(uint32_t value) {
    return value + 29u;
}

uint32_t R1_NOINLINE r1_comparison(uint32_t value) {
    return value <= 13u ? 0xa1u : 0xb2u;
}

uint32_t R1_NOINLINE r1_branch_inversion(uint32_t flags, uint32_t value) {
    if ((flags & 4u) == 0u) {
        return value ^ 0x55u;
    }
    return value + 0x23u;
}

uint32_t R1_NOINLINE r1_bounds_added(const uint8_t *data, uint32_t logical_length, uint32_t index) {
    if (data == NULL || logical_length > 16u || index >= 16u) {
        return UINT32_MAX;
    }
    if (index >= logical_length) {
        return UINT32_MAX;
    }
    return data[index];
}

uint32_t R1_NOINLINE r1_bounds_removed(const uint8_t *data, uint32_t logical_length, uint32_t index) {
    if (data == NULL || logical_length > 16u || index >= 16u) {
        return UINT32_MAX;
    }
    return data[index];
}

uint32_t R1_NOINLINE r1_pointer_offset(const uint8_t *data) {
    if (data == NULL) {
        return UINT32_MAX;
    }
    const uint8_t *selected = data + 2u;
    return *selected;
}

uint32_t R1_NOINLINE r1_array_index(const uint8_t *data, uint32_t index) {
    if (data == NULL) {
        return UINT32_MAX;
    }
    return data[(index + 1u) & 3u];
}

uint32_t R1_NOINLINE r1_overflow_guard(uint32_t count) {
    if (count > UINT32_MAX / 4u) {
        return UINT32_MAX;
    }
    return count * 4u;
}

uint32_t R1_NOINLINE r1_signedness(int32_t delta) {
    return (uint32_t)delta < 8u ? 1u : 0u;
}

uint8_t R1_NOINLINE *r1_allocation_size(uint32_t count, r1_allocator allocate, void *context) {
    if (allocate == NULL || count > 32u) {
        return NULL;
    }
    return allocate((size_t)count * 4u + 16u, context);
}

uint32_t R1_NOINLINE r1_loop_bound(const uint8_t *data, uint32_t count) {
    if (data == NULL) {
        return UINT32_MAX;
    }
    uint32_t limit = count < 8u ? count : 8u;
    uint32_t total = 0u;
    for (uint32_t index = 0u; index <= limit; ++index) {
        total += data[index];
    }
    return total;
}

uint32_t R1_NOINLINE r1_call_target(const r1_operations *operations, uint32_t value) {
    if (operations == NULL || operations->primary == NULL || operations->secondary == NULL) {
        return UINT32_MAX;
    }
    return operations->secondary(value);
}

uint32_t R1_NOINLINE r1_error_handling(uint32_t status, uint32_t value) {
    if (status != 0u) {
        return UINT32_MAX;
    }
    return value;
}

uint32_t R1_NOINLINE r1_null_validation(const uint32_t *marker, uint32_t value) {
    if (marker == NULL) {
        return UINT32_MAX;
    }
    return value;
}

uint32_t R1_NOINLINE r1_structure_field(const r1_record *record) {
    if (record == NULL) {
        return UINT32_MAX;
    }
    return record->granted;
}

uint32_t R1_NOINLINE r1_security_flag(uint32_t flags) {
    return flags | 5u;
}

uint32_t R1_NOINLINE r1_primary(uint32_t value) {
    return value + 0x11u;
}

uint32_t R1_NOINLINE r1_secondary(uint32_t value) {
    return value ^ 0x2du;
}

uint32_t R1_NOINLINE r1_unchanged(uint32_t value) {
    return (value << 5u) | (value >> 27u);
}

uint32_t R1_NOINLINE r1_cosmetic(uint32_t value) {
    return value ^ 0x517u; /* Spacing and comment only. */
}

uint32_t R1_NOINLINE r1_added(uint32_t value) {
    return value + 0x67u;
}
