/*
 * fnptr: function-pointer dispatch tables, callbacks and an observer bus.
 *
 * A command table indexed by enum, a searched table of (id, handler) pairs, higher-order helpers (foreach, reduce,
 * map, count_if), an insertion sort and a binary search that take a comparator, and a small publish/subscribe bus. The
 * optimiser can turn calls through a constant table or a constant comparator into direct calls or inlined code, while
 * -O0 keeps every indirect call, so the same source has very different call graphs at different levels.
 * Freestanding C11: no libc, no mutable globals.
 */
#include <stddef.h>
#include <stdint.h>

#define FP_BUS_CAP 8u
#define FP_MAX(a, b) ((a) > (b) ? (a) : (b))
#define FP_ENTRY_COUNT (sizeof fp_entries / sizeof fp_entries[0])

typedef uint32_t (*fp_binop)(uint32_t, uint32_t);
typedef int (*fp_cmp)(int32_t, int32_t);
typedef void (*fp_visit)(uint32_t value, void *ctx);
typedef int (*fp_pred)(uint32_t value, void *ctx);
typedef int32_t (*fp_handler)(void *ctx, uint32_t event, int32_t arg);

enum fp_cmd { FP_CMD_ADD, FP_CMD_SUB, FP_CMD_MUL, FP_CMD_DIV, FP_CMD_MIN, FP_CMD_MAX, FP_CMD_XOR, FP_CMD_COUNT };

struct fp_entry {
    uint32_t id;
    fp_binop fn;
};

struct fp_bus {
    fp_handler handler[FP_BUS_CAP];
    void *ctx[FP_BUS_CAP];
    uint32_t count;
};

/* ---- binary operations -------------------------------------------------------------------------------------- */

uint32_t fp_cmd_add(uint32_t a, uint32_t b) {
    return a + b;
}

uint32_t fp_cmd_sub(uint32_t a, uint32_t b) {
    return a - b;
}

uint32_t fp_cmd_mul(uint32_t a, uint32_t b) {
    return a * b;
}

/* Division by zero yields 0 instead of trapping. */
uint32_t fp_cmd_div(uint32_t a, uint32_t b) {
    return b == 0u ? 0u : a / b;
}

uint32_t fp_cmd_min(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

uint32_t fp_cmd_max(uint32_t a, uint32_t b) {
    return FP_MAX(a, b);
}

uint32_t fp_cmd_xor(uint32_t a, uint32_t b) {
    return a ^ b;
}

const fp_binop fp_cmd_table[FP_CMD_COUNT] = {
    [FP_CMD_ADD] = fp_cmd_add,
    [FP_CMD_SUB] = fp_cmd_sub,
    [FP_CMD_MUL] = fp_cmd_mul,
    [FP_CMD_DIV] = fp_cmd_div,
    [FP_CMD_MIN] = fp_cmd_min,
    [FP_CMD_MAX] = fp_cmd_max,
    [FP_CMD_XOR] = fp_cmd_xor,
};

const struct fp_entry fp_entries[] = {
    {0x10, fp_cmd_add}, {0x11, fp_cmd_sub}, {0x12, fp_cmd_mul}, {0x20, fp_cmd_div},
    {0x30, fp_cmd_min}, {0x31, fp_cmd_max}, {0x40, fp_cmd_xor},
};

/* ---- dispatch ----------------------------------------------------------------------------------------------- */

/* Run the operation selected by cmd through the table; unknown commands yield 0. */
uint32_t fp_dispatch(uint32_t cmd, uint32_t a, uint32_t b) {
    if (cmd >= FP_CMD_COUNT) {
        return 0;
    }
    return fp_cmd_table[cmd](a, b);
}

/* Linear search in the (id, handler) table; unknown ids yield 0. */
uint32_t fp_dispatch_id(uint32_t id, uint32_t a, uint32_t b) {
    for (size_t i = 0; i < FP_ENTRY_COUNT; i++) {
        if (fp_entries[i].id == id) {
            return fp_entries[i].fn(a, b);
        }
    }
    return 0;
}

/* Constant table indices: an optimiser that sees the table contents can replace both indirect calls. */
uint32_t fp_apply_const(uint32_t a, uint32_t b) {
    return fp_cmd_table[FP_CMD_MUL](a, b) + fp_cmd_table[FP_CMD_ADD](a, b);
}

/* ---- higher-order helpers ----------------------------------------------------------------------------------- */

void fp_foreach_u32(const uint32_t *p, size_t n, fp_visit cb, void *ctx) {
    for (size_t i = 0; i < n; i++) {
        cb(p[i], ctx);
    }
}

/* Left fold; a NULL operation leaves the initial value untouched. */
uint32_t fp_reduce(const uint32_t *p, size_t n, fp_binop op, uint32_t init) {
    uint32_t acc = init;
    if (op == NULL) {
        return init;
    }
    for (size_t i = 0; i < n; i++) {
        acc = op(acc, p[i]);
    }
    return acc;
}

void fp_map_inplace(uint32_t *p, size_t n, fp_binop op, uint32_t operand) {
    for (size_t i = 0; i < n; i++) {
        p[i] = op(p[i], operand);
    }
}

size_t fp_count_if(const uint32_t *p, size_t n, fp_pred pred, void *ctx) {
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        if (pred(p[i], ctx) != 0) {
            count++;
        }
    }
    return count;
}

/* Visitor that adds every value to the uint64_t behind ctx. */
void fp_visit_sum(uint32_t value, void *ctx) {
    *(uint64_t *)ctx += value;
}

int fp_pred_even(uint32_t value, void *ctx) {
    (void)ctx;
    return (value & 1u) == 0u;
}

/* Predicate: value is above the uint32_t threshold behind ctx. */
int fp_pred_above(uint32_t value, void *ctx) {
    return value > *(const uint32_t *)ctx;
}

/* ---- sorting with comparators ------------------------------------------------------------------------------- */

int fp_cmp_asc(int32_t a, int32_t b) {
    return (a > b) - (a < b);
}

int fp_cmp_desc(int32_t a, int32_t b) {
    return (a < b) - (a > b);
}

/* Order by absolute value; INT32_MIN is handled through unsigned negation. */
int fp_cmp_abs(int32_t a, int32_t b) {
    uint32_t ua = a < 0 ? 0u - (uint32_t)a : (uint32_t)a;
    uint32_t ub = b < 0 ? 0u - (uint32_t)b : (uint32_t)b;
    return (ua > ub) - (ua < ub);
}

void fp_insertion_sort(int32_t *p, size_t n, fp_cmp cmp) {
    for (size_t i = 1; i < n; i++) {
        int32_t key = p[i];
        size_t j = i;
        while (j > 0 && cmp(p[j - 1], key) > 0) {
            p[j] = p[j - 1];
            j--;
        }
        p[j] = key;
    }
}

/* Index of an element equal to key under cmp, or n when there is none; p must already be sorted by cmp. */
size_t fp_bsearch(const int32_t *p, size_t n, int32_t key, fp_cmp cmp) {
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = cmp(p[mid], key);
        if (c == 0) {
            return mid;
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return n;
}

/* Constant comparator: an inliner can specialise the sort for fp_cmp_asc. */
void fp_sort_ascending(int32_t *p, size_t n) {
    fp_insertion_sort(p, n, fp_cmp_asc);
}

/* ---- observer bus ------------------------------------------------------------------------------------------- */

void fp_bus_init(struct fp_bus *bus) {
    for (uint32_t i = 0; i < FP_BUS_CAP; i++) {
        bus->handler[i] = NULL;
        bus->ctx[i] = NULL;
    }
    bus->count = 0;
}

/* Add a subscriber; returns its slot, or -1 when the handler is NULL or the bus is full. */
int32_t fp_bus_subscribe(struct fp_bus *bus, fp_handler h, void *ctx) {
    if (h == NULL || bus->count >= 8u) {
        return -1;
    }
    bus->handler[bus->count] = h;
    bus->ctx[bus->count] = ctx;
    return (int32_t)bus->count++;
}

/* Deliver an event to the subscribers in order until one returns nonzero; that value is returned (0 if none did). */
int32_t fp_bus_publish(struct fp_bus *bus, uint32_t event, int32_t arg) {
    for (uint32_t i = 0; i < bus->count; i++) {
        int32_t r = bus->handler[i](bus->ctx[i], event, arg);
        if (r != 0) {
            return r;
        }
    }
    return 0;
}

/* Remove the first subscription of h and close the gap; returns 1 when something was removed. */
int32_t fp_bus_unsubscribe(struct fp_bus *bus, fp_handler h) {
    for (uint32_t i = 0; i < bus->count; i++) {
        if (bus->handler[i] == h) {
            for (uint32_t j = i + 1; j < bus->count; j++) {
                bus->handler[j - 1] = bus->handler[j];
                bus->ctx[j - 1] = bus->ctx[j];
            }
            bus->count--;
            bus->handler[bus->count] = NULL;
            bus->ctx[bus->count] = NULL;
            return 1;
        }
    }
    return 0;
}

/* Handler that counts events in the int32_t behind ctx. */
int32_t fp_handler_count(void *ctx, uint32_t event, int32_t arg) {
    (void)event;
    (void)arg;
    *(int32_t *)ctx += 1;
    return 0;
}

/* Handler that vetoes one event number (stored behind ctx) by returning the argument. */
int32_t fp_handler_veto(void *ctx, uint32_t event, int32_t arg) {
    return event == *(const uint32_t *)ctx ? arg : 0;
}
