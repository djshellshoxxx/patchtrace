/*
 * tailcalls: tail calls, sibling calls and bounded recursion.
 *
 * Number-theory helpers written as accumulator-style tail recursion, a recursive-descent calculator (mutual recursion
 * through expr -> term -> factor -> expr), an array-backed binary search tree and a few one-line wrappers. At -O0 every
 * call is a real call; from -O1 on, self tail calls become loops and sibling calls become jumps, while the wrappers
 * usually disappear into their callers. Every recursion here is bounded by construction (64-bit width, an explicit
 * nesting limit or the node pool size), so rewriting recursion as a loop never changes behaviour.
 * Freestanding C11: no libc, no mutable globals.
 */
#include <stddef.h>
#include <stdint.h>

#define TC_MAX_DEPTH 24u
#define TC_COLLATZ_CAP 500u

enum tc_error { TC_OK = 0, TC_ERR_SYNTAX = 1, TC_ERR_DIV0 = 2, TC_ERR_DEPTH = 3, TC_ERR_TRAILING = 4 };

struct tc_cursor {
    const char *pos;
    int32_t error;
};

struct tc_node {
    int32_t key;
    int32_t left;
    int32_t right;
};

uint32_t tc_parse_expr(struct tc_cursor *c, uint32_t depth);

/* ---- number theory with accumulators ------------------------------------------------------------------------ */

/* Euclid's algorithm: at most 93 steps for 64-bit inputs. */
uint64_t tc_gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t r = a % b;
        a = b;
        b = r;
    }
    return a;
}

uint64_t tc_lcm(uint64_t a, uint64_t b) {
    if (a == 0 || b == 0) {
        return 0;
    }
    return b / tc_gcd(a, b) * a;
}

/* Thin wrapper: the call is a sibling call that only widens its arguments. */
uint64_t tc_gcd_u32(uint32_t a, uint32_t b) {
    return tc_gcd(a, b);
}

/* Square-and-multiply with the result in an accumulator; needs 1 <= mod <= 2^32 and base, acc < mod. */
uint64_t tc_pow_mod_acc(uint64_t base, uint64_t exp, uint64_t mod, uint64_t acc) {
    uint64_t squared;
    if (exp == 0) {
        return acc;
    }
    squared = base * base % mod;
    if ((exp & 1u) != 0u) {
        acc = acc * base % mod;
    }
    return tc_pow_mod_acc(acc, exp >> 1, mod, squared);
}

uint64_t tc_pow_mod(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod <= 1) {
        return 0;
    }
    return tc_pow_mod_acc(base % mod, exp, mod, 1);
}

/* Sum of the decimal digits (at most 20 steps). */
uint32_t tc_digit_sum(uint64_t n, uint32_t acc) {
    if (n == 0) {
        return acc;
    }
    return tc_digit_sum(n / 10u, acc + (uint32_t)(n % 10u));
}

/* Number of set bits (at most 64 steps). */
uint32_t tc_bit_count_acc(uint64_t n, uint32_t acc) {
    for (; n != 0; n >>= 1) {
        acc += (uint32_t)(n & 1u);
    }
    return acc;
}

/* Collatz trajectory length, cut off after TC_COLLATZ_CAP steps. */
uint32_t tc_collatz_len(uint64_t n, uint32_t steps) {
    if (n <= 1 || steps > TC_COLLATZ_CAP) {
        return steps;
    }
    if ((n & 1u) != 0u) {
        return tc_collatz_len(3 * n + 1, steps + 1);
    }
    return tc_collatz_len(n / 2, steps + 1);
}

/* Fibonacci with two accumulators. */
uint64_t tc_fib_acc(uint32_t n, uint64_t a, uint64_t b) {
    while (n != 0) {
        uint64_t next = a + b;
        a = b;
        b = next;
        n--;
    }
    return a;
}

uint64_t tc_fib(uint32_t n) {
    return tc_fib_acc(n > 93u ? 93u : n, 0, 1);
}

/* Moves needed for n disks (n clamped to 64 so the result fits); plain recursion, not a tail call. */
uint64_t tc_hanoi_moves(uint32_t disks) {
    if (disks == 0) {
        return 0;
    }
    if (disks > 64u) {
        disks = 64u;
    }
    return 2 * tc_hanoi_moves(disks - 1) + 1;
}

/* Ackermann function, depth bounded by the argument limits enforced in tc_ackermann. */
uint32_t tc_ack_inner(uint32_t m, uint32_t n) {
    if (m == 0) {
        return n + 1;
    }
    if (n == 0) {
        return tc_ack_inner(m - 1, 1);
    }
    return tc_ack_inner(m - 1, tc_ack_inner(m, n - 1));
}

uint32_t tc_ackermann(uint32_t m, uint32_t n) {
    if (m > 3u || n > 5u) {
        return 0;
    }
    return tc_ack_inner(m, n);
}

/* Weighted sum of six values. */
uint64_t tc_weigh6(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6;
}

/* Five arguments in, six out: the callee needs more stack argument space than the caller owns. */
uint64_t tc_weigh5(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    return tc_weigh6(a, b, c, d, e, a ^ b);
}

/* ---- recursive-descent calculator (modulo 2^32 arithmetic) -------------------------------------------------- */

void tc_skip_space(struct tc_cursor *c) {
    while (*c->pos == ' ' || *c->pos == '\t') {
        c->pos++;
    }
}

/* Decimal digit test; replaces the TC_IS_DIGIT macro and is meant to be inlined. */
static inline int tc_is_digit(char ch) {
    return ch >= '0' && ch <= '9';
}

/* Unsigned decimal literal; sets TC_ERR_SYNTAX when no digit is present. */
uint32_t tc_parse_number(struct tc_cursor *c) {
    uint32_t value = 0;
    if (!tc_is_digit(*c->pos)) {
        c->error = TC_ERR_SYNTAX;
        return 0;
    }
    while (tc_is_digit(*c->pos)) {
        value = value * 10u + (uint32_t)(*c->pos - '0');
        c->pos++;
    }
    return value;
}

/* Parenthesised sub-expression, split out of tc_parse_factor; the cursor sits on the opening parenthesis. */
uint32_t tc_parse_group(struct tc_cursor *c, uint32_t depth) {
    uint32_t value;
    c->pos++;
    value = tc_parse_expr(c, depth + 1);
    tc_skip_space(c);
    if (c->error == TC_OK && *c->pos != ')') {
        c->error = TC_ERR_SYNTAX;
    } else if (c->error == TC_OK) {
        c->pos++;
    }
    return value;
}

/* factor := number | '(' expr ')' | '-' factor; every nesting level costs one unit of depth. */
uint32_t tc_parse_factor(struct tc_cursor *c, uint32_t depth) {
    tc_skip_space(c);
    if (depth > TC_MAX_DEPTH) {
        c->error = TC_ERR_DEPTH;
        return 0;
    }
    if (*c->pos == '(') {
        return tc_parse_group(c, depth);
    }
    if (*c->pos == '-') {
        c->pos++;
        return 0u - tc_parse_factor(c, depth + 1);
    }
    return tc_parse_number(c);
}

/* Skip blanks and return the character under the cursor; shared by the two operator loops. */
char tc_peek_op(struct tc_cursor *c) {
    tc_skip_space(c);
    return *c->pos;
}

/* term := factor (('*' | '/' | '%') factor)* */
uint32_t tc_parse_term(struct tc_cursor *c, uint32_t depth) {
    uint32_t value = tc_parse_factor(c, depth);
    for (;;) {
        char op;
        uint32_t rhs;
        op = tc_peek_op(c);
        if (c->error != TC_OK || (op != '*' && op != '/' && op != '%')) {
            return value;
        }
        c->pos++;
        rhs = tc_parse_factor(c, depth);
        if (c->error != TC_OK) {
            return value;
        }
        if (op == '*') {
            value *= rhs;
        } else if (rhs == 0u) {
            c->error = TC_ERR_DIV0;
            return value;
        } else if (op == '/') {
            value /= rhs;
        } else {
            value %= rhs;
        }
    }
}

/* expr := term (('+' | '-') term)* */
uint32_t tc_parse_expr(struct tc_cursor *c, uint32_t depth) {
    uint32_t value = tc_parse_term(c, depth);
    for (;;) {
        char op;
        uint32_t rhs;
        op = tc_peek_op(c);
        if (c->error != TC_OK || (op != '+' && op != '-')) {
            return value;
        }
        c->pos++;
        rhs = tc_parse_term(c, depth);
        if (c->error != TC_OK) {
            return value;
        }
        value = op == '+' ? value + rhs : value - rhs;
    }
}

/* Evaluate an expression: returns TC_OK and stores the value, or an error code and leaves *result alone. */
int32_t tc_calc(const char *expr, uint32_t *result) {
    struct tc_cursor c = {expr, TC_OK};
    uint32_t value = tc_parse_expr(&c, 0);
    tc_skip_space(&c);
    if (c.error == TC_OK && *c.pos != '\0') {
        c.error = TC_ERR_TRAILING;
    }
    if (c.error == TC_OK) {
        *result = value;
    }
    return c.error;
}

uint32_t tc_calc_or_zero(const char *expr) {
    uint32_t value = 0;
    if (tc_calc(expr, &value) != TC_OK) {
        return 0;
    }
    return value;
}

/* ---- array-backed binary search tree ------------------------------------------------------------------------ */

/* Index of the node that holds key, or -1. */
int32_t tc_tree_find(const struct tc_node *nodes, int32_t at, int32_t key) {
    while (at >= 0 && key != nodes[at].key) {
        at = key < nodes[at].key ? nodes[at].left : nodes[at].right;
    }
    return at >= 0 ? at : -1;
}

/* Height of the subtree below `at`; 0 for an empty subtree. */
int32_t tc_tree_height(const struct tc_node *nodes, int32_t at) {
    int32_t lh;
    int32_t rh;
    if (at < 0) {
        return 0;
    }
    lh = tc_tree_height(nodes, nodes[at].left);
    rh = tc_tree_height(nodes, nodes[at].right);
    return 1 + (lh > rh ? lh : rh);
}

/* Append a leaf node to the pool and return its index. */
int32_t tc_tree_new(struct tc_node *nodes, uint32_t *used, int32_t key) {
    uint32_t slot = *used;
    nodes[slot].key = key;
    nodes[slot].left = -1;
    nodes[slot].right = -1;
    *used = slot + 1u;
    return (int32_t)slot;
}

/* Insert key below the existing node `at`. Returns the new index, or -1 if the key exists or the pool is full. */
int32_t tc_tree_insert(struct tc_node *nodes, uint32_t *used, uint32_t cap, int32_t at, int32_t key) {
    struct tc_node *node = &nodes[at];
    int32_t *link;
    if (key == node->key) {
        return -1;
    }
    if (key < node->key) {
        link = &node->left;
    } else {
        link = &node->right;
    }
    if (*link >= 0) {
        return tc_tree_insert(nodes, used, cap, *link, key);
    }
    if (*used >= cap) {
        return -1;
    }
    *link = tc_tree_new(nodes, used, key);
    return *link;
}
