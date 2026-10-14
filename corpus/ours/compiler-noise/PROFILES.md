# Optimisation-level profiles of the compiler-noise projects

For every project: which of `-O0 -O1 -O2 -O3 -Os` is expected to differ most in machine code, why, and what was measured.
Expectations are written first; the measured outcome says whether each one held.

## Method

* Compiler: clang 18.1.3, `clang --target=x86_64-pc-windows-msvc -ffreestanding -std=c11 -O<level> -c <file>.c -o <obj>`.
* Count: `llvm-objdump -d --no-show-raw-insn <obj>`, instruction lines between one function label and the next, excluding
  alignment padding (`nop*`, `int3`). Jump tables and constant tables live in `.rdata` and are not counted.
* All counts below are for version `v1` of the project. The tables list the functions that make the point; every other
  function was measured too.
* "Identical" (stability tables) means the normalised disassembly of the old and new definition is equal: relocated
  displacements masked, local labels canonicalised, jump targets relative to the function start.
* Reproduce one number: compile as above, then `llvm-objdump -d --no-show-raw-insn x.obj` and count the lines of one
  function.

## switchtables

Expected to differ most: `-O0` against every other level. Only the optimiser builds jump tables, constant lookup tables and
bit tests; `-O0` keeps a compare cascade with stack traffic. `-O1`, `-O2` and `-O3` should be nearly identical for switch
bodies, and `-Os` may differ on sparse switches.

| function | -O0 | -O1 | -O2 | -O3 | -Os |
|---|---|---|---|---|---|
| st_tlv_payload_len | 41 | 7 | 7 | 7 | 7 |
| st_palette_rgb | 47 | 8 | 8 | 8 | 8 |
| st_isa_cycles | 64 | 35 | 35 | 35 | 38 |
| st_status_phrase (sparse, 30 cases) | 187 | 82 | 82 | 82 | 97 |
| st_ip_proto_kind | 66 | 29 | 29 | 29 | 47 |
| st_errno_text_id | 47 | 38 | 38 | 38 | 46 |
| st_day_of_year (calls st_days_in_month in a loop) | 41 | 80 | 173 | 173 | 82 |

Measured: the `-O0` gap held everywhere (about 6x for both `st_tlv_payload_len`, 41 to 7, and `st_palette_rgb`, 47 to 8). `-O1`, `-O2` and `-O3`
had equal counts for 20 of the 21 functions. The exception is `st_day_of_year`, where `-O2` and `-O3` fold
`st_days_in_month` into the loop (80 to 173 instructions); `-Os` stays at 82. `-Os` is larger than `-O2` on four sparse
or table-like switches (`st_status_phrase` 97 vs 82, `st_ip_proto_kind` 47 vs 29, `st_errno_text_id` 46 vs 38,
`st_isa_cycles` 38 vs 35) and smaller on `st_alu` (55 vs 66). The reason for the `-Os` growth was not investigated.

Cosmetic stability, v1 to v2: `st_lex_step` (parameter rename) is identical at every level. `st_tlv_payload_len` (default
label moved to the top) differs only at `-O0`. Reordering the case labels of `st_month_offset` changes the code at every
level, including `-O2` (`addl $-2` / `cmpl $0xa` versus `decl` / `cmpl $0xb`: the lookup table covers a different range).
`st_status_class`, `st_days_in_month`, `st_char_class`, `st_isa_cycles`, `st_month_abbrev` and `st_alu` also differ at
every level.

## loops

Expected to differ most: `-O1` against `-O2`/`-O3` for every vectorisable loop (SIMD blocks with runtime overlap checks and
scalar remainders), then `-O0` against `-O1` (register allocation). `-O3` should be close to `-O2`, `-Os` close to `-O1`
because it does not vectorise. Loops with early exits or loop-carried dependences (`lp_reverse_bytes`, `lp_compare_bytes`,
`lp_popcount32`) should stay flat from `-O1`.

| function | -O0 | -O1 | -O2 | -O3 | -Os |
|---|---|---|---|---|---|
| lp_add_sat_u8 | 34 | 14 | 151 | 151 | 14 |
| lp_move_bytes | 42 | 20 | 149 | 153 | 20 |
| lp_histogram_u8 | 31 | 14 | 96 | 96 | 15 |
| lp_sum_u8 | 20 | 12 | 40 | 40 | 12 |
| lp_copy_bytes | 20 | 9 | 62 | 62 | 9 |
| lp_fnv1a | 24 | 15 | 42 | 42 | 15 |
| lp_fill_bytes | 18 | 8 | 44 | 44 | 308 |
| lp_reverse_bytes | 35 | 14 | 14 | 14 | 14 |
| lp_compare_bytes | 37 | 17 | 17 | 17 | 17 |
| lp_popcount32 | 16 | 9 | 9 | 9 | 9 |
| lp_bit_length | 15 | 10 | 10 | 10 | 10 |

Measured: the `-O1` to `-O2` jump held (`lp_add_sat_u8` 14 to 151, `lp_move_bytes` 20 to 149, `lp_histogram_u8` 14 to 96), `-O3`
equals `-O2` or exceeds it by at most 5 instructions, and the dependence-bound loops are flat from `-O1`. `-Os` stayed
within one instruction of `-O1` on 24 of 26 functions, with two exceptions: `lp_fletcher32` (46 vs 38) and `lp_fill_bytes`,
which is 308 instructions at `-Os`, seven times its `-O2` size (inspected: a tail-folded, predicated SSE2 loop that builds
lane masks with `pcmpgtd`/`packssdw` and stores each byte under a `testb $0x1` guard). `lp_rotate_bytes` is the one
function where `-O0` is the smallest (25 vs 55 at `-O1`, 64 at `-O2`); this is consistent with the optimiser inlining the
three `lp_reverse_bytes` calls, which was not inspected.

Cosmetic stability, v1 to v2: `lp_fnv1a` (rename) and `lp_sum_u8` (for to while) are identical at every level;
`lp_inet_checksum` (carry fold extracted) and `lp_add_sat_u8` (ternary to if) differ only at `-O0`; `lp_copy_bytes`
(index loop to end-pointer walk) and `lp_sum_strided` (hand strength reduction) are identical at `-O1` and `-Os` but differ at
`-O0`, `-O2` and `-O3`; `lp_fill_bytes`, `lp_popcount32` and `lp_find_byte` differ at every level.

## tailcalls

Expected to differ most: `-O0` against `-O1` (self tail calls become loops, sibling calls become jumps), then `-O1`
against `-O2` (small wrappers and accumulator helpers are inlined into their callers). The mutually recursive parser
(`tc_parse_*`) should grow wherever the inliner merges the levels.

| function | -O0 | -O1 | -O2 | -O3 | -Os |
|---|---|---|---|---|---|
| tc_gcd_u32 (one-line wrapper) | 10 | 3 | 20 | 22 | 14 |
| tc_fib (wrapper over tc_fib_acc) | 16 | 6 | 37 | 37 | 16 |
| tc_gcd (self tail call) | 18 | 11 | 19 | 21 | 13 |
| tc_tree_find (self tail call) | 48 | 15 | 15 | 15 | 15 |
| tc_ackermann (wrapper, recursion in tc_ack_inner) | 16 | 6 | 6 | 6 | 6 |
| tc_parse_factor (mutual recursion) | 73 | 235 | 192 | 199 | 67 |
| tc_parse_expr (mutual recursion) | 55 | 162 | 127 | 134 | 43 |

Measured: `tc_gcd_u32` is `movl %edx,%edx; movl %ecx,%ecx; jmp tc_gcd` at `-O1` (inspected, 3 instructions with a
`IMAGE_REL_AMD64_REL32` to `tc_gcd`) and 20 instructions at `-O2`, consistent with the gcd loop being inlined (not
inspected). `tc_tree_find` drops from 48 to 15 at `-O1` and stays there. Unexpected: the parser is largest at `-O1` (235),
not at `-O2`/`-O3`, and `-Os` is as small as `-O0` (67 vs 73); the counts are consistent with the recursive-descent
functions being inlined into each other at `-O1` to `-O3`, which was not inspected further.

Cosmetic stability, v1 to v2: the recursion-to-loop rewrites (`tc_gcd`, `tc_fib_acc`, `tc_bit_count_acc`) differ at `-O0` and
`-O1` and are identical from `-O2`, where the optimiser has turned the recursion into the same loop. `tc_digit_sum`
(ternary to if) differs only at `-O0`. `tc_parse_term` and `tc_parse_expr` (helper extracted) are identical from `-O2`.
`tc_pow_mod_acc` (statements reordered) differs at every level, `tc_tree_height` (rename) at none.

## fnptr

Expected to differ most: `-O0` against `-O1` for the tiny handlers and dispatchers (the table and callback are resolved or
inlined once the optimiser sees constants), and `-O1` against `-O2`/`-O3` where a constant comparator or constant table index
lets the inliner specialise the caller.

| function | -O0 | -O1 | -O2 | -O3 | -Os |
|---|---|---|---|---|---|
| fp_sort_ascending (constant comparator) | 9 | 19 | 49 | 49 | 17 |
| fp_apply_const (constant table indices) | 17 | 5 | 5 | 5 | 5 |
| fp_dispatch_id (table search) | 33 | 12 | 27 | 27 | 12 |
| fp_bus_unsubscribe | 63 | 45 | 69 | 74 | 42 |
| fp_cmp_abs | 36 | 11 | 11 | 11 | 11 |
| fp_foreach_u32 | 21 | 26 | 26 | 26 | 26 |

Measured: `fp_apply_const` collapses from 17 to 5 instructions by `-O1`, consistent with the two indirect calls through the
constant table becoming direct arithmetic, and `fp_sort_ascending` grows from `-O0` to `-O2` (9, 19, 49), consistent with the
sort being inlined and specialised for the constant comparator (neither inspected). `fp_foreach_u32` is larger at `-O1` and
above than at `-O0` (26 vs 21), the opposite of the usual direction.

Cosmetic stability, v1 to v2: `fp_dispatch_id`, `fp_reduce`, `fp_insertion_sort`, `fp_bus_publish` and `fp_cmd_min` differ
only at `-O0` and are identical at every optimised level. `fp_count_if` (rename) and `fp_bsearch` (`/ 2` to `>> 1` on an
unsigned value) are identical at every level, while `fp_foreach_u32` (index loop to pointer walk) and `fp_cmp_asc`
(branch-free sign expression to explicit comparisons) differ at every level.

## Not covered

`bigfn`, `bitfiddle`, `structs` and `stringsnolibc` are not part of this pass, so no profile is claimed for them.
