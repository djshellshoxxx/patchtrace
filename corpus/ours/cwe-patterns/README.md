# cwe-patterns: known-answer fixes for common weakness classes

Eleven small, realistic, freestanding C11 libraries (arenas, rings, parsers, pools, tables; 251 to 393 lines per version,
no libc, no `static` functions, only `stddef`/`stdint`/`stdarg` headers). Each one models the kind of patch vendors ship:
a vulnerable version, the fix, and a benign refactor of the fix; five projects also carry a constant-only variant of the
fix. `suite.json` gives exact truth for every function in every pair. All code is original and MIT licensed.

| dir | meaning |
|---|---|
| `v1` | vulnerable |
| `v2` | fixed (the patch); every function the patch touches is `changed` with the right `kind` |
| `v3` | benign refactor of `v2`: renames, independent statements reordered, loop and branch style, operand order, definitions moved |
| `v2c` | (5 projects) `v2` with only a constant changed, so the patched function is `changed` / `constant-change` against `v2` |

Pairs: `v1->v2`, `v2->v3`, and `v2->v2c` where `v2c` exists. Every `v1->v2` pair also adds at least one helper and removes
one (the unsafe API or a wrapper that became dead), several of them look-alikes (N7).

## Projects

| project | CWE | what v1 gets wrong | `v1->v2` changed functions (kind) | `v2c` constant |
|---|---|---|---|---|
| `ringbuf` | 787 | `rb_push` copies any length into a 30-byte slot payload | `rb_push` (bounds-check-added) | `rb_payload_limit` 30 -> 24 |
| `tlvparse` | 125 | `tlv_next` trusts the 16-bit length, `tlv_peek_type` reads at the end | both (bounds-check-added) | `tlv_record_fits` cap 512 -> 256 |
| `arena` | 190 | `count * size` is computed in 32 bits and wraps to a tiny allocation | `ar_alloc_array`, `ar_alloc_table` (type-width-change) | none |
| `handlepool` | 416 | handle generation is never advanced or compared, a stale handle aliases the next owner | `hp_release_slot`, `hp_slot_for` (lifetime-fix) | none |
| `msgpool` | 415 | `msg_send` releases a buffer `msg_encode` already released | `msg_send` (call-removed), `mp_release` (lifetime-fix) | none |
| `authcfg` | 862 (cf. 287) | `ac_set` and `ac_factory_reset` skip the authorization helper their siblings call | both (auth-check-added) | required role OPERATOR -> ADMIN in `ac_set` |
| `pathnorm` | 22 | `..` survives normalisation, containment is a raw prefix test, a blacklist misses `..\` | `pn_normalize`, `pn_is_under` (path-normalization), `pn_resolve` (call-removed) | segment stack 16 -> 8 |
| `jobslots` | 362 | cancel frees a slot while its callback is still running | `js_run`, `js_cancel` (lock-added) | none |
| `symtab` | 476 | unchecked allocation result and unchecked lookup result are dereferenced | `sy_intern`, `sy_ref` (null-check-added) | none |
| `fmtlog` | 134 | a peer message is used as the format string of a length-prefixed formatter | `lf_log_event` (format-string-fix) | none |
| `namefield` | 193 | `>` instead of `>=` in a name-length test and in an index test | `nf_set_name`, `nf_get` (comparison-change) | name limit 16 -> 12 |

## Truth conventions

- Labels follow `corpus/README.md`: `same` (identical text), `changed`, `cosmetic`, `added`, `removed`. `corpus_check.py`
  verifies the text rule and that no function is missing or listed twice.
- Truth is source-level. A `same` function whose callee changed (a wrapper around the patched function, or the callers of a
  patched helper) can still differ in a built image when the compiler inlines the callee. That is the intended N4-style
  effect and is why such callers are not relabelled.
- `v2c` constants are literals (or an enumerator name such as `AC_ROLE_ADMIN`) written inside the function, because a
  `changed` entry must differ textually; a macro defined elsewhere would leave the function text identical.
- Taxonomy tags used: N1 near-duplicate getters and loops, N2 thin wrappers, N3 shared helpers, N5 definitions reordered in
  `v3` (ten of the eleven projects, all but `symtab`), N6 similar control flow with different semantics (the
  `constant-change` rows, `namefield`, and `same` siblings that share the patched code's shape, for example `ac_delete`,
  `msg_reply`, `sy_unref`), N7 look-alike added/removed helpers, N11 switch-dominated bodies (`tlv_type_name`,
  `tlv_type_is_known`, `lf_vformat`, `lf_level_name`). N4, N8, N9, N10 and N12 are not used here.

## Gaps

Five patterns from the original plan are not authored yet: CWE-195 (signed/unsigned comparison), CWE-457 (uninitialised
field), CWE-369 (divide by zero), CWE-674/835 (recursion or loop limit) and CWE-20 (header field validation). Add them as
new project directories; nothing here depends on them.

## Checks run on every version

- `python tools/corpus_check.py suite corpus/ours/cwe-patterns/<project>` reports 0 findings (and `all` for the repo).
- `clang -std=c11 -ffreestanding -fsyntax-only -Wall -Wextra -Werror -pedantic-errors` plus `-Wshadow -Wmissing-prototypes
  -Wstrict-prototypes -Wundef -Wcast-qual`, and `gcc -std=c11 -ffreestanding -Wall -Wextra -Werror -pedantic`.
- `clang --target=x86_64-pc-windows-msvc -ffreestanding -O2 -c` (also `-O0` and `-Os`): no undefined symbols in any object
  (`llvm-nm -u`), and every `-O2` object links with `lld-link /dll /noentry /nodefaultlib`, so no CRT is needed.
- Behaviour, with throwaway harnesses that are not part of this repo (gcc `-fsanitize=address,undefined`): in `v1` the
  exploit input trips a sanitizer or visibly breaks the invariant, `v2` and `v2c` reject it, and `v3` produces results
  identical to `v2` over 20,000 to 40,000 randomised operations per project.
