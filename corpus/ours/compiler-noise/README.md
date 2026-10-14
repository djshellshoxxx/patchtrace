# compiler-noise: same behaviour, different machine code

Suite of freestanding C11 projects (MIT, written for this repo) for testing diff engines against compiler noise: sources whose
behaviour is identical but whose machine code differs a lot between optimisation levels and between equivalent rewrites, plus
real one-line fixes hidden among such rewrites. Format and label vocabulary: `corpus/README.md` (`suite/1`).
Per-level instruction counts and which levels differ most: `PROFILES.md`.

## Projects

| project | prefix | what it stresses | functions in v1 | lines per version |
|---|---|---|---|---|
| `switchtables` | `st_` | dense and sparse switches that become jump tables, lookup tables, bit tests or compare chains | 21 | 440-472 |
| `loops` | `lp_` | sums, copies, saturating adds, scans, popcount, checksums: loops that unroll or vectorise | 26 | 294-350 |
| `tailcalls` | `tc_` | tail recursion, sibling-call wrappers, a mutually recursive calculator, an array-backed tree | 26 | 309-342 |
| `fnptr` | `fp_` | enum-indexed and searched dispatch tables, callbacks, comparator-driven sort, an observer bus | 29 | 270-299 |

Not in this pass: `bigfn`, `bitfiddle`, `structs`, `stringsnolibc`.

Each project is `suite.json` plus `v1 ... v4`, one `<project>.c` per version. Every function has external linkage, names are
unique per version and carry the project prefix, and the only headers are `stddef.h` and `stdint.h`. The four `static inline`
helpers (`st_in_range`, `lp_min_size`, `tc_is_digit`, `fp_max_u32`) replace macros on purpose, to provoke inlining (N4).
All recursion is bounded by construction (64-bit width, an explicit nesting limit, a node pool), so recursion-to-loop
rewrites do not change behaviour.

## Version pairs

Every project has the same four pairs, each with an `intent` in `suite.json`:

* `v1 -> v2` refactor-only control: no function changes behaviour, so any "patched" verdict is a false positive.
* `v2 -> v3` mixed: three real one-line changes (a comparison change, a constant change, an argument-order change) hidden
  among macro-to-inline, helper extraction, function splitting, hoisting and recursion/loop rewrites.
* `v3 -> v4` layout and presentation: definitions reordered (text identical, addresses shift), whitespace-only and
  comment-only edits, renamed locals, and one function swapped for a look-alike with different meaning.
* `v1 -> v4` cumulative: derived by composing the steps.

## Truth conventions

* `same` means identical function text. One text-identical function whose behaviour changes through a changed callee
  (`tc_pow_mod` in `tailcalls`, `v2 -> v3`) is still `same`; its note says so and it carries N4.
* `cosmetic` includes whitespace-only and comment-only edits; the entry's note says which.
* An extracted or split-out helper is `added` (N4) and the function it was taken from is `cosmetic`; the `split` label is
  not used. A swapped look-alike is a `removed` plus an `added` entry (N7).
* Constant data tables (`st_isa_cycle_table`, `st_month_names`, `fp_cmd_table`, `fp_entries`) are not functions and have no
  truth entries; some are reordered or generated from the old code between versions.
* Strata (calibration spec 5.4) that occur: N1 near-duplicate loops and handlers, N2 one-call wrappers, N4 extracted and
  inlined helpers, N5 definitions reordered, N6 one-line semantic changes, N7 look-alike swap, N11 switch and table bodies,
  N12 large rewrites that stay the same function. N3, N8, N9 and N10 do not occur.

## How the truth was checked

* `python tools/corpus_check.py suite corpus/ours/compiler-noise/<project>` reports 0 findings for every project.
* Portability: every file builds warning-free (`-Wall -Wextra -Wpedantic -Wshadow -Werror`) for the host and for
  `x86_64-pc-windows-msvc` at `-O0 -O1 -O2 -O3 -Os`, has no undefined symbols in any of those objects, links with
  `lld-link /dll /noentry /nodefaultlib`, and compiles with `clang --target=x86_64-pc-windows-msvc -ffreestanding -O2 -c`.
* Behaviour (harness kept outside the repository): each version was built for the host at `-O0` and `-O2` with trapping
  UBSan. Every `cosmetic` function was compared against its predecessor on exhaustive or randomised inputs (edge values,
  guard bytes around buffers, logged callbacks) with no difference; every `changed` function has a witness input; checksum,
  parsing, number-theory and comparator functions were also compared against independent Python models; `-O0` and `-O2`
  builds of each version agree.
