# mini-projects: multi-file freestanding C11 histories

Realistic small projects (3 to 5 source files plus headers, about 1300 to 2200 lines per version) with a believable
release history, written for this repo and MIT-licensed. Each project directory holds `v1` .. `vN` source trees,
`HISTORY.md` (one paragraph per version transition) and `suite.json` (`suite/1`, complete function-level truth for every
consecutive pair plus one first-to-last pair). Rules as in `corpus/README.md`: freestanding headers only, no libc calls,
external linkage everywhere, unique function names per version.

## Projects

| project | what it is | versions | functions (v1 / last) |
|---|---|---|---|
| `jsonlite` | JSON tokenizer and recursive-descent parser over caller buffers, plus serializer | v1 .. v6 | 49 / 78 |

Only `jsonlite` is present. Other planned projects (arena allocator, LZ compressor, HTTP-like parser, stack VM) were
not written and are deliberately not stubbed.

## Strata covered by jsonlite

- `changed` with kinds bounds-check-added, null-check-added, call-added, error-handling-change, type-width-change,
  constant-change, large-rewrite, other (security fixes in v2 and v3).
- `cosmetic` (local renames, reorderings, ternary/if rewrites, comments inside bodies) and cosmetic-by-callee-rename.
- `renamed`, `moved` (every moved function also carries a small in-body tidy, see the note below), `split`, `merged`,
  `inlined`, `added`, `removed`.
- Taxonomy: N1 (writer wrapper family, key/raw-key twins), N2 (thin wrappers), N4 (split, merge, inline), N5
  (definitions regrouped in `json_util.c` with unchanged text), N11 (switch- and table-dominated bodies), N12 (word-at-a-time
  scanner rewrite that is still the same function).
- Long-range pair `v1 -> v6` composed from the consecutive pairs (renames that absorb later edits, splits and merges
  carried through).

## How the histories were validated (not part of the corpus)

Every version was built and run on the host with gcc ASan/UBSan against a harness kept outside the repo. Each seeded bug has a
reproducer that fails on the buggy version and passes on the fixed one; consecutive versions that claim to preserve
behaviour were compared on 6000 generated and mutated documents (identical dumps); the string-scanner rewrite was
compared against the plain byte loop on 20000 random strings. A semantic-dependency check confirmed that no `same`
function reads a macro, enumerator, struct offset or table that changed between versions.

## Notes for consumers

- `moved` entries always differ in text: `tools/corpus_check.py` requires text-different for `moved` (it only accepts
  `same` for identical text), so each moved function was tidied while being moved.
- Predicates return `int`, not `bool`: a return type spelled with the `stdbool.h` macro makes the checker's text slice
  empty, which silently disables its same/cosmetic/changed text checks for that function.
- `same` means source-text identical. A caller of a changed callee is `same`; a header constant is never changed under a
  function that is labelled `same`.
