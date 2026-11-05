# Unified audit 2026-11-04, slice fus (fusion, sources, keys, registry, addressing)

Base main 25b2ac8. Format: ID | severity | file:line | defect | status.

FUS-01 | High | sources/manual.py:88 (atoms) | A manual pairing whose side has no usable address (no-address, `EXTERNAL:` key, outside image) lost that side, and the survivor became a tier-M one-sided claim (older-only/newer-only) that overrides every engine edge | fixed: test_unresolvable_side_does_not_become_a_one_sided_claim (correction skipped, `manual-unresolved:N`, added to `DEGRADING` so the run is `partial`)
FUS-02 | High | sources/manual.py:88 | Manual category `unmatched` with one function per side became an affirmative tier-M matched pair (opposite of the analyst's declaration; `correct_match` accepts any category with any sides) | fixed: test_manual_unmatched_with_both_sides_is_never_an_affirmative_pairing (two one-sided claims)
FUS-03 | Medium | fusion/arbiter.py:83 `key` | Atoms equal in every key field but `native` kept `set()` iteration order (hash/insertion dependent) in `Decided.atoms` and `Support.atom_index` (D-16) | fixed: test_atoms_differing_only_in_native_text_have_a_fixed_order (native is the last key part); no digest change
FUS-04 | Medium | sources/__init__.py:read_snapshot (U7-10) | `for line in handle` buffered a whole hostile line before the cap test | fixed: test_oversized_line_is_refused_without_reading_it_whole (`readline(LINE_MAX_BYTES + 1)`)
FUS-05 | Low | arbiter.strength `-edge[0], -edge[1]` (U7-08) | Suspected orientation asymmetry | no defect: brute force (160k edge sets) + 4000 hypothesis examples incl. groups, manual, one-sided: lexicographic greedy over equal-strength edges yields the same edge set under swap. Pinned by test_orientation_swap_mirrors_every_row (all decision kinds, groups, contests), test_input_order_is_invisible_with_groups. No config/engine digest impact.
FUS-06 | Info | invariants | corroboration rule oracle, valid persisted row for every decided row, one row per function, shared origin once, unknown no vote | pinned: test_uncontested_pair_rows_obey_the_corroboration_rule, test_every_decided_row_is_a_valid_persisted_row, test_every_function_is_in_exactly_one_row
FUS-07 | Low | secondary.py:239 | `bindiff-stub-rows-demoted:N` counts alternative-candidate rows (already tier C) as demoted | deferred: informational count only
FUS-08 | Low | secondary.py:_emit/_rzdiff | `to_rva(...) is None` guards are unreachable for a set whose basis was accepted (basis requires every address inside the image); rz-diff lacks the pair guard that `_emit` has | deferred: unreachable today
FUS-09 | Low | manual.py | Manual `modified`/`unchanged`/`split`/`merged` with only one side resolvable-by-shape (one side empty in the snapshot) still becomes a one-sided claim | deferred: needs a decision on category semantics (ASK)
FUS-10 | Low | sources/__init__.py:read_snapshot | `SnapshotMatch.model_validate_json` is not strict-JSON (duplicate keys last-wins); no total byte cap beyond L-38 rows x per-line cap. Input is the owner's file, hash-checked | deferred

## ghidriff.py (frozen, read-only audit)
No defect that changes a verdict found. Notes (ASKS): (1) `load_raw` stats then checks `is_symlink` (benign race, owner file). (2) `enrichment.identity.parse_address` accepts `0x1_0` (underscore via `int(...,16)` after a `0x` prefix) = 0x10; non-prefixed path rejects `_`; harmless. (3) `_relations` loops `parsed` per target without `budget.tick()` inside the inner list (bounded by 100 MiB raw).

## ASKS
- docs/specs 06 s6: state that manual category `unmatched` never supplies a pairing even with both sides, and that an unresolvable side skips the correction (`manual-unresolved`, degrading).
- docs/specs 05 s1.2 BinDiff row says "every step with confidence <= 0.75 is C"; code never reads confidence (R02 s7, `registry.BINDIFF_STEPS` by name only). Reword the spec.
- compute.py `DEGRADING_*` lists are owned elsewhere; `manual-unresolved` is added to `sources.DEGRADING` (already consumed by `compute.is_degrading`).

## Unverified
BinDiff function-algorithm strings in `BINDIFF_STEPS` could not be checked against google/bindiff sources (raw.githubusercontent.com paths returned 404 for the guessed files).
