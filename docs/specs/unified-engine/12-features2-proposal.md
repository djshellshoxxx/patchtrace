# SPEC-31 / 12 Proposal: `features/2` with families U and F (amendment A-07, proposal only)

Status: PROPOSAL text for the owner of the calibration track (SPEC-28 C9), written by slice S6a on 2026-10-14. Nothing here is built, shipped or decided: `features/1` (`src/patchtrace/calibration/features.py`), `display_level()` and every stored artifact stay exactly as they are. Numbers marked [inf] are suggestions to preregister, not measurements. The unified side of every field named below exists today as strict contracts (`unified-match/1`, `change-facts/1`, `02-data-model.md` s4); family F needs the S3 facts to carry real values.

## 1. Why a proposal and why not code
- C-09 / D-11: the unified decision is rule-based and ordinal. No probability exists in a unified row, and none may be invented before a SPEC-28 artifact passes its gates (display level `ordinal`). A learned model over unified evidence is the only route to a number, so the feature schema has to be agreed first.
- A-07: the PatchTrace body-bytes similarity "later slice" of the C9 spec is provided by `pt-bytes` (F-PT-BYTES); the vector that learns from it is `features/2`. This text hands over the families; the C9 owner decides names, counts and profiles.
- There is no labelled unified data yet. The labels will come from `known-answer-labels/1` (SPEC-32), whose pairs the S6a corpus builds (`tools/unified/corpus`). Until unified results exist on that corpus (S3 and the S6b gate runs), a model would train on nothing.

## 2. What stays the same (additive change only)
- `features/1` keeps its families `G B R S P X`, their column names and their order. `features/2` is a superset: the same shared columns first, then the new families. An artifact names the schema it was trained on; the app builds the vector for that schema; a `features/1` artifact keeps working unchanged.
- Engine-native values stay raw and separate; nothing is averaged or pre-combined (C9 s6.1). U and F carry facts of the unified result, never a combined score.
- A contested, ambiguous, unknown or one-sided row gets no vector: policy routes it (C9 s9.5). The unified `contested` decision is the same rule as `X.contested`.
- Missing is not negative (C9 s6.5): without ProgramIR there are no F facts, the family is missing and the profile changes. No imputation, no zero fill.

## 3. Family U: the unified decision of a pairing row
One vector per `UnifiedMatch` row whose decision is `matched`, `tentative` or `candidate`. Suggested columns (kind: num, cat or flag; source field):

| Feature | Kind | Source | Note |
|---|---|---|---|
| `U.decision` | cat, 3 levels | `decision` | the three pairing decisions only; the others are routed |
| `U.best_tier` | cat, 5 levels M A B C W | max of `atoms[].tier` | ordinal meaning, one-hot in the vector |
| `U.n_components` | num | `len(support)` | components after the union-find of D-tags, so engines that share an analysis count once |
| `U.n_classes` | num | distinct `atoms[].cls` among supporting atoms | D-32: corroboration needs two components AND two evidence classes |
| `U.n_atoms` | num | `len(atoms)` | bounded by L-39 |
| `U.has_tier_a` | flag | any atom with tier A | |
| `U.card` | cat, 4 levels | `atoms[].cardinality` of the best atom | 1:1, 1:N, N:1, N:M |
| `U.step` | cat, about 8 groups | `atoms[].step` of the best atom | grouped: manual, name, bytes-exact, masked-exact, structural, call-graph, propagation, residual |
| `U.flags` | 12 flags | `flags` | tiny, thunk, import, hub, icf, oversize, truncated, ir-missing, pdata-confirmed, library, mask-missing, mask-unlocated |
| `U.ir_mode` | cat, 5 levels | manifest `ir_older.producer_mode` | gzf, analyze, binexport, rizin, none |

About 41 columns [inf]. `U.contest_strength` is a diagnostic stratum only: contested rows are not modelled.

Dependency tags (C9 s6.4). A unified row inherits the union of the tags of the sources whose atoms support it, computed per row from the registry, so the `independence_index` stays honest: Ghidriff atoms {D_ghidra, D_symbols, D_callgraph, D_compiler}; BinDiff atoms as `B`; rz-diff and `pt-bytes` atoms {D_bytes} (`pt-bytes` only when the extent is confirmed, D-10); in-house ladder steps read the ProgramIR, so {D_ghidra} for a Ghidra producer (the BinExport producer would give D_ida), plus D_symbols for the name steps and D_callgraph for propagation. No new tag is needed while Ghidra is the only IR producer; a rizin producer would need `D_rizin`.

## 4. Family F: the change facts of a pair
One vector per row with `ChangeFacts`. Suggested columns:

| Feature | Kind | Source | Note |
|---|---|---|---|
| `F.n_equal`, `F.n_differs`, `F.n_unavailable` | num | `channels` (C0..C8) | counts, not nine one-hot states (36 columns would eat the budget) |
| `F.c0_equal`, `F.c1_equal`, `F.c6_equal` | flag | channel states | raw bytes, masked bytes, canonical pseudo-code |
| `F.n_deltas`, `F.n_semantic` | num | `deltas` | log1p; semantic = constant, comparison, condition, callee, call-added, call-removed, data-ref, struct-offset, string |
| `F.has_semantic`, `F.has_structural`, `F.has_nuisance`, `F.has_frame_eh`, `F.has_unknown` | flag | classes of the deltas | structural = cfg, block-added, block-removed; nuisance = size-only, refcount-only, address-only, register-only, layout-only, name-only |
| `F.proof` | cat, 5 levels | `proof` | none, UNCH/1, COS-ADDR/1, COS-LAYOUT/1, COS-PSEUDO/1 |
| `F.targets_unmapped` | num | `targets[1] + targets[2]` | address operands with no counterpart or in conflict |
| `F.eh` | cat, 4 levels | `eh` | equal, differs, absent, unavailable |

About 24 columns [inf]. The verdict itself (`unchanged`, `cosmetic`, `material`, `review`) is deliberately NOT a feature: it is the rule-based output the model would otherwise just restate.

Dependency tags: F reads the ProgramIR, so {D_ghidra} (or the producer's tag) plus {D_bytes} for the byte channels C0, C1, C2, C5.

## 5. Column budget and profiles
`features/1` is bounded at 64 columns and uses 63 for `G+B+R`. U and F add about 65 [inf]. Suggested: raise the bound to 96 and add a profile `U` (families U, F, S, P) beside the existing engine profiles, instead of appending U and F to every profile. The unified row summarises the engines, so a profile that carries both the raw engine columns and U would count the same evidence twice. The C9 owner owns this decision.

## 6. Hazards the C9 owner has to rule on
1. Label leakage. The SPEC-32 labels for `unchanged` and `cosmetic` are themselves derived from the body facts "raw identical" and "masked identical" (SPEC-32 s7). `F.c0_equal`, `F.c1_equal` and the proofs restate those facts, so a model for the CHANGE target trained on `known-answer-labels/1` would learn the labeller. Suggestion: the byte-channel flags and `F.proof` are excluded from any model whose labels come from those body facts; they remain valid for the PAIRING target, whose truth comes from debug info and source identity.
2. Two targets. C9 today predicts pairing correctness (target A). A second target "the pair truly changed" (SPEC-32 `changed` versus `unchanged` and `cosmetic`) becomes possible, and F is its natural input (point 1 limits which columns). Whether to add it is a C9 decision.
3. Scope of the claim. A Tier R-only artifact keeps the Tier R claim ("measured on test builds of open-source code; says nothing about Windows system files") and cannot lift the display above `ordinal`. Unified rows add no evidence about Windows system files.
4. Evidence about the ENGINE is not evidence about a MODEL. The gates G-U1..G-U8 (`08-evaluation.md`) decide whether the unified engine may default on. A `features/2` artifact needs its own SPEC-28 gates on top.
5. Schema stability. `change-facts/1` and `unified-match/1` are frozen additively. A new `ChangeClass`, `RowFlag` or `EvidenceClass` value would silently add a one-hot level: the extractor must map unknown values to `other` and the artifact must record the level set it was trained on.

## 7. Tests the extraction slice would need (red first)
- Golden: every `features/1` vector is byte-identical under `features/2` code.
- Pure field mapping for each U and F column from a hand-built `UnifiedMatch` and `ChangeFacts`; unknown enum values map to `other`.
- Routing: contested, ambiguous, unknown and one-sided rows produce no vector; a pair without ProgramIR has no F family and changes the profile.
- Independence: two supporting atoms that share a D-tag count as one component; the per-row tag union is deterministic.
- Permutation and orientation: shuffling atoms or support entries changes no column; swapping older and newer mirrors only the columns that name a side (none, by design).

## 8. What S6a hands over
This text; the frozen unified contracts to read; and the corpus that the labels come from (`tools/unified/corpus`: release pairs, byte-identical rebuilds, link-order and optimisation-level A/A pairs, 12 classes of planted mutants, all as `known-answer-labels/1`). No code, no schema file, no change to `tools/generate_schemas.py`.
