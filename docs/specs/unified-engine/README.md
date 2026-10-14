# SPEC-31: Unified binary-diff engine (derived, one window)

Status: developer-ready design, docs only, 2026-10-14, base `main` = `cb25132`. Nothing here is implemented. Owner of the design: lead architect session; builders follow `../../plans/unified-engine-plan.md`. Inputs (cited, never repeated): research `../../research/unified-engine/01..05` (R01..R05), existing specs listed in s4, Diaphora draft PR files (`docs/diaphora-optional-engine-20261014` @ `b75ac57`).

One sentence: extract one validated ProgramIR per binary (riding on Ghidriff's own Ghidra analysis when possible), turn every engine's stored output into tier-labelled evidence atoms, match in-house with a BinDiff/VT-style uniqueness ladder, decide per row with independence components and no averaging, prove "cosmetic" or corroborate "material" with typed change channels, and show the DERIVED result as a view mode of the existing single `MainWindow`.

## 1. Reading order (token-efficient)
1. [00-decisions](00-decisions.md) (decisions D-xx, conflicts C-xx, USER questions U-xx) - always.
2. [01-architecture](01-architecture.md) and [02-data-model](02-data-model.md) (contract freeze; numbers L-xx live only in 02 s6) - always.
3. Your slice's file only: [03-extraction](03-extraction.md) (S1), [04-matching-pipeline](04-matching-pipeline.md) (S2, S5), [05-fusion-and-noise](05-fusion-and-noise.md) (S0b, S3), [06-adapters](06-adapters.md) (S0b), [07-ui-and-cli](07-ui-and-cli.md) (S4), [08-evaluation](08-evaluation.md) (S6 and every slice's tests), [09-licensing](09-licensing.md) (S1/S2 ports), [10-amendments](10-amendments.md) (every slice, first step).
4. Plans: [plan](../../plans/unified-engine-plan.md), [backups](../../plans/unified-engine-backups.md), [troubleshooting](../../plans/unified-engine-troubleshooting.md).

## 2. Glossary

| Term | Meaning |
|---|---|
| ProgramIR | `program-ir/1`: per-artifact sidecar SQLite with functions, blocks, calls, strings, constants, instruction blobs and computed keys (02 s3) |
| producer / mode | who made the IR: Ghidra (`gzf` reuse of Ghidriff's analysis, or `analyze`), BinExport2, rizin (03 s1) |
| atom | one piece of pairing evidence from one source: source, step, tier, cardinality, endpoints, native text (02 s4) |
| source | an evidence origin with a registry row: ghidriff, bindiff, rz-diff, diaphora, manual, pt-ladder, pt-bytes |
| family / component | registry grouping of sources by dependency tags; components = union-find over joining tags (05 s1.1) |
| tier | M manual, A unique exact/identity key, B corroborating key, C candidate, W weak external evidence |
| decision | per row: matched, tentative, candidate, contested, ambiguous, older-only, newer-only, unknown |
| contest strength | strong (an M/A/B atom disagrees) or weak (only C/W); ordering only, never hides (D-12) |
| materiality | L2 verdict: unchanged, cosmetic (named proof), material (semantic delta + second channel), review, unknown, not-applicable |
| channel C0..C8 / proof | typed change observations / sound normalisations `COS-ADDR/1`, `COS-LAYOUT/1`, `COS-PSEUDO/1` (05 s2) |
| L1 / L2 | correspondence (which functions pair) / change significance (what changed) (R01 s0) |
| ladder, pass P00..P19, propagation, implied match | in-house matcher stages (04) |
| S0 | the no-IR mode: fusion over stored outputs only (B-00) |
| result / pointer row | sidecar `unified-result/1` directory under `runs/<run_id>/unified/` + tiny enrichment row (02 s4) |
| L-xx, B-xx, T-xx, G-U*, D-xx, C-xx, U-xx, A-xx | limit, backup, troubleshooting entry, gate, decision, conflict, USER decision, amendment ids |

## 3. Traceability matrix (every requirement of the request -> where it is met)

| Requirement | Sections |
|---|---|
| ONE engine integrating the cores of PatchTrace, BinDiff, Ghidriff/rz-diff and other tools' best ideas | 00 D-03..D-26; 01 s1-s2; 04 s4 (origin column); 05 s1.2; 06 |
| maximum analysis power | 03 (IR with masks, pdata, relocations); 04 (19 passes, propagation, residual); 05 s2 (operand channel first, proofs); 06 (all sources kept) |
| minimal false positives and noise | 04 I2/I6, s5.1 votes/conflicts; 05 s1.5, s3 (F1-F15), s4; 08 G-U1, G-U2, G-U3, G-U6 |
| modular, best practices, minimal bugs | 01 s2-s3 (module map, DAG, enforcement tests), s7 (extension points); 02 (strict contracts); 04/05 pure pseudocode; 08 s5 (red/green per module) |
| minimal build issues; Windows standalone alpha keeps building | D-20; plan s4 (no new dependency, data file, frozen smoke), s5 (flags); 08 s7; troubleshooting T-11, T-26, T-28 |
| SINGLE comparison window | D-18; 07 s1-s3, s9; backups B-10 (still one window) |
| backup for every element too costly to integrate | backups s1 (B-00..B-20), s2 (MVUE), s3 (never-cut list); plan s1 "Fallback" column |
| token efficiency (authors and builders) | this reading order; numbers only in 02 s6; plan s1 model tiers and token bands; citations instead of repetition |
| weakest points for the second agent | s5 below |
| adding a channel never changes fusion or UI | D-08; 01 s7; 06 s1 |
| incorporate or supersede the ChatGPT specs | 00 C-05..C-07, s3.1; 10 A-09..A-11 |
| Diaphora optional, out of process, ideas only | D-24; 06 s5; 09 s2 |
| spec number SPEC-31 | 00 header, D-01 |
| hard rule: never execute targets, no silent upload, offline | 01 s9.1-9.2; 03 s4, s11; 08 G-U8 (socket audit hook) |
| hard rule: no fabricated disassembly | 03 s4 (`text` from Ghidra only); 07 s3 ("unavailable" with reason) |
| hard rule: no uncalibrated score as confidence; display 'ordinal' | D-11; 05 s1.4; 07 s1.3 |
| hard rule: orientation, provenance, analyst control, project integrity | D-02, D-17, D-29; 02 s5, s7; 07 s6 |
| hard rule: never average, preserve conflicts, missing = unknown | D-11, D-12, D-14; 05 s1.3-s1.4 |
| hard rule: unified result DERIVED, never overwrites Ghidriff | D-02, D-07; 02 s4; 08 `test_unified_run_never_mutates_project_snapshot` |
| hard rule: AI only explains | D-30; 07 s4 `explain_context`; troubleshooting T-30 |
| hard rule: additive persistence, versions, backed-up idempotent migration, one SQLite writer | 02 s4, s7; 01 s4; 10 A-04 |
| hard rule: core Qt-free, UI thin | 01 s3; 07 s1-s2, s4 |
| hard rule: no GPL/AGPL copying; Apache ports with notices; licences from primary files | 09 (all); D-21, D-22 |
| hard rule: primary sources only | 00 header (one source fetch: ghidriff main); research notes' source lists |
| quality bar: contract-first; purpose, typed I/O, invariants, pseudocode, limits, failure modes, tests, security per module | 02; 03 s2-s11; 04 s1-s10; 05 s1-s5; 06 s1-s9; 07 s4-s11 |
| pitfalls: Job Object and pipe inheritance | D-28a, 01 s4, 10 A-06, T-22 |
| pitfalls: SQLite 32 MiB row / 128 MiB cap | D-07, 02 s4 (pointer rows <= L-31), T-10 |
| pitfalls: Qt thread teardown | 07 s9, T-20 |
| pitfalls: cache keys over all input digests | 02 s5 |
| pitfalls: BinExport2 protobuf needs upb | 06 s7 (BinExport2 producer only after C3; SPEC-31 adds no protobuf) |
| pitfalls: deterministic ordering | D-16; 04 I4; 08 G-U4; T-13 |
| pitfalls: cooperative cancellation | 01 s4; 04 I7; 07 s6 |
| pitfalls: pure-Python speed at 60k functions | 04 s5.2; 02 L-35; 08 s6; T-15; B-03, B-05 |
| no TBD without owner and trigger | every deferred item is a B-xx with a trigger or an A-xx with a slice |

## 4. Existing specs read and how SPEC-31 relates (details in 10)
Fully: `secondary-engine.md` (SPEC-11), `multi-engine-orchestration.md` and `multi-engine-evidence-panel.md` (SPEC-28), `multi-engine-evidence-calibration.md` (SPEC-27), `calibration-corpus-and-model.md`, `enrichment.md` (SPEC-07), `binexport2-support.md` (SPEC-10b, sections 1-5), `bindiff-execution.md` (SPEC-29, sections 1-4), `bindiff-adapter.md` (SPEC-10), `architecture.md` (SPEC-01), `schemas.md` (SPEC-02), `ui.md` (SPEC-04), `nway.md` (SPEC-09), the four QBinDiff/radiff2 specs, `three-tool-evidence-adapters.md`. By headings: `series-window.md`, phase-C plans and hard-problem notes, `ghidra-semantic-runtime-roadmap.md`, phase-C research.

## 5. Weakest points (for the reviewer; strongest doubt first)
1. W1 Independence assumption A-IND-1: SLEIGH decoding is treated as non-joining and `.pdata`-confirmed extents make `pt-bytes` an independent component (05 s1.1); if wrong, "matched via two tier-B components" overstates corroboration. Only G-U7 checks it.
2. W2 GZF reuse depends on Ghidriff internals (read on `main`, not on the pinned `4f5d895`) and on importing a GZF through pyghidra 3.x / `GhidraProject` [unv]; the fallback doubles Ghidra time.
3. W3 Performance numbers (L-35, L-08) are unmeasured estimates for pure Python at 60k functions and 2-3 M instructions (ingest of untrusted JSONL, SQLite sidecar build, ladder, alignment); no prototype exists.
4. W4 Soundness of cosmetic proofs: COS-ADDR trusts tier-A L1 mappings of operand targets; COS-PSEUDO trusts the decompiler plus the canonicaliser; the leakage gate only covers the planted mutation classes.
5. W5 Thresholds (L-09..L-26, implied votes 2/0, reference-vector 0.95/10/0.05, LAP floor 0.6, gate targets 99.5 %/95 %/20 %) are other tools' priors, not measured on Windows PE (no PE was available to the research).
6. W6 The extractor's Ghidra API surface (instruction and per-operand masks, operand type flags, string data, external locations) and the meaning of SLEIGH operand masks for x86-64 RIP-relative operands are [unv]; L1 masking correctness hinges on them.
7. W7 Policy choices that may under- or over-sell: constant-only edits land in `review` (not `material`) without C6/C8; the greedy edge choice inside contested clusters; hiding `cosmetic`/`unchanged` by default (U-03).
8. W8 Legal and latent-defect items: the BinDiff port with attribution has had no patent/NOTICE review (U-01); QBinDiff/binkit licences were not re-pinned; the two defects found by code reading (Windows pipe-handle inheritance, nway `EXTERNAL:` keys) are not reproduced yet.
Also open: sidecars under `runs/` are copied by project backups (size unmeasured, up to L-07 per side).
