# SPEC-31: Unified binary-diff engine (derived, one window)

Status: developer-ready design, docs only, 2026-10-14, base `main` = `cb25132`; independently reviewed and corrected the same day on the integration branch (`ce108cd`), see [11-review-log](11-review-log.md). Implementation status (2026-10-14): S0a (contracts, limits, keys, store; 02 s9) and S0b (S0 mode: sources, fusion, S0 facts, pipeline, worker, CLI; 02 s10) are implemented, everything else here is design. Owner of the design: lead architect session; builders follow `../../plans/unified-engine-plan.md`. Inputs (cited, never repeated): research `../../research/unified-engine/01..05` (R01..R05), existing specs listed in s4, Diaphora draft PR files (`docs/diaphora-optional-engine-20261014` @ `b75ac57`).

One sentence: extract one validated ProgramIR per binary (riding on Ghidriff's own Ghidra analysis when possible), turn every engine's stored output into tier-labelled evidence atoms, match in-house with a BinDiff/VT-style uniqueness ladder, decide per row with independence components AND evidence classes and no averaging, prove "unchanged"/"cosmetic" only with target-consistent named proofs or corroborate "material" with a second channel that sees the same change, and show the DERIVED result as a view mode of the existing single `MainWindow`.

## 1. Reading order (token-efficient)
1. [00-decisions](00-decisions.md) (decisions D-xx, conflicts C-xx, USER questions U-xx) - always.
2. [01-architecture](01-architecture.md) and [02-data-model](02-data-model.md) (contract freeze; numbers L-xx live only in 02 s6) - always.
3. Your slice's file only: [03-extraction](03-extraction.md) (S1), [04-matching-pipeline](04-matching-pipeline.md) (S2, S5), [05-fusion-and-noise](05-fusion-and-noise.md) (S0b, S3), [06-adapters](06-adapters.md) (S0b), [07-ui-and-cli](07-ui-and-cli.md) (S4), [08-evaluation](08-evaluation.md) (S6 and every slice's tests), [09-licensing](09-licensing.md) (S1/S2 ports), [10-amendments](10-amendments.md) (every slice, first step).
4. Plans: [plan](../../plans/unified-engine-plan.md), [backups](../../plans/unified-engine-backups.md), [troubleshooting](../../plans/unified-engine-troubleshooting.md).
5. [11-review-log](11-review-log.md) only when you need the evidence behind a rule (measurements M1-M9, findings R-xx).

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
| channel C0..C8 / proof | typed change observations / named rules `UNCH/1`, `COS-ADDR/1`, `COS-LAYOUT/1` (structural) and `COS-PSEUDO/1` (decompiler-relative, never hidden) (05 s2.5) |
| evidence class | what information a step reads (E-NAME, E-BODY, E-CFG, E-CALL, E-DATA, E-DECOMP, ...); corroboration needs two components AND two classes (05 s1.1) |
| target consistency / DATA-MAP | every address operand must reach the counterpart (rows for functions, DATA-MAP/1 for data) before any unchanged/cosmetic claim (05 s2.7) |
| MAT-ANCHOR / S3b | `material` needs a second channel that observes the same change / on-demand decompile of the top review pairs (05 s2.5, s2.8) |
| EH-EQ | unwind/handler metadata equality, precondition of structural proofs (05 s2.5) |
| L1 / L2 | correspondence (which functions pair) / change significance (what changed) (R01 s0) |
| ladder, pass P00..P19, propagation, implied match | in-house matcher stages (04) |
| S0 | the no-IR mode: fusion over stored outputs only (B-00) |
| result / pointer row | sidecar `unified-result/1` directory under `runs/<run_id>/unified/` + tiny enrichment row (02 s4) |
| L-xx, B-xx, T-xx, G-U*, D-xx, C-xx, U-xx, A-xx, R-xx, M-x | limit, backup, troubleshooting entry, gate, decision, conflict, USER decision, amendment, review finding, review measurement ids |

## 3. Traceability matrix (every requirement of the request -> where it is met)

| Requirement | Sections |
|---|---|
| ONE engine integrating the cores of PatchTrace, BinDiff, Ghidriff/rz-diff and other tools' best ideas | 00 D-03..D-26; 01 s1-s2; 04 s4 (origin column); 05 s1.2; 06 |
| maximum analysis power | 03 (IR with masks, pdata, relocations); 04 (19 passes, propagation, residual); 05 s2 (operand channel first, proofs); 06 (all sources kept) |
| minimal false positives and noise | 04 I2/I6, s5.1 votes/conflicts; 05 s1.3 (classes), s1.5, s2.5 (proofs, MAT-ANCHOR), s2.7 (DATA-MAP), s3 (F1-F18), s4; D-31..D-35; 08 G-U1, G-U2 (review mutants), G-U3, G-U6, G-U7 |
| modular, best practices, minimal bugs | 01 s2-s3 (module map, DAG, enforcement tests), s7 (extension points); 02 (strict contracts); 04/05 pure pseudocode; 08 s5 (red/green per module) |
| minimal build issues; Windows standalone alpha keeps building | D-20; plan s4 (no new dependency, data file, frozen smoke), s5 (flags); 08 s7; troubleshooting T-11, T-26, T-28 |
| SINGLE comparison window | D-18; 07 s1-s3, s9; backups B-10 (still one window) |
| backup for every element too costly to integrate | backups s1 (B-00..B-23), s2 (MVUE), s3 (never-cut list); plan s1 "Fallback" column |
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
| pitfalls: Job Object and pipe inheritance | fixed upstream (jobs.py:14-17, D-28a, A-06, T-22); JVM never memory-capped, worker capped (01 s4, L-42, T-38) |
| pitfalls: SQLite 32 MiB row / 128 MiB cap | D-07, 02 s4 (pointer rows <= L-31 = 128 KiB), T-10 |
| pitfalls: Windows path length, CRLF, 32,767-character limits | 02 s3/s4 (16-hex dirs), 02 s7.6 (`.gitattributes`), 03 s11 (request file) |
| independent review, research hardening | 11 (findings R-01..R-32, measurements M1-M9, residual risks, USER decisions) |
| pitfalls: Qt thread teardown | 07 s9, T-20 |
| pitfalls: cache keys over all input digests | 02 s5 |
| pitfalls: BinExport2 protobuf needs upb | 06 s7 (BinExport2 producer only after C3; SPEC-31 adds no protobuf) |
| pitfalls: deterministic ordering | D-16; 04 I4; 08 G-U4; T-13 |
| pitfalls: cooperative cancellation | 01 s4; 04 I7; 07 s6 |
| pitfalls: pure-Python speed at 60k functions | measured prototypes (11 M5, M7, M8); 04 s5.2; 02 L-35; 08 s6; T-15; B-03, B-05 |
| no TBD without owner and trigger | every deferred item is a B-xx with a trigger or an A-xx with a slice |

## 4. Existing specs read and how SPEC-31 relates (details in 10)
Fully: `secondary-engine.md` (SPEC-11), `multi-engine-orchestration.md` and `multi-engine-evidence-panel.md` (SPEC-28), `multi-engine-evidence-calibration.md` (SPEC-27), `calibration-corpus-and-model.md`, `enrichment.md` (SPEC-07), `binexport2-support.md` (SPEC-10b, sections 1-5), `bindiff-execution.md` (SPEC-29, sections 1-4), `bindiff-adapter.md` (SPEC-10), `architecture.md` (SPEC-01), `schemas.md` (SPEC-02), `ui.md` (SPEC-04), `nway.md` (SPEC-09), the four QBinDiff/radiff2 specs, `three-tool-evidence-adapters.md`. By headings: `series-window.md`, phase-C plans and hard-problem notes, `ghidra-semantic-runtime-roadmap.md`, phase-C research.

## 5. Weakest points after the review (strongest doubt first; the author's W1-W8 and how each was resolved are in [11](11-review-log.md) s4)
1. MSVC-built binaries were not available: operand typing, RVA-form switch handling and FID tagging were verified on clang/nasm PEs only (11 M3); the first S1 live run on an MSVC fixture is the check.
2. Narrowed independence assumption A-IND-1 (05 s1.1) and the borrowed thresholds (02 s6.1) remain hypotheses until G-U7 and G-U3 run on Tier R.
3. COS-PSEUDO/1 is decompiler-relative (listed, never hidden); EH-EQ compares C++ EH data only by handler and length.
4. DATA-MAP rule (c) region shift has a documented residual (U-12); B-21 removes it.
5. The BinDiff port still needs the patent/NOTICE review (U-01) and the `v8` commit SHA for PROVENANCE (09 s3).
Also open: sidecars under `runs/` are copied by project backups (IR up to L-07 per side; GZFs only while transient, 03 s8).
