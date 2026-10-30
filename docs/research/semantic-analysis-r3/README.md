# R3: semantic change detection — research and validation dossier

**Date:** 2026-10-30. **Status:** research checkpoint; acceptance **open**, not a certified false-negative rate. **Baseline:** `main` at `a04f5a299a8d4afef023261e52e08d14678cf1e7`. **Scope:** [R3 owner brief](../../specs/unified-engine/README.md) / SPEC-31. This directory adds evidence to the existing engine; it does not establish a second semantic pipeline.

## Executive findings

1. **Retain the existing L1/L2 separation.** L1 is correspondence, not equivalence. L2 already offers IR-backed C0–C5, target mapping, EH-EQ, named `UNCH/1`, `COS-ADDR/1`, `COS-LAYOUT/1`, and decompiler-relative `COS-PSEUDO/1`, plus `MAT-ANCHOR` for material changes. Source: `src/patchtrace/unified/{compute.py,facts/*}`. An older SPEC-31 README and the opening paragraph of 05 describe an earlier implementation point: **`compute.py` now passes `ir_sides` and includes `refacts_stage`**; don't treat stale milestone text as actual execution state.
2. **Never equate equal bytes or equal structure with equivalent behavior.** The two relocatable-object tests below contain pairs with **identical disassembled instruction bytes but different relocation targets**: `global_a` → `global_b`, and `target_a` → `target_b`. These are *differently referenced objects* even before layout/linking; material behavior is conditional on those targets' values/implementations. Actual PE-linked target consistency requires a separate run. See `experiment-and-benchmark.md`.
3. **Source edits can be smaller than structural summaries.** A strict-to-inclusive comparison and an integer threshold edit retained the same function-level byte length and instruction count in the controlled GCC-O2 sample but changed instruction bytes. A heuristic treating stable size or CFG as benign can hide a fix. `facts/operands.py`, `facts/layout.py` and `MAT-ANCHOR` should prevent this; a *full PatchTrace end-to-end pass was not performed* here.
4. **A specific proof-contract discrepancy exists.** The proof table in SPEC-31 05 §2.5 requires EH-EQ for `COS-PSEUDO/1` when IR is present. The baseline `_pseudo_proof` checks only `ev.eh != 'differs'`, permitting `unavailable`. This is a **source-inspection defect hypothesis**; it needs the documented failing regression, a conservative patch, a proof-version bump and CI before counting as corrected. Missing EH evidence should not justify a benign conclusion when IR exists. See [proof-contract ledger](#proof-contract-ledger).
5. **An SMT engine should not become a required dependency.** Alive2 validates *LLVM IR refinement under bounds* (not arbitrary Windows PE equivalence); angr, Triton, Z3 and BINSEC/Rel illustrate the power and costs of symbolic methods but also the significance of call, memory, environment and path assumptions. Use a bounded **optional experiment** after cheap structural/semantic evidence is inconclusive.
6. **Real accuracy is currently unknown in this R3 run.** The 10 static pairs below are a **fixture-generation and disassembly sanity check**, not PatchTrace verdict samples. No function-level confusion matrix, runtime percentile, false-cosmetic rate or security-fix recall is claimed. Existing Tier R and G-U gates can produce these measurements without a parallel benchmark framework.

## Repository reconciliation (observed, not inferred)

- Default branch `main`: `a04f5a2` on 2026-10-30. More recent work may arrive after this checkpoint; refresh refs before integration.
- Repository policy: `AGENTS.md`, `CLAUDE.md`, `SECURITY.md`. Target bytes are untrusted **data**, never executed; derived results do not replace committed original runs; private evidence, no silent transmissions; backend is Qt-independent; real Windows acceptance cannot be replaced by Linux mocks.
- Relevant specifications: `docs/specs/unified-engine/{00-decisions,01-architecture,02-data-model,03-extraction,04-matching-pipeline,05-fusion-and-noise,08-evaluation,13-remaining-work-plan}.md`.
- Research to reuse: `docs/research/unified-engine/01..05`, `docs/research/ue-matching-literature.md`, `docs/research/ue-open-questions.md`, `docs/research/calibration/prior-art-corpus-factories.md`.
- Current owners' potentially overlapping PRs: [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) (persist bounded Ghidra C, targets a stacked GUI branch), [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) (Tier R persistence), [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) / [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) (A/A and compiler-noise recipe controls), [#71](https://github.com/djshellshoxxx/patchtrace/pull/71) / [#90](https://github.com/djshellshoxxx/patchtrace/pull/90) (synthetic fixture repairs). These are not evidence of completed acceptance and their branch bases may be old. This R3 branch must not merge or rewrite their work.
- There are already `tools/calibration/tier_r/`, `tools/unified/mutations/`, `tests/test_unified_{verdict_ir,datamap,layout_eh,anchors,mutations,...}.py`; use these as the benchmark factory, label contract, and test seams.

### Actual implementation inventory

| Area | Status at checked baseline | Evidence / remaining acceptance |
|---|---|---|
| L1 correspondence/fusion | Implemented: `unified/ladder/*`, `fusion/*`, `compute.py` | No equivalence claim; review current-head end-to-end G-U and platform results |
| C0/C1 hashes, C2 operand deltas, C3 graph | Implemented in `facts/irchannels.py`, `operands.py`, `layout.py` | Native Windows MSVC operand cases, indirect transfers, real PE images |
| C4 calls/C5 constants/C6 decompiler text | Implemented in `facts/channels.py`, `facts/pseudo.py`, `facts/anchors.py` | Verify Ghidriff text identity and live decompiler availability; don't treat C6 as independent from its originating data group |
| `DATA-MAP/1` | Implemented in `facts/datamap.py`; confirmed-pair voting, unique-string SHA, guarded region shift | Single-use globals, switched targets, section boundaries, ambiguous duplicates and pair-vote order |
| `EH-EQ` | Implemented in `facts/eh.py`; unavailable, absent, differs, equal | Real MSVC `__C_specific_handler` and C++ handler data not universally supported |
| `UNCH/1`, `COS-ADDR/1`, `COS-LAYOUT/1`, `COS-PSEUDO/1` | Implemented in `facts/verdict.py` with conservative blockers and limits | Verify IR + unavailable EH does not get a pseudo-cosmetic proof; see defect ledger |
| `MAT-ANCHOR` | Implemented in `facts/anchors.py` | Only promotes when another data group sees same change; analyze false negatives independently |
| On-demand Ghidra C | Implemented in `compute.py:refacts_stage`, `facts/refacts.py` | Test current-head native GZF retention and bounded cancellation; #86 independent persistent text storage |
| Mutation and A/A corpus | Registry and generators present; `tools/unified/mutations/classes.py` enumerates 12 generated classes and two pending cases | Build/label is not verdict accuracy; run both engines through G-U2 and locked corpus |
| Full semantic equivalence | **Not claimed / not built** | Formal proof or solver feasibility only; no universal claims |
| CVE attribution | Out of R3 verdict contract | R4 handoff requires external advisory/build provenance, not heuristic causal assertion |

## Proof-contract ledger

| ID | Status | Reproducible concern / rule | Required action |
|---|---|---|---|
| R3-PC01 | source-inspection discrepancy; regression proposed | `facts/verdict.py::_pseudo_proof` allows IR+EH `unavailable` to receive `COS-PSEUDO/1`; SPEC-31 05 §2.5 table says EH-EQ when IR exists | Red test: C6/C4/C5 equal, C0 differs, no structural proof, IR present, EH `unavailable` must be `review`; implement safe predicate; bump `PROOF_VERSIONS`; run Linux/Windows suites |
| R3-PC08 | source-inspection discrepancy; regression added | `PSEUDO_BLOCKERS` omitted `register-only`; decompiler equality could incorrectly mark an IR register change cosmetic, contrary to SPEC-31 §2.5 review rule | Block IR register-only in pseudo-proof; test with C4/C5/C6 equal and no structural proof; bump proof implementation version and run CI |\n| R3-PC02 | validation open | `UNCH/1` depends on all address operands being correctly recognized and mapped, including relocated RIP operands and branch targets | Lost relocation/mask field and changed linked target mutants; verify extractor and reader provenance |
| R3-PC03 | validation open | `COS-LAYOUT/1` requires a **polarity-preserving** block bijection, not equal CFG sizes or multiset hashes | Swap then/else targets and invert condition/control pair; assert only genuinely equivalent inversion passes |
| R3-PC04 | validation open | `MAT-ANCHOR` is intentionally stricter than a materiality signal; `review` is acceptable on missing C6 but **never** `cosmetic` for changed guard | Rerun small condition/constant-only mutants through native IR and recorded C text |
| R3-PC05 | validation open | `DATA-MAP/1` region-shift inference is a heuristic requiring negative tests for swapped existing globals | Existing global swap with two other positive voters; single-use datum without voters stays `review` |
| R3-PC06 | validation open | Security mitigations (CFG, /GS, SEH) can introduce or remove code and metadata even when application source is unchanged | Two build-flag variants, compare protection metadata and verdict; don't suppress as benign compiler noise |
| R3-PC07 | validation open | Truncated input, capped delta list, alignment cap, failed decompiler or unmapped target cannot imply unchanged | Explicit unavailable and cancellation cases; published result must remain atomic, deterministic and versioned |

### Evidence and taxonomy

L2 classes remain `unchanged`, `cosmetic`, `material`, `review`, `unknown`; non-two-sided rows use `not-applicable`. The distinction is evidentiary: `material` means *the classifier's semantic/material change claim is corroborated under its documented observation model*, **not** that a CVE or exploit exists. Conversely `review` is not a detection failure when a changed case lacks proof needed for `material`; for *security screening*, a changed fixture passed only if it is `material` or `review` and is **never** `cosmetic`/`unchanged`.

For every `unchanged`/`cosmetic` decision preserve the rule name, observed deltas, complete target mapping status, EH state, input hashes, function RVAs, evidence versions, limitations, and source run identifier. Display structural proofs and decompiler-relative `COS-PSEUDO/1` distinctly in the existing unified GUI; the latter must stay visible even when other cosmetic rows are collapsed. An L1 match, even a tier-A unique match, only determines the compared pair.

## Compiler-noise taxonomy (strictly under assumptions)

| Transformation | Expected first response | When a benign proof is eligible | Danger case / negative test |
|---|---|---|---|
| Image base / branch displacement / RIP addressing | Changed address fields | `COS-ADDR` only if all actual referents map; `EH-EQ` | Different linked global/callee; changed import |
| Register allocation | Changed registers / temp SSA names | Targeted dataflow equivalence; not an allowed current structural proof | Calling convention / alias / flags changed |
| Instruction scheduling | Same effect under independent operations | Require dependence and memory-order analysis; otherwise `review` | Two memory stores reordered, volatile/atomic access |
| Stack frame and prologue | Changed frame | Currently `review` | Buffer resize, security-cookie change |
| Basic-block reorder / harmless jump | Different layout | Strict `COS-LAYOUT/1` mapped polarity/successors | Then/else swapped without predicate inversion |
| Inlining, outlining, ICF | Non-1:1 correspondence | Group/tentative evidence only; do not assert equivalence | Removed check hidden in inlined path |
| Loop unrolling/vectorization | Different structure/instructions | Optional bounded differential testing or proof; otherwise `review` | Changed loop bound / signed comparison / FP semantics |
| Constant propagation | Changed literals | No cosmetic inference from same CFG alone | Threshold or bitmask security fix |
| Exception/unwind metadata | `EH-EQ` validation required | Equality only under parsed supported format | Added try scope / different handler |
| /GS, CFG, security switches | Changed runtime protection and metadata | **Not** an automatic cosmetic transformation | Dropped indirect-call validation or stack canary |

Assumptions: same calling conventions, defined input domains, no unmodeled I/O or external effects, compatible loader/ABI/runtime. Same C source or a decompiler similarity ratio is *not* a proof. Undefined behavior, compiler bugs, differing lib implementations, and build-security flags defeat naive “same source” equivalence.

## Test/benchmark strategy and acceptance

Reuse SPEC-31 08 gates and Tier R; do **not** change calibration thresholds by looking at the final held-out test data.

1. Pair sources by pinned recipe, compiler version, flags, architecture and source mutation; record source digest and object / PE digest, relocation symbols, referenced targets, expected class and exact witness input when available. Synthetic object tests are preliminary; final classifier tests must use supported PE AMD64 linked images and actual `unified run`.
2. Freeze a held-out partition by **source project/lineage**, not random functions from the same binary. Keep positive mutations and negative A/A, compiler-only, relocation, layout, build-security and metadata controls separate. Include adversarial “changed source but optimized away” cases as **not ground-truth material** unless the binary effect is proved.
3. Use the same fixture and adjudication for before/after; record exact engine SHA, source/IR schema versions, platform, native dependency versions, failures and analysis budgets.
4. Report a row-normalized confusion matrix with truth categories (unchanged, benign representation, material, unestablished) versus `unchanged/cosmetic/material/review/unknown`. Treat `review` and `unknown` distinctly (triage workload, no benign claim). Report class-wise `false_benign = #(material→unchanged|cosmetic) / #(material eligible)`, `false_material = #(benign→material) / #(benign eligible)`, and detection coverage `#(material→material|review) / #(material eligible)`. State excluded/unknown counts and confidence intervals (Wilson/cluster bootstrap by lineage).
5. Report p50/p95/p99 wall time, peak RSS, IR extraction time, decompiler calls, timeouts, skipped rows, Windows versus Linux reproducibility, and drift after native dependency changes.
6. Gate: **zero observed** material→benign in planted suites is a *sample result*, not a universal proof of zero risk. Any such case blocks release until reproduced and repaired. Preserve SPEC-31 G-U1..G-U8 thresholds and independent review. No final accuracy metrics without complete runs.

## Research questions to resolve before promoting R3

- Can Ghidra 12.x raw/high P-code represent signed/unsigned comparisons, carrying/overflow flags and byte-level memory effects accurately enough to create a low-cost targeted guard-change evidence channel *without* trusting decompiler C? Compare against existing C2/C6.
- Which PE loader features (base relocations, exports, import thunks, guard tables, exception scopes, jump tables) are extracted with reliable target classification on the Windows acceptance corpus, and which are `unavailable`?
- What happens when a *definition moved but instruction bytes remain equal*? Build the existing pending `moved-rva-call` mutator with a linker layout-controlled witness; inspect resolved call and symbol identity.
- Can selected bounded symbolic checks disprove equivalence (produce a model/witness) more often than the current proof rules, with a strict CPU/RSS/time budget, **without** claiming equivalence on timeout?
- Can function-level code delta anchors be traced to an actual vulnerable program behavior? This is a distinct R4 evidence question: advisory → product/build applicability → paired binary provenance → changed function → plausible security hypothesis.

## Contents and completion tracking

- [Methods and tools](methods-and-tools.md): primary references, comparison, soundness and deployment choices.
- [Experiment and benchmark](experiment-and-benchmark.md): actual compiled object observations, fixture design and full metric contract.
- [R4 handoff](r4-handoff.md): vulnerability-correlation dependency contract.
- **Completed this checkpoint:** repo/spec/code inventory; first principles and sources; one small static 10-pair cross-toolchain experiment. **Open:** PatchTrace full-suite/CI, actual G-U results, Windows live native checks, quantified accuracy, runtime-memory, R3-PC01 verification/repair if not included in this PR, optional solver prototype.
- **Status:** research **partially completed**, R3 acceptance **not yet met**. Subsequent commits must update this document with actual test-run identifiers, evidence and defects rather than turning projected gates into completed checkboxes.
