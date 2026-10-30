# R7 — advanced binary security analysis (research workspace)

**Research status:** active / experimental; no production feature gate has been opened.  
**Live baseline:** `main` at `a04f5a299a8d4afef023261e52e08d14678cf1e7` (reconciled 2026-10-30).  
**Research branch:** `research/r7-advanced-binary-analysis-20261030`.  
**Concurrent owners:** R1 PR #128, R2 #131, R3 #129, R4 #130, R5 #132, R6 #133. Do not edit their files or treat pending PRs as merged.

## Scope and evidence vocabulary

Objective: explain *what changed* in matched binary code and what security hypotheses the **observed** change permits, without declaring an automatically verified vulnerability.

- **Observed:** digest-verified artifact, exact function/instruction RVA, extractor output and data/control dependency with owner and analysis version.
- **Derived:** deterministic inference with an explicit rule ID, exact input evidence, assumptions, and provenance.
- **Hypothesis:** proposed security relevance / CWE with alternatives and counterevidence; may be wrong.
- **Analyst conclusion:** independent recorded review. Model text cannot produce or silently promote this state.

No component in this workspace changes matches, verdicts, CVE mappings, project persistence, production provider behaviour, or ranking. A P-code operation or synthetic graph is not a proof of source-level semantics.

## Repository-first capability inventory

| Existing surface on main | Verified implementation/read | R7 boundary / gap |
|---|---|---|
| `unified/ir/{records,schema,ins}.py`, `program-ir/1` | strict Ghidra fact ingestion, indexed functions/blocks/calls/constants/refs, compressed `ins/1` instructions, hashes/masks/flow | no high-P-code SSA def-use or memory-SSA / PDG tables; do not create a replacement ProgramIR |
| `unified/extract/{ghidra_script,runner}.py` | separate Ghidra/pyghidra extraction plus optional C decompile | no versioned high-P-code op export; native decompiler API feasibility must be measured |
| `unified/facts/{irchannels,verdict}.py` | comparison channels, target consistency and proof tiers (`UNCH/1`, `COS-ADDR/1`, etc.) | R7 must not override these proof or materiality decisions |
| `enrichment/signals.py` | deterministic BND/INT/OVF/VAL/ERR/SIZE/SCRUB hints | signals do not prove a guarded sink or vulnerability root cause |
| `intelligence/{hypotheses,lexicon,explain,contracts}.py` | rule-hypotheses, advisory-CWE provenance, unknowns, immutable `intelligence/1` reports | CWE attached to advisory is not independently recovered from binary |
| `evidence.py`, `interpretation.py`, `providers.py` | bounded evidence contexts, schema/citation validation and explicit remote consent | no measured R7 explanation-fidelity benchmark |
| `tools/calibration/`, `corpus/ours/cwe-patterns` | grouped evaluations, synthetic positives/negatives, known-answer infrastructure | no accepted R7 root-cause/P-code/PDG generalization evidence |
| R1–R6 open draft PRs | parallel ground truth, matching, semantic, correlation, calibration, release research | read on their own heads before cherry-pick; avoid concurrent edits |

These are observations from the stated baseline, not promises that all paths are complete or CI-green. Current baseline has **26 open PRs** at the first reconciliation, not 26 R7 dependencies.

## Experimental modules (development-only, not shipped)

- `tools/research/r7/slicer.py`: small, deterministic *ephemeral* def-use graph prototype for high-P-code-shaped **synthetic** facts; bounded backward/forward traversals; provenance as caller-supplied metadata, not verified against a binary. Does not parse executable files or execute target code. Does not alter `program-ir/1`.
- `tests/test_r7_slicing.py`: positive/negative/edge cases, truncation, alias and unknown-path assertions.
- `tools/research/r7/patterns.py`: a conservative **synthetic** new-predicate-to-memory-sink motif that only emits candidate/not-observed/inconclusive; never security certainty, CWE or real control dominance.
- `tests/test_r7_patterns.py`: 13 positive/negative/abstention fixtures; in combination with slicing, **40 local synthetic tests passed**.
- `docs/research/advanced-analysis-r7/qa.md`: exact local commands, environment, pass counts, CI/native blockers and run limitations; root `docs/qa.md` remains unchanged to preserve concurrent R3 work and because source fetch was truncated.
- `tools/research/r7/bench.py`: synthetic throughput and peak-memory study, not native Ghidra acceptance.
- `01-literature-and-methods.md`: primary references, semantics, comparisons, limitations, licenses and feasibility.
- `02-acceptance-and-roadmap.md`: benchmark matrix, gates, integration wiring, AI/CWE evaluation, defer decisions.

## Production acceptance gates (not waived by a green synthetic test)

1. Export decompiler high-P-code only via an opt-in bounded read, using the existing GZF/extractor subprocess and owner-verified `artifact_sha256`, `ir_key`, and `function_rva`. Fail closed on missing/unanalysed GZF, timeout, mismatched version/hash, or unsupported language. Keep high-P-code sidecars outside canonical `program-ir/1` until a versioned additive contract has passed review.
2. Verify Stable Ghidra sequence numbers, SSA varnode identity, normalised register/stack/address spaces, `MULTIEQUAL` and `INDIRECT`; measure decompiler optimisation-induced drift using both sides of matched R1–R5 fixtures.
3. Derive control dependence from an actual CFG/post-dominator construction. A fixture-provided `control` edge is **not** verified dominance. Require memory alias, pointer-effect, call-effect and indirect-call unknowns; no full-flow coverage claims.
4. Verify guard-to-sink reachability across the **newer** and **older** versions and reject negative controls (cosmetic comparison, guard on unrelated variable, undominated or unreachable sink, equivalent refactor, compiler noise).
5. Compare precision/recall with current PatchTrace; slice coverage, citation fidelity, unknown rate, run time/RSS, reproducibility and cancellation. Split by binary family, toolchain and CVE lineage; do not leak paired lineages across folds.
6. Keep model outputs hypothetical: fail invalid evidence IDs and non-owned RVAs; measure false claims, wrong CWE, omissions, alternatives, counterevidence, privacy and token use. Local provider evaluated separately from remote; no model execution without explicit user consent.
7. Required full Linux and Windows CI, native Ghidra tests, hostile-input audit, independent review and compatibility evidence precede production integration. No claim of completed acceptance until observed.

## Checkpoint format

Record head SHA; draft PR; exact command + Python/Ghidra/compiler versions; fixture provenance and hashes; measured TP/FP/TN/FN; repeatability; memory/time; pass/fail/skip; unknowns; accepted/deferred techniques; unverified native or AI gates. **Never label synthetic correctness as real-binary security accuracy.**

## Immediate engineering order

1. Add bounded, nonpersistent slice prototype and red/green tests under the research tooling namespace.
2. Run deterministic synthetic tests, mutation negatives and benchmark with exact environment.
3. Implement a **separate** read-only high-P-code extraction spike only after the current GZF runner constraints are reconciled with R3 ownership.
4. Use actual cross-compiler corpus measurements and known-answer experts to determine whether the spike offers measurable analyst benefit.
5. Only then propose additive contract changes; keep R7 isolated meanwhile.
