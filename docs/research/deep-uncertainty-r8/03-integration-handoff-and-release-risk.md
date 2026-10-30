# R8 → R6 integration handoff and architecture risk decision

**Date:** 2026-10-30. **Base:** `main` `a04f5a299a8d4afef023261e52e08d14678cf1e7`.  
**Owner artifact:** [draft PR #135](https://github.com/djshellshoxxx/patchtrace/pull/135) on `research/r8-deep-uncertainty-20261030`.  
**Overall R8 gate:** **NOT RELEASE READY**. Two narrow compiler/source properties were experimentally established, one small proposed production correction is committed but full application/native tests are pending, and the other A–I uncertainty areas remain open.

## 1. What changed, and what did not

| Path | Change | Intended invariant |
|---|---|---|
| `src/patchtrace/unified/facts/pseudo.py` | `_number` distinguishes suffix-sensitive integer/float tokens, base-sensitive large unsuffixed integers and parses octal | Never derive weak cosmetic pseudo-proof by erasing a type-relevant literal distinction; preserve small same-type value normalization |
| `src/patchtrace/unified/registry.py` | `CHANNEL_VERSIONS[canon]` 1 → 2 | Re-key `config_digest` and avoid reuse of legacy C5/C6 evidence |
| `tests/test_r8_literal_types.py` | New focused canonicalizer and C5/C6 regression tests | Preserve meaningful changes without breaking `0x100` ≡ `256` and `010` ≡ `8` value equivalence |
| `docs/specs/unified-engine/05-fusion-and-noise.md` | R8 amendment at end | Make proof-scoped typed literal behavior explicit |
| `tools/research/r8_icf_probe.py` | Compiler-only deterministic COFF/PE /OPT:ICF toggle | Prove source alias and machine entry identity are not one-to-one |
| `docs/research/deep-uncertainty-r8/` | Register, exact compiler evidence, ICF identity note and this handoff | Independent provenance, reproducibility and remaining blockers |

**No changes:** R2 fusion/arbiter logic, R3 semantic proof ordering, L1 ladder, database schema, default unified-engine feature flag, numeric probability/calibration policy, CVE attribution, AI interpretation, network/telemetry or binary execution. No third-party binaries are committed. No release or production deployment.

**Threat model:** `COS-PSEUDO/1` is relative to decompiler text and susceptible to missing type/data/ABI facts. The correction reduces one known *canonicalizer* source of unsound sameness. It does **not** establish general binary semantic equivalence or demonstrate a measured PatchTrace false-benign rate.

## 2. Reconcile these active external owners BEFORE merging

| Area | Live draft PR as checked | Integration conflict / action |
|---|---|---|
| Truth and labels | R1 #128 | Add ICF on/off two-export fixture to Tier R; record two names/one RVA truth, reject forced one-to-one label |
| Matching, fusion, scaling | R2 #131 | Check affected alias group, leftover endpoints and B+B independence; do not overwrite its arbiter/compute fixes |
| Semantic proofs, EH | R3 #129 | **Textual or semantic conflict likely:** both edit `src/patchtrace/unified/registry.py` and `docs/specs/unified-engine/05-fusion-and-noise.md`. R3 bumps `COS-PSEUDO/1` proof version 1→2 and tightens EH/register veto. Preserve **both**: `('canon',2)` in `CHANNEL_VERSIONS` **and** R3 `('COS-PSEUDO/1',2)` in `PROOF_VERSIONS`. Add both regression suites; do not drop either amendment |
| CVE/KB applicability | R4 #130 | The source/type/ICF cases are *not* CVE-to-function causal evidence; only source-fix lineage may upgrade a candidate |
| Calibration | R5 #132 | Treat duplicated ICF aliases as one underlying code region within lineage-grouped partitions; no new probability threshold or claim |
| Integration/release ledger | R6 #133 and milestone coordinator #126 | Reconcile QA/todo/tracker additions below; preserve existing entries and old failing run evidence |
| AI security interpretation | R7 #134 | Continue classifying explanations as hypotheses; avoid promoting canonicalized text to verified behavior or high-confidence CWE |
| Other shared PRs | #78/#79/#82/#86 and open integration PRs | Check current head, pending reviews, target base, CI and workers again; do not assume drafts were merged |

## 3. Concrete red/green and source verification sequence

Checkout the **reconciled** branch in the normal trusted PatchTrace development runner. Do not alter private artifact inputs. Record exact version, OS and command. Suggested focused commands (adjust only to repository's current `AGENTS.md`/CI contract):

```bash
python -m pytest -q tests/test_r8_literal_types.py tests/test_unified_facts.py tests/test_unified_verdict_ir.py
python -m pytest -q tests/test_unified_mutations.py tests/test_unified_gu_mutants.py
python -m ruff check src/patchtrace/unified/facts/pseudo.py src/patchtrace/unified/registry.py tests/test_r8_literal_types.py tools/research/r8_icf_probe.py
python tools/research/r8_icf_probe.py
```

Use `python -m pytest -q` plus the repository's current full QA command and Windows native acceptance once dependencies are installed. The R8 author could not clone the repository into the local isolated execution sandbox because the GitHub hostname did not resolve; **none of the above repository-integrated test commands has been claimed as executed**. In that sandbox the exact original `_number` source was copied in isolation and its 5-control pytest run was: before change **4 failed/1 passed**, after correction **5 passed**. This is a valid reproducible unit-level demonstration, **not a green repo test**.

The ICF script DID execute twice on the author host with Clang/LLD 17 and reproducible `/Brepro` DLL hashes; both reported `status=PASS` with on=alias and off=unique. The script never executed a DLL. See `02-icf-function-identity.md` for exact observations and checksums.

## 4. Native acceptance gates: precise pass/fail criteria

**G-U2 false-benign:** For every independently verified material mutant whose original decompiler emits the type distinction, C5/C6 should report meaningful difference or missing evidence and final result must not be `cosmetic`/`unchanged` merely due to prior token collision. Show raw code, code provenance and exact output fields. Include the old canonicalizer as the negative control. For missing/decompiler-suppressed types, abstain; don't claim the correction supplies absent evidence.

**G-U1 A/A:** For each literal-control pair identical inputs across both sides, all expected endpoints accounted for and no invented material result. Value-preserving alternate base in *same type* should remain normalized. New `canon/2` must not change source-to-result matching keys except through explicit version policy.

**G-U3 identity:** Compare ICF-off → ICF-on and ICF-on → ICF-off with exact source/PDB/export labels withheld from matcher; explicitly represent duplicate RVAs/alias groups. One machine-code region may correspond to multiple source names. Do not label two export symbols as two independent functions in precision denominator; abstain on unresolvable lineage. Run repeated, reversed and input-permuted cases.

**G-U4 deterministic/cache:** Before/after config digest must differ for `canon` 1 vs 2. `PROOF_VERSIONS` retain the R3 fix. Repeat results across Windows/Linux on identical IR/fixtures; differences are triaged not hidden.

**G-U5 performance:** Record wall time, peak RSS and cancellation on dense clone/ICF-heavy binaries; bounded fallback may abstain but cannot force a false one-to-one answer.

**G-U7 independence:** Correlation from shared underlying code must not count duplicate aliases as independent votes/samples. Report B+B acceptance by independently judged source lineage and evidence-class pair, including identical twins.

**G-U8 integrity:** No target execution, network calls or unauthorized data transfer; source snapshots unchanged; errors and missing native inputs remain visible. R8's research script runs compiler/linker/objdump as trusted build tools only, not the produced PE.

**Release decision:** An exact-head run must pass all relevant Linux + Windows QA, S0/IR unit, G-U2 native, corpus and integrity gates, and resolve R3 version/spec conflicts. Pending, skipped, cancelled, mock-only or insufficient-data checks never imply readiness.

## 5. Follow-up experiments for remaining R8 risks

| Order | Work item / owner | Evidence to gather | Success/abstain |
|---|---|---|---|
| P0 | R8/R3: decompiler native literal cases | Clang-cl/MSVC PE, GZF hash, actual Ghidra C5/C6 and older/newer IR, specific verdict | No false benign on admitted material cases; unknown if type was lost upstream |
| P0 | R1/R2: function identity ICF fixture | PE exports+PDB source truth with on/off and both directions; hidden matcher symbols | No forced unique correspondence; grouped/ambiguous outcome with full endpoint coverage |
| P0 | R2/R5: evidence dependency audit | Actual source signal provenance per atom, joint error classes; same-clone false match controls | No independence assumption without empirical class+component support and lineage CI |
| P0 | R5: locked lineage calibration | Independent projects, compiler/optimization OOD, leakage/dedupe guard, cluster bootstrap and threshold sensitivity | No numerical correctness probability without a validated locked test |
| P0 | R4: KB/CVE/function causality | Official vendor advisory + exact build applicability + source/patch chain and contradictory cumulative-KB controls | Candidate labels until independently verified causal fix |
| P1 | R3/R7: EH/CFG/data-flow limits | real Win64 SEH and complex C++ EH PEs, indirect edges, provenance, bounded high-P-code slice | `review` on unresolved/mismatched metadata, not `unchanged` |
| P1 | R2: dense graph performance | 10k/60k/250k injected alias collisions; I/O and memory profiles, cancel latency | L-35 budgets or graceful fail-closed no-results |
| P1 | R7: AI claim fidelity | Prompt-injected metadata, citations outside functions, CWE ambiguity, conflicting model reports | Reject invalid citations; preserve deterministic verdict independence |

No unmeasured likelihood or false-match percentage is assigned.

## 6. Suggested `docs/qa.md` entries for the existing coordinator (not silently injected)

| ID | Date | Platform & input | Observed evidence | Status |
|---|---|---|---|---|
| R8-LIT-01 | 2026-10-30 | Python 3.13.5 source-equivalent copied `_number`; GCC 14.2 ELF/Clang 17 COFF | 4 red + 1 control; corrected 5 green, type-sensitive compiler `.text` hashes | SOURCE UNIT CORRECTED / FULL REPO + NATIVE G-U2 OPEN |
| R8-IDENT-02 | 2026-10-30 | Clang/LLD 17 /O2 /Gy /opt:icf vs /opt:noicf /Brepro PE x64 | 2 deterministic runs; both exports RVA 1000 folded, 1000/1010 unfolded; SHA in research doc | LINKER ASSUMPTION VALIDATED / PATCHTRACE MATCHER OPEN |

## 7. Suggested `tasks/todo.md` entries for the existing coordinator

- [ ] R8-P0-01 Integrate typed literal `canon/2`, review source and red/green tests; preserve R3 `COS-PSEUDO/1` v2 proof fix simultaneously.
- [ ] R8-P0-02 Complete native PE/Ghidriff C5/C6 proof/abstention calibration, exact-head CI and G-U2 false-benign acceptance.
- [ ] R8-P0-03 Admit ICF on/off ambiguous function fixture with hidden-label truth and test G-U3/G-U4 both directions.
- [ ] R8-P0-04 Confirm no grouped ICF alias duplicates in calibration split/sampling or evidence-independence counts.
- [ ] R8-P0-05 Reconcile active R1–R7 changed files and pending CI before merging R8 PR #135.
- [ ] R8-P1-06 Address the remaining uncertainty register items only after P0 accuracy issues are bounded.

The milestone coordinator owns the canonical shared QA/todo files; this packet supplies exact entries without overwriting other workers' edits.

## 8. Architecture risk decision

- **No universal source-to-address bijection.** Treat one RVA as a machine-code location, not a unique source function ID; retain alias/group uncertainty.
- **No automatic behavioral-equivalence claim from C6.** Typed normalization closes one gap but decompiler omissions remain; stronger `UNCH/1` and structural proofs still require target/EH/IR conditions.
- **No engine-count or function-count independence assumption.** Dependence must be evaluated by shared underlying evidence and source lineage.
- **No numeric confidence or CVE causality promotion from structural similarity.** Use explicit epistemic states and abstain when evidence is missing.
- **Integration and release status: BLOCKED on exact-head CI and native acceptance.** Retain draft PR; do not merge before owners reconcile required gates.
