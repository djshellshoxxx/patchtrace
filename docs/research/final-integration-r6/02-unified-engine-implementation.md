# 02 — Unified engine implementation, L1/L2 correctness and persistence

**Scope:** SPEC-31 ``00–13; current main `a04f5a2`, R2 draft [#131](https://github.com/djshellshoxxx/patchtrace/pull/131), R3 draft [#129](https://github.com/djshellshoxxx/patchtrace/pull/129). **Status:** source-backed engineering runbook; implementation fixes in R2/R3 must be reconciled and tested before counting as merged.

## 1. End-to-end stage contract

```text
Verified PE AMD64 pair and immutable primary Ghidriff snapshot
 -> plan/guard and SHA/orientation/PE RVA normalization
 -> Ghidra GZF reuse or own extraction -> validated program-ir/1 sidecars
 -> Ghidriff, secondary, manual and ladder evidence atoms
 -> P01–P19 uniqueness ladder, propagation and bounded residual
 -> dependency-aware multi-engine fusion and contest preservation (L1)
 -> typed change channels, DATA-MAP/1, EH-EQ and named proof/anchor (L2)
 -> immutable unified-result/1 sidecar / transactional pointer
 -> CLI explain, single Qt window and evidence-backed reports
```

**Invariants:** ordered whole-file SHA-256 pair is identity; each endpoint is its file SHA-256 plus RVA, never just a name, address or timestamp. Raw VA addresses require per-image VA→RVA conversion; unknown or mixed bases fail closed. A Ghidriff `EXTERNAL:<hex>` index is not an import name. Ghidriff remains the primary source; derived unified output cannot rewrite `ComparisonProject.matches`, primary raw JSON, history or analyst notes. L1 matching never proves semantic equivalence and L2 cannot influence L1 assignment. An observed material delta does not prove a CVE fix. Missing evidence is unknown, not a negative vote.

## 2. Current code and exact owner interfaces

| Interface | Source entry points | Required test |
|---|---|---|
| Plan / guard | `unified/pipeline.py`: `make_plan`, `prepare`, `UnifiedOptions`, `UnifiedRequest` | Reject foreign/stale run, mismatched binary SHA and wrong orientation |
| Config and cache | `unified/keys.py`: `ir_key`, `result_key`, `changed_inputs`; `compute.py`: `pass_tables_digest` | Changing policy or manual corrections invalidates derived result, not raw/IR |
| Extract / ingest | `unified/extract/` and `unified/ir/ingest.py::ingest` | Strict JSONL header/footer, limits, SHA, valid types and references, no target execution |
| IR reader | `unified/ir/reader.py::IrReader.open`, `FunctionTable` | Read-only, content verified SQLite, bounded blocks/instructions and corrupted-file rejection |
| Source adapters | `unified/sources/ghidriff.py::GhidriffAdapter` and sibling adapters | Artifact/space/older-newer identity, missing source = unknown |
| Ladder | `unified/ladder/engine.py::run_ladder`, `run_ladder_data` and `types.py::Correspondence` | Exact, weak, ambiguous, group, leftover and adversarial cases |
| Fusion | `unified/fusion/arbiter.py::decide`, `to_match`; `unified/registry.py` | Independent evidence classes/components, deterministic conflict handling |
| Semantic changes | `unified/facts/{channels,operands,datamap,layout,eh,anchors,verdict,refacts}.py` | Proof obligations, unsafe benign false negatives, unmodeled cases return review/unknown |
| Child worker | `unified/compute.py::{compute_stage,refacts_stage,run_request}`; `unified/worker.py` | Cancellation, process-tree kill, error type and no partial publish |
| Durable result | `unified/store.py::{write_result,verify_result_dir,read_rows,read_facts}` | Immutable parts, pointer integrity, retention/migration and exact original snapshot stability |
| Read/GUI | `unified/{read_model,panel,cli}.py` and `ui_unified.py` | All decisions/facts/explanations reachable, non-blocking 10k-row tables |

Do not build a replacement matching architecture: the production ladder already includes residual passes P16–P19. Historical plans and module index sections dated 2026-10-14 mislabel newer implementation as merely planned.

## 3. L1 matcher: behavior and unresolved correctness

The implemented pass ladder uses P01 imports, P02 exports, P03 trusted names, P04/P05 exact/masked hashes, P06–P09 progressively weaker keys, P10 compact CFG key, P11 incident call graph, P12–P15 string/import/constant refinement, P16 reference-vector cosine, P17 rare basic-block votes, P18 layout-gap hints, P19 rejection-aware constrained assignment. Strong uniqueness constraints are deliberately favored over recall when input is ambiguous. Accepted anchors propagate to neighboring callers/callees; hubs, very large neighborhoods and ambiguous token buckets have caps.

Current residual limits from R2 code audit: **20 top candidates per direction**, **300 members per blocking bucket per side**, P19 assignment components of **at most 200 nodes per side**, 30 s assignment clock, similarity floor 600/1000 and two-sided margin 50/1000. Dual-direction union may leave more than 20 edges per node. P19 output is soft tier C, **never automatic tier A**. Oversized token buckets abstain instead of forming a dense global assignment.

R2's controlled, synthetic scale results: 100,000 unique-key functions/side: 3.430 s ladder and 250.6 MiB peak process RSS; 100,000 selective-residual functions/side: 31.064 s ladder and 1116.1 MiB. The latter is **not a 100k-row LAP benchmark**—distinctive twin tokens let P16 resolve candidates. A 100k common-only case emitted zero candidates at the blocking cap: safe resource use with reduced recall, not accuracy. On one synthetic 1k generator, 985/992 truth pairs and zero incorrect pairs were found; not held-out Windows precision. Nonisomorphic CFGs can collide on P10 MD keys; do not promote structural-key agreement to a proven 1:1 match.

**R2 integration slice UE-01:** import narrowly scoped changes from draft #131: deterministic native atom sort, preserve the actual B+B independent-class/component witness and strongest opposing atom under evidence caps, reject impossibly small caps, explain manual split/merge groups as analyst corrections rather than automatic B+B, and expose IR-only unmatched functions as W/E-UNKNOWN one-sided observations without falsely declaring “added” or “removed.” Also apply the iterative dominator-tree interval loop/back-edge optimization after independent graph equivalence tests. Add `matching/2` to the *derived result config digest*, keeping `ude/1` and IR key schemas stable, and prove previous cached decisions cannot survive a changed matching policy.

**Remaining L1 research:** structural group `CorrGroup` memberships/reasons are preserved in ladder memory but not fully represented in unified persisted results; design an additive group representation and old-reader test. Calibrate dependence errors per evidence-class pair with genuine truth. Measure candidate recall under reordering, ICF folding, same-body duplicates, renames, inlining, matched neighbors with call graph hubs, real Win32/MSVC compiler changes. Only consider a new global graph optimizer after measuring real residual component sizes and showing a gain over bounded rejection.

## 4. Fusion arbitration and evidence explainability

Ordinal tiers: M=analyst manual, A=strong unique identity, B=corroborating, C=candidate, W=weak external. Native BinDiff/Ghidriff/rz-diff similarity is display/provenance data **not** a percentage probability.

The registry groups dependent evidence by shared symbols, Ghidra extraction, call graph or byte representations. Pool evidence **within** a component. An auto-accepted B+B match must be supported by at least two *independent components* and two *different evidence classes*; two algorithms sharing underlying Ghidra or symbols cannot vote as independent oracles. Conflicting endpoints remain `contested`, including weak opposition, with strength and alternative set explained. Manual M groups are explicit corrections, not a vote of native tools. Absence of any source does not count as opposition.

**R2 defect reproductions (make them regression tests):** eight atoms with identical strength but differing native text emitted nondeterministic order under hash seeds; 70 E-BODY atoms could evict the essential E-DATA witness under the 64-atom cap; an opposing atom could be evicted leaving “contested” without a contest pointer; an empty-support manual N:M group was misexplained; unmatched IR functions were dropped. The draft fixes have local/focused validation, not current-head Windows production acceptance. Tests: input permutations and Python hash seeds; proof witness and strongest opposition survive cap; cap too small raises typed error; manual group text accurate; no invented added/removed rows; foreign RVA rejected; unchanged original snapshot checksum.

## 5. L2 change detection and proof contracts

L2 is based on `facts/channels.py`/IR, operand typing, control-flow/layout, `datamap.py`, exception handling `eh.py`, decompiler text and independent anchor observations. Output is `unchanged`, `cosmetic`, `material`, `review`, `unknown`, `not-applicable`. Named proof rules and their limitations must be stored beside every verdict:

| Rule | Minimum semantic obligation | Explicit blocker examples |
|---|---|---|
| `UNCH/1` | Raw/canonical bytes truly equal AND every actual callee/data target consistent, EH equal/absent, complete deltas | Same bytes at different RVA referencing a different target; missing relocation/target; hidden capped deltas |
| `COS-ADDR/1` | Only typed address changes, mapped same target identity, structure and EH valid | A→B global/callee reference, changed import thunk, unresolved RIP-relative target |
| `COS-LAYOUT/1` | Mapped CFG blocks with polarity-preserving successor bijection and EH-EQ | Then/else swapped with same predicate, dropped guard, handler scope changed |
| `COS-PSEUDO/1` | Canonical decompiler C equal **relative to decompiler observation model**, eligible corroborating channels and EH-EQ when IR exists | EH unavailable with IR; register-only/frame change; changed guard; truncation. Always display as cosmetic-but-reviewable |
| `MAT-ANCHOR` | Semantic/block delta and a second channel which observes **that same** change | Two independent but unrelated differences do not corroborate; unavailable C6 leaves `review` |
| none | Changes without safe proof → `review`; no data → `unknown` | No missing or unsupported input may be converted to “unchanged” |

**Verified main defect hypotheses supported by source inspection:** `facts/verdict.py::_pseudo_proof` checks `ev.eh != 'differs'`, allowing `eh='unavailable'` in IR-backed `COS-PSEUDO/1`, though SPEC-31 requires EH-EQ. Main's `PSEUDO_BLOCKERS` lacks `register-only`. Draft R3 #129 updates both; not yet a proven merged fix. Required red→green tests R3-PC01 and R3-PC08, then proof version/policy cache update, exact-head Linux and Windows native validation.

**Other falsification tests:** unchanged bytes with COFF relocation to another global/callee; changed integer constant but same CFG length; signed versus unsigned comparison; changed pointer/struct-field offset; swapped then/else blocks; genuine branch inversion with correct bijection; same-source security compiler flag changes (/GS, CFG, /guard:cf); added SEH/try scope; inlined/outlined checks; different global-to-global DATA-MAP votes; missing decompiler; register-only, frame-only, alignment/delta cap. For a planted material security mutation, accepted classifier outcome is `material` or `review`—**never** `unchanged`/`cosmetic`. “No observed false benign over 0 evaluated mutants” is not a pass.

R3's 10 compiled GCC/Clang/COFF object comparisons demonstrate byte-same/different-relocation possibilities. They are static object observations, **not** linked Windows PE or PatchTrace end-to-end verdicts. After R1 pilot, run linked PE AMD64 native Ghidra/Ghidriff and `unified run` with source-independent labels, including the pending moved-RVA-call and try-scope cases. Do not add general-purpose SMT to the release path to avoid these proof obligations.

## 6. ProgramIR, persistence and cache integrity

- `program-ir/1` is a verified, read-only SQLite sidecar per binary under `runs/<run_id>/unified/ir/`. Its key covers artifact SHA, extraction producer/version, relevant limits and canonical content; a raw GZF is trusted only after Ghidriff-written program identity and analysis state checks. Never execute a target PE to acquire IR.
- `unified-result/1` is staged beneath `runs/<run_id>/unified/results/` and published only after a manifest/part hash, row/function reference, ownership and guard check. Pointer rows are additive and must not be erased by generic enrichment retention. Crashes leave previous committed results untouched.
- Exact result key covers ordered artifact hashes, source/native snapshots and provenance, manual digest, registry/pass/semantic proof version, IR digests, limits and orientation. A match or proof policy change requires a cache version bump; CVE metadata update may rederive context but must not rewrite Ghidriff primary evidence.
- `IrReader.open` and `verify_result_dir` reject tampered/writable or unowned files. SQLite work belongs to its creating thread; Qt worker thread does not transfer an active SQLite connection. Large input pages and rejected JSON are bounded.
- Preserve multiple analysis runs and analyst corrections. When reopening: compare both artifact hashes, original run ID, raw output digest, unified manifest and match/facts counts, notes and export results. Failed child, cancellation, stopped application, lost sidecar, partial database migration, locked file and backup/restore must not corrupt previous completed runs.

Tests (existing names, verify present before invocation): `test_unified_run_never_mutates_project_snapshot`, `test_unified_rows_survive_enrichment_retention`, `test_old_reader_ignores_unified_kinds`, `test_cancel_keeps_previous_result`, `test_worker_output_is_validated_before_publish`, `test_ir_reader_refuses_writable_or_tampered_file`, `test_same_class_never_corroborates_across_components`, `test_result_key`. Add a regression for policy `matching/2` invalidation and legacy result opening.

## 7. Integration slices and exit criteria

| Slice / owner | Inputs | Executable acceptance and output |
|---|---|---|
| UE-01 — R2 fusion/ladder integrator | main, #131, source/spec diff | R2 focused red→green, full pytest/Ruff + schema, deterministic CI, prior raw/snapshot SHA unchanged |
| UE-02 — R3 proof owner | #129, proof spec/versions | PC01/PC08 tests fail on old and pass corrected; proof cache invalidates; no false benign on negative fixtures |
| UE-03 — live-harness owner | `tools/unified/live_pairs.py`, actual Ghidriff | Fix separate `identical` status and examine raw backend failures; write nonzero labelled outcomes; no fabricated engine rows |
| UE-04 — group persistence owner | `ladder/types.py`, adapter/result model | Roundtrip exact group members, ambiguity, provenance; old-reader compatibility; no false group semantics |
| UE-05 — native extraction/verdict owner | verified PE/PDB and Ghidra/Java | Same-image GZF/analyze content identity where documented, x64 linked PE negative tests, Windows and Linux logs |
| UE-06 — quality integrator | R1 accepted data, UE-03/05 | SPEC-31 G-U1..G-U8 genuine nonempty corpus results, no missing required source/oracle |
| UE-07 — GUI owner | read model and user workflow | Single main window, full proof evidence, keyboard/DPI/10k rows, interruption recovery and reports |

The current global blocker is **UE-03, the real live acceptance harness**, followed by R1 truth admission and UE-05 native proof verification. Do not set `unified/enabled` default true or label L1 precision accepted until the complete gate artifact passes.

## 8. Commands and receipts on a real checkout

```bash
python -m patchtrace unified --help
python -m patchtrace unified run --help
python -m patchtrace unified show --help
python -m patchtrace unified explain --help
python -m patchtrace unified _worker --self-check
python -m ruff check src tests tools
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

For live runs record actual exact versions and tools, OS, commits, SHA-256 of both binaries, source/PDB/IR sidecar hashes, selected flags/sources, command and exit codes, result/manifest digest, measured elapsed/RSS, labelled counts, missing/abstain/false-match rates, CI URL and original logs. A mocked extractor or synthetically created `SecondaryMatchSet` is **unit** evidence only.

**Research still required:** true source-independent correspondence, correlated two-component error rate, N:M truth, linked Windows relocation/EH proof soundness, large real PE performance, native GZF equivalence and decompiler-failure handling. Each is bounded by the above experiments, not an invitation to redesign the matcher.
