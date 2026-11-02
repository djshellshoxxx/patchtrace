# Unified synthetic fixture handoff and remaining gaps

## Consolidation status — 2026-11-02

This reconciliation compares [PR #90](https://github.com/djshellshoxxx/patchtrace/pull/90)
at `941c617b6854291e2448cad6d7d5710a24a8543d` with landed main
`ce8c65bf41541cf6adb52289d2a530ce2817a53a` and the immutable consolidation candidate
`ca80cc0f310ad1a82174cd17ee1fa8443b016b73`. It covers the PR's five changed paths.

The two collection/fixture defects in the original handoff below are no longer
current blockers in either examined snapshot:

| Historical PR #90 change | Observed in both snapshots |
|---|---|
| Remove `test_unified_synthetic_pe-2.py` and `test_unified_fixture_gate_u6-2.py` | Both duplicate paths are absent. |
| Correct canonical `test_unified_fixture_gate_u6.py` | Byte-identical to PR #90: blob `3ae05b9cc009502453333236dbb371239e59616e`; independent simulated project ids and case metadata are retained. |
| Add the targeted Hypothesis health-check suppression | Canonical `test_unified_synthetic_pe.py` retains only `HealthCheck.function_scoped_fixture` suppression. Compared with PR #90, it also splits the imports and binds `timestamp`/`padding` by keyword in `@given`. |
| Preserve the 36-line handoff continuation | Previously absent in both snapshots; restored below from the exact PR #90 head. |

Fresh focused validation on candidate `ca80cc0`: **8 passed in 1.95s** with
`QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q
tests/test_unified_synthetic_pe.py tests/test_unified_fixture_gate_u6.py`.
Whole-repository `python3 -m ruff check src tests tools` and `git diff --check`
also passed for this documentation reconciliation. No target image was executed.

The original handoff and the continuation below are **historical records**:
their `UNVERIFIED`, branch-presence, and pending-validation statements describe
the October 16 delivery. They do not reverse the current-path observations above.
The broader “work not reached” inventory has not been recertified by this bounded
comparison. These fixture results do not establish G-U3 oracle parity, G-U1..G-U8
live acceptance, complete Linux/Windows equality, performance budgets, or frozen
Windows acceptance; those remain separate checks under
[SPEC-31 evaluation](../../docs/specs/unified-engine/08-evaluation.md).
This note preserves the missing evidence and records the represented functional
delta; it does not certify full PR #90 absorption, integration acceptance, or closure.

## Original handoff — 2026-10-16

Status: UNVERIFIED. This is a partial Prompt 3 delivery stopped at 25 added files.
No Python, pytest, Ruff, assembler, decoder, generated target, external engine, benchmark or schema generator
was executed. Repository reads and writes used GitHub APIs. No test-pass claim is made.

All changes are new files below tests/. Existing source, tests, tools, workflows and configuration were
not edited. Only chatgpt/unified-fixtures-1 was written. The prompt's requested research gap file is placed
here because the direct-write instruction limits additions to tests/ and tests/fixtures/.

### Blocking integration corrections (historical)

The no-edit restriction also prevented correcting two files after their first commit. Complete replacement
variants are supplied with the requested -2 suffix:

| Original new file | Corrected new variant | Static defect in original |
|---|---|---|
| tests/test_unified_synthetic_pe.py | tests/test_unified_synthetic_pe-2.py | The given-decorated test deliberately reuses tmp_path, but its settings omit HealthCheck.function_scoped_fixture suppression. A normal Hypothesis run is expected to reject the test before examples. The replacement explicitly suppresses only that documented check. |
| tests/test_unified_fixture_gate_u6.py | tests/test_unified_fixture_gate_u6-2.py | mutation_doc assigns every case to project p, so all cases share one lineage. A claimed passing script instead returns insufficient-data. The replacement creates distinct simulated project/lineage ids through the existing label_doc helper. |

Both originals remain in the branch to obey the no-edit/no-delete rule. An ordinary full pytest discovery
will still collect those originals. The integrator must replace or exclude them before this draft is ready.
Do not mistake the corrected variants for evidence that either version has run.

### Delivered behavior and boundaries

assembler.py emits only bounded authored bytes. It supports register/immediate MOV, ADD and CMP,
near conditional jumps, direct CALL/JMP, RIP-relative LEA, RET, single-byte NOP runs, table-relative
switch dispatch and relative thunks. It resolves local and external labels after layout. It is not a
general assembler or disassembler. RSP/RBP and extended registers are intentionally unsupported.

synthetic_pe.py reuses tests/pe_builder.py for headers/imports and emits function layout, custom sections,
named/ordinal imports, correct per-function export targets and .pdata leaf extents. It validates authored
names and count/size bounds. The unwind records describe no stack adjustment or saved registers;
do not use these records to claim valid non-leaf Windows ABI behavior. Images are data only.

pairs.py has explicit unchanged, moved, renamed, inlined, split, merged, constant-changed,
condition-changed, added-check and removed-code relations. N:M truth is not flattened to a false 1:1 label.
nuisance.py authors register reallocation, independent instruction scheduling, polarity-preserving block
reordering, NOP padding and jointly shifted relative calls. They are compiler-noise analogues, not
claims about output of a named compiler or version. No target code is executed to establish equivalence.

The G-U1..G-U7 modules call the existing tools/unified evaluators. Scripted good and broken engines are
explicit outcome generators, not mocks counted as live runs. G-U2 retains the pending physical factory
classes; G-U3 retains the BinDiff oracle blocker. All sample hashes/tool banners inherited from
unified_s6_helpers are fictional test constants. They are never recorded as downloaded artifacts.
Paired bootstrap diagnostics use the existing deterministic whole-lineage implementation. The
statistical plan distinguishes branch coverage from real statistical power.

The golden exercises the real result writer and read model and compares a small stable public
projection. It is authored by hand, marked UNVERIFIED and never rewritten automatically by tests.
The timing helper measures small fixture construction only. It cannot preempt a hung operation;
a test-runner deadline must enforce the requested 30-second per-file ceiling during validation.

### Work not reached

1. A hermetic PE-byte-to-ProgramIR adapter for these generated images. No new product API is assumed.
   Existing seams are VerifiedArtifactReader.open_path, ir.pe_tables.read_pe_tables, the existing
   extraction/ingest code and tests/unified_ir_builder.py. The current pair tests verify authored byte
   layout and relation bookkeeping; they do not run the real ladder or facts engine over the images.
   A complete integration must preserve actual extraction provenance and must not invent disassembly.
2. Physical PE generators for every G-U2 registry class: bound, signedness, callee-swap, field-offset,
   global-swap, index-swap, branch-swap and buf-resize need dedicated precise encodings and truth tests.
   The simpler supplied pair kinds are not substitutes for those class-specific fixtures.
   moved-rva-call and try-scope remain distinct pending physical cases. The generic engine outcome
   scripts do not establish any of these classes on emitted PE bytes.
3. A real compiler-independent IR fixture path exercising P00-P19, target consistency, EH-EQ and
   MAT-ANCHOR on all generated mutations and nuisance variants, including imperfect/abstaining engines.
4. Complete manifest-byte golden parity under repetition, input permutation and swapped orientation.
   Current G-U4 tests use existing outcome row-digest semantics and simulated platforms. They do not
   establish Linux/Windows equality or compare complete manifests after removing created_utc.
5. Expanded read-model goldens for every state, hostile names, native source cells, ambiguous and
   one-sided groups, partial/stale precedence, provenance details, collapsed filters and all nine
   ordering groups. Existing repository tests cover portions; this addition supplies a small golden only.
6. A proper paired G-U7 excess-error statistic e_BB - 2*e_A and interval with observed tier-A errors.
   The added diagnostic happens to use a zero-error tier-A script, where the factor of two is numerically
   invisible. It is not a test of the full ratio/paired-bound formula. The real evaluator currently gates
   point rates while reporting a class-rate CI; any policy change needs an explicit spec decision.
7. Bounded fresh-process timing of 10k, 60k and 250k real IR plus largest Tier R pair, measured RSS,
   facts/read-model budgets, exact UI data() call counts, extraction cost and Windows frozen runs.
   The added G-U5 test exercises the evaluator using scripted measurements, never measured performance.
8. Actual mutation-tool runs proving which product-code mutations each fusion property kills.
   The properties target four specific mutant behaviors but no external mutation runner was executed.
9. Focused pytest, Ruff, independent byte decoding, parser compatibility and runtime-budget verification.
   Python 3.12 import behavior, Hypothesis installation and filename collection of -2 variants also need
   verification. No dependencies or pytest settings were changed to make these tests collect.
10. G-U8 remains outside the requested G-U1..G-U7 evaluator additions. The existing snapshot-integrity,
    network-audit, script-AST, old-reader, schema, accessibility and frozen-smoke checks remain required.
    No release flag or gate status was changed.

### Review and validation order

First integrate the two corrected variants and remove/exclude the two known defective originals.
Then inspect all new files and independently decode the authored instruction encodings without executing
the targets. Run focused pytest and Ruff on the new files. Use a runner-level per-file timeout; report
actual duration and failures. Check that the golden still matches after real collection. Broaden to
existing PE, fusion, gate and read-model tests only after focused failures are resolved. Keep Windows
and live-engine checks separately marked not verified. Do not generate or commit Microsoft binaries,
PDBs, downloaded Winbindex labels or GPL/AGPL implementation code.

Integrator-only request: confirm appropriate LF attributes for these JSON/Markdown/Python fixtures
without modifying existing repository attributes during this task.

The continuation below is preserved as written in
[PR #90's handoff](https://github.com/djshellshoxxx/patchtrace/blob/941c617b6854291e2448cad6d7d5710a24a8543d/tests/unified_support/fixture-gaps.md).
Its branch and verification statements are historical; the November 2 status above applies to the examined snapshots.

## 2026-10-16 continuation: canonical test collection repairs (PR follow-up)

The two **known integration blockers** listed near the top have been addressed on the
isolated branch `chatgpt/unified-fixture-collection-fix-20261016`, based on PR #71
head `161a88345efc6484f4d7809fc6963a0193bd0057`.
The complete corrected `-2` text was copied into its original canonical pytest
filename, then the ignored `-2` duplicate deleted. Exact replacements:

- `test_unified_synthetic_pe.py` now uses the Hypothesis
  `HealthCheck.function_scoped_fixture` suppression for its explicitly reused
  `tmp_path`; other health checks are still enforced.
- `test_unified_fixture_gate_u6.py` now creates distinct simulated project
  lineages through `label_doc` and preserves case metadata for each of its
  scripted examples.

This is a **collection/fixture correctness repair only**; production unified
engine behavior, gate thresholds, contracts, source code and live acceptance
are unchanged. The original superseded files no longer exist on this branch.
They still exist on PR #71 until this fix is merged into that source branch.

Verification remains **PENDING** until focused tests, `ruff`, and current-head
Linux/Windows CI run. Start with:

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_unified_synthetic_pe.py tests/test_unified_fixture_gate_u6.py
python -m ruff check src tests tools
```

Then test all unified synthetic fixture files and the repository-wide suite.
Review expected G-U3 oracle blockage and fixture-only evidence separately.
Merge the fix branch into PR #71 only after its own current-head checks pass.
PR #71 remains a draft and must not be merged into the integration branch
until full checks, synthetic PE/gate parity and related acceptance pass.
Do not mark G-U1..G-U8 live gate acceptance from scripted fixtures.
