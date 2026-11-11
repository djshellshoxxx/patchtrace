# Unified synthetic fixture handoff and remaining gaps

Status: UNVERIFIED. This is a partial Prompt 3 delivery stopped at 25 added files.
No Python, pytest, Ruff, assembler, decoder, generated target, external engine, benchmark or schema generator
was executed. Repository reads and writes used GitHub APIs. No test-pass claim is made.

All changes are new files below tests/. Existing source, tests, tools, workflows and configuration were
not edited. Only chatgpt/unified-fixtures-1 was written. The prompt's requested research gap file is placed
here because the direct-write instruction limits additions to tests/ and tests/fixtures/.

## Blocking integration corrections

The no-edit restriction also prevented correcting two files after their first commit. Complete replacement
variants are supplied with the requested -2 suffix:

| Original new file | Corrected new variant | Static defect in original |
|---|---|---|
| tests/test_unified_synthetic_pe.py | tests/test_unified_synthetic_pe-2.py | The given-decorated test deliberately reuses tmp_path, but its settings omit HealthCheck.function_scoped_fixture suppression. A normal Hypothesis run is expected to reject the test before examples. The replacement explicitly suppresses only that documented check. |
| tests/test_unified_fixture_gate_u6.py | tests/test_unified_fixture_gate_u6-2.py | mutation_doc assigns every case to project p, so all cases share one lineage. A claimed passing script instead returns insufficient-data. The replacement creates distinct simulated project/lineage ids through the existing label_doc helper. |

Both originals remain in the branch to obey the no-edit/no-delete rule. An ordinary full pytest discovery
will still collect those originals. The integrator must replace or exclude them before this draft is ready.
Do not mistake the corrected variants for evidence that either version has run.

## Delivered behavior and boundaries

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

## Work not reached

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

## Review and validation order

First integrate the two corrected variants and remove/exclude the two known defective originals.
Then inspect all new files and independently decode the authored instruction encodings without executing
the targets. Run focused pytest and Ruff on the new files. Use a runner-level per-file timeout; report
actual duration and failures. Check that the golden still matches after real collection. Broaden to
existing PE, fusion, gate and read-model tests only after focused failures are resolved. Keep Windows
and live-engine checks separately marked not verified. Do not generate or commit Microsoft binaries,
PDBs, downloaded Winbindex labels or GPL/AGPL implementation code.

Integrator-only request: confirm appropriate LF attributes for these JSON/Markdown/Python fixtures
without modifying existing repository attributes during this task.
