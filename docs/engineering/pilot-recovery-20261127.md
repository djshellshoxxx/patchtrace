# Pilot retained-context recovery

Prepared 2026-11-27 America/Vancouver in the isolated `feature/pilot-retained-context-completion-20261127`
worktree. Base: `b0fc9d26cf148d6195ec7c74aa9c0c5a8104b068`, whose Pilot/Leads/report
source matches main `151a3869d055ffcb0c4a76fcdbb2703e56a23451`.

## Goal and boundaries

Complete the unmerged Pilot current-input freshness and retained CVRF feature from
PR #314 (`b41d6631e679ad2777d248fa087ea71582a5bf63`) and its reviewed #321 continuation
(`f851d74d134a09cb9b12013d2c1adba1fde0c24f`). Select only the audited source/test closure.
This feature reads existing project-owned retained context; it does not depend on
PW-01 inventory, fetch sources, open another project in a worker, run an analysis
target, or make native attribution claims. No persisted schema migration is planned.

Keep current `enrichment/storage.py`, `kbcorrelation/context.py`, `wiring.py`,
`saved_scope.py`, acquisition evidence and the newer CSAF transport/cache amendment.
Use the existing held-file primitive, and preserve historical assessments, source
evidence and append-only review events on failure. Historical donor QA remains
attributed to its original source, never to this worktree.

## Incremental plan

1. **Storage boundaries.** Specify and reproduce unbounded retained advisory reads
   and failed staging-creation cleanup. Use bounded held reads with recorded source
   sizes; grant staging cleanup authority only after successful exclusive creation.
2. **Current assessment freshness.** Introduce immutable owner-thread capture and
   share it across stored-result selection, production publication, CLI, desktop
   navigation and report/2. Keep stale history readable while refusing current use.
3. **Retained CVRF context.** Admit bounded source-bound project contexts, select
   heads within each investigation, preserve withdrawal/conflicts, recompute rules
   from recorded fields, and retain CSAF precedence. Wire the same context identity
   into collection and freshness checks together.
4. **Integration qualification.** Run affected current-source tests, generated
   schema drift checks if contracts change, Ruff and preservation checks. Root owns
   independent review, full-application/platform gates and remote publication.

## Initial evidence

A read-only baseline check showed that changing an authored in-memory project
revision from 3 to 4 leaves CLI `_known`, report `_known`, and the publication guard
unchanged. The CLI compares pair/run/raw/KEV only; report compares pair/run/raw.
Current collection reads only CSAF when constructing its CVE universe.

The #314 `native_bundle` test helper lacks saved coverage. Current `saved_scope`
correctly refuses that fixture. #321 already supplies exact authored index coverage;
use that fixture rather than weakening current admission.

Environment is ready: Python 3.12, pytest 9.2.0, Pydantic 2.14.2 and PySide6 6.12.0.
Every test command uses the shared interpreter with explicit `PYTHONPATH=src` from
this worktree; the shared virtual environment is not rebound.

## Slice results

### 1. Storage boundaries

Completed source: `c2cb06de23d48ba0c7c9973ed3541b62ada6e7cc`.

Specifications and authored regression tests added before production changes.
The baseline produced **10 failed, 10 passed in 5.94 s**: seven bounded advisory
read/output failures and three failed-creation cleanup failures. Runtime remained
at the stated base for this red run. After the bounded reader and successful-mkdir
ownership changes, the focused and adjacent store/durability selection passed
**84 tests in 6.75 s**, with no skips. Targeted Ruff and whitespace checks passed.

Commands (shared interpreter, this worktree):

```text
PYTHONPATH=src python -m pytest -q tests/test_advisory_read_bounds.py tests/test_pilot_stage_ownership.py
PYTHONPATH=src python -m pytest -q tests/test_advisory_read_bounds.py tests/test_pilot_stage_ownership.py tests/test_intel_storage.py tests/test_pilot_store.py tests/test_pilot_store_durability.py
```

Raw logs and JUnit are retained in the task evidence directory as `storage-red`
and `storage-green`. Current acquisition/project storage and newer CSAF
transport/cache limits were not changed. Native Windows read sharing remains
part of root's final platform gate.

### 2. Current assessment freshness

Completed source: `9c187dd9c1fb91ecd5f53e0c969839f644ee62e5`.

Specifications and current-store CLI/desktop/report controls added before source changes.
The real-store UI fixture now retains the advisory it claims to use, following current
evidence contracts. At slice 1 source, the three new regression files produced
**34 failed, 10 passed in 8.34 s**. They reproduce changed pairing/revision, replaced
or withdrawn advisories, corrupted required sources, KEV changes, late publication,
stale CLI history, unsafe historical navigation and stale report leads.

An initial integration run produced **58 failed, 199 passed in 29.75 s** because
an incomplete local source transfer omitted the unchanged desktop rendering method.
The existing method was restored exactly, without changing its behavior. After that
correction, the focused and adjacent selection passed **257 tests in 32.43 s**, with
no skips. Targeted Ruff and whitespace checks passed.

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_pilot_current_inputs.py tests/test_ui_leads_freshness.py tests/test_report2_current_leads.py
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_pilot_current_inputs.py tests/test_ui_leads_freshness.py tests/test_report2_current_leads.py tests/test_pilot_cli.py tests/test_ui_leads.py tests/test_pilot_store.py tests/test_pilot_store_durability.py tests/test_report2_adapters.py tests/test_report2_cli.py
```

Raw logs and JUnit are retained as `freshness-red`, `freshness-integration-failed`
and `freshness-green`. Production reads and publication now use the same immutable
capture; desktop navigation rechecks it at activation. Stored history and review
events remain readable, and report/2 records omitted stale leads as unknown.
The ordinary freshness capture comes from `328a3a36`; retained-CVRF composition
will be added with its matching collector in slice 3.

### 3. Retained CVRF context

The final reviewed donor specification and four current-store regression files
were added before runtime changes. Module/spec indices register the bounded
capture and pure composition seam. Current saved-scope admission remains unchanged;
the authored native CVRF fixture includes its exact captured index coverage.
The context/current-input/port selection produced **60 failed, 57 passed in 12.43 s**
at slice 2 source. The real authored KB journey returned exit 4 because Pilot did
not read its CVRF-only CVE; retained-context replacement/withdrawal also failed to
invalidate results, late publication or report export. Other failures pin the
missing capture module and structural port. The additional metadata-budget and
SQLite storage-class suites were restored before code changes and run after the
module existed; they were not counted as executed red tests.

After integration, the four retained-context suites and key/port controls passed
**152 tests in 13.52 s**, with no skips. Their runtime is the reviewed #321 closure,
composed with the current shared storage and KB contracts. CLI and desktop stale
messages additionally name the retained KB context and project revision in plain
language. No persisted contract or generated schema changed.

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_pilot_kb_context.py tests/test_pilot_kb_current_inputs.py tests/test_pilot_keys.py
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_pilot_kb_context.py tests/test_pilot_kb_current_inputs.py tests/test_pilot_kb_metadata_budget.py tests/test_pilot_kb_storage_classes.py tests/test_pilot_keys.py
```

Raw logs and JUnit are retained as `cvrf-red` and `cvrf-green`.

### 4. Integration qualification

The complete affected selection passed **2,058 tests in 110.45 s**, with no skips.
This includes all Pilot and Leads tests, all report/2 tests, advisory sidecar and
storage tests, current KB context/field provenance/saved-scope/advisory-admission
tests, KB schema parity and specification registration. Counts overlap the slice
results above and must not be added together.

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_pilot*.py tests/test_ui_leads*.py tests/test_report2*.py tests/test_advisory_read_bounds.py tests/test_intel_storage.py tests/test_kbc_context.py tests/test_kbc_card_context_sources.py tests/test_kbc_saved_scope_validation.py tests/test_kbc_saved_scope_flow.py tests/test_kbc_saved_scope_revision_identity.py tests/test_kbc_advisory_source_admission_20261120.py tests/test_kbc_schemas.py tests/test_spec_registry.py
PYTHONPATH=src python -m ruff check src tests tools
git diff --check
```

Whole-tree Ruff and whitespace checks passed. Logs and JUnit are retained as
`integration`. Preservation checks show no changes from the base to
`enrichment/storage.py`, `kbcorrelation/context.py`, `wiring.py`, `saved_scope.py`,
`card_provenance.py`, `owned_publication.py` or `intelligence/csaf/transport.py`.
The newer CSAF race-safe cache amendment remains intact. Independent read-only
review has begun against the stable runtime/test source.

### Review correction: strict retained JSON — 2026-11-27 America/Vancouver

Independent review of `f7337f5f5cbb6f27bddbd8d7756f0381d3f526cb` found that the
shared multi-row reader and Pydantic both accepted duplicate object members by
keeping the last value. A matching stored checksum did not establish unambiguous
JSON. Two independent root/nested controls failed while six adjacent controls
passed. The maintained spec and four duplicate-member controls (including escaped
key spellings), plus a valid-formatting control, were added before the correction.
Together with the unchanged independent controls, the red run produced **6 failed,
7 passed in 1.39 s**.

The bridge now calls the existing strict JSON decoder on the original bounded
`body_json` during structure admission, before semantic model interpretation.
Malformed bodies become unavailable with the existing fixed warning; no retained
row is rewritten. The shared `EnrichmentStore` is unchanged. The correction and
all retained-context/budget/storage-class/current-input/report checks, including
the original independent controls, passed **148 tests in 13.69 s**, no skips.
Targeted Ruff and whitespace passed. Logs/JUnit: `json-admission-red` and
`json-admission-green` in the existing evidence directory.

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests python -m pytest -q tests/test_pilot_kb_json_admission.py ../pilot-independent-review.py
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests python -m pytest -q tests/test_pilot_kb*.py tests/test_pilot_current_inputs.py tests/test_report2_current_leads.py ../pilot-independent-review.py
```

Independent review also found an asynchronous desktop ownership issue: a newly
loaded receipt can precede replacement of the displayed model, letting freshness
check the new receipt while an action uses an old row. Its correction follows
below; publication remains held until re-review. The strict-JSON correction was
committed as `fe36e09fe5010ac4ac49268f67f511864faa71b8`. The independent reviewer
approved that exact bridge source after 83 adjacent/independent controls and the
five maintained new controls passed separately, with no skips.

### Review correction: displayed model ownership — 2026-11-27 America/Vancouver

The independent deferred-build regression and six maintained controls produced
**7 failures in 2.26 s** on the strict-JSON corrective source. They demonstrate
function-button/direct/evidence-line/anchor activation against an old displayed
model after loading a newer receipt, navigation without a receipt after failed
reload, and late old-model filtered rows replacing current rows. A further
late-build-after-failed-reload control failed separately in **1.25 s**. The
displayed-result ownership specification and all controls preceded source edits.

Navigation now requires that the loaded receipt own the displayed assessment.
Missing/invalid receipts and pending replacement models produce plain refusal
messages; no freshness result for an old view is written onto the fresh receipt.
Model-build callbacks check receipt ownership before installation. Filtered-row
callbacks retain their originating model and cannot overwrite another model's
table; a replacement build also cancels older row work. Matching fresh models
resume navigation, while historical explanations remain copyable.

The focused UI and ordinary/retained-context freshness selection, including the
unchanged independent UI regression, passed **130 tests in 17.00 s**, no skips.
Whole-tree Ruff and whitespace checks passed, and all seven protected common
modules remain byte-identical to the original base. Logs/JUnit:
`ui-ownership-red`, `ui-late-build-red` and `ui-ownership-green`.

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests python -m pytest -q tests/test_ui_leads_display_ownership.py ../pilot-independent-ui-review.py
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests python -m pytest -q tests/test_ui_leads_display_ownership.py tests/test_ui_leads_freshness.py tests/test_ui_leads.py tests/test_pilot_current_inputs.py tests/test_pilot_kb_current_inputs.py ../pilot-independent-ui-review.py
```

## Acceptance state

All three implementation slices passed their affected-source qualification.
Both independent-review findings now have separate spec-first corrections and
green focused controls. Strict JSON has independent approval; desktop ownership
re-review is pending. Full current-head, native Windows,
packaging and hosted gates remain with the integration owner. No remote publication or live fetch occurred in
this isolated worktree. Authored fixtures are not live-provider, manual desktop or
vulnerability-attribution evidence. The source does not claim total store
responsiveness or upstream freshness/authenticity of retained CVRF records.

## Final independent approval and common-base integration

Independent review approved `30ca3f90fd605cce3bb27bd6d216610defc1b048`, tree `11701339b9276ee6cfcd93fbe84a6cb2f5219efc`, after both reproduced findings were corrected. Final independent selections passed 76 and 34 tests without skips; these overlapping lanes are not added to the author counts. The seven protected common modules remain base-identical.

Root merged the shared packaged-version qualification follow-up at `5b44dc5d3578caf459b33994348e81b7b387466e`, tree `b6a9baa2c44582b094593bf1e193dce2dd7319df`, preserving both evidence records and adding only the common packaging test/documentation correction. The complete final 50-module affected selection, now including both review corrections, passed **2,070 tests with zero skips in 94.44 seconds**. Exact command/source and console output are retained under `docs/engineering/evidence/pilot-recovery-20261127/`.

Implementation review and affected integration are complete. The full application and current published-head hosted/native/platform gates remain unfinished; no live-source accuracy, Windows desktop, release or L1/L2/L3 completion is inferred from authored tests.
