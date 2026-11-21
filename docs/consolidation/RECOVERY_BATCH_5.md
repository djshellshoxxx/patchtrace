# Recovery batch 5: acquisition completion identity

## Scope and disposition

This follow-up recovers the bounded acquisition repair from
`c3868d8335a8f32f676905032dc1a6d0e9f22fd6`, retained on
`codex/essential-project-safety-20261031` (PR #148). It is based on local
integration commit `3cde10aec12418f92b34a0f5a90c79c1785c88d9`, separately from
the frozen PR #322 candidate qualification. It addresses the acquisition
identity finding in issue #118 without claiming that the entire issue, source
branch or acquisition provenance specification is complete.

The recovered behavior preserves the product selected for the approved plan,
checks freshly inspected bytes against that plan before mutations, and records
the relationship between the previewed index pair and the conservative local
pair. The source pair ID and local pair ID remain distinct. Full index proposal,
release-window and source-entry persistence remains open.

## Existing source, rather than rediscovered implementation

The frozen retained-branch census was reused. A bounded object scan of its 161
retained heads found 107 with `kbcorrelation/service.py`, representing nine
unique service blobs; 54 heads predate that path. Four service variants on 14
heads contain this acquisition binding. The census itself was not changed.

| Inspected ref | `service.py` blob | Acquisition binding |
| --- | --- | --- |
| Main `fdc2696c23bdbfe7668348f25e3b336ce33039f7` | `d40b4b2a12c24275604611eae6b97c34495376e1` | Absent |
| PR #319 `a56ab13aaf9916fc12bea70ba1494075991b7f09` | `d40b4b2a12c24275604611eae6b97c34495376e1` | Absent |
| PR #320 `188b4962e527c82b29e599f75cd952029b749348` | `44f187d5cd50a39ced5084de8f4b668d0792521f` | Absent |
| Original recovery `c3868d8335a8f32f676905032dc1a6d0e9f22fd6` | `b48f0f10888c8a301457f315a2f54cb3744fc5dc` | Present |

The original source also supplies the acquisition completion specification and
five regression cases. Later retained ports
`639962f1c0761bf171334eed2a09f3bb0cc08f89` and
`37a6fed01e9bcf910f6ae1dd154fd9387f1b6a0d` attribute the same work to that
source. Neither main nor the inspected PR #319/#320 heads includes it by ancestry.
PR #320's additional held-input work leaves this acquisition callback on the
ordinary manual import path; it does not supply the missing plan/scope binding.

## Reproduced failures

An external read-only audit first exercised the current source through the real
CLI, workspace store and project creation, using authored synthetic PE bytes, a
fake HTTP opener and a socket-denial fixture. No target binary was executed.
The first two controls failed; an expanded replay produced four failures in
1.29 seconds:

1. With no prior product selection, the previewed AMD64 product became a null
   selected scope in both the committed investigation and project context.
2. With a previously selected ARM64 product and an explicit AMD64 acquisition,
   final import reused ARM64 and rejected the valid AMD64 files.
3. With the correct AMD64 product already selected, completion still retained
   neither the source pair ID in its response nor a persisted acquisition binding.
4. Replacing a staged file after the acquisition port reported verification
   caused different bytes to be imported successfully under the approved plan.

The authored newer-file example approved SHA-256
`4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168`
but accepted replacement SHA-256
`698f8d9e26a83c9379e7c44041af156cea9dae973d045a0a4ba0ad3d68aa85f0`
with exit 0. The bridge checked the port's recorded digest, while ordinary manual
import independently accepted the newly inspected bytes. Final import now
compares those inspected digests with the captured plan before changing state.

The isolated recovery's seven controls then reproduced five failures and two
passes on the unchanged runtime. The added cases cover an already matching
product and replacement of either side. The two passing controls establish that
existing revision-change refusals remain valid.

## Adaptation to the current implementation

The runtime recovery is confined to `src/patchtrace/kbcorrelation/service.py`.
It preserves the public `import_pair` callback and passes an optional internal
`_acquired` tuple containing the captured revision and immutable acquisition
plan. This keeps the existing post-guard lifecycle instrumentation effective.

Inside the existing workspace lock, completion checks the investigation/revision
and exact ordered inspected hashes. It validates the planned scope against the
investigation and admitted advisory index, then commits that scope when needed.
The existing manual pair construction, approval and attachment remain in use.
The acquisition response adds `source_pair_id`, `verified_pair_id` and `scope_id`.
An append-only `acquisition-pair-binding` decision records both pair IDs, plan SHA,
scope and ordered binary SHA-256 values.

The newer cancellation checkpoints, `_acquire_owner` checks, expected source
snapshot, saved search validation and admitted-index reuse remain intact.
The saved search describes the original advisory document selector; changing to
the explicitly approved product does not replace that coverage. Source records
added after admission stay excluded from the captured context.

The verified local pair remains grade B/tier E, with user-asserted lineage and an
unverified fix boundary. This change does not authenticate the index, establish a
vulnerability repair, or make the index and manual pair IDs interchangeable.
No Pydantic model, database schema, identity algorithm, transport or GUI changes
are included. The specification amendment preceded the runtime change.

## Verification

| Check | Observed result |
| --- | --- |
| Seven retained/expanded controls against unchanged runtime | 5 failed, 2 passed in 2.46 seconds |
| Recovered controls plus existing acquisition CLI and lifecycle tests | 43 passed in 3.10 seconds |
| Thirteen affected test files, including manual/product-only callers, saved scope, E0, repair and schemas | 255 passed in 33.14 seconds |
| Whole-tree `ruff check src tests tools` | Passed |
| `git diff --check` | Passed |
| Independent read-only review of actual runtime diff and modern ownership/admission/repair boundaries | No substantive blocker found |

The 255-case command used the isolated editable environment verified with
`python -I`, `PYTHONDONTWRITEBYTECODE=1`, `QT_QPA_PLATFORM=offscreen`,
`-p no:cacheprovider`, a dedicated `/tmp` fixture directory and JUnit output.
Its files were:

```text
tests/test_kbc_acquire_pair_binding.py
tests/test_kbc_acquire_cli.py
tests/test_kb_acquire_lifecycle_20261105.py
tests/test_kbc_service.py
tests/test_kbc_selection_guard.py
tests/test_kb_investigation_service.py
tests/test_kbc_saved_scope_flow.py
tests/test_kbc_saved_scope_validation.py
tests/test_kbc_saved_scope_revision_identity.py
tests/test_kb_product_start_20261106.py
tests/test_kbc_e0_e2e.py
tests/test_kbc_recovery.py
tests/test_kbc_schemas.py
```

Durable workspace receipts are `verification/acquisition-binding-{red,green,callers}.log`
and matching XML files. The callers XML SHA-256 is
`d93ea227689d29f081a759cd737eed79171e4dac5aa0a332d1e90824e91d06b6`.
The initial read-only reproduction and observations are retained separately as
`verification/issue118_pair_review.py`, `issue118-pair-review-final.{log,xml}`
and `issue118-pair-*.json`. Completed passing temporary fixtures were removed;
failed reproduction inputs and durable receipts were retained.

These results qualify authored offline behavior, real local persistence and
offscreen caller integration. They do not establish live symbol-server
compatibility, native Windows acceptance or a complete suite pass for this
follow-up. The frozen PR #322 qualification belongs to its own source head.
No remote branches, pull requests or issues were changed by this recovery.
