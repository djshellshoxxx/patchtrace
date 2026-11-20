# Strings forced-publication recovery — 2026-11-19

## Scope and uniqueness

Baseline: `f2458aae22ea6177be64cfc2fb439a79950f00ff` (PR #322). Donor:
`6096e64d4e7b8f0ecc6af884f7d220e07790d85a` (PR #320), principally the
publication work retained by `bc7eb632` and `1341dc21`.

The fetched branches contain five distinct `src/patchtrace/strings/export.py`
blobs. The baseline blob `d31789af27098afb2191aeda4eaf1e2d2bd0b63e` closes
the staged source before pathname replacement; no successful-force source or
parent guard exists. The donor blob `3896fce5d973f93a1149d59da920471a8fa0ed9d`
contains held-source checks and rooted operations absent from the baseline.
The three older alternatives do not provide those behaviors. Classification:
**PARTIALLY UNIQUE — EXTRACT**, not whole-branch adoption.

The extraction deliberately preserves the baseline's verified-anchor creation
guards and typed `NotImplementedError` handling, which a wholesale donor copy
would lose. It does not import the donor's separate streaming publisher or
Strings comparison workflow. Existing immutable evidence publication remains
no-replace by default. No persisted JSON schema changes.

## Resulting behavior

- Linux force writes and verifies an anonymous source before creating its
  exclusive temporary link. A sync-time source-name replacement is impossible.
- Both rename arguments use the held original directory. Replacing the selected
  parent cannot redirect writes or cleanup into the substitute directory.
  An observed parent change refuses the export receipt.
- Source identity, type, metadata, bounded byte digest and post-rename
  destination identity are checked. Observed source substitution or in-place
  modification cannot produce a false successful digest receipt.
- Windows force uses the existing held native source and rooted directory with
  an explicit replacement flag. Force cannot be combined with immutable-content
  reuse. Portable native-call assertions are not native filesystem acceptance.
- Cleanup closes only owned handles, preserves the primary operation exception,
  and never deletes a mutable Linux stage name. Before the Linux source is
  linked, a partial write leaves no named residue. After linking, a failure may
  leave owned or foreign stage bytes for inspection.
- The shared Linux no-replace publisher also verifies the held bytes after
  linking. Verification reads are bounded by the intended length plus one byte,
  including a source that grows during verification.

## Known residual blocker

**Linux final source-name substitution remains open.** Linux's final rename here
still identifies its source by name. A writer can substitute that name after
the final pre-rename check; foreign bytes can become visible before the
post-rename identity check reports failure. The regression
`test_final_linux_source_race_is_reported_without_deleting_foreign_bytes`
demonstrates this outcome. There is no rollback or prior-target-preservation
claim for this interval. Disabling Linux force would change the existing
overwrite capability rather than provide a compatible implementation.

These checks also do not lock a successfully published Linux file against later
external edits. Native Windows source/parent/reparse behavior still needs its
own platform qualification. This slice is not sufficient for release promotion.

## Evidence and verification

The [evidence archive](evidence/strings-force-recovery-20261119.zip) and
[manifest](evidence/strings-force-recovery-20261119-manifest.json) preserve
unaltered command outputs, JUnit and hashes of the tested source files.

| Receipt | Result | Interpretation |
| --- | --- | --- |
| Baseline with recovered force/integrity controls | 30 failed, 1 passed, 1 skipped | Includes behavioral reproductions and controls for APIs absent from baseline; not 30 distinct vulnerabilities. |
| Initial corrected focused selection | 58 passed, 1 skipped | Ownership, native-call, byte-integrity, anchor and capability controls. |
| Original named-stage fixture selection after implementation | 14 failed, 16 passed | Retained evidence: fixtures assumed `mkstemp` and absolute pathname rename; they required adaptation to anonymous and dirfd ownership. |
| Adapted complete focused selection | 88 passed, 1 skipped | Preserves cancellation, I/O failure, foreign-stage and descriptor-lifetime assertions. |
| Final affected integration selection | **264 passed, 3 skipped in 9.64 s** | Adds final-parent substitution, missing-capability, CLI, offscreen Strings Qt and shared-publisher caller coverage. Counts overlap earlier selections. |
| Whole-tree configured Ruff | **Passed** | `python -m ruff check src tests tools`. |

All three final skips are explicit native Windows ownership/reparse acceptance
tests. No skipped case is credited as passed. No live binary tool, native
Windows, full-suite or release acceptance claim is made here.

Reproduce final affected tests from the repository with its pinned development
environment:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_strings_export.py tests/test_strings_export_publication.py \
  tests/test_strings_export_force_cancellation.py tests/test_strings_export_force_cleanup.py \
  tests/test_strings_export_force_ownership.py tests/test_owned_publication_replace.py \
  tests/test_owned_publication_integrity.py tests/test_strings_export_source_ownership.py \
  tests/test_owned_publication.py tests/test_strings_cli.py tests/test_ui_strings_panel.py \
  tests/test_ui_strings_run.py tests/test_research_qualification_winpairs_publication.py \
  tests/test_tier_r_output_persistence.py tests/test_tier_r_credit_completion.py
python -m ruff check src tests tools
```

Independent review and integration are assigned to the coordinator. The root
task ledger should retain the Linux race, native Windows checks and unrelated
empty-export metadata work as open.
