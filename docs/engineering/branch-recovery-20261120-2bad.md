# Branch recovery census and independent review — 20 November 2026

This worker inspected exact integration candidate
`67f7e08ea9bee61653f8ab5ad66048d3e7141810` (PR #344) against main
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`. The companion
[machine receipt](branch-recovery-20261120-2bad.json) contains every observed
remote branch name, exact head, ancestry and nonmerge patch comparison.
No remote ref was modified. This document is supporting evidence for the
existing task ledger, not another task ledger.

## Ref coverage and duplication controls

| Classification | Branches |
| --- | ---: |
| Topic heads contained in main | 128 |
| Additional heads contained in the integration candidate | 27 |
| Nonancestor heads with no unmatched nonmerge patch | 16 |
| Heads retaining unmatched patches | 181 |
| Main and exact integration candidate | 2 |
| **Total remote branches** | **354** |

There are 59 local tags after the parent's origin refresh. Compared with the
generation-30 census, 13 branch names were added and none of its retained
branch heads moved. The candidate is a descendant of main. A patch-equivalent
head still needs semantic review; an unmatched historical patch may already be
implemented by a later, different change. These counts authorize neither
deletion nor wholesale merging. This worker did not independently refresh all
PR metadata, CI or releases.

Three old donor scopes are already implemented in the current candidate:

| Retained donor | Reviewed behavior | Disposition |
| --- | --- | --- |
| `audit/ai-reports` at `dd6402b9` | Provider total deadline and Windows-path redaction with spaces | Preserve current code; it also contains later cancellation protection |
| `audit/desktop` at `4d5e48ab` | Plain-text consent, escaped tooltips, empty export destination handling, self-test cleanup | Preserve current code |
| `haiku/cli-help-suppress-20261027` at `37940b70` | Hidden internal CLI worker help while preserving parsing | Preserve current code |

The maintained tests in `test_audit_ai_reports.py`, `test_secondary_help.py`
and `test_audit_desktop.py` passed **19 cases in 5.14 seconds** on exact
`67f7e08e`. This is scoped behavior evidence, not complete review of every
historical branch or native engine compatibility.

## Concrete local work to recover

The separate local repository at
`/workspace/scratch/8c4bcaaa669f/PatchTrace`, branch
`consolidate/feature-completion-20261119-8c4b`, has final head `c5ed4a0b`.
Its local continuation is not represented by the 354 remote-branch census.
It contains useful ordinary application work missing from PR #344.

### 1. Preserve report outcomes when staging cleanup fails

Recover **specification and tests first** from
`ddbcacf4d22d1ef0868f0ed9f9207a5ccf0245a9`, then the implementation from
`b3d7d3999370b09f9c6c061680e12026ba36d8bf`. The two commits touch only:

- `docs/specs/architecture.md`, section “Report staging cleanup”.
- `tests/test_report_export_cleanup.py`.
- `src/patchtrace/reports.py`.

The existing candidate unconditionally calls `staged.unlink()` in `finally`,
even after `os.replace()` consumes the stage. A cleanup error can therefore
mask a successful export, typed write failure, backup refusal or interruption.
The donor avoids cleanup after successful replacement and preserves the
primary failure, adding a fixed cleanup note if removal also fails.

The donor-exact seven-case test file, SHA-256
`24975b9c225e0e574eb6e94062bd41d6dc9cce26df3c58d2a24bb7389ff7acc4`, was replayed
against both source trees:

| Runtime source | Result |
| --- | --- |
| Candidate `67f7e08e` | **7 failed in 0.78 seconds**; staging `PermissionError` masked the expected outcome |
| Local donor `c5ed4a0b` | **7 passed in 0.60 seconds** |

The complete `reports.py` delta between those two sources is exactly this
cleanup repair. Root owns integration and fresh affected verification; this
worker did not modify product code. These authored local filesystem controls
do not establish native Windows or full-suite acceptance.

### 2. Recover header help and evidence announcements

Donor `f6f4c1dce74a7e7e506d9d23219bf7b2c9e6630f` adds registered header
tooltip IDs with plain-title fallback and routes evidence-state changes through
the existing host announcer. The bounded source lives in
`gui/table_spec.py`, `gui/qt/table.py` and `ui_evidence.py`, with its contract in
`docs/specs/gui-framework.md` and existing GUI test files.

Two donor tests were run with the current candidate explicitly selected by
`PYTHONPATH` and pytest's `pythonpath` override. Both failed on `67f7e08e`
in 2.24 seconds: `ColumnSpec` did not accept `tip_id`, and the evidence state
change emitted no announcement. The same two tests passed on `c5ed4a0b`
in 1.85 seconds. This is offscreen behavior evidence, not screen-reader or
native accessibility acceptance. Recover the narrow source/spec/test scope
after independent integration review.

### 3. Review ordinary project-creation ownership next

The donor contains a specification commit `ecd6307d` followed by implementation
`fd42abbb` for request-owned ordinary project creation, in
`ui_new_project.py`, `ui.py` and `test_ui_project_creation_lifecycle.py`.
This worker discovered that source but did not independently replay it.
Review its tests against the new integration head before recovery. It is a
separate scope from the active TaskRunner final-progress callback repair.

## Independent PR #344 review

Reviewed the changed contract, source and test files between exact base
`371b067068da3c4898ebb7b6eae5d0dd13ebea00` and head `67f7e08e`.
No blocking finding was identified in this bounded component-name change:

- The exact-plain-`str` gate precedes `strip()`, filename normalization,
  saved-owner inspection and file-index construction.
- `candidate_pairs` and `candidate_preview` both enter the guarded snapshot.
- Refusal uses fixed `PT-KBC-INPUT` text without submitted component content;
  padded ordinary strings retain their existing behavior.
- The malformed-value tests deny sockets and detect file-index availability
  probes and row reads.

The six new cases and 30 maintained candidate-journey cases passed together:
**36 passed in 2.38 seconds**, using the existing repository environment and
`QT_QPA_PLATFORM=offscreen`. This independent worker review does not transfer
predecessor CI results, qualify native Windows, or close unrelated blockers.
No analysis, matching or offensive capability was developed.

## Evidence and environmental limits

Commands, source identities, outcomes, test digest and scoped dispositions are
recorded in the machine receipt. Detailed stdout was observed in the tool
transcript; a complete stdout archive is not claimed. Disposable test fixtures
and projects remain under `/tmp/patchtrace-branch-recovery-2bad` for the parent
to inspect. One initial overlay scratch-directory creation failed with
`ENOSPC`; its pytest invocation ran no tests. The successful replays used
`/tmp`, and the parent subsequently restored overlay capacity.

No full-suite run, remote mutation, main merge, release or deployment occurred
in this worker. The source branches and donor history must remain retained
until the coordinator records qualified integration and applicable acceptance.
