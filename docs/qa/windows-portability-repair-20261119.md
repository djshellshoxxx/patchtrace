# Windows consolidation follow-up — 2026-11-19 UTC

## Source and scope

Base PR #316: `f2b6827fc6270b96fb241b0722f2878de5a17361`.
Combined repaired source: local `655815ea` (the following commit adds only this
record). Original source and failed evidence remain intact. This is a repair
candidate for #316, not permission to merge its broader unfinished stack into
main. Every publication and eventual merge retains `[no release]`.

The original hosted Windows QA job `135257238573`, run `44433724017`, reported
**37 failed, 25,516 passed, 151 skipped, two expected failures and 45 errors**.
The source-pinned logs remain available from the
[original run](https://github.com/djshellshoxxx/patchtrace/actions/runs/44433724017).

## Repairs

| Failure | Correction | Preserved assertion |
| --- | --- | --- |
| Project creation compared Windows pathname and descriptor change-time observations | Bind common physical identity; check stability separately within each observation API | Wrong/replaced objects and changing metadata still refuse; failed creation remains retryable |
| Portable C stdin fixture defined public Windows API symbols | Namespace all scripted API functions before compiling the unchanged production fragment | All handle identity, inheritance, ownership, error and cleanup assertions remain |
| Held input fixtures unlinked files while their owner still held descriptors | Release the fixture's readers before unlinking, then reopen the project | Reopened immutable project copies must work after source removal |
| Foreign SQLite fixture retained its connection after a transaction context | Close the fixture connection; close the authored interrupted connection before simulating replacement | Foreign bytes, companion files and replacement ownership must remain preserved |
| Same-length tamper fixture acquired CRLF expansion | Write exact bytes; replay under the existing CRLF text fixture | The canonical-byte check, not a size mismatch, must reject the mutation |
| Windows symbolic-link spelling includes a native prefix | Capture and compare the exact stored target before/after refusal | The original link and absent target remain unchanged |
| Windows formatter fixture observed 16 attempts but no stdio error | Use a writable stdio stream backed by a real read-only descriptor | The original 16-attempt and nonzero-error conjunction remains; source bytes remain intact |
| Restricted Tier-R child crashed during an unnecessary home lookup | Resolve the optional default only when no explicit corpus root exists | Missing home still refuses when a fallback is actually needed; child environment is not widened |

The profile-navigation data-loss repair is independently scoped on the stable
foundation branch and is not included in this repair tree.

## Executed verification

Python 3.12.14; PySide6 6.12.0; pytest 9.2.0; Ruff 0.17.5; Linux, offscreen Qt.
Commands ran with `PYTHONPATH=src` to bind imports to this worktree.

- Original 7-file portability selection: **180 passed, eight skipped** on Linux.
  This did not reproduce or invalidate the recorded Windows failures.
- New CRLF witness against the original tamper fixture: **one failed, one
  passed**; the actual refusal was the unintended file-size mismatch.
- Corrected 7-file portability selection: **180 passed, eight skipped**.
- Independently authored creation observations: **one failed/eight passed**
  before repair; the author's real SQLite/GUI selection passed **117** afterward.
- Four corpus-home controls failed before repair. The author's affected
  calibration selection passed **73, five skipped** afterward.
- Combined 12-file repaired selection: **312 passed, eight skipped** in 93.18 s.
  Files: `test_project_creation_stat_views`, `test_audit116_create_rollback`,
  `test_gui_creation_retry`, `test_creation_operation_checkpoint`,
  `test_creation_replacement_refusal`, `test_project_cli`,
  `test_kbc_held_input_admission`, `test_calibration_corpus_home`,
  `test_windows_network_stdin`, `test_windows_network_diagnostics`,
  `test_release_source_stat`, `test_strings_export_publication`.
- `python -m ruff check src tests tools` and `git diff --check`: passed.
- Independent source review of fixture commit `780175c9`: no blocking finding.
  Persistence and corpus changes were separately reviewed before combination.

These overlapping selections are not an additive count. Eight Windows/POSIX
specific omissions are skips, not platform acceptance. Native Windows reruns,
the full combined suite, packaging and native containment remain pending.

## Unchanged blocking evidence

The exact strict scanner command from `tools.dependency_security.static_argv`
still reports **80 findings** (S608 35, S105 14, S110 12, S101 9, S310 6,
S314 2, S603 1, S108 1). No suppression, rule removal, ignored exit code or
success relabeling was introduced. These are scanner findings requiring
individual assessment, not 80 confirmed exploitable vulnerabilities.

The native Windows containment and unified repeatability receipts, previous Qt
cancellation, manual desktop/clean-machine acceptance and broader retained
work remain separate blockers. This change does not claim release readiness,
native accuracy, an effective network sandbox or completion of #316.
