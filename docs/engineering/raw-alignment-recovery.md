# Paired physical-offset desktop recovery

Date: 2026-11-19. Scope: RD-F03 desktop controls on the current consolidation
candidate. This is a local implementation and regression receipt, pending the
owner's independent review and integrated qualification.

## Proven missing behavior and source selection

The starting commit was `afa1af3cafc00cf4df5fe27778f91332180756d4`. It already
contained `representations/alignment.py` and `raw_alignment_view.py`, including
bounded alignment, original-byte preservation, physical offsets, display-only
gaps and original-window copy text. It did not contain
`src/patchtrace/ui_raw_alignment.py` or a desktop caller for the paired-window
model. The module index explicitly recorded that the desktop controls were not
wired. This is the distinct missing portion identified in the consolidation
inventory, rather than a replacement for the existing backend.

The retained sources are PR #309 at
`3c9d3f074481b2f609330fa49ab9019eb6637849` and PR #319 at
`8d130aefe1be6e737cff1d90d2a5b1658d60a3a6`. Both contain identical controller
and direct GUI test files. The implementation commit selected for the bounded
`ui.py` patch is `ee41edbd2406dc6ca400bd8824a111358ac8a2a7`.
The recovered controller retains the donor blob
`538921688e7ee749d1adce8da80b32def947c836` unchanged.

Before adding production code, the recovered 22-case GUI regression file was run
against the starting implementation. All 22 cases failed because the controller
module or MainWindow integration was missing. These failures demonstrate one
missing coherent desktop workflow; they are not a claim of 22 separate defects.
The raw output and JUnit results are retained under
`evidence/raw-alignment/baseline.{log,xml}.gz`.

## Recovery boundary and behavior

The new UI adapter owns the paired-window controls and registered tooltips.
Older and newer offsets are independently entered as hexadecimal physical file
offsets, with a 16..4096-byte window in multiples of 16. Exact EOF is permitted
and represented explicitly. Hex and Binary support the opt-in mode; existing
fixed-offset rendering and Base64 retain their prior behavior.

The controller uses the existing TaskRunner with a request containing only
verified readers and immutable scalar values. The worker returns the existing
Qt-free alignment view model. Results distinguish equal, inserted, deleted,
replaced and unresolved spans; both physical ranges remain visible. Selecting a
span moves both current displays without inferring a following window or a
function relationship.

Copy buttons, Ctrl+C and the paired context menu use the original window's
formatted bytes and provenance, excluding display-only gaps. Editing inputs,
changing match, representation, project, revision or orientation, replacing or
clearing inspection, hiding the pane and closing the window invalidate the
generation. Late results and errors are rejected by both TaskRunner ownership
and the controller's complete context check. Inspection invalidation occurs
before reader closure; application quit uses the existing task shutdown owner.

Only the narrow raw-related `ui.py` diff was imported. The current
`make_inspection_thread` and `publish_metadata_cache` integration remains intact.
No profiles, saved-search, native research-tool or TaskRunner implementation was
copied from the donor. `ui.py` is 3,072 lines against the unchanged 3,077-line
ceiling. The relevant specification and module index were updated before the
implementation was added. There is no persistence or schema contract change.

## Fresh validation

The environment used Python 3.12.14, PySide6/shiboken6 6.12.0, pytest 9.2.0,
pytest-qt 4.5.0, pydantic 2.14.2 and Ruff 0.17.6 on Linux x86-64. All Qt runs used
`QT_QPA_PLATFORM=offscreen` and the dedicated project virtual environment.
Exact commands, counts and SHA-256 hashes are in
`evidence/raw-alignment/receipt.json`.

| Run | Result | Evidence |
| --- | --- | --- |
| Missing-controller baseline, recovered direct GUI cases | 22 failed | `baseline.log.gz`, `baseline.xml.gz` |
| Initial recovered controller plus backend/view-model cases | 77 passed | `recovered.log`, `recovered.xml` |
| Expanded initial integration | 187 passed, 4 failed, 4 teardown errors | `integration-initial.log.gz`, `integration-initial.xml.gz` |
| Expanded integration after fixture adaptation | 191 passed | `integration.log`, `integration.xml` |
| Ruff across `src`, `tests`, `tools`; whitespace validation | Passed | `quality.log` |

The initial integration failure was a dependency mismatch in
`tests/test_pe_metadata_cache_qt.py`: its minimal QObject owner borrows
MainWindow's inspection lifecycle methods but does not construct the desktop.
The new pre-close invalidation call raised `AttributeError` on that owner. A
one-line invalidation double now supplies that dependency, alongside its
existing logging double. The production inspection implementation and all
existing metadata-cache, worker-thread and GUI-thread assertions are unchanged.
The failed run is retained, rather than overwritten by the passing rerun.
Failure logs and XML are losslessly gzip-compressed to preserve pytest's exact
output, including its trailing whitespace; `gzip -dc` reads these captures.

The final 191-case run includes the 77 direct/backend cases, four new boundary
cases, representation tests, host seam and tooltip audits, the metadata-cache
Qt integration tests and stale inspection-failure tests. Counts overlap between
runs and must not be added together. The four new cases cover:

- A verified artifact changed after initial alignment, including restoration of
  the old mtime: touched-block verification refuses the next result and copy,
  preserves the clipboard and avoids exposing the filesystem path in status.
- A worker held across inspection clearing and real reader closure: the task
  token is cancelled and the late closed-reader error cannot replace the
  cleared UI or restore copy eligibility.
- Older and newer exact-EOF windows independently: the empty side remains zero
  bytes with explicit EOF/unavailable presentation, and copy retains original
  window text without display gaps.

The recovered GUI cases exercise actual Qt events and the actual TaskRunner,
keyboard/context-menu copy, stale contexts, worker cancellation, public raw
navigation, window closure, an isolated QApplication quit process, and status
layout at 960-pixel width with 12..28-pixel fonts. The controlled worker delays
test lifecycle ordering; they do not represent external backend compatibility.

## Qualification limits

No target binary was executed. Tests create and inspect synthetic project
artifacts. This work does not claim native Windows or Linux manual acceptance,
assistive-technology acceptance, native alignment performance, a full repository
test pass, release qualification or independent review. Those remain the
owner's integration and release gates. No remote branch, PR, merge, package or
release was created by this recovery slice.
