# TaskRunner final-progress lifecycle repair

## Source and scope

- Baseline: `67f7e08ea9bee61653f8ab5ad66048d3e7141810` (PR #344 integration source).
- Repair: `ffd50497b184aa81d908f9686d10f9720948daf6` on `codex/ui-lifecycle-20261120-2bad`.
- Worktree: `/tmp/PatchTrace-ui-2bad`; it was relocated from this session's workspace to preserve disk capacity.
- Ownership: `gui/qt/tasks.py`, its existing test file, the GUI integration specification, and these dedicated evidence files. Shared engineering ledgers are coordinator-owned.

This is a GUI lifecycle correction. It adds no acquisition, correlation, matching, analysis, execution or network capability.

## Confirmed defect and behavior

`TaskRunner._deliver` checked ownership and visibility before flushing final progress. The progress handler is a GUI-thread callback. It can synchronously cancel the channel, submit a replacement, hide the panel, or destroy the bridge. The old delivery then still invoked its result or error callback. A final-progress exception could also leave the undelivered task's closures retained because progress ran outside the release `finally` block.

Twelve authored cases failed on the unchanged baseline implementation using real Python worker threads, queued Qt delivery and the maintained runner. Two cooperative-token controls passed. The failures cover ordinary channels and coalesced lanes; no external binary was run.

The repair rechecks channel generation, closed state, bridge validity and visibility after final progress. Cancelled or superseded outcomes are released on the GUI thread. Hidden outcomes remain parked until applying resumes, without repeating final progress. Replacement tasks retain their own busy state. Moving final progress inside the cleanup block also releases an undelivered event when the callback raises.

Setting a returned cancellation token alone retains its existing cooperative meaning. A worker may deliver its cancellation outcome. `TaskRunner.cancel(channel)` invalidates the channel generation and drops that outcome. No public signature, persisted schema, timeout, retry or acceptance threshold changed.

## Existing-work check

The fetched Git history contains the retained `04a44d95` TaskRunner `on_discard`/InspectionSession proposal. Its delivery path still flushes progress immediately before applying the callback without rechecking ownership. That broader resource-ownership proposal was not imported. This repair is a distinct bounded correction on the current source.

## Verification

| Selection | Result | Evidence limit |
| --- | --- | --- |
| New controls against original implementation | 12 failed, 2 passed in 1.55 seconds | Authored tests, actual repository source and offscreen Qt |
| Complete maintained `test_gui_tasks.py` | 67 passed in 6.50 seconds | Includes all 14 new controls and existing success/lifecycle cases |
| Six downstream UI and stress files | 128 passed in 27.17 seconds | Task cancellation floods, Strings run state, Search, Evidence UI, host lifecycle |
| Changed Python files, Ruff | Passed | No lint suppression added |
| Complete patch whitespace | Passed | `git diff --check` |

The two fixed selections contain **195 unique cases**, with no overlap, confirmed from their JUnit identities. They are focused qualification. They do not qualify the full repository, native Windows, packaging or project release.

The first invocation did not collect tests: the workspace overlay had no free space. That environmental failure is retained separately. Bytecode and pytest cache writes were disabled, test data and receipts used tmpfs, and this worker's new worktree was relocated intact. No older work or failed evidence was deleted.

Compressed raw logs, JUnit reports, exact source blobs and SHA-256 values are retained in [the receipt](evidence/ui-progress-reentrancy-20261120/receipt.json).

## Handoff

1. Independently review `ffd50497` and the progress-to-result lifecycle boundary, including hidden results, replaced channels, errors and callback cleanup.
2. Integrate only the three bounded source/spec/test files plus these dedicated evidence files; retain the original baseline and failure receipts.
3. Run the coordinator's current-source combined/full gates and applicable hosted/native checks. Record exact integrated source identities; do not reuse this selection as complete suite evidence.
4. Update the authoritative engineering ledger under the coordinator's ownership. Main promotion and release remain subject to existing blockers and source-specific acceptance.
