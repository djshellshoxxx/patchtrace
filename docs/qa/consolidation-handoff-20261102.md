# PatchTrace consolidation — 2026-11-02

This checkpoint records consolidation, not release completion. Focused test counts
belong to individual immutable commits and are not additive final-candidate evidence.

## Landed and published inputs

PR #153 was independently reviewed and merged after its exact head's applicable
hosted checks passed. Main became `ce8c65bf41541cf6adb52289d2a530ce2817a53a`,
tree `0f90e002704d93e8343568acf0bde443dcc4b2eb`.

| Input | Published commit | Local input with the same verified tree |
|---|---|---|
| Main after #153 | `ce8c65bf41541cf6adb52289d2a530ce2817a53a` | `0f57eaa18ec1cd7971526c9ea8828aa8909cf14a` |
| Combined #159, including #152 | `56374f867594dd923383c91ea71970cb7d24d173` | `419324610bfecaa843f4ed4a0130f57383f62a65` |
| Full #157 plus schema #160 | `ca411e77f43a9fd95ca5e0bcc7d2b58071ccae37` | `5cdbd968e77c34dd4194ffe3cc35f42de6df24d3` |
| Full #154 plus protocol #161 | `9b9452b4677ee3809a6e0f43d49567a8d15602e6` | `bdf214e874f19a8a15382703e5c480e792b3568b` |
| Backup #162 | `f1a55c4cf21ddb0dea243bd417b74f86caaed142` | `5a4155c758a22739d9d5b229cfb48063a22cc03f` |

The complete replay and protocol branches are reconciled, including tests, schemas,
specifications, and QA receipts. Publication must retain the actual remote parents;
the local snapshots do not reproduce published commit ancestry.

Reviewed additions repair backup byte stability, wrapped raw-controls containment,
child-test imports, target-OS path interpretation, and pinned LF fixture checkouts.
The backup adds one full read/hash pass and does not provide an atomic snapshot.
Original pins, assertions, native acceptance rules, and Rizin quarantine remain.
PR #158's unique empty-synthetic regression and #90's 36-line historical fixture
handoff are preserved. The latter does not certify wider unified-engine acceptance.

Independent review receipts accompany the main reconciliation, portability, backup,
UI, and final replay/protocol merges. Final assembled-source tests are recorded
separately; prior focused checks are not final-head acceptance.

## Preservation and remaining gates

The published main and replay trackers contain corrupted binary blobs. Recovery
uses exact Git identities, reproducible transformations, intact prior text, and
verified additions. See both `combined-*-tracker-recovery` receipts and the main
`combined-tracker-recovery-20261102.json`. Original objects remain in history.
Text unique to an already-truncated span cannot be reconstructed; that uncertainty
is retained rather than replaced with invented completion claims.

`consolidation-inventory-20261102.json` preserves the initial 152-branch / 48-PR
inventory and bounded historical absorption review. It is a dated starting snapshot,
not a current count or feature-completion percentage. Older documentation, help,
skill, and test branches retain unique work and are preserved.

Before landing the combined candidate, require its immutable full local run and
exact published-head Linux/Windows QA, Qt, packaging/smoke, and applicable review
checks. The main post-#153 Sonar baseline reported reliability/security gate failures
although #153's exact PR analysis passed; the distinction must remain explicit.

Exact #159 had no corpus/live-Rizin run because path filters did not trigger.
#152 corpus run `41503829018` and live check `41503829017` were blocked by
`rz-diff-orientation-unverified`, pin 0.9.1. Portability repairs do not clear that
separate acceptance debt. No locked evaluation, compared target binary, or native
analysis process was executed for these local consolidation repairs.

Retire superseded PRs only after unique content is verified in landed history.
All original branches remain preserved during this pass.
