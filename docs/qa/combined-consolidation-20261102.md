# Combined candidate reconciliation — 2026-11-02

This is local integration evidence, not hosted or native acceptance. No compared
target binary, native analysis tool, real corpus, or locked evaluation was run.

## Exact inputs and local commit mapping

| Input | Published commit | Verified tree | Local representation |
|---|---|---|---|
| Current main after PR #153 | `ce8c65bf41541cf6adb52289d2a530ce2817a53a` | `0f90e002704d93e8343568acf0bde443dcc4b2eb` | Snapshot `0f57eaa18ec1cd7971526c9ea8828aa8909cf14a` |
| PR #159 combined candidate | `56374f867594dd923383c91ea71970cb7d24d173` | `816864d631ec19ac8c0e8a273b18fda42ac01599` | Existing local commit `419324610bfecaa843f4ed4a0130f57383f62a65` |

Both published commit/tree pairs were read through the GitHub connector. Ten
missing current-main blobs were fetched as base64 at the exact published commit,
decoded, and individually checked against their Git blob IDs. The resulting
whole tree matched the current-main tree above. The actual main commit object
was unavailable locally, so the explicit snapshot has
`63d11d316c70e1f1e83baa80acabd3cf3c4c2245` as its parent. It is not the published
main commit and does not reproduce main's two-parent ancestry. The merge uses
the candidate local commit as its first parent and this snapshot as its second.
Remote publication must retain the published-parent mapping explicitly. The actual merge base
used for tracker recovery is `25c9795bd9cd58bfad855f30594ee3a0c7584cec`.

## Conflict decisions

The reconciliation preserves the candidate's finite saved investigation scope,
scope-limited active revision selection, complete source identity, key-policy
version 3, and per-field provenance. It adds current main's JSON-locatable
CVRF/CSAF card fallback, single-snapshot revision handling, and disputed
applicability across ambiguous native and synthetic snapshots. No scope is
inferred or widened to make context construction succeed.

Current main's verified-backup completion rule and its tests are retained:
successful return requires owned-stage removal and observed absence. The newer
source, specification, module row, and review receipts are kept together. No
additional backup implementation repair is included in this merge.

PR #158's unique regression with an entirely empty synthetic document is
retained verbatim from `e1b79e048d3963d747bc9f07448b039a250180ed`, alongside
PR #153's synthetic-document-without-remediation regression. The source fix
itself was already present in current main.

The new XML-to-CSAF fallback test initially failed when combined with the saved
scope contract because its advisory lead supplied empty coverage. The test now
captures coverage from its constructed index. The production missing-scope
refusal and its regressions remain intact.

## Delivery-tracker recovery

The published current-main `tasks/todo.md` blob
`72552207db2bc02d111e2766296e7358b1c1cc16` is binary, containing 24 NUL bytes.
Base64 re-encoding reveals a rendered truncation-warning prefix followed by the
tracker payload. Removing that exact prefix recovers valid beginning/end text
and four added sections, with one damaged and truncated middle span. The intact
common-base tracker supplies that span (base lines 251–593); the intact candidate
retains its complete history. A three-way text union then preserves every
nonblank line, including multiplicity, from both the candidate and reconstructed
main tracker. The same preservation check covers both QA appendices.

The original blob identity, recovery transformation, restored range, and output
hashes are recorded in
`combined-tracker-recovery-20261102.json`. This cannot prove that no new text had
existed only inside the already-truncated middle; such text cannot be inferred.
The original binary remains available by its Git blob identity.

## Checks and limits

- Initial focused merge check: **109 passed, 1 failed** (the omitted coverage in
  the newly merged XML-to-CSAF test described above).
- Final subsystem check: **1,131 passed** in 30.37 seconds with
  `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q
  tests/test_kbc_*.py tests/test_verified_backup_publication_admission.py`.
- Whole-tree `python3 -m ruff check src tests tools` and `git diff --check` passed.
- Full combined pytest, exact-head hosted checks, and Windows execution are
  still required. The integrator coordinates one immutable full run after the
  remaining reviewed fixes are assembled.
- Known Windows byte-integrity and wrapped-summary UI failures are not declared
  repaired here. Separate helper work owns the backup implementation follow-up.

The local console and JUnit logs are retained in the consolidation receipt
archive. Historical checks in earlier appendices keep their original scope;
their counts are not additive and they are not fresh evidence for this merge.
