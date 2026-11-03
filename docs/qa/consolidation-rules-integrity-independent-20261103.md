# Independent review — rules integrity consolidation

## Decision and exact scope

**APPROVE the bounded slice for integration, subject to required resulting-head hosted gates. No correctness blocker or regression was found in the reviewed delta.** This is not final-release, full rule-authoring, or Windows special-device race acceptance.

- Head: `2fe7a2bff2caa1f95a0c858ec58b0a9121049951`.
- Tree: `b341d7169b61a604172ab38133c0ddef43121bbd`.
- Parent: `2b6a4965cc4e0e1f3822109d8a13ebf236ff9bb0`, tree `2e7cd8e258821f50d776ca3b3a4caef594e2a417` (local representation of published #163 at `6e82fd70f315b99c6798a42c9061a1424a02933e`).
- Author worktree: `/tmp/patchtrace-rules-integrity-20261103`, clean on inspection.

I read repository instructions, relevant module/specification material, the prior rules-lane disposition, all three production changes, contracts and actual callers, new regressions, and the author receipt/raw logs. No source/test edits, broad or native tests, compared-target execution, or remote mutations were performed by this reviewer.

## Exact preservation

Independent Git-object checks confirm exactly eight changed paths: the seven final #146 files below and the author QA receipt. Recomputed blob hashes, checked against both the frozen checkout and immutable `798e11ef345ed7a7a65508a466eaf77ee85ef77c`, all match:

| Path | Verified blob |
|---|---|
| `src/patchtrace/rules/export.py` | `49d0614cdd18e7df21f3ff95ef4a260f9296cbe8` |
| `src/patchtrace/rules/matrix.py` | `c30d6fbdea224e40d1e60b075020c79a01bd5ec3` |
| `src/patchtrace/rules/store.py` | `0aa5a5fc3d73677d8a3584bfae62e39adcc9e7f0` |
| `tests/test_rules_export.py` | `c6eacb28e13ed7db15a30b196daccd67dbb42a45` |
| `tests/test_rules_matrix.py` | `ffe46b4ea056f1e1dd9a8192390a584624fb1a84` |
| `tests/test_rules_store.py` | `2a9f7b509f4677e63d922b6a5df26eaeda21e8d1` |
| `docs/specs/yara-x-rule-workflow.md` | `4db7a640d441717fbf65b8ef26fcb8fd489adaf4` |

The author's tested tree `8b8254c8fee12b1de6f515760dd7ce3b8f4fb680` differs from the reviewed tree only by `docs/qa/rules-integrity-consolidation-20261103.md`. Callgraph, saved scope, receipt lineage, contract/schema definitions, dependency pins, worker and CLI/backend implementation, and all prior evidence are unchanged. `git diff --check HEAD^ HEAD` passed.

## Source and integration assessment

### Grid identity

`rescored` indexes observations by target ID and rule-version ID, then verifies both content hashes before reuse. Equal-text rule versions retain their distinct observations. When exact identity is unavailable, fallback requires exactly one stored observation for the target/rule hash pair; zero or multiple candidates raise `PT-RULE-INTEGRITY`, reason `cache-identity`. No last-wins content deduplication occurs.

Requested `RunRule` identities are rebuilt, raw observations are reordered, and `score` changes only expectation-derived verdicts. State, hit counts, offsets/RVAs, elapsed time and refusal reasons remain with their observations. Final `MatrixRun.model_validate` enforces unique row/column identities, grid shape and cell invariants.

The actual CLI computes the cache key then uses `RuleStore.find_test`, which selects only complete, contract-validated runs. The failed-run/zero-cell representation therefore cannot reach this loop through the production cache caller. Direct arbitrary calls on failed runs are not newly qualified. The CLI uses the reordered grid for displayed rows and totals. New tests cover row/column reordering, distinct timeout/no-hit observations for equal-text versions, and ambiguous fallback refusal.

Nonblocking wording nit: the inherited docstring summarizes lookup by hashes; code and the appended specification correctly prefer identity plus hashes.

### Export before output

The writer builds its basename validator from the existing `ExportRecord.basename` metadata, retaining plain-line, length and separator constraints. `out.name` is validated before folder resolution or file opening. Rejected names now produce `PT-RULE-EXPORT` / `name` without output. Both CLI export and the GUI action call this writer. Existing hard gates, warning confirmation, Git-tree opt-in, exclusive creation and append-only recording remain intact. This qualifies the changed basename refusal, not a new claim that all possible export failures are atomic. The new invalid-long-name regression checks that no output remains.

### Sidecar parsing

Existing containment/file/digest checks remain unchanged. `_inline` translates JSON/encoding `ValueError` failures (including Unicode decoding) and parser `RecursionError` into `PT-RULE-INTEGRITY` / `sidecar-json`. `_read` already catches that error, records the skipped entry and continues listing. Neither the row nor sidecar is removed. The three new cases preserve the pointer hash while corrupting JSON, encoding or nesting, so they exercise parsing rather than only hash refusal. Other pre-existing filesystem-I/O behavior is unchanged.

### Regular-file acquisition

`_digest` checks regular-file status before acquisition and on the open descriptor. POSIX `O_NONBLOCK` prevents the identified FIFO replacement from waiting before handle verification. The managed handle closes on refusal; existing `OSError` mapping remains. This bounds the identified special-file acquisition failure, not total hashing time, arbitrary file growth, or atomic snapshot semantics. The old hash loop is otherwise unchanged.

The later worker still enforces its byte/read limit and compares read size/hash against gathered identity before scanning. The slice does not broaden worker inputs or remove that verification. The preserved specification and conditional regression explicitly leave native Windows named-pipe/device races unverified.

## Validation evidence

I inspected and independently rehashed the raw author logs:

| Evidence | Recorded result | SHA-256 |
|---|---|---|
| Red original-candidate selection | 6 failed, 74 deselected | `75fd43476475e29f07bb70dca380031232f993bd5adbe383f8bc9d4743dd94bf` |
| Green six-file rules selection | 420 passed, no skips, 11.94 seconds | `12021a43701332dd7df77f2011e421dfb2b19685cddf5045c095e3cc08b5d832` |
| Whole-tree Ruff | All checks passed | `82b3e6a6c090a57601d22943bd23fca9218d1031dbe5a7b754092f9a156b4f18` |

The six green files cover matrix, export, store, CLI, view and contract/schema assertions. These are author-run results whose identity and logs were independently verified, not 420 newly rerun independent tests. The source/caller review and existing focused regressions resolved the concrete questions, so I added no redundant tests and repeated no broad suite.

`rules.cli.BACKEND` remains `None`, with no production assignment found. This slice does not connect or qualify the rule proposal evidence loader. It does not settle #126's separate KB diagnostic disposition, retire unrelated branches, lift engine quarantine, or establish corpus, packaged-native, human desktop or release acceptance.

## Separate backup coverage followup

**APPROVE the test-only delta at `c35dceb319e960a462748cbe17b03c05e0766255`.** Immutable diff inspection shows one file, 24 added lines, no production change. The new test creates a real verified SQLite backup, injects failure only into its second fingerprint observation, requires exactly two observations, verifies refusal and byte preservation, restores the real I/O function, and verifies cached trust remains revoked until `find_verified_backup` performs full verification. Successful trusted reuse is required afterward.

This directly closes CodeRabbit's nonblocking second-observation coverage suggestion and additionally checks cache invalidation/recovery. It would fail if the second observation were skipped or if refusal retained cached trust. The coordinator reports 17 passes in 1.02 seconds and changed-test Ruff success; I reviewed the test but did not rerun or independently recover those separate logs. No new source defect or Windows/native acceptance claim follows from this coverage change.
