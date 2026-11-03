# PR #126 → #146: rules-lane consolidation disposition

Date: 2026-11-02. Scope: this lineage only, compared with current main `ce8c65b` and published PR #163 tree `2e7cd8e`. This is a read-only source, object, and existing-check audit. No tests, native programs, FIFO probes, repository edits, or remote mutations were performed. New artifacts are this report and a scratch immutable-source receipt.

## Decision

**Seven rules paths remain unabsorbed and form a suitable next, narrowly bounded consolidation slice.** Three production files, three test files, and the workflow specification are identical between the pre-lane baseline, current main, and the published candidate. The latest #146 versions contain changes missing from all three.

Use the final #146 rules source, including its repairs to #126's first implementation. A wholesale #126 merge would revisit newer callgraph behavior, saved-scope semantics, and the expanded milestone ledger. Although #126's title/body describe documentation, its actual current delta contains production code and tests across 15 files. #146 changes three files on top, adding one new path: this lineage touches 16 distinct paths.

Neither PR is ready for closure merely because the integration contains 16 other heads. For main consolidation, #146 needs final rules intent represented and validated on the resulting immutable head. #126 also needs the KB diagnostic decision below. Integration into the existing parent branch is a separate question, approved within the narrow scope of the final section. The ongoing full-suite run was left undisturbed.

## Immutable identities and method

| Object | Exact commit | Exact tree |
|---|---|---|
| [#126 current head](https://github.com/djshellshoxxx/patchtrace/pull/126), open draft | `8d958f0a1950a29c1d1cef9525a114654f4c9904` | `241d1c4277622aee907b3ae15f8583edc4cdd0ba` |
| [#146 current head](https://github.com/djshellshoxxx/patchtrace/pull/146), open draft | `798e11ef345ed7a7a65508a466eaf77ee85ef77c` | `e29d83a20e9a6d2d3e1a023f51fb30350d88bc73` |
| Current remote main | `ce8c65bf41541cf6adb52289d2a530ce2817a53a` | `0f90e002704d93e8343568acf0bde443dcc4b2eb` |
| Explicit local snapshot of main's exact tree | `0f57eaa18ec1cd7971526c9ea8828aa8909cf14a` | `0f90e002704d93e8343568acf0bde443dcc4b2eb` |
| Local representation of published #163 comparison tree | `2b6a4965cc4e0e1f3822109d8a13ebf236ff9bb0` | `2e7cd8e258821f50d776ca3b3a4caef594e2a417` |

The local main snapshot in `/tmp/patchtrace-combined-consolidate-20261102` is not the remote commit or its ancestry. The #163 comparison checkout is `/tmp/patchtrace-publish-20261102`; its local commit identity is reported separately from any remote head identity. #126's API comparison base is `a04f5a299a8d4afef023261e52e08d14678cf1e7`, not current main. #146's base is the exact current #126 head.

Current PR metadata and check runs were read through the GitHub connector. Local trees were inspected without lazy fetching. Eight missing #146 blobs were fetched at the immutable head and decoded as data; every Git blob hash was verified. Source was not imported or executed. The scratch receipt is `/tmp/patchtrace-rules-lane-blobs-20261102.json`.

## Absent rules intent

### Saved-grid identity and reordering

Current main and #163 rescore stored cells positionally against reordered targets/directions. #126 starts remapping by hashes, but that intermediate implementation cannot distinguish separate rule-version identities with identical text. Final #146 maps by target/version identity and verifies associated content hashes. Content-only fallback is allowed only for one matching stored observation; ambiguity returns `PT-RULE-INTEGRITY`, reason `cache-identity`. It rebuilds requested rule identities and validates the resulting grid.

This retains distinct raw observations, including timeout/no-hit results associated with separate same-content versions. Both the reordering regression and the strengthened duplicate-content regression are absent from #163. **Do not port #126's intermediate hash-only version.** Evidence: [final matrix source](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/src/patchtrace/rules/matrix.py) and [matrix tests](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/tests/test_rules_matrix.py).

### Regular-file acquisition

Current digest code opens/reads the path without this lane's regular-file checks. #126 adds checks before acquisition and against the acquired handle. #146 adds nonblocking POSIX acquisition so special-file replacement cannot stall before handle verification. Its regressions cover rejection of a character device and bounded acquisition after replacement. This audit inspected, but did not reproduce, those scenarios.

The source/specification explicitly do not establish Windows named-pipe/device-race acceptance. Successful existing Windows jobs do not remove that limitation. Evidence: [matrix source](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/src/patchtrace/rules/matrix.py) and [workflow specification](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/docs/specs/yara-x-rule-workflow.md).

### Export failure before output

Current export writes the file before constructing the record, so a basename rejected by the record contract can leave output behind. The lane reuses `ExportRecord.basename` validation before writing and returns `PT-RULE-EXPORT`, reason `name`, on failure. The existing contract includes plain-line validation, length bounds, and a separator prohibition. Its new regression checks that no file is created. Evidence: [export source](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/src/patchtrace/rules/export.py) and [export tests](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/tests/test_rules_export.py).

### Corrupt sidecar handling

Current `_inline` directly parses JSON after validating path/hash. The lane converts parse/encoding and recursion failures to `RuleError`, with `PT-RULE-INTEGRITY` and reason `sidecar-json`. Existing `_read` already catches `RuleError` and records a skipped entry, allowing listing to continue. New cases cover malformed JSON, invalid UTF-8, and excessive nesting. Evidence: [store source](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/src/patchtrace/rules/store.py) and [store tests](https://github.com/djshellshoxxx/patchtrace/blob/798e11ef345ed7a7a65508a466eaf77ee85ef77c/tests/test_rules_store.py).

### Coverage and specification

The additional excessive-nesting expectations case tests existing behavior: current `rules/contracts.py::strict_json` already translates `RecursionError` into `ValueError`, handled by the expectations reader. The contracts, errors, and limits blobs are identical between #146 and #163. No pin/contract change is required for this slice.

Fourteen new workflow-specification lines document identity preservation, unique fallback, final-grid validation, and regular-file acquisition, retaining the Windows limitation. New functions absent from #163 are:

- `test_a_stored_run_reused_in_another_order_keeps_each_result_on_its_own_file_and_rule`
- `test_rescore_keeps_distinct_versions_with_identical_rule_content`
- `test_a_device_as_an_extra_build_is_refused_without_reading_it`
- `test_regular_file_replaced_by_fifo_before_open_does_not_block`
- `test_a_name_the_record_cannot_hold_is_refused_before_any_file_is_made`
- `test_a_sidecar_that_passes_its_hash_but_is_not_json_is_skipped`

### Exact seven-path proof

The middle-column blob is identical at `a04f5a2`, current main's exact tree, and #163's exact tree. The right column is final #146. These are absent changes rather than textual differences between equivalent rewrites.

| Path | Common baseline/main/#163 blob | Final #146 blob |
|---|---|---|
| `src/patchtrace/rules/export.py` | `5662bf05ef11d27d6488a063bdc921f7ffd1aba2` | `49d0614cdd18e7df21f3ff95ef4a260f9296cbe8` |
| `src/patchtrace/rules/matrix.py` | `cf60f1e712fe49d0d90c06146e60a2cd3cd0bc60` | `c30d6fbdea224e40d1e60b075020c79a01bd5ec3` |
| `src/patchtrace/rules/store.py` | `fb25a9c48391575cfe35feb94ab951d5af01ad9a` | `0aa5a5fc3d73677d8a3584bfae62e39adcc9e7f0` |
| `tests/test_rules_export.py` | `8a46e460677a413f8825293f705a2f5d018cff49` | `c6eacb28e13ed7db15a30b196daccd67dbb42a45` |
| `tests/test_rules_matrix.py` | `fccffe95c1e05ff3373e5f37391a1872a0944219` | `ffe46b4ea056f1e1dd9a8192390a584624fb1a84` |
| `tests/test_rules_store.py` | `6ce0fa6343985f8dbb0561d5b17b15e702eefb64` | `2a9f7b509f4677e63d922b6a5df26eaeda21e8d1` |
| `docs/specs/yara-x-rule-workflow.md` | `435283d1bb8f3fc0b1ef2d8a11b4544de28364bd` | `4db7a640d441717fbf65b8ef26fcb8fd489adaf4` |

## Other lineage paths

| Intent and paths | Main | #163 | Disposition |
|---|---|---|---|
| Ledger: `docs/plans/milestone-ledger-20261030.md` | Absent | Original 5,446 bytes are an exact prefix of the 52,200-byte ledger | Already preserved in candidate. Retain every newer appendix. |
| CG-1: `callgraph/algo.py`, `tests/test_callgraph_algo.py`, `docs/specs/program-e/WB2-integration-plan.md` | Earlier implementation | Shared per-query edge-examination budget across shortest/reverse/enumeration, completed-witness preservation, dedicated regressions | Superseded. Keep candidate behavior/specification. |
| CG-2: `callgraph/labels.py`, `tests/test_callgraph_labels.py` | Earlier parser | Guarded ASCII conversion/full matching, valid long-integer semantics, exact-record precedence, `callgraph/2` invalidation | Superseded. #126's 1–9 digit cap would regress deliberately supported values. |
| KBC-12: `kbcorrelation/index.py`, `tests/test_kbc_bugfixes_20261029.py`, `docs/specs/kb-patch-search-source-adapters.md` | No named warning; global active revisions | Literal warning/spec/test absent; service/context select finite scope before active revisions | Explicit semantic disposition required below. |

Source paths abbreviated to `callgraph/` and `kbcorrelation/` above are under `src/patchtrace/`. Candidate `tests/test_callgraph_path_budget.py` covers actual hubs, traversal boundaries, rejected-neighbor accounting, retained witnesses, ordering, cancellation and CLI partial output. `tests/test_callgraph_count_suffix_guard.py` covers long accepted counts, non-ASCII/trailing-input rejection, real ingestion, and cache invalidation. This is observed source coverage, not a fresh execution result.

### KB distinction

#126 introduces `NAMED_SUPERSEDED` for a named older revision excluded by global active revision selection; its regression expects `not_observed` with superseded rows. Candidate service/context instead restrict the index before revision selection. A newer document outside saved scope must not suppress an explicitly selected older snapshot. The current saved-scope specifications and `tests/test_kbc_saved_scope.py::test_unselected_newer_same_month_revision_neither_replaces_nor_suppresses_selected_snapshot` preserve this for files and cached scopes.

The unscoped direct-index API still selects global active IDs and emits the generic `SUPERSEDED` warning. The named-file distinction is not literally implemented. Before closing #126, decide whether that direct-API diagnostic remains required. If yes, reconcile it without restoring global suppression in scoped service/context; if no, record why the newer scope contract supersedes the older acceptance case. Do not silently claim the old warning/test is integrated.

## Receipts and exact-head checks

Candidate `docs/qa/completion-verification-20261031.json` already retains the `coordinator-rule-repairs` entry for exact head `798e11e`: **157 passed in 19.42s**, a six-file focused command, and historical log SHA-256 `bb34154010e1d4f2d77aa32c5b2d1ad10d846b19aba3fcc535e2879fa2ea531f`. Its independent-review field records two reproduced/repaired defects and unverified Windows device races. The historical raw log was not recovered or re-executed here. Handoff/issue dispositions correctly preserve #146 as a separate candidate.

Check-run APIs were read for both exact current heads on 2026-11-02. Each returned all **19 checks: 16 success, 3 skipped; none failed or running**. Successes include Linux/Windows QA, Linux Qt shards and Windows Qt, package, both smoke platforms, SonarCloud, and five existing native lanes. CodeRabbit, release, and release-gate are skipped. There is no new CodeRabbit approval to claim.

| Head | QA/package/Qt run | Existing native run | Completion date |
|---|---|---|---|
| #126 `8d958f0` | [41064367759](https://github.com/djshellshoxxx/patchtrace/actions/runs/41064367759) | [41064367739](https://github.com/djshellshoxxx/patchtrace/actions/runs/41064367739) | 2026-10-30 |
| #146 `798e11e` | [41172562182](https://github.com/djshellshoxxx/patchtrace/actions/runs/41172562182) | [41172562184](https://github.com/djshellshoxxx/patchtrace/actions/runs/41172562184) | 2026-10-31 |

These recorded source-head results, freshly inspected today, update the handoff's old queued-status observation. They do not validate a future combined tree or the unclaimed Windows race behavior. No new native action occurred.

## Next main-consolidation slice and closure conditions

After the ongoing immutable full run finishes and its actual traces are assessed, prepare the seven exact #146 paths, a dated integration receipt, and append-only tracker updates. Preserve current callgraph behavior, saved scope, all ledger continuations, and historical receipts. No tool-pin change, check suppression, or broader feature work is indicated.

Freeze the resulting tree. Independent review should cover remapped cell identity, ambiguous fallback refusal, export-before-write validation, sidecar skipping, and acquisition guards. Then run focused rule regressions and relevant existing rule CLI/store/view compatibility checks under the normal harness, plus required exact-head lint/schema/hosted gates. Keep the ongoing full-suite result bound to its own immutable source; it cannot be relabeled as testing a later rules slice. No extra tests are authorized during the current full run.

For main consolidation, **#146 closure requires** final source/test/spec intent represented, independent review and applicable exact-head gates recorded, and the Windows acceptance limit retained in a tracked disposition. Existing source-head checks alone are insufficient.

**#126 closure requires** all 16 lineage paths accounted for: seven rules paths integrated; the ledger preserved; five callgraph paths superseded by current behavior and coverage; and three KB paths adjudicated against the saved-scope contract. Preserve source-head/resulting-tree mapping. This does not establish completion of all issue #105 or authorize unrelated closures.

## Follow-up review: #146 into its existing draft parent

**Recommendation: APPROVE the source consolidation of exact #146 head `798e11e` into the existing #126 draft branch at `8d958f0`. This is not approval to merge either lane into main.** No source-correctness blocker was found in the three-file repair. This narrow recommendation preserves the draft parent's unresolved main-integration and native acceptance work.

### Ancestry, base, and scope

Live PR metadata was read again after the source review; both heads were unchanged. #146 still targets `claude/modest-hamilton-kz2gta` at `8d958f0a1950a29c1d1cef9525a114654f4c9904`. Its source branch is `codex/coordinator-rule-repairs-20261031` at `798e11ef345ed7a7a65508a466eaf77ee85ef77c`. GitHub reports `mergeable: true`, `mergeable_state: clean` for #146; #126 remains draft and dirty against main.

Local immutable objects prove a strict, linear descendant relationship: left/right commit counts are `0 / 2`. The exact chain is:

| Commit | Exact parent | Scope |
|---|---|---|
| `19013569956c3af929e9eccc4f20e5d22a4f8faa` | `8d958f0a1950a29c1d1cef9525a114654f4c9904` | Rule-identity/acquisition repair and specification |
| `798e11ef345ed7a7a65508a466eaf77ee85ef77c` | `19013569956c3af929e9eccc4f20e5d22a4f8faa` | Strengthened distinct-observation regression |

The only changed paths relative to the exact current #126 head are `src/patchtrace/rules/matrix.py`, `tests/test_rules_matrix.py`, and `docs/specs/yara-x-rule-workflow.md`. A strict fast-forward would retain every parent commit and produce exactly the already-reviewed tree `e29d83a20e9a6d2d3e1a023f51fb30350d88bc73`, with no conflict resolution or new source content. Any later branch movement requires rechecking the expected parent/head; this review is not transferable to an unknown replacement SHA.

### Source correctness

The remapping repair checks stable target/version identity and both hashes before reusing an observation. It reconstructs the requested `RunRule` identities, keeps raw cell observations intact, changes only expectation-derived verdicts, refuses ambiguous content fallback, and invokes the existing `MatrixRun` uniqueness/shape validation. The normal cache lookup accepts only complete runs, so it does not expose the zero-cell failed-run representation to this code. Contracts remain unchanged. The stronger regression checks differing timeout/no-hit observations and ambiguity refusal, in addition to the inherited reorder controls.

The acquisition change preserves regular-file checks before and after handle acquisition, keeps the existing read/hash loop and `OSError` mapping, and uses a managed handle that closes on the post-open refusal path. POSIX nonblocking acquisition addresses the specific gap in the parent implementation; the specification and conditional regression retain the platform boundary. No worker, engine, consent, ownership, or persisted-contract behavior is broadened.

One nonblocking documentation nit remains: `rescored`'s inherited docstring summarizes lookup by hashes, while the new implementation correctly prefers identity plus hashes. The added specification states the more precise policy. This wording does not justify replacing the frozen source or holding the parent repair.

### Review state and acceptance constraints

The all-thread and all-review APIs returned **zero inline review threads and zero submitted reviews**. Thus there are no unresolved review findings, but there is also no formal GitHub review approval to claim. The complete discussion contains two bot comments: [CodeRabbit skipped the draft](https://github.com/djshellshoxxx/patchtrace/pull/146#issuecomment-6539544154), and [SonarCloud reported its quality gate passed](https://github.com/djshellshoxxx/patchtrace/pull/146#issuecomment-6539550027). This static review is separate from the historical independent-review receipt.

Beyond the 19 check runs above, the commit-status API returned `security/snyk (djshellshoxxx): success`. The actual Linux [QA job 124453430277](https://github.com/djshellshoxxx/patchtrace/actions/runs/41172562182/job/124453430277) and Windows [QA job 124453430324](https://github.com/djshellshoxxx/patchtrace/actions/runs/41172562182/job/124453430324) both record success for the full `python -m pytest -q --junitxml=qa-results.xml` step and repository Ruff step. Windows build, frozen smoke, portable ZIP, installer build and install/uninstall steps also record success. Their workflow file is byte-identical between #146 and the comparison checkout. The already inspected Qt jobs are successful. No new run was triggered.

The PR body explicitly says to keep draft, requires exact-head Linux/Windows/Qt checks, leaves Windows special-device race acceptance unverified, and disclaims project/native-corpus/release acceptance. The recorded checks now satisfy the named automated-check prerequisite; the platform limitation and broader acceptance exclusions remain. **Draft state is still a GitHub PR workflow constraint. This review does not waive it or any configured branch requirement.** Retaining #126 as a draft while consolidating its reviewed repair is the scope approved here; a literal PR merge must follow the normal owner-directed workflow.

This parent-branch consolidation would not change main, the frozen #163 tree, the currently running full suite, or the KB/callgraph dispositions above. It must not be reported as delivery of the rules fixes to main or as closing all issue #105. No local source edit, test, remote mutation, or external message was made during this review.
