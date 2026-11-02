# Independent review of completed targeted validation

Date: 2026-11-02. **Approved as a faithful reconciliation: every original failing/error node now has an exact-node passing result, without source or assertion edits.** This is a review of completed receipts; I did not rerun tests or change repositories, controls, or GitHub state.

## Original outcomes reconciled

The original full run remains recorded as **59 failed, 19,154 passed, 402 skipped, 7 xfailed, 9 errors**. I matched its 68 distinct bad node IDs against the actual targeted JUnit testcases, rather than relying only on aggregate summaries.

| Original group | Original failures | Original setup errors | Exact-node passing receipt |
|---|---:|---:|---|
| Host socket restrictions | 46 | 9 | `patchtrace-loopback-rerun-20261102.xml`: **55 passed in 30.10s** |
| Isolated interpreter could not locate PatchTrace | 7 | 0 | `patchtrace-isolated-imports-20261102.xml`: **7 passed in 3.55s** |
| Missing search dependency / unavailable suggestions | 6 | 0 | Six exact original nodes passed within `patchtrace-extra-affected-20261102.xml` |
| **Total** | **59** | **9** | **68 of 68 original nodes passed; zero unmatched** |

The six search nodes comprise four RapidFuzz-import failures and two suggestion assertions. The reported **21 search passes** comprise those six original failures plus 15 formerly skipped cases. They are not 21 original failures.

The extras run accurately remains **334 passed, 1 failed in 42.58s**, with no skipped cases. Its sole failure, `tests/test_rules_actions.py::test_the_preview_is_exactly_the_file_and_never_replaces`, was an additional formerly skipped rule test, not one of the original 68 bad nodes. The unchanged Git-tree export guard rejected its initial destination. `patchtrace-export-rerun-20261102.xml` subsequently records that same test **passed, 1/1 in 1.12s**, using the fresh `/dev/shm` base. Thus all 335 distinct extra-selection nodes now have passing receipts across those two runs; the earlier failed result is retained.

Every targeted XML has unique testcase IDs. The socket XML exactly matches the 55-node selection, whose SHA-256 is `fa7c77b516110bd675a7e832cfda60b52c6463fe06380379465a47f69bdbc911`. Exact per-node reconciliation and XML hashes are saved in `/tmp/patchtrace-completed-validation-reconciliation-20261102.json`.

## Source preservation independently verified

- Commit: `f2b7d981008dea25ac09ea82734da64a1dccb96d`.
- Tree: `985078aed0feb4f909690d6082ec4940540cda17`.
- Shared checkout: `/tmp/patchtrace-final-20261102`; HEAD is unchanged and Git status is clean.
- Tested archive: `/tmp/patchtrace-isolated-imports-venv-20261102/source-f2b7d981`.

I independently recomputed the Git blob hash of **all 3,413 tracked files in both locations** against the immutable commit: **zero mismatches or missing files**. I also rechecked the archive against its pre-extras SHA-256 manifest: **3,413 matches, zero changes**. Original failure JSON and JUnit hashes remain unchanged. This supports the environment-only nature of the fixes; installed editable metadata/dependencies are distinct from original source files.

## Rerun controls

I read `/tmp/patchtrace-local-reruns-20261102.py`, its environment receipt, and both resulting logs/XMLs. The harness enforces the exact socket-selection hash, 55 unique nodes, and the nine permitted test modules. Its recorded namespace has **only `lo`**, only local IPv4 routes, and **no default route**. It preserves loopback proxy bypass, uses the installed frozen archive without inherited `PYTHONPATH`, and records zero exit codes for both runs. The tests and assertions were unchanged; no skips or consent overrides were added.

The export base `/dev/shm/patchtrace-export-control-jbkhvymt` has no Git ancestor, verified by the harness and independently at review time. Only pytest's temporary-directory location changed. The export test still exercises the actual writer and replacement refusal, with the Git-tree guard intact.

## Limits

This does **not** convert the original full run into a green full-suite run, and its counts must not be arithmetically relabeled. The passing evidence is from targeted runs in corrected environments: an editable installation, the existing pinned extras, and approved local sockets. The import receipt also records differing ordinary/isolated dependency visibility, including no PySide6 in isolated children; it proves those unchanged assertions in that environment, not every dependency combination.

No new full-suite run occurred. Remaining unexecuted/blocked acceptance, Windows packaging/native compatibility, and release acceptance are outside this review. The justified conclusion is that **all 59 original failures and all nine setup errors have been resolved by passing exact-node validations on unchanged source**, with the original and later receipts preserved separately.
