# Windows raw-stage publication repair — 2026-11-16

Blocked head: `f64620f7771b205558871fe09448eb1dd6df715a`.
Workflow: [43841894396](https://github.com/djshellshoxxx/patchtrace/actions/runs/43841894396).

Linux full QA passed: 21,812 passed, 45 skipped, 6 xfailed, with Ruff clean.
Windows Qt job 133212524046 finished with 110 failed, 8,865 passed, 1,080 errors.
All 1,190 failure/error summary rows identify the same WinError 5 raw-stage
deletion failure. The first setup stack was ProjectService.sample ->
sample.create_sample -> apply_analysis -> _prepare_analysis ->
stage.unlink at service.py:254.

The exclusive hard link shares file attributes with its staging name.
Setting destination read-only before deleting staging therefore makes the
staging file undeletable on Windows. The repair keeps exclusive publication,
fsync and ownership-ledger rollback unchanged, removes staging first, then
protects the published inode. A real-hard-link regression simulates Windows
read-only deletion semantics on every platform and covers apply/discard,
exact bytes, protection, no residual stage and preservation of earlier data.

The execution workspace became unavailable before this repair could run
locally. Its regression and platform verification must run in hosted CI;
no local pass is claimed. Prior Linux results apply to the blocked head only.
The full Windows QA job was still running when this record was prepared.

Reviewed follow-ups from #298 and #299 are included in the repaired integration
so one resulting head can be qualified. Native API receipts remain scoped as
documented in native-api-20261116/README.md. Main is not merged while any
required check is failing or incomplete.
