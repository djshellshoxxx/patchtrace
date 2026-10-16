# PatchTrace integration handoff — 2026-10-16, merge-first session

This is a **live-branch coordination note**, not an acceptance certificate. On every continuation read `AGENTS.md`, `CLAUDE.md`, `docs/plans/master-todo-d.md`, the LBL-31 handoff on PR #78, current GitHub PRs, merge bases and current-head Actions. Do not treat CI from an earlier SHA as current. Never execute inspected binaries, claim synthetic labels are real-world accuracy, change the ordinal calibration display, force-push another worker's branch or merge a failed/unverified draft.

## Source-of-truth and merge completed

- Repo: `djshellshoxxx/patchtrace`; main observed after merge at `70e33fd77570329ba23afc58a38616270636d37c`.
- **PR #77** (`docs: Instance C handoff and a ChatGPT prompt`) passed `QA and Windows standalone` at head `cebf38a30ce3d4967ed00a4773f8f9898a9ea708`. Reviewed its two documentation-only file patches, marked it ready and **squash-merged** to main at `70e33fd77570329ba23afc58a38616270636d37c`. `docs/plans/instance-c-handoff.md` now exists on main.
- No other merge was accepted at this checkpoint. The original #77 draft status prevented direct merging until ready-for-review was set.

## Open integration gates, exact evidence

| Track / PR | Current evidence and owner-safe action | Status |
|---|---|---|
| **#64** (`claude/instance-d-gui` -> main) | Last inspected head `53f366e8b50ac60a95bdb3734b815daac82cd63d`; QA run [38825090271](https://github.com/djshellshoxxx/patchtrace/actions/runs/38825090271) Linux passed; Windows **2 failed / 17,876 passed / 79 skipped / 6 xfailed**. Both are `test_masked_body_rule_rejects_address_only_changes_and_records_them` (string-literal/shout, callee-swap/dispatch). Do **not** merge until repaired and current-head CI green. | BLOCKED |
| **#78 LBL-31** (`chatgpt/lbl31-output-persistence-20261015` -> `claude/instance-d-gui`) | Head `5f30a79119b59e337b11a21d81b5e3b12d2bd92a`. [QA run 38883698492](https://github.com/djshellshoxxx/patchtrace/actions/runs/38883698492): Linux QA and Windows Qt 5x succeeded; Windows QA and Ubuntu Qt 20x were still running at last check. Corpus Tier R run 38883698797 succeeded. Patch includes a COFF/ELF function boundary fix likely relevant to the two #64 Windows failures; **not yet proof** until fresh Windows suite completes. After all gates green, mark ready and merge #78 into D using expected head SHA, then recheck D CI. | WAITING CI |
| **#76 Java retry** (`codex/java-version-retry-20261015` -> main) | [QA run 38802363214](https://github.com/djshellshoxxx/patchtrace/actions/runs/38802363214): Linux **15,751 passed** but Ruff I001 import ordering error; Windows also failed Ruff. | BLOCKED |
| **#80 Java retry QA correction** (`chatgpt/java-probe-qa-fix-20261016` -> #76) | Fixes I001 and adds bounded-retry/cancellation/missing-Java/OSError tests, no production changes. Run 38889191976 was in progress. Review and merge #80 to #76 only with current-head green, then require new #76 CI before merging #76 to main. | WAITING CI |
| **#81 duplicate Java correction** | Created from #76 with just the Ruff fix; closed without merge upon discovering the broader parallel #80. Do not revive or duplicate the work. | CLOSED, SUPERSEDED |
| **#61 skills/SPEC-56** | QA run [38664539071](https://github.com/djshellshoxxx/patchtrace/actions/runs/38664539071) failed frozen Windows smoke (`No module named 'patchtrace.unified.ir.cfg'`) on historical head; main has since advanced, so require new integrated branch build before any merge. | BLOCKED |
| **#83 UE-R7** | Separate unified P15 unresolved-callee exact-identity correction, base D; verify and merge only with full current-head CI, avoiding concurrent edits to D. | OPEN, VERIFY |
| **#79 and #82 LBL-32** | Both propose recipe-card A/A and noise controls, overlapping in `tier_r/shard.py`. #79 is stacked on #78 and deduplicates same pinned project/commit; #82 is based directly on D and carries LBL-31 changes. **Compare semantics, coverage, provenance and real recipe acceptance; select one integration path**, or factor distinct parts. Never blindly merge both. | DUPLICATE/OVERLAP |
| **#67-#72 partial drafts** | Not presumed verified. #72 explicitly requests remaining draft/unmerged. #71 and #70 reported incomplete/unverified; inspect and validate separately, do not sweep-merge. | HELD |

## Exact next sequence

1. Poll current-head CI for #78 and #80, not earlier runs. Inspect failed job logs and repair on owner-safe isolated branches with red regression first. If green, merge in dependency order: #78 -> D and #80 -> #76 (merge commits on dependency branches to preserve ancestry); rerun D/#76 CI. Merge #76 or #64 to main only after the new SHA's Linux/Windows QA, Ruff and relevant native tests pass; respect expected head SHA and branch ownership.
2. Reconcile #79 versus #82 before accepting LBL-32. Confirm no case selection can fabricate or suppress labels, source identity and licensing are verified, old/new controls remain clearly separated, and A/A and compiler-noise metrics do not become vulnerability/accuracy percentages. Keep the preregistered locked evaluation untouched.
3. Continue the next unowned requirement from `docs/plans/master-todo-d.md` and `docs/plans/ledger-D.md` (unified G-U1..G-U8 live gates, label correctness and Tier R/Tier W acceptance, modular architecture, Windows standalone). Add specs before contract changes, focused red-green tests, exact evidence, full CI and schema drift checks. Do not mistake fixture-gate pass for actual engine success.

## Verification and ownership

This coordination session inspected source branches, diffs and GitHub Actions jobs, including full failure logs for #61, #64 and #76. It did **not** clone/run the repository locally: the execution container could not resolve `github.com`; GitHub connector reads/writes worked. No synthetic evaluation was promoted to real-world accuracy. The active implementation work belongs to the original PR owners; this note is tracked on the dedicated `chatgpt/merge-first-handoff-20261016` branch for review.

For the following session, begin with the real main head and open PR list; verify whether #78, #80, #79, #82 and #83 have progressed since this snapshot. Keep `tasks/todo.md` and `docs/qa.md` aligned when feature merges actually land.
