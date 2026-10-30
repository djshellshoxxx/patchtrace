# PatchTrace consolidation and deep review — 2026-10-30

Owner authorization: review, repair, consolidate and merge required changes. Baseline is PR #123
`99f8328ce89d02f200cf9fbc5852d9801761af28`, which contains PR #110's essential integration and
the #113/#117/#119/#122 repair stack. Main at review start is `5214720`; a local merge-tree check
showed combining that main with #123 gives exactly #123's tree. No source branch is deleted or rewritten.

## Confirmed defects repaired

| Finding | Repair and regression evidence |
|---|---|
| Windows 10/11 scopes with the same release/architecture collide; merged product references inherit an order-dependent file-index key | Known-client `kbc.scope/2` includes `winbindex_key`. Legacy selected scopes fail closed and require new search/selection. Historical context exports remain byte-identical. Product/index/service suites cover separation and compatibility. |
| Skipped, failed or partial decompile refresh may replace a prior material result and delete code | Same-ID upgrades require a successful decompile stage and successful code-part storage. Five regressions preserve the exact committed directory and verdict on failed refresh. |
| Ledger claimed #67 launch/input protections that were absent | Ported private copied-and-hashed inputs, isolated probes/launches, exact preview consent, empty correction and duplicate preparation guards, positive log-tail limits and PE prefix precheck. Preserve local-symbol launcher and sequential analysis. |
| Parser safety fixes stranded in #102-related hostile branch | Ported `e3a1eb5`/`077b04e`: JSON depth 128, unusable path-component refusal, relocation work count including padding, huge ratio rejection and bounded tool-version parsing. Keep per-entry Winbindex Unicode quarantine from #123. |
| Windows Setup checksum uses CRLF and release verifies only portable ZIP | Ported relevant `475bd2d` helper/test; write LF ASCII bytes and verify Setup sidecar in release workflow. Windows PR QA remains enabled. |
| Hidden BinExport CLI worker leaks `==SUPPRESS==` into help | Reuse `37940b7` regressions; omit argparse help instead of adding a redundant private-action filter. Worker remains parseable. |

The isolated interpreter now requires Ghidriff installed in the selected environment; user-site,
current-directory and PYTHONPATH-only installations are intentionally excluded. New private binary copies
can consume up to 2 GiB of scratch. No analysed input is executed or uploaded.

## Reconciliation disposition

| Sources | Disposition |
|---|---|
| #110, #123 | Consolidation foundation. Their source ancestry is retained in the delivery branch. |
| #112–#115, #117, #119, #122 | Repair alternatives superseded by #123. Check changed content rather than merging duplicate stacks. |
| #64, #101, #103, #108, #109, #83, #88, #89 | Relevant work incorporated by #110; #107 and #111 also exist on main. |
| #67 | Missing essential fixes now selectively ported and tested; prior ledger statement was incomplete. |
| #100 | All 36 introduced files already present identically; shared-file changes are newer integration fixes. |
| #102 | Preserve original author branch/PR. Report backup already retained; parser and checksum fixes selected. Icon/version resource and CI restructuring remain separate; do not disable Windows PR QA. |
| #69 | Preserve draft: 24 unique synthetic fixture/test files require current-dialect reconciliation; protocol-only crash harness is not application recovery evidence. |
| #72 | Preserve ten proposed documents. Reconcile essential KB/KEV/search/strings/graph requirements against current specs before importing; no runtime implementation is lost. |
| #71, #90 | Corrected fixtures represented in current integration; avoid obsolete duplicate `-2.py` files. |
| #70 | Older help drafts superseded by current help. |
| #78, #79, #82, #85 | Deferred calibration work: output/artifact persistence, A/A hard-failure controls, recipe collision checks and exclusive preregistered final look are unique. Reconcile before calibration claims; wholesale merges would revert newer deduplication. |
| #94 | Test-only timing stabilization; no production performance evidence. |
| #61, #68, #98 | Workflow skills, proposed corpus recipes and older wiki prose retained for selective follow-up. |

113 remote refs were inventoried; only 7 were ancestors of starting main and 17 of starting integration.
Non-ancestry alone is not evidence of lost work because the repo contains squash-era histories.
Preserve historical feat/fix/audit branches until individual content dispositions are established.

## Verification

Before this review's edits, exact #123 head had successful QA workflow `41004210486` (Linux/Windows
full suites, Ruff, repeated Qt, Windows standalone/portable/installer, Linux package and 22.04/24.04
smoke jobs), and native Windows Ghidriff workflow `41004210319` (five jobs).
Those runs are baseline evidence only and do not validate this review's new code.

Local focused runs: 149 parser/GUI tests; 175 unified tests; 155 KB tests; 262 backend/core tests with
3 platform skips. Counts overlap and must not be added. Dependency check and Ruff passed. Full
combined suite and new exact-head cross-platform/native CI are required before merge. Track their
actual results in docs/qa.md; no native BinDiff/rz-diff completion claim follows from mocked tests.

## Outstanding completion gates

Real unified G-U1–G-U8 evidence, a pinned/verified BinDiff oracle where required, native BinExport/BinDiff
and rz-diff interoperability, real MSRC/Winbindex/provider captures, extraction-to-unified end-to-end
acceptance, cancellation/result preservation, GUI discoverability and Windows release acceptance remain
separate work items. Existing tests do not establish all these gates. No overall completion percentage
or project-complete claim is made.


## Connected SonarCloud check triage

PR #124's initial check `124005071516` reports an E security/C reliability gate. Findings were read from its 50 GitHub annotations, not inferred from the rating. Two genuine command-option boundaries in `tools/run_test_suite.py` were corrected: terminate Git options before the caller's base ref and pytest options before node IDs derived from logs. The old `--base=--lock` path was reproduced creating a locked worktree instead of selecting a ref. The direct caller's documented pytest arguments remain supported.

The launcher-report copy also now reads at most 64 KiB + 1 and atomically replaces its destination: a size-check/read race cannot retain excess data and a destination link cannot overwrite a different file. Two regressions fail before the fix. The MSVC action in the imported corpus workflow is pinned to `0b201ec74fa43914dc39ae48a89fd1d8cb592756`, dereferenced from the verified upstream annotated v1.13.0 tag.

Manually reviewed findings that do not establish defects:

| Finding | Evidence / disposition |
|---|---|
| CLI output paths in test runner, ci_summary, live_pairs, buildenv_value_gate, bindiff_pin | Explicit caller-selected `--log`, `--out` or `--github-output`; imported document contents do not select a destination. Confining them to the checkout would break intended absolute output paths. |
| Launcher report file content called path traversal | Report bytes are content, not a destination path; call site supplies fixed `quarantine/ptlaunch-report.json`. Bounded/atomic retention is strengthened separately. |
| `_subjects` variable tuple lengths | Tuple is a collection of zero/one/many CVEs, iterated by the caller, never positionally unpacked. |
| `_content_addressed` same return | Both branches return the same canonical path after intentionally different retention/deduplication side effects. |
| KEV optional provider | Non-None metadata implies a snapshot with a required KevColumnProvider; same-thread rendering does not yield between reads. |
| Same-expression mutation assertions | Invoke computation twice to verify seed/input determinism; not an existing object's `x == x`. |
| Bidirectional characters in tests | Intentional hostile-input sanitization fixtures, not executable control flow. |
| Source-installed Ghidriff in advisory live workflow | Exact Git revision is pinned; building the external source is deliberate native integration, not an unbounded package selection. |

No Sonar rule was disabled, issue state changed, or required protection bypassed. This triage does not make the remote gate green; track its actual state separately.
