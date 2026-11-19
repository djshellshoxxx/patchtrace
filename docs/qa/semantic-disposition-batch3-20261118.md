# Semantic disposition batch 3: source-pinned QA receipt

This docs-only review inspects 20 original branch tips against actual published
PR #316 source **`55f3d0742f7d4cf32357a42b8b1cc76d85875e71`**, tree
`11a0c1598764ebd3fd8d3b540377aa52e949f88a`. Eighteen focal scopes are retained,
one old helper retains a confirmed backup defect, and one historical highlighter
guard is missing. [Complete ledger](../plans/autonomous-consolidation-20261118/semantic-disposition-batch3.md)
and [machine-readable evidence](../plans/autonomous-consolidation-20261118/semantic-disposition-batch3.json)
record exact tips, source replacements, all inspected paths and unreviewed residue.

## Sealed evidence

[Receipt archive](semantic-disposition-batch3-20261118.zip): **182 members**, **1,398,852 bytes**,
SHA-256 **`a5bd917cd16279fd1ca3f9b0a87926d98aff5de55916ad2c264f5628fccc46c2`**. Every member was reopened and checked;
`evidence-manifest.json` records size/SHA-256 for all other members. The packet
retains complete source patches/current comparisons, blob/AST projections,
full-history source proofs, exact current source/spec/test snapshots, original
probes and raw command/log/XML receipts. The frozen inventory is unchanged.

## Exact-source executions

| Invocation at `55f3d074` | Actual result | Pytest summary | JUnit suite duration |
|---|---|---|---|
| 36 current focal replacement files, including the actual global tooltip sweep | 666 passed, 4 skipped, 0 failures/errors | 62.85 s | 62.782 s |
| External public backup publication probe | 2 failed, 1 passed, 0 setup errors | 0.31 s | 0.225 s |
| Three original unchanged historical highlighter nodes | 1 failed, 2 passed, 0 setup errors | 0.51 s | 0.439 s |

The four skips are `test_windows_containment_failure_fails_closed`,
`test_windows_assignment_denial_terminates_suspended_child`,
`test_ghidra_output_path_rejects_overlong_windows_path`, and
`test_work_dir_windows`. Reasons are native Windows Job Object/cleanup, long-path
and local-app-data acceptance. They are not passing controls on this Linux host.
All commands use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`,
`QT_QPA_PLATFORM=offscreen` and absolute current `PYTHONPATH` pointing to this
worktree’s `src` and `tests`. Shared per-branch test mappings and historical
positive neighbors are not additional executions or additive completion credit.

## B3-C1: retained backup reservation ownership defect

The unchanged probe `test_backup_reservation_review.py`, SHA-256
`2fb21e2ff6b346f8c0ec96a1cac1abdfbd9547c87fd519f68153991816c20006`,
uses actual `ProjectService.sample` and `ProjectService.backup`. Replacing the
reserved destination with a foreign empty directory causes two preservation
failures: ordinary rename publication replaces it, and rename-error cleanup
removes it. A held descriptor records the replacement directory losing its link.
The original project database bytes remain unchanged and ordinary backup/reopen
passes. This is a **POSIX empty-replacement** finding, not native Windows or
general source-project corruption evidence.

The historical `audit/core` helper is AST-identical to current
`persistence._publish_no_replace`, so this is retained incomplete behavior,
not a missing port. Contract: `cli-project-compare.md` §3.6 and `architecture.md`
§3. Root owns a separate publication repair and is checking the installer’s
duplicated helper on later continuation source. This packet preserves the
original two-red/one-positive result and makes no later-fix claim.

## B3-C2: omitted highlighter dispatch guard

The full historical `tests/test_ui_codetext.py` is retained unchanged from
`c7fb422c750f1d0e5591277b91492874afd79af7` as
`historical-controls/codetext/test_ui_codetext.py` (16,911 bytes), SHA-256
`238abb33cad9ff066f73564c97ee1215e514735c17aa62ea26a4e39d8f5721e3`.

| Historical node | Result at current source |
|---|---|
| `test_bulk_load_skips_span_dispatch_outside_the_window` | Failed: actual span calls include off-window blocks |
| `test_windowed_highlighter_formats_only_the_window` | Passed |
| `test_scroll_updates_window_within_budget` | Passed |

The failing node’s later call-count/state assertions were not reached; retain
and exercise them after a separately reviewed repair. Current `controller.spans`
filters internally, so the existing tests correctly pass visible formatting and
scroll behavior while the earlier dispatch optimization remains absent. The
proposed source scope is `ui_codetext.py::CodeHighlighter.highlightBlock`, the
WBQ contract and focused regressions, including failure/disabled states and a
high-DPI offscreen run. No native timing or blanket historical-port claim follows.
The branch’s unrelated native distinct-I/O helper is retained, with later worker
reporting added; it was inspected but not executed.

## Evidence checks and limitations

Document/source-path checks and `git diff --check` pass. Production, tests, tools
and workflows have no diff from the pinned source. The read-only provenance
preflight stopped on an inaccurate text needle; its initial script/log remain
retained, then the exact actual call/prefix and full merge history were used.
A nonexistent guessed spec filename was removed before document validation.
These are evidence-script corrections, not repaired product-test failures.

No full historical/integrated suite, live provider/acquisition, target/native
engine, Windows, frozen package or manual/screen-reader acceptance ran. There
was no fresh GitHub/hosted observation or remote mutation. Sixty of 131 original
reconciliation tips have scoped selections after this batch; 71 remain
unselected, with broader native/package/research residue explicit. No product
percentage, whole-branch closure, merge or release is credited. Independent
review/selective integration of this docs checkpoint is pending root.
