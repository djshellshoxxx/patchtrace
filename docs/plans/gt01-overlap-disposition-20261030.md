# GT-01 repair overlap disposition (2026-10-30)

Integration baseline: `f18687fd035b67961c1072af84f8c2b3442979e0`. Sources compared: R1 PR #128
`04bd023df566f43939296f7df1766e46186e7fff`, GT-01 PR #138
`ca1a36c0caea44a9225e487f3ba7b0828c90a567`. Source branches remain intact.

| Concern | Adopted implementation | Disposition and verification still required |
| --- | --- | --- |
| Completed analysis run before unified matching | R1 `tools/unified/live_pairs.py` calls `ProjectService.apply_analysis(raw_path, run)` only on `status=completed` | PR #138 duplicates the call; retain its separate regression in `tests/test_unified_live_pairs.py` and R1's true store/pipeline test in `tests/test_unified_live_pairs_r1.py`. No invented terminal state. |
| Ubuntu Qt dependency | R1 workflow provisions `libegl1 libopengl0 libgl1` before pytest | PR #138 has `libegl1` alone; do not duplicate the installation step. Original failure was `libEGL.so.1`; additional packages remain subject to QA review. |
| Linux Ghidra archive mode | R1 workflow verifies pinned archive hash and restores executable mode bits from the trusted archive metadata in both live jobs | Preserve R1's POSIX regression that exercises the actual recovery shell step. Do not import unrelated R1 corpus/research changes. |
| Failed native output | R1 retains bounded `*.failures.txt` sidecars and collects failed pair IDs, separately for each orientation | Add PR #138's useful log-tail idea **only for a failed** `run_comparison` return whose first value is a quarantine directory, as documented by `backend.py`; use full-log redaction **before** the final 2,048-character bound, reject symlinks, and size-bound reads. Never treat failure as a valid pair. Add orientation/redaction tests. |
| Identical A/A input | R1 explicitly reports `identical` as no native run; no fabricated outcome | PR #138 also excludes identical inputs; R1's explicit reason and direct native `--force-diff` research is retained separately. A **spec-backed independent native-control implementation and exact-head live acceptance** remain outstanding. |
| Stored diagnostics credentials | Redact collected failure text with existing `backend.redact_log` before writing bounded sidecar | New regression verifies output secrecy; do not suppress failures. |
| R1 research, receipts, other modifications | Not copied except R1's one focused regression test module and two shared GT-01 files | PR #128 remains untouched, with 154 source/research/receipt paths pending independent disposition. No broad R1 merge. |
| GT #138 original code changes | No second `apply_analysis`, EGL install, or independently broken diagnostic block | PR #138 remains unmerged. Its two regression additions are adopted by content, not by wholesale cherry-pick. |

## QA and acceptance gate

Original workflow [41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449)
produced 27 failed child jobs and zero evaluated pair outcomes; advisory report was **not** a pass.
Its underlying native analysis logs were not preserved in the workflow outcomes.
This branch is **not GT-01 accepted** until focused/full Linux and Windows checks,
the exact-head `unified-live-gates` native matrix, and G-U1–G-U8 independently
show qualifying evidence with denominators. Do not merge this draft on static
review or advisory workflow conclusion. The current environment can edit GitHub
but does not contain a runnable Git checkout/native Ghidra/Windows executor.
Do not substitute synthetic regression tests for native acceptance.

## Next technical checks

1. Verify actual `analysis.log` tail from the next failed native run, review executable
   mode/Java/tool versions/argv/exit codes, and repair only demonstrated failures.
2. Establish spec-conformant, two-sided A/A runs without re-labeling `identical` as completed.
3. Run `QT_QPA_PLATFORM=offscreen python -m pytest -q`, `python -m ruff check src tests tools`,
   Linux/Windows QA, and the pinned native workflow at the *exact head SHA*.
4. Coordinate tracker entries with the #126/#137 owner, and do not merge until
   applicable reviews and required gates pass.
5. GT-02 is R2 PR #131's owned matching work; GT-03 is workstream B,
   with native license/tool availability retained as explicit blockers.
