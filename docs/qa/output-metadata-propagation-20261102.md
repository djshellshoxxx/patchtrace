# Tier R accepted metadata propagation — 2026-11-02

This follow-up addresses two new exact-head #157 review findings:

- `PRRT_kwDOVEPRFc6y0m1F`: an accepted provider name longer than 512 characters could be copied into a `WrongMatch` and reject the entire report.
- `PRRT_kwDOVEPRFc6y0m1K`: an accepted producer version longer than 200 characters could be copied into a training feature row and reject that row.

Both failures reproduced before the fix. A synthetic wrong-match prediction with a 616-character provider name failed in `finalize_report` at the stale 512-character bound. The existing retained-output test preserved a 517-character engine version, but `train.build_pair_rows` rejected it at the stale 200-character `EngineRun.version` bound.

The text bounds now have one owner in `tools.calibration.tier_r.contracts`: engine names are capped at 4,096 characters and versions at 1,024. `WrongMatch.old_name/new_name` use the name bound, and training `EngineRun.version` uses the version bound. The normalized output validator imports the shared constants. `TierRReport.json` and the nested report schema in `OutputCredits.json` were regenerated. The SPEC-32 section now states that copied report and feature-row metadata retain the same bounds without truncation.

## Verification

- Red: both focused regressions failed on the pre-fix source for the stated bound violations.
- Green: both focused regressions passed.
- `tests/test_tier_r_*.py tests/test_train_pipeline.py`: **483 passed, 9 skipped, 11 warnings** in 33.74 s.
- Whole-tree Ruff and `git diff --check`: passed.
- The suite reported native compiler/tool acceptance as blocked because Clang/LLVM/MinGW are unavailable on this host; these checks were not counted as live acceptance.

The exact amended PR head still requires fresh hosted QA and review. No corpus evaluation, model fit, release, or native-tool acceptance is claimed.
