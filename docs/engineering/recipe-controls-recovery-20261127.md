# Recipe-card controls and truthful shard outcomes — 2026-11-27

The current-main recovery starts at `b0fc9d26cf148d6195ec7c74aa9c0c5a8104b068`, the packaged-version continuation. Retained PRs #79/#82 supplied the incomplete card-control direction; their old branches are not merged wholesale. Common packaging qualification correction `e72dfaf91499403abdec8cdedeaf434ff0619744` is integrated at local `3777208be4fd1f7c973f56d67ff055eecb046242`.

## Incremental implementation plan and result

1. **Admit one catalogue snapshot.** Replace separate permissive recipe/card reads with the shared strict recipe loader and established I2/I3 card inputs. Validate all records and duplicate IDs before eligibility filtering. Reuse this immutable snapshot throughout a planning call. The initial 16 refusal/ownership regressions failed; the first corrected selection passed 64 tests. Implementation: `bd4c817a`.
2. **Plan and dispatch both recipe sides.** Add exact `aa-card:<id>:old|new` and `noise-card:<id>:old|new` IDs. Deduplicate by `(project, ref)` using the lexicographically smallest case ID, reject conflicting commit pins, preserve distinct refs of one commit, and validate every selected ID before any runner call. Fetch the selected card before running its control. The initial selection recorded 23 failures and 85 passes; the corrected selection passed 108. Implementation: `898ef216`.
3. **Preserve refusal and control failures.** Check each direct dependency's actual project/ref/upstream URL as well as the card and recipe. Stop after failed, blocked or timed-out fetches. A/A findings or non-byte-identical output remain failed in the shard and merged results. The initial selection recorded 25 failures and 116 passes; the corrected selection passed 141. Implementation: `02904849`.
4. **Preserve explicit evaluation failures.** Independent review found that the generic exit-1 classification could turn a real `EvaluationRetentionError` into ordinary findings. Explicit failed/error summaries now stay failed for exit 0 or 1; blocked/timeouts and ordinary findings retain their meanings. New controls recorded 25 failures and 14 passes before correction. The affected evaluation/output-completion selection then passed 266 tests with two native-toolchain skips. Implementation: `69a6c872b0c4dbb5be41ccd6d3b46251ade29932`.

The specification was amended before each new behavior. These counts are overlapping selections, not an aggregate test total. No report schema or workflow is changed by this feature.

## Independent and combined verification

Independent review executed the initial 141-test selection, 19 additional constructed runner/merge controls and a real CLI planning oracle. Root independently reviewed the final classifier correction and passed 180 recipe/shard controls. The real CLI retention failure was produced with a constructed provider; it is output-status evidence, not a native engine run.

The final broad selection at `3777208b` covered all `test_tier_r*.py`, `test_calibration*.py`, `test_lbl26*.py` and `test_train_lbl26.py`: **847 passed, 11 skipped, 5 warnings in 73.91 seconds**, across 35 modules. The five warnings are expected unverified legacy-output warnings exercised by existing controls. Whole-tree `python -m ruff check src tests tools` passed. Eight skips require unavailable LLVM/MinGW/MSVC toolchains; the other three were optional scikit-learn reference checks. Those three were subsequently run against the already-installed primary runtime libraries (scikit-learn 1.8.0, NumPy 2.3.5, SciPy 1.17.0) with the project source and pinned pytest/Pydantic: **3 passed, 15 deselected, 1 existing plugin deprecation warning in 2.45 seconds**. The original environment was not changed. No native success is inferred from the remaining eight skips. Full application and current published-head hosted qualification remain pending.

## Actual catalogue planning observations

The checked catalogue contains 102 cards and 16 recipes. Existing project/recipe/licence eligibility admits 83 cards and yields 133 unique `(project, ref)` control representatives. `smoke` stays at 10 cases. `cards` now contains 216 cases (83 card builds and 133 A/A controls); `noise` contains 158 (25 authored-suite and 133 recipe controls); `full` contains 1,174, including both sets of 133 recipe controls. No catalogue source was fetched to obtain these counts.

The retained catalogue has 42 unique refs, affecting 44 card sides, without a matching recipe-book ref/commit pin. This recovery preserves existing eligibility and reports native build outcomes through the existing refusal path; it does not invent missing pins or claim those cards have built. A source-specific runner must establish recipe build/noise results and byte-identical A/A acceptance.

## Evidence and remaining gates

The planner shares one validated catalogue snapshot within a call. The existing `tier-r-plan/1` digest covers IDs/options/assignments, not source bytes; plan and execution therefore require the same unchanged checkout. Command subprocesses reload the catalogue. This is documented rather than represented as portable provenance for edited input.

Local raw receipts are `lbl32-verification.json` and `verification/lbl32-combined.{json,log,xml}` in the coordinating task workspace. They record observed failures, source identity, commands and the combined result. Current-head Linux/Windows/Qt packaging checks, applicable hosted Tier R checks, and guarded integration remain unfinished. The LBL-31 complete artifact/training handoff, recipe-source mutations, catalogue pin coverage, lock decisions and separate L1/L2/L3 accuracy gates are separate queue items and are not marked complete here.
