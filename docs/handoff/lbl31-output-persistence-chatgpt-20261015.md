# LBL-31 handoff: Tier R engine-output persistence and training artifact bridge

Status: **IMPLEMENTED; FOCUSED VERIFICATION PASSED; FULL CI / LIVE TRAINING PENDING**. This file is a precise progress register for the independent ChatGPT slice. It is not evidence that any tests passed.

Repository baseline: `claude/instance-d-gui`, independent feature branch `chatgpt/lbl31-output-persistence-20261015`. Do not modify the shared integration branch directly or merge this draft PR without green verification. The earlier `docs/handoff/label-training.md` and `docs/specs/program-e/LBL-DATA-integration-plan.md` supply the acceptance criteria. No other worker's branches were touched.

## Requirements and statuses

| Requirement | Implementation | State | Verification needed / next action |
|---|---|---|---|
| Persist `tier-r-engine-output/1` canonical documents and digest | `tools/calibration/tier_r/{evaluate,output_store}.py` | Implemented | `test_evaluate_persists_exact_scored_document_and_digest`; run on both OSes |
| Reject oversized, invalid, stale or missing responses rather than scoring as successful | `output_store.py`, `evaluate.py` | Implemented | Negative tests in `tests/test_tier_r_output_persistence.py`; exercise 64 MiB boundary |
| CLI output directory distinct from report | `tools/calibration/tier_r/cli.py` `evaluate --outputs` | Implemented | CLI positive, duplicate-directory negative tests |
| Shard actually invokes evaluator | `tools/calibration/tier_r/shard.py` `--engine` -> `--engines` correction | Implemented | `test_evaluation_uses_real_cli_engines_option` and live smoke run |
| Shard carries raw labels and engine outputs separately, never within aggregate | `tier_r/{training_artifacts,shard}.py`, `--collect-artifacts` | Implemented | `test_shard_to_merge_training_artifacts_end_to_end_with_fake_provider`; sample real shard |
| Merge refuses missing/corrupted or foreign engine/label files | `training_artifacts.py`, `shard merge --artifacts` | Implemented | Tamper/missing tests and Actions artifact fetch verification |
| Separate JSON-only GitHub artifact and opt-in `train run --smoke` | `.github/workflows/corpus-tier-r.yml`, `tests/test_ci_summary.py`, `tests/test_tier_r_shard.py` | Implemented | GitHub workflow YAML parsing, PR CI, dispatch with `train=true` |
| Update module index | `docs/modules.md` | Implemented | Review after code integration |
| Real CI evidence and native runner execution | GitHub Actions | **Unverified** | Run QA and `corpus-tier-r` smoke on Ubuntu, optional Windows, review full logs and report digest |
| Corpus growth, complete calibration gates, preregistration lock, Tier W, unified gate G-U1..G-U8 | Other authoritative plans and branches | **Incomplete or separately owned** | Do not claim project completion; follow `docs/handoff/label-training.md` and master tracker |

## Review commands

```sh
PYTHONPATH=src python -m pytest -q -p no:cacheprovider \
  tests/test_tier_r_output_persistence.py \
  tests/test_tier_r_eval_cli.py \
  tests/test_tier_r_eval_metrics.py \
  tests/test_tier_r_shard.py \
  tests/test_ci_summary.py
python -m ruff check tools/calibration/tier_r tests/test_tier_r_output_persistence.py tests/test_tier_r_shard.py tests/test_ci_summary.py
python -m tools.calibration.tier_r.shard plan --seed 1 --shards 2 --engines rz-diff --subset smoke --plan-out plan.json
```

Review run: `python -m tools.calibration.tier_r evaluate --labels <folder> --engines rz-diff --outputs <fresh-folder>` or dispatch the Tier R workflow with `subset=smoke, engines=rz-diff, train=true`; the latter downloads JSON artifacts and runs unlocked training. If the toolchain/engine is missing, record blocked, not passing.

## Limits and safety

No Windows binaries, Microsoft-derived datasets or target execution were added. Data is per-function label metadata/engine predictions, never binaries. The feature branch is unmerged. The CLI supports saved output for the three schema-supported engines (`rz-diff`, `ghidriff`, `bindiff`); the attention provider has no matching strict `tier-r-engine-output/1` persisted contract, and requests with output persistence fail closed instead of silently losing data. Keep the shipped calibration status at `ordinal` until its real gate conditions pass.

The preregistration is still a draft; this slice does not execute the single-use locked test and makes no numerical Windows-system-file accuracy claim.

## Exact next action

1. Run the focused tests above using an actual checkout/Actions job. Fix first failure test-first; confirm both normal and hostile fixture cases.
2. Inspect `corpus-tier-r.yml` run artifacts for correct directory layout (GitHub upload/download root semantics), and rerun the determinism merge with SHA checks.
3. Confirm an unlocked smoke training report is generated or truthfully BLOCKED/insufficient-data; inspect `train-out/report.json`. Only then mark LBL-31 Verified.
4. Continue with `LBL-32` A/A and noise case planning and the still-needed `LBL-33` corpus growth; don't lock preregistration until audit and owner sign-off.

## Continuation 2026-10-16: verification and merge gate

Resumed PR #78 at f20cc572394a4365b399e3643532f71424ce9f4c. Current implementation commit: 0843de5fcde928aa3d457856a3dd2f767ea24ff9. Integration remains claude/instance-d-gui at 53f366e8b50ac60a95bdb3734b815daac82cd63d; main observed at 4cf78d64dd542b508fdf89b2bac70ca16630fa29. User explicitly requested merging after verification. No merge performed: fresh Linux/Windows gates are pending.

### Completed and verified locally
- Fixed Windows COFF mutation assembly extraction: stop at function-end, next function declaration or section boundary instead of incorporating later functions/data into a target's masked body. Four new boundary regressions failed before the fix; five pass afterward (ELF control included). Native Windows confirmation remains CI-owned.
- Fixed artifact integration assertion to reject per-function tables while accepting integer aggregate counts. Original test reproduced locally.
- Validate mutation operator before compiler/base preparation; the existing unknown-operator test now passes even when clang is missing.
- Preserve verification/upload of training reports after a deliberate insufficient-data exit. Added a regression that failed before the workflow change; the job still reports the training failure, never silently converts it to success.
- Fixed five import-order findings and the malformed module-index newline.
- Focused label/artifact/mutation suite: **140 passed, 25 skipped**, 2.38 s. Skips explicitly report unavailable clang/LLVM live acceptance.
- Unified gate regressions: **98 passed**, 13.62 s. Files: test_unified_gate_eval, test_unified_gates, test_unified_fixture_gate_u1 through u7, test_unified_row_gates. These are fixture/evaluator evidence, not live engine gate acceptance.
- Repository-wide Ruff: **all checks passed**. git diff --check passed.
- Exercised evaluate -> persisted output -> export/verify artifacts -> real train CLI -> report verification twice using a synthetic provider: 1 label, 1 output; both training calls returned 1 honestly for insufficient data, both report verification calls returned 0. Byte-identical report SHA-256: 17df2443a697358fb8dade263e1516a80727872f9d5ec8f374688f0e143bcd02. G0/G1/G2/G3 all insufficient-data. Not evidence of real corpus accuracy.

### CI evidence and unfinished gates
- Inspected prior QA run 38854002866: Linux 17919 passed / 1 failed; Windows 17885 passed / 3 failed. Failures were the artifact assertion plus Windows string-literal/callee-swap masked-body checks. Windows Qt repeated gate passed. These results describe the OLD head.
- Inspected successful prior corpus run 38854002993: two training artifacts downloaded and merge verification succeeded. Deterministic second merge matched report SHA 97f2b2be48ec7f67495184d5f96b394596b34e7b351a880eaeb604d3e558c8c5. Summary warned once; unlocked training job was skipped, so it is NOT live training acceptance.
- New implementation QA run 38883165154 and corpus run 38883165226 were in progress when checked. Documentation follow-up may supersede them: always query latest PR head and checks before merging.
- Local complete offscreen pytest was started; no completed full-suite result is claimed. The local environment lacks LLVM; apt setup failed due container setgroups/seteuid permissions. No production binary executed.
- LBL-31 status: implementation and focused synthetic verification complete; native Windows, full current-head CI and live train=true dispatch remain open. Calibration display remains ordinal.

### Exact next action (do not rebuild completed work)
1. Read PR #78 current head and current QA/corpus runs. Inspect any failures, especially the two Windows mutation tests. Do not merge stale or failing checks.
2. Once reviewed current-head Linux/Windows QA and corpus checks pass, merge PR #78 into claude/instance-d-gui with a merge commit (user authorized). Do not merge unrelated drafts wholesale. Read the merge result and verify target ancestry.
3. Dispatch corpus-tier-r with subset=smoke, engines=rz-diff, train=true when workflow-dispatch capability is available; verify/upload the honest insufficient-data report. The synthetic consumer check above does not replace this.
4. Continue LBL-32 recipe-card A/A and noise planning, then LBL-33 verified corpus admission, per LBL-DATA. No preregistration lock or calibration promotion.

### Local interpreter diagnosis
The incomplete full local run reported failures in test_evidence_host::test_loading_the_spec_imports_no_qt and test_evidence_table::test_the_module_imports_no_qt. Focused reproduction showed ModuleNotFoundError: patchtrace under python -I: pip had installed editable PatchTrace into user-site, which isolated mode correctly excludes. Created /tmp/patchtrace-verify-venv and installed .[dev,search,rules]; both tests then passed with no source/test changes. Use that virtual environment for further local testing. This does not make the earlier incomplete full run green. Current-head GitHub Linux/Windows CI remains the merge gate; documentation commits supersede earlier run IDs.

## Continuation: fresh Windows QA failure and targeted follow-up (2026-10-16)

Run [38883698492](https://github.com/djshellshoxxx/patchtrace/actions/runs/38883698492) on head `5f30a791` completed its Windows QA with **2 failed / 17,891 passed / 81 skipped / 6 xfailed** (53 min). This supersedes any earlier statement that current-head QA was all green. Failures:

1. `tests/test_mutations_more.py::test_masked_body_rule_rejects_address_only_changes_and_records_them[string-literal-shout]`: no `NoMutationSite` raised. Windows COFF literal-symbol handling may differ by compiler; do not relax the label rule. Added regression for quoted/unquoted COFF decorated RIP labels, widened the address-operand mask, and modified the existing failure to print **actual before/after normalised function assembly** on future Windows failure. Linux/Windows native correctness of this repair is NOT YET VERIFIED.
2. `tests/test_unified_read_model.py::test_filter_and_sort_budget_at_100000_rows`: default sort took 0.8823358 s against 0.75 s test budget, while source and function-column sort were 0.0699/0.0756 s. Added direct-index sorting fast path for the always-present default tuple key; existing `test_default_sort_fast_path_matches_generic_stable_order` checks ties/descending semantics. Windows budget acceptance NOT YET VERIFIED.

Commits after the failed run include `1a9f246` (COFF fixture), `1e0b2cd` (mask), `0380502` (sort fast path), `3e62fee` (COFF quoted/unquoted cases), and `44f9adb` (diagnostic on native failure). Latest PR head should be looked up again before considering a merge; earlier corpus success 38883698797 is **stale as a merge gate** for this new head. GitHub triggers fresh full QA and corpus runs after updates. Do not merge #78 until ALL required current-head QA and corpus checks are green. No new native success is claimed.

LBL-32 subsequent work is isolated in draft PR #82; it was forked at PR78's earlier 5f30a791. Update #82's ancestry with these post-fork fixes before its integration. Recipe A/A/noise is not a substitute for resolving these Windows correctness gates. Training `train=true` and real unified acceptance remain open.
