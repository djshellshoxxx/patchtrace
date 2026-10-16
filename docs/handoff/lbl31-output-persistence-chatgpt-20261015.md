# LBL-31 handoff: Tier R engine-output persistence and training artifact bridge

Status: **IMPLEMENTED; UNVERIFIED**. This file is a precise progress register for the independent ChatGPT slice. It is not evidence that any tests passed.

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
