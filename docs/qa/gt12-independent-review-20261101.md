# Independent GT12 benchmark harness review

**Cleared for root-scheduled, serial acceptance-sized runs.** Reviewed initial harness commit `4c8f9a6a765701669009780b3d3e12643a3b6246` and follow-up `1f5f0b808149a30d222a35937667b36a5407bc0d` in `wt-bench`. Final tree: `a032bf5324cb9ded5826adcb3078aa505731ba15`. No remaining concrete blocker was identified. Reviewer made no repository edits, remote mutations, full-suite runs or acceptance-sized measurements.

## Measurement and contract review

| Stage | Actual measured operation | Separately reported preparation | Gate |
| --- | --- | --- | --- |
| `facts` | `FactsContext.build`, then each pair's production `collect` and `verdict.judge`; total is context plus facts | deterministic instruction generation, real IR ingest and reader opening | 5,000 changed pairs; 60 s × existing 5 slack |
| `read_model` | production `load_unified` from strict persisted rows/facts | synthetic records, publication and release of builder row lists | informational; SPEC31 has no separate read-model build-time budget |
| `ui_calls` | production model assignment through actual viewport paint; actual sort and selective filter through paint | persisted read-model load, empty widget/model creation and fixed geometry/style | 100k: first paint 200 ms, sort 150 ms, filter 100 ms, each × existing 5 slack; 10k/100k exact call ceilings and cross-size growth |

The UI preparation exclusion matches SPEC31 07 section 13's explicit background read-model loading boundary and C6's first-paint-after-model-ready definition. The timed first paint includes `set_view_model` and its row filtering. Sorting/filtering execute the production model methods, not precomputed output assignment. Correctness verification and fixture counts occur outside timings, as measurement observers rather than omitted product work. Peak RSS includes process setup and workload preparation.

No L35 value changed. The C6 call ceiling remains `floor(7 * visible_cells * 1.2) + 20`, with no wall-clock slack added to counts. Paint-event observation and positive `data()` call requirements prevent empty/unpainted operations passing. The 10k-to-100k check adds a bounded call-growth requirement.

Facts use unique addresses and varied seeded instruction bodies, with five mutation families (comparison constant, branch condition, immediate, memory displacement, IAT callee). Every generated pair must be machine-changed, have deltas, receive a nonbenign verdict and avoid limits. Read/UI fixtures have unique rows, five materiality kinds, varied names and native source values, three populated source cells per row, and strict persisted facts/rows. They are synthetic workload evidence, not live engine accuracy or the largest Tier R pair.

Required missing facts/read/UI sizes remain explicit `pending` entries. Tiny smoke rows have no acceptance timing gates. Overall G-U5 still requires its separate Windows/frozen and largest Tier R evidence; this review does not clear those requirements.

## Review finding resolved

The initial report omitted the chosen seed and requested instruction count. Non-default runs therefore lacked their replay inputs. The follow-up stores `seed` and `requested_insns` on every generated measurement, including failed or timed-out children, without changing workloads, timings or thresholds. Source commit and tracked dirtiness remain recorded; fixture digests and Qt version/platform/style accompany the workload counts.

## Independent bounded verification

- Final focused command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=src /workspace/scratch/142cb233d750/bench-venv/bin/python -m pytest -q --tb=short tests/test_unified_bench.py tests/test_unified_bench_stages.py tests/test_unified_gates.py` — **52 passed in 7.62 s**. Log: `gt12-independent-final-tests.txt`.
- Tiny actual CLI: `QT_QPA_PLATFORM=offscreen /workspace/scratch/142cb233d750/bench-venv/bin/python -m tools.unified.bench --stages facts,read_model,ui_calls --sizes 25 --seed 23 --insns 13 --out /workspace/scratch/142cb233d750/reconciliation/gt12-independent-final-tiny.json`.
- That report records the exact clean final SHA, replay inputs, 25 changed pairs, 25 distinct persisted rows/facts, 75 populated source cells, and all three unrun acceptance stages/sizes as pending. Verdict: **insufficient-data**.
- Actual offscreen Qt tiny counts: first paint 504 calls / 72 visible cells, sort 504 / 72, filter 126 / 18; one actual paint per operation. Filter selects 3 of 25 rows. These are smoke observations only.
- Independent sensitivity controls deliberately replace production Qt `sort` with a no-op, then selectively disable the production filter. Both real Qt workloads fail `ui-operations-correct`. This checks that the harness detects broken operations rather than merely accepting edited count dictionaries.
- An independently forced child timeout returns failed status and retains non-default seed/instruction inputs.
- Scoped Ruff, `git diff --check` and clean-worktree checks passed.

Controls and results: `gt12-independent-controls.py`, `gt12-independent-controls.txt`; tiny JSON/text: `gt12-independent-final-tiny.{json,txt}`. No performance conclusion is extrapolated from these tiny runs. Acceptance-sized Linux measurements and native Windows/frozen measurements remain to be run and assessed.

## Final source SHA-256

| File | SHA-256 |
| --- | --- |
| `tools/unified/bench.py` | `24fadbe540794d0080cd4d46bedb187b37b320434534115f0b2a508b3037f623` |
| `tools/unified/bench_workloads.py` | `939f14cbd5a343644be1198f006a67715550e44a1bcc3b9edb9c0e2e53ccf227` |
