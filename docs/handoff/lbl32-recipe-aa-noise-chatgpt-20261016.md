# PatchTrace continuation handoff: LBL-31 integration and LBL-32 recipe probes

Date: 2026-10-16. This is a per-slice persistent completion register. Read `AGENTS.md`, `CLAUDE.md`, `docs/handoff/label-training.md` and `docs/handoff/lbl31-output-persistence-chatgpt-20261015.md` first. The authoritative integration branch is `claude/instance-d-gui`, not `main`. Do not modify other workers' branches.

## Observed state at this checkpoint

- LBL-31 PR #78 (`chatgpt/lbl31-output-persistence-20261015`, head `5f30a79119b59e337b11a21d81b5e3b12d2bd92a`, base `claude/instance-d-gui` at `53f366e8b50ac60a95bdb3734b815daac82cd63d`): persisted Tier R engine outputs and digest-verified artifacts. Focused local verification 140 pass/25 live-tool skips, unified fixtures 98 pass; see its own handoff. Full current-head QA run 38883698492 had Ubuntu QA success and Windows Qt gate success when checked, with Windows QA and Ubuntu Qt gate still running. Current-head corpus run 38883698797 completed success (two shards plus merge; train=true was not requested, so unlocked training job skipped). Do **not** merge #78 until both outstanding QA legs pass and exact current head matches.
- The user explicitly authorized merge after passing checks. Mark #78 ready and merge with merge commit into the integration branch after all checks pass, verify the resulting target commit and ancestry. Do not merge #64 or unrelated drafts as part of this slice.
- Local container lacks direct GitHub DNS; GitHub connector writes/reads are authoritative. Native build and full tests on this LBL-32 branch were not executed in this session.

## LBL-32 implementation, isolated feature branch

Branch `chatgpt/lbl32-recipe-aa-noise-20261016` forked from the LBL-31 head above, and must be targeted to `claude/instance-d-gui` **after #78 merges**. Do not merge the two PRs out of order.

| Requirement | Implementation / evidence | Status |
|---|---|---|
| Two pinned sides for recipe A/A | `shard.py` creates `aa-card:ID:old|new` in cards/full and dispatches fetch then `aa --card ID --side SIDE` | Implemented, untested on Actions |
| Two pinned sides for recipe noise | `shard.py` creates `noise-card:ID:old|new` in noise/full and dispatches fetch then `noise --card ID --side SIDE` | Implemented, untested on Actions |
| Accept only permitted recipe cards | Uses existing `_cards` filter for a present recipe and `PERMISSIVE_SPDX` | Covered by new synthetic test, not yet run |
| Reject invalid side/path/traversal/Tier W/Microsoft | `case_steps` grammar and existing `refuse_microsoft`; negative test IDs added | Covered by new synthetic test, not yet run |
| Preserve smoke/suite and deterministic planner | Legacy cases unchanged; plan digest auto-updates for cards/noise/full | Covered by existing and new tests, not yet run |
| Verify actual shard orchestration | Fake-runner records fetch immediately before old/new probes in each subset | Covered by new tests; never claim native toolchain evidence |
| Specs and module index | `docs/specs/known-answer-corpus.md`, `docs/modules.md`, `tasks/todo.md` | Written |
| Full Linux/Windows test and real recipe acceptance | Actions, real corpus `cards`/`noise` dispatch; QA rows | Pending |
| Recipe mutation sources | Separate `factory.BaseSource` contract/spec implementation | Not part of this slice |
| Corpus enlargement / prereg lock / Tier W / unified live gates | Master completion register, distinct tracks | Still incomplete |

## Immediate next actions

1. Fetch run 38883698492 and verify Linux QA, Windows QA, both Qt gate jobs are `success`; run 38883698797 already `success`. If failure: inspect failing job logs and repair test-first, never merge failing checks. If green: mark #78 ready, merge with `merge` (head SHA lease), verify `claude/instance-d-gui` advanced and #78 is merged.
2. Create an LBL-32 PR targeting `claude/instance-d-gui` from `chatgpt/lbl32-recipe-aa-noise-20261016`. Run `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools` via GitHub's cross-OS QA. Focus first on `tests/test_tier_r_shard.py`; only promote after checks and a reviewed diff.
3. Dispatch `corpus-tier-r` with `cards` and `noise` on the new code when Actions workflow-dispatch is available. Record case counts, per-card statuses, incomplete pin/build failures and A/A byte reproducibility in `docs/qa.md`. The already-successful smoke run is not evidence of recipe A/A/noise.
4. Continue LBL-32 recipe-source mutation only after completing its spec, then LBL-33 admitted C-recipe growth. Do not lock the preregistration, promote calibration from ordinal or assert unified accuracy before the real gates pass.

No target binaries, Microsoft material, PDBs or model-generated commands were executed. No labels have been invented.
