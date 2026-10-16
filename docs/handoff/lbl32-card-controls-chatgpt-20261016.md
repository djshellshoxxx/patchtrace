# PatchTrace LBL-32 persistent handoff: recipe-card A/A and noise planner

Last updated: 2026-10-16. Working branch: `chatgpt/lbl32-card-controls-20261016`; draft stacked [PR #79](https://github.com/djshellshoxxx/patchtrace/pull/79) targeting `chatgpt/lbl31-output-persistence-20261015` ([PR #78](https://github.com/djshellshoxxx/patchtrace/pull/78)), which targets `claude/instance-d-gui` ([PR #64](https://github.com/djshellshoxxx/patchtrace/pull/64)). Main observed at `4cf78d64dd542b508fdf89b2bac70ca16630fa29`. Refresh the refs and checks on resume; another agent can advance them.

## Requirement register (do not mistake a committed implementation for a verified gate)

| Requirement | Location | Status | Exact remaining evidence |
|---|---|---|---|
| Enumerate both recipe-card revisions for A/A in `cards`/`full` | `tier_r/shard.py::_card_controls`, `enumerate_cases` | Implemented | `test_recipe_cards_have_both_side_controls_in_plans`; live recipe A/A |
| Enumerate both recipe-card revisions for noise in `noise`/`full` | same | Implemented | tests and real toolchain-noise cases |
| De-duplicate adjacent release cards sharing a project/pinned commit | same | Implemented | `test_recipe_controls_deduplicate_shared_adjacent_revision`; verify deterministic shard merge |
| Fetch each pinned source in its own shard before `aa|noise --card --side` | `shard.py::case_steps` | Implemented | 4-parameter argv test, runner smoke |
| Reject unknown side, traversal, Microsoft/Tier W | case-id regex, `refuse_microsoft` | Implemented | six negative cases (tests); security review |
| Keep code and records modular, preserve aggregate-only shard, no recipe-source mutations | shard planner only; LBL-DATA amendment; modules index | Implemented | inspect actual workflow artifacts; recipe mutation remains open |
| Full current-head Linux/Windows pytest, Ruff, Qt repeat and live A/A/noise proof | GitHub Actions | **Pending verification** | Inspect exact PR #79 SHA checks; run `subset=cards` and `subset=noise` dispatch when available |
| Integrate stacked changes | PR #79 | **Unmerged** | First green current-head QA for #78; merge #78 into D; rebase/retarget #79 carefully, green QA then merge |

## Commits and evidence

- First regression tests: `4fc52eb26a2d0e254647e6424083d5d90c15c18f`; code: `0bb62903042598d32f9c3c731e6bb33dad4d5345`.
- Serialization fault caught during file inspection. Corrected by rebuilding source from clean parent in `0b8e5c2b08f67ccd28d19286b88731f0105c4903`; verified normal file size and parser text through GitHub read. No corruption left in the current branch snapshot.
- Duplicate-pin regression test first: `df22737d587463e6b25a590fd30d69125a9ed946`; corresponding implementation: `5caf7d30210bea37487d5ff0d947794991102e8e`.
- No executed pytest/Ruff result is claimed for LBL-32. GitHub queued QA after opening PR #79; CI must complete and be inspected before approval.
- For LBL-31, prior corpus run `38883698797`: plan, both shards, merge and Windows smoke advisory succeeded; `train=true` was skipped. QA run `38883698492`: Linux QA and Windows Qt five-repeat passed; latest observed Windows QA and Linux 20-repeat were still running. **Do not merge #78 until all required checks are terminal-green.**

## Exactly what to do next

1. Read `AGENTS.md`, `CLAUDE.md`, `docs/handoff/lbl31-output-persistence-chatgpt-20261015.md`, `docs/specs/program-e/LBL-DATA-integration-plan.md`, then refresh PR #78/#79 heads and checks.
2. If #79 tests fail, reproduce focused failing case first, fix on `chatgpt/lbl32-card-controls-20261016` only and rerun. Focused command: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_tier_r_shard.py`; static lint: `python -m ruff check src tests tools`. Full gate: `QT_QPA_PLATFORM=offscreen python -m pytest -q` and CI Windows.
3. When #78 is all green, user authorization to merge already exists. Use `expected_head_sha` and merge method `merge` into `claude/instance-d-gui`. Confirm resulting target commit before moving the stacked PR base. Never merge other unrelated drafts.
4. Run `corpus-tier-r` smoke with `train=true` for LBL-31 and `cards` plus `noise` for LBL-32 from a verified workflow ref; record exact artifact identities, observed A/A byte identity, blocked tools and summary digests. Unavailable dispatch remains an explicit external gate.
5. Finish LBL-32 recipe-source mutation only after its `mutations/engine.py` source-base design is specified, reviewed and tested. Continue LBL-33 corpus-growth admission after R1 diagnostic checks. Do not lock preregistration or promote ordinal calibration without the owner lock and live gates.

Safety: no executed target images, no proprietary Microsoft labels, no fabricated match evidence, no network without per-operation consent. Source checkouts are pinned and permissive-only. Mocked fixture tests never count as live matching or training validation.

## Continuation: hard A/A gate and upstream Windows QA findings

- Added an additional red-first test and implementation on PR #79: `test_nonidentical_aa_rebuild_is_a_failing_gate` checks both CLI exit 1 and an inconsistent exit 0 carrying non-empty `not_byte_identical`. `run_shard` now records status `failed` and a bounded cause rather than allowing an ordinary `findings` status to pass aggregation. `merge` includes it in `failing_cases` and cannot report a successful run with a non-byte-identical A/A rebuild. Commits: test `0946afcc657dfc921a5162222ee481763ba18ace`, implementation `ee3428184267b616a4032e60969df5cd3f60bf57`, stronger exit-zero test `7d4166aa76a124f1167b8f581c1232a1d10a13fa`. **Pending** QA confirmation; do not claim run acceptance.
- PR #78 previously failed current-head Windows QA at run `38883698492`, job `116916633534`: `2 failed, 17891 passed, 81 skipped, 6 xfailed`. Tests: `test_mutations_more.py::test_masked_body_rule_rejects_address_only_changes_and_records_them[string-literal-shout]` (quoted COFF string symbols were not masked), and `test_unified_read_model.py::test_filter_and_sort_budget_at_100000_rows` (default sort measured 0.882 s vs a 0.75 s threshold). Linux QA had passed and the Windows Qt five-repeat passed, but Windows full gate was **red**. The upstream LBL-31 branch received regression tests, COFF RIP symbol normalization, and a low-allocation default unified sort fast path with stable-order regression. Windows-targeted Clang 17 on the local tool container reproduced the quoted COFF literal syntax and a focused regex check passed; these are NOT Windows QA acceptance. Full fresh runner checks were queued.
- **Concurrent edits observed:** PR #78's head advanced independently during this session from `55a14e2` to newer `1e0b2cd` and `3e62fee` commits. Do not assume this handoff owns the entire PR #78 patch set. Reinspect the branch and its checks, do not force-push or rewrite other contributors' edits; #79 is independent and still stacked on its older parent ref.
- Last reviewed PR #79 full QA and corpus CI were queued/active, not completed. No user or release claim has been promoted; calibration is still ordinal. Workflow-dispatch action is not exposed through the currently available GitHub connector, so live `subset=cards`/`subset=noise` and `train=true` dispatches remain external.
