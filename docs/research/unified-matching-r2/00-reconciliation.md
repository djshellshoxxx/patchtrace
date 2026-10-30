# R2 repository reconciliation and evidence boundary

## Baseline and instructions

The GitHub API reported default branch `main`, commit
`a04f5a299a8d4afef023261e52e08d14678cf1e7`, tree
`2aee54f7216b16a6a412f9188de674fc68287e43`, on 2026-10-30.
This merges PR #124. Repository rulesets returned an empty list and the branch
reported `protected: false`; these observations do not waive the repository's
review and validation instructions. Sources: [branch](https://api.github.com/repos/djshellshoxxx/patchtrace/branches/main),
[merge](https://github.com/djshellshoxxx/patchtrace/commit/a04f5a299a8d4afef023261e52e08d14678cf1e7),
[rulesets](https://api.github.com/repos/djshellshoxxx/patchtrace/rulesets).

Read `AGENTS.md`, `CLAUDE.md`, `SECURITY.md`, `docs/modules.md`, relevant SPEC-31
files, the existing research, the known-answer corpus specification, QA and task
registers. The attachment explicitly authorizes experiments, justified code and
test changes, research checkpoints and a draft PR. GitHub merge remains subject
to review and the prescribed gates. No release or deployment is part of R2.

Local reconciliation found an older clean detached checkout at `95e0954` and a
clean main-derived checkout on `codex/r1-ground-truth-research-20261030`. Treat the
latter as separately owned R1 work even before it appears as a remote branch.
R2 was cloned into its own writable checkout at the exact main SHA and three
disjoint research worktrees. The parent workspaces were read only.

## Existing and outstanding work

The paginated branch listing returned **117 branches**, and the open PR listing
returned **20 PRs**. Exact heads, dates, and local ancestry/content comparisons
are in [reconciliation.json](results/reconciliation.json). A branch not being an
ancestor does not prove its feature is absent: earlier merges can carry rewritten
or superseding implementations. Source and tests determine current status.

| Work | Observed ownership/state | R2 treatment |
|---|---|---|
| #125 milestone prompt, #126 milestone ledger | Other coordinator's documentation branches | Read ledger; leave branches and scope intact |
| #127 dockable workspace | Separate draft UI specification | Outside matching research |
| #78 output/artifact persistence; #79/#82 A/A controls; #85 final-look receipt | Open calibration branches; `output_store.py`, `training_artifacts.py` and `prereg_gate.py` absent from main | Preserve unique work; R1/calibration owner must reconcile before locked training |
| #71/#90 synthetic fixtures | Many exact files already present; corrected canonical fixtures differ from draft duplicates | Use current canonical tests; do not restore `-2` duplicates |
| #86 retained decompilation | Current main already has retention code, with later compute/store changes | Inspect present implementation; do not replace it wholesale with the older branch |
| #94 sort timing | Older stacked test-only proposal | Current performance tests govern; no unrelated merge |
| #102 native/packaging/parser work | Existing external contributor, partly superseded | Preserve; adapter comparisons do not imply adoption of whole PR |
| Local R1 branch | Separate research session at same main SHA | No changes to its corpus, calibration or fixtures |

PR review submissions for #78, #86, #94 and #102 were empty at inspection. This
is absence of review evidence, not approval. R2 does not close or merge these PRs.

### Later ownership checkpoint

At 2026-10-30 23:14 UTC, main still resolves to the same baseline and the open PR
count is 26. New research work is now explicit: [R1 #128](https://github.com/djshellshoxxx/patchtrace/pull/128),
[R3 #129](https://github.com/djshellshoxxx/patchtrace/pull/129),
[R4 #130](https://github.com/djshellshoxxx/patchtrace/pull/130),
[R5 #132](https://github.com/djshellshoxxx/patchtrace/pull/132) and
[R6 #133](https://github.com/djshellshoxxx/patchtrace/pull/133), alongside R2 #131.
R1 owns corpus, labels, live-pair harness and its workflow repairs. R3 changes
`facts/verdict.py` and the COS-PSEUDO proof version in `registry.py`; R2 does not
copy or override those L2 changes. R5 owns calibration research and R6 integration
research. Shared QA/task/module/spec documents need additive conflict resolution
when these branches integrate. Exact observed heads and current R2 checkpoint
checks are in [integration-checkpoint.json](results/integration-checkpoint.json).

R1's later local development artifacts include a reviewed cJSON release pair.
R2 reused only verified read-only inputs and made private copies for native
analysis; it did not mutate the R1 checkout, store, labels, tools or calibration
state. The review is explicitly unblinded and accepts only two positive records.
See [the native cJSON report](08-native-cjson-development.md).

At 23:33 UTC, a further read-only reconciliation found **29 open PRs**. Exact
heads and overlap observations are in
[ownership-checkpoint-final.json](results/ownership-checkpoint-final.json).
R1 #128 at `0271f186` now includes the `Path(sys.executable).absolute()` test
correction for the venv-context failure reproduced by R2, plus live-pair backend
configuration/analysis retention, failure receipts, executable permissions and
EGL/OpenGL workflow repairs. Those remain R1-owned. Its explicit A/A shortcut
refusal is not the independent analysis needed to pass A/A acceptance.

[R7 #134](https://github.com/djshellshoxxx/patchtrace/pull/134) adds bounded slicing
research prototypes; [R8 #135](https://github.com/djshellshoxxx/patchtrace/pull/135)
changes adjacent L2 pseudo-token normalization and `canon/2` registry identity;
[integration QA #136](https://github.com/djshellshoxxx/patchtrace/pull/136) preserves
synthetic KB fixtures/protocol tests from a different base. R6 #133 has advanced
to `3010f289` and remains a documentation dossier. None of these five reviewed
PR file lists changes an R2 production or R2 test path. Shared tracker overlap is
R1/R7; R8 shares the fusion/noise specification. Preserve R2 `matching/2`, R8
`canon/2` and R3 proof-version changes together during later integration. No
other contributor's changes were adopted or branches altered by this work.

The previous coordinator ledger is at
[its exact head](https://github.com/djshellshoxxx/patchtrace/blob/8d958f0a1950a29c1d1cef9525a114654f4c9904/docs/plans/milestone-ledger-20261030.md).
It reports #124 merged and several competing repair PRs closed. R2 rechecked
the main head and actual run/job results rather than treating that ledger as live.

## Native evidence on the baseline

| Workflow at exact baseline | Run | What the inspected evidence establishes |
|---|---:|---|
| QA and Windows standalone | [41060959610](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610) | Linux/Windows QA and Qt jobs success; packaging/smoke jobs success; release skipped. This is baseline evidence, not R2-head evidence. |
| Native Windows Ghidriff acceptance | [41060959854](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959854) | Five native-case jobs success. Establishes their exercised integration paths, not broad correspondence precision. |
| Live rz-diff | [41060959715](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959715) | Both OS jobs success; Linux log contains live result `status: passed`. Fixture smoke, not a representative accuracy estimate. |
| Live unified extraction | [41060959558](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959558) | Linux and Windows extraction jobs success. Does not imply whole-pipeline live gate success. |
| Tier R smoke | [41060959579](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959579) | Two shards and deterministic merge succeed; summary says warning. Ghidriff installation skipped; selected engine is rz-diff. |
| Unified live gates, advisory | [41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449) | Workflow success coexists with 27 failed jobs and 3 successful jobs. The actual report says NOT READY. |

### Why the last green badge is insufficient

The [Linux pair job](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449/job/124094490545)
recorded `Ghidriff run identical: None` for byte-identical A/A cases and backend
failures for other variants. It wrote **0 outcomes**. The source in
`tools/unified/live_pairs.py:analyse_pair` accepts only `run.status == 'completed'`;
the backend's separate `identical` status therefore cannot supply the expected
retained programs through that path. The source-level mismatch is confirmed;
the generic filesystem/lock diagnosis for the other failures is not enough to
identify their root cause without the original backend logs.

The [Linux bench/integrity job](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449/job/124087550789)
measured synthetic ladder and ingest costs successfully, then pytest initialization
failed because `libEGL.so.1` was unavailable. That failure is a runtime dependency
issue, not evidence of an algorithmic false match.

The [gate report job](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449/job/124122131077)
reported:

- G-U1: 15 missing A/A pairs.
- G-U2: zero evaluated mutants for each of 12 classes; each requires 20.
- G-U3: zero matched rows; precision is unavailable.
- G-U4: zero repeated or mirrored pair comparisons and no chain checks.
- G-U5: synthetic benchmark subreports pass; facts, read-model/UI and whole-pipeline
  largest-pair measurements remain pending.
- G-U6: no legacy output; G-U7: no evaluated tier-A/class-pair error evidence.
- G-U8: several integrity checks pass, but the required frozen-smoke result is missing.

The emitted gate report SHA-256 is
`6328006a60e94c51aec6e0cc182f84bb3dbc8bfdd76c32685d0e888e06204710`.
Do not report 0 errors over 0 outcomes as perfect accuracy. Keep default-off and
ordinal confidence until the required representative evidence exists.

## Execution environment

Python 3.12.14 and the already installed task dependencies were verified:
pytest 9.2.0, Ruff 0.17.3, Hypothesis 6.170.14, pydantic 2.13.5, PySide6 6.12.0,
NetworkX 3.7. The existing Python environment is used without modifying its
owner's files; tests resolve this worktree's `src` using repository configuration.
Direct Git fetch failed at the inherited proxy (`browser-proxy:8889`). GitHub
connector reads/writes work, so publication uses its Git-data API. No proxy or
credential policy was changed. Native tool availability and later test results
are recorded in the validation report; unavailable tools are not silently mocked.

## Research ownership

The integrator owns baseline reconciliation, current inventory, baseline results,
cache-version integration, QA/task entries and publication. Literature owns the
upstream comparison report. Graph research owns graph/performance experiments
and the measured loop-count optimization. Fusion research owns evidence
preservation, deterministic ordering and truthful explanation regressions. Shared
schemas and corpus ownership stay with the integrator or existing R1 owner.
