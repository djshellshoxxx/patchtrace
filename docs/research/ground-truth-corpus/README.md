# R1: ground-truth corpus research

Research date: 2026-10-30. Baseline: [`a04f5a299a8d4afef023261e52e08d14678cf1e7`](https://github.com/djshellshoxxx/patchtrace/commit/a04f5a299a8d4afef023261e52e08d14678cf1e7).
Working branch: `codex/r1-ground-truth-research-20261030`.

## Purpose and current status

Make the existing Tier R factory a defensible measurement instrument for function
correspondence and patch classification. Reuse `known-answer-labels/1`, the
factory, existing evaluation/lineage APIs and immutable derived unified results.
This is a research and benchmark task, not authority to tune production matching
decisions on the final test set.

**R1 is in progress. No new real-engine accuracy result or completion claim is
made by this initial checkpoint.** Existing catalogue coverage, build success,
label admission and engine acceptance are different milestones.

The research is divided into primary-source literature/dataset evaluation,
ground-truth and metric soundness, real patch provenance, and a reproducible
pilot. Findings are recorded as verified observations, source-reported claims,
design decisions, or open questions. References are attached to the claims they
support. Public dataset/tool code licences do not grant blanket redistribution
rights over third-party binaries.

## Repository reconciliation

The live default branch is `main`, at the baseline above. PR
[#124](https://github.com/djshellshoxxx/patchtrace/pull/124) merged the essential
integration; its `95e0954` tree and the merge tree are identical. The existing
checkout was clean and detached at that parent. Work uses a separate checkout
and a new branch; no existing branch, worktree, untracked item or project snapshot
was overwritten.

Live inspection found 117 branch names and 20 open PRs. The current coordinator
is [#126](https://github.com/djshellshoxxx/patchtrace/pull/126), on
`claude/modest-hamilton-kz2gta`; [#127](https://github.com/djshellshoxxx/patchtrace/pull/127)
owns a separate dockable-workspace specification. Historical corpus PRs
[#68](https://github.com/djshellshoxxx/patchtrace/pull/68),
[#78](https://github.com/djshellshoxxx/patchtrace/pull/78),
[#79](https://github.com/djshellshoxxx/patchtrace/pull/79),
[#82](https://github.com/djshellshoxxx/patchtrace/pull/82) and
[#85](https://github.com/djshellshoxxx/patchtrace/pull/85) remain visible; do not
mistake open historical PRs for proof that their code is absent from main.
No other live agent session can be inferred from a branch name alone. This
research's three workers have disjoint files; the integrator owns shared specs,
pilot tooling, QA and task-log updates.

The GitHub branch endpoint reported no protection and the ruleset list was empty.
Repository instructions still require independent review and Linux/Windows
validation before code merges. This research will preserve those gates.

## Initial evidence that changes the work plan

1. Main already contains the Tier R source factory, contracts, compiler profiles,
   mutation operators, label validators, evaluators, annotation conversion,
   lineages, artifact persistence and preregistration checks. Build on these
   components; do not create a competing corpus framework.
2. Main's general QA and native Ghidriff/rz-diff checks passed, but the separate
   [unified live gate run 41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449)
   has failed benchmark jobs. Its Linux build job reports 273 pairs, including
   20 generated mutants in each of 12 classes. That is **build evidence**, not
   matching accuracy evidence.
3. The same run's Linux A/A/release job wrote **zero outcomes**. It rejected
   backend status `identical` and reported backend analysis failures on other
   pairs. The Linux integrity job failed before tests because `libEGL.so.1` was
   missing. These original failures must remain visible when fixes are tested.
4. Normalized body equality and source/debug identities require a separate
   admission argument. A broad address mask can erase a changed referenced
   object or scalar literal. An unchanged source revision also does not establish
   defined behavior, identical dependencies, or one-to-one function mapping.

## Deliverable map

The research notes, protocol, pilot results and final handoff are developed here.
Source generators remain under `corpus/ours/`; implementation extends
`tools/calibration/tier_r/` and existing evaluators. Built binaries, PDBs, JVM
projects and large temporary outputs stay outside the repository. Only reviewed
source, bounded labels/manifests, aggregate results and reproduction instructions
are candidates for commits.

R1 acceptance requires independently defensible pilot labels, repeatable builds,
partition leakage checks, tested metrics, at least one genuine matching-engine
evaluation, recorded limitations, and required review/CI evidence. A missing
compiler, failed engine or unreviewed label is not a passed gate.
