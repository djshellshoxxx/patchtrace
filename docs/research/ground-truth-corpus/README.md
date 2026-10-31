# R1: ground-truth corpus research

Research dates: 2026-10-30–31. Baseline: [`a04f5a299a8d4afef023261e52e08d14678cf1e7`](https://github.com/djshellshoxxx/patchtrace/commit/a04f5a299a8d4afef023261e52e08d14678cf1e7).
Working branch: `codex/r1-ground-truth-research-20261030`.

## Purpose and current status

Make the existing Tier R factory a defensible measurement instrument for function
correspondence and patch classification. Reuse `known-answer-labels/1`, the
factory, existing evaluation/lineage APIs and immutable derived unified results.
This is a research and benchmark task, not authority to tune production matching
decisions on the final test set.

**The research and implemented pilot now include genuine engine results, repeat
builds, independent source/binary reviews and preserved failures. Integration
acceptance remains subject to final CI/review gates; the larger coverage targets
are not complete.** Existing catalogue coverage, build success, label admission
and engine acceptance remain different milestones.

The research is divided into primary-source literature/dataset evaluation,
ground-truth and metric soundness, real patch provenance, and a reproducible
pilot. Findings are recorded as verified observations, source-reported claims,
design decisions, or open questions. References are attached to the claims they
support. Public dataset/tool code licences do not grant blanket redistribution
rights over third-party binaries.

## Read the findings

| Report | Purpose |
|---|---|
| [01 — Literature and datasets](01-literature-and-datasets.md) | Primary papers and official tools/datasets, identities, licences, construction methods, leakage and suitability |
| [02 — Truth and evaluation](02-ground-truth-and-evaluation.md) | Admission rules, source/debug/binary evidence, explicit metric denominators and partition design |
| [03 — Real patch candidates](03-real-world-patch-candidates.md) | All 35 security cards, 102 commit edges, 16 recipe projects, exact pins and weak associations |
| [04 — Pilot protocol](04-pilot-protocol.md) | Spec-first implementation boundary and demonstrated provenance/harness defects |
| [05 — Results and failures](05-results-and-failure-analysis.md) | Real builds, accepted populations, engine observations, repeatability, resources and failure analysis |
| [06 — Limitations](06-limitations-and-open-questions.md) | What each research question can answer, open gates and concrete next work |
| [07 — Handoff](07-handoff-and-reproduction.md) | Reproduction commands, dependencies, ownership and integration instructions |

The numerical result worth investigating is specific: on one reviewed,
export-name-visible MinGW O2 fixture, Ghidriff and unified recovered **16/16
accepted paired identities**; Ghidriff supplied explicit change signals for
**6/13** accepted material changes, while unified classified **11/13** as material
and left two for review. Four intrinsically ambiguous identities were excluded
before scoring, and two one-sided interfaces were not explicitly observed.
The corresponding fully name-hidden freestanding input produced **zero
discovered functions**. These conditions cannot be pooled into a general
accuracy claim. The [result receipts](05-results-and-failure-analysis.md#matching-and-change-observations)
record all observations and denominators.

Two selected cJSON security-check changes were independently traced through
pinned source, DWARF and compiled guards, then observed by Ghidriff and unified.
The review is unblinded, limited to those two functions, and the binaries retain
92 export names; 111 other label records remain unresolved. A real same-source
GCC/Clang control exposed three unified material flags, including a concrete
conditional-branch/store evidence defect documented for the next production
task. No matching algorithm or threshold was changed to improve these results.

Fifteen profile/optimization cells build using the existing factory. Two actual
provenance defects were fixed: recipes that emit the same artifact now retain
separate immutable receipts, and cached analysis cannot substitute another
configuration's `BuildResult`. Thirty final matrix endpoints were checked, three
incorrect O3 metadata records were repaired by rerunning the factory, and the
engine/debug/PDB hashes remained unchanged. The
[provenance validation](results/matrix-provenance-validation.json) is separate
from accuracy validation.

The repository now contains 23 strict pilot label documents, development-only
partition audits, exact review overlays, immutable build receipts, actual
observation arrays, control experiments and a detailed handoff. The additional
native A/A control succeeded twice with identical bytes and distinct basenames,
observing all 21 project correspondences; its change verdicts remain unknown.
No target binary was executed and no held-out test was consumed.

The external review follow-up recovered two missing hidden-pilot receipts and
used real rebuilds to correct five control labels' variant metadata. Exact
historical labels remain available; accepted artifact hashes and matching
observations are unchanged. The [current integrity inventory](results/final-label-integrity.json)
checks 23 active labels and 39 receipt files representing 36 unique hashes.
Reproduction now explicitly pins linker invocation paths: an alias embedded in
PDB metadata can change full artifact hashes even with equal normalized recipe
digests. [Review dispositions](results/external-review-followup.md) link every
finding to its correction or explicit limitation.

The localhost-enabled Linux suite completed with **18,212 passed, 303 skipped
and 6 expected failures**; focused regressions separately cover the final
provenance and receipt-safety corrections, including **175 tests** in the last
focused group. The [final integration review](results/final-integration-review.md)
records its automated scope and independence limits. Final GitHub checks and
required independent review still govern integration; the research PR is
[#128](https://github.com/djshellshoxxx/patchtrace/pull/128).

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
