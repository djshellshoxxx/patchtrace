# R2 — Unified binary matching research and validation

Research date: 2026-10-30 (America/Vancouver). Baseline: `main` at
`a04f5a299a8d4afef023261e52e08d14678cf1e7`. Working branch:
`codex/r2-unified-matching-research-20261030`.

## Scope and evidence policy

This is the R2 assignment: function correspondence, matching algorithms, correlated
multi-engine evidence, false matches, residual assignment, explanation and scale.
It preserves Ghidriff as primary, derived unified results, L1/L2 separation, ordinal
confidence, and explicit analyst decisions. R1 corpus work is separately owned;
this work reuses its existing fixtures and records unmet native acceptance gates.

The work includes source inspection, primary-source research, executable
counterexamples, synthetic benchmarks and narrow regression-backed repairs. A
passing fixture is not native-tool acceptance. An advisory workflow's successful
conclusion is not a passing accuracy gate. Unknown precision remains unknown.

## First checkpoint

- Reconciled 117 remote branches and 20 open PRs against the current default branch.
- Read the current implementation and earlier unified-engine research before
  proposing changes. The residual passes P16–P19 already exist; older unchecked
  task entries saying they are not started are historical, not current status.
- Located concurrent R1 work and created separate R2 worktrees with exclusive
  file ownership. No existing checkout, branch or uncommitted work was overwritten.
- Inspected actual jobs and logs for main's native and unified workflows.
  Unified live run `41063115449` has 27 failed jobs and 3 successful jobs even
  though the workflow conclusion is success. Its gate report is **NOT READY**:
  zero measured matched rows, no live correspondence precision, and incomplete
  G-U1 through G-U8 acceptance. The report correctly keeps the feature flag off.
- Began focused baseline tests and isolated literature, graph/performance and
  fusion/identity investigations. Findings and repairs are recorded in later
  checkpoints; this initial checkpoint does not claim completion.

See [repository reconciliation](00-reconciliation.md) and the
[machine-readable snapshot](results/reconciliation.json).

## Planned report sections

1. Current implementation and verification inventory.
2. Matching algorithms, upstream implementations and licensing.
3. Graph matching, residual assignment, pass ablations and performance.
4. Evidence fusion, function identity, false matches and explanation.
5. Baseline accuracy evidence, measurements and implementation validation.
6. Remaining acceptance gates and an executable R3 handoff.

Each section distinguishes code present, executed local evidence, native CI
evidence, proposed improvements and unanswered questions. No locked test set is
used for tuning, no calibration artifact is trained, and no probability is inferred
from an ordinal tier or native engine similarity score.
