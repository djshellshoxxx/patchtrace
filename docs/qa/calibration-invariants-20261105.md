# D2 deterministic metric invariants — 2026-11-05

Isolated branch `work/calibration-invariants-20261105`, worktree
`/tmp/pt-independent-calibration-20261105`, starting at published PR #218
`afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`. Scope is the existing dev-only
`tools/calibration/metrics.py`, nine authored numerical regression cases and
a precise section 9 specification clarification. No matching interfaces,
native/unified workers, training CLI, retention or shared tracker files changed.

## Reproduced defects

The original equal-mass ECE split equal prediction ties by input row index.
For predictions `[0.5, 0.5, 0.5, 0.5]`, unit weights and two bins, labels ordered
`[1, 1, 0, 0]` gave `0.5`, whereas a row permutation to `[1, 0, 1, 0]` gave
`0.0`. Thus arbitrary ordering of indistinguishable scores changed the reported
calibration error. Unequal integer weights also broke permutation/replication
agreement. Bins now close only after a whole score tie block; predictions and
weights determine those boundaries, without consulting labels. Whole ties can
exceed the target mass and reduce the number of bins.

Weighted AUC computed negative mass as total weight minus positive weight.
For positive/negative weights `[1e16, 1]`, floating-point cancellation erased the
negative class and returned `None` for perfect, reversed and tied scores. A
four-row mixed-tie fixture even returned approximately `1.5`. Summing each
class mass independently restores the weighted pairwise ordering calculation.

Initial regressions: **7 failed / 2 passed in 2.28 s**. The repair is checked
against all 24 row permutations of small tie fixtures, integer replication,
and an independent exact `Fraction` pairwise AUC oracle. One-class AUC remains
undefined. These are authored numerical fixtures, not human training labels.

## Validation and source accounting

Read the module index and accepted calibration specification/amendments before
edits. Reviewed historical PR #176 head
`597a8b106491cd587cedf1273ee5ef6d56d71508` file list and calibration-spec tail:
that work concerns preregistration/replay/persistence and includes no metric
implementation to port. Its source receipts and frozen protocol are preserved.
The invariant clarification was written before the implementation change.

`env -u PYTEST_ADDOPTS PYTHONPATH="$PWD/src" QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_calibration_invariants_20261105.py tests/test_calibration_metrics.py tests/test_calibration_cv.py tests/test_calibration_tools.py`

**71 passed in 43.90 s.** This includes existing synthetic math/pipeline checks;
no actual corpus was opened and no real model was trained or promoted.
`python -m ruff check src tests tools` and `git diff --check` passed. No serialized
model/schema fields changed and no new module or dependency was introduced.

## Remaining gates and limits

Independent review and publication are coordinator-owned. Existing complete
PR #205 qualification was not restarted or interrupted. No real binary
matching precision, calibration, corpus availability, model promotion,
preregistration approval, final evaluation, native or Windows gate is claimed.
The primary fixed-width ECE, selection thresholds, claim gates and shipped
runtime are unchanged. These repairs do not add general handling for arbitrary
floating-point overflow across the full metric library.
