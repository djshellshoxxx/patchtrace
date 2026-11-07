"""How many independently labeled cases does an accuracy claim need? (reuses the repo's exact binomial bound)

More cases do not make a tool more accurate; they make the measurement of its accuracy tighter. The one-sided
exact (Clopper-Pearson) lower bound on accuracy after `correct` of `n` independent cases is what a claim like
"at least 90%" can honestly rest on. Cases from the same project, binary or release are NOT independent: count
the effective n (for example distinct projects), not the raw case count.
"""
from __future__ import annotations

from tools.calibration.stats import clopper_pearson_upper


def lower_bound(correct: int, n: int, alpha: float = 0.05) -> float:
    """One-sided (1 - alpha) exact lower confidence bound on accuracy."""
    if n <= 0 or not 0 <= correct <= n:
        raise ValueError('need n > 0 and 0 <= correct <= n')
    return 1.0 - clopper_pearson_upper(n - correct, n, alpha)


def min_cases(target: float, max_errors: int = 0, alpha: float = 0.05, limit: int = 10_000) -> int:
    """Smallest n whose lower bound reaches `target` when at most `max_errors` cases are wrong."""
    if target <= 0 or target >= 1 or max_errors < 0:
        raise ValueError('target must be in (0, 1) and max_errors >= 0')
    n = max_errors + 1
    while n <= limit:
        if lower_bound(n - max_errors, n, alpha) >= target:
            return n
        n += 1
    raise ValueError(f'target {target} is not reachable within {limit} cases for {max_errors} errors')


def table(ns: tuple[int, ...] = (15, 29, 50, 75, 100), errors: tuple[int, ...] = (0, 1, 2, 3, 5),
          alpha: float = 0.05) -> dict:
    rows = {str(n): {str(e): round(lower_bound(n - e, n, alpha), 3) for e in errors if e <= n} for n in ns}
    needed = {f'{t:.2f}': {str(e): min_cases(t, e, alpha) for e in errors[:4]} for t in (0.80, 0.90, 0.95)}
    return {'alpha': alpha, 'lower_bound_by_n_and_errors': rows, 'min_cases_for_target_by_errors': needed,
            'note': 'effective n counts independent sources (projects), not cases; stratify and report by class'}
