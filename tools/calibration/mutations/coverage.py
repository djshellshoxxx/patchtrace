"""Planted-mutation coverage per weakness class (audit 20261014-C, finding D1).

Each SEMANTIC operator is mapped to the CWE class its change most resembles (MITRE CWE, https://cwe.mitre.org).
This is a PROJECT HEURISTIC for coverage accounting only: a planted comparison flip is "an incorrect comparison",
not a claim that the mutant is an exploitable vulnerability. COSMETIC operators are hard negatives (the function
changed on disk but not in meaning) and are reported separately: a corpus needs both sides, or the engine
evaluation rewards "flag everything" / "flag nothing".
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .contracts import COSMETIC_OPERATORS, SEMANTIC_OPERATORS

OPERATOR_CWE: dict[str, str] = {
    'cmp-flip': 'CWE-697',            # Incorrect Comparison
    'const-change': 'CWE-682',        # Incorrect Calculation
    'bounds-check-insert': 'CWE-119',  # Improper Restriction of Operations within the Bounds of a Memory Buffer
    'bounds-check-remove': 'CWE-119',
    'call-add': 'CWE-670',            # Always-Incorrect Control Flow Implementation
    'call-remove': 'CWE-670',
    'arg-swap': 'CWE-683',            # Function Call With Incorrect Order of Arguments
    'loop-bound': 'CWE-193',          # Off-by-one Error
    'off-by-one': 'CWE-193',
    'int-width': 'CWE-681',           # Incorrect Conversion between Numeric Types
    'signedness-flip': 'CWE-195',     # Signed to Unsigned Conversion Error
    'callee-swap': 'CWE-628',         # Function Call with Incorrectly Specified Arguments
    'field-offset': 'CWE-188',        # Reliance on Data/Memory Layout
    'global-swap': 'CWE-682',
    'index-swap': 'CWE-129',          # Improper Validation of Array Index
    'branch-swap': 'CWE-670',
    'buf-resize': 'CWE-131',          # Incorrect Calculation of Buffer Size
    'string-literal': 'CWE-547',      # Use of Hard-coded, Security-relevant Constants
    'api-use': 'CWE-676',             # Use of Potentially Dangerous Function
}
CWE_CLASSES = tuple(sorted(set(OPERATOR_CWE.values())))
MIN_PER_CLASS = 5


def coverage(planted: Iterable[str], *, min_per_class: int = MIN_PER_CLASS) -> dict:
    """`planted` = operator name of each ACCEPTED planted case. Returns per-class counts, classes with no mutant
    (`missing`), classes with fewer than `min_per_class` (`thin`), and the hard-negative (cosmetic) count."""
    ops = list(planted)
    unknown = sorted({o for o in ops if o not in OPERATOR_CWE and o not in COSMETIC_OPERATORS})
    if unknown:
        raise ValueError(f'unknown operators: {unknown}')
    counts = Counter(OPERATOR_CWE[o] for o in ops if o in OPERATOR_CWE)
    per_class = {c: counts.get(c, 0) for c in CWE_CLASSES}
    return {'per_class': per_class, 'missing': [c for c, n in per_class.items() if n == 0],
            'thin': [c for c, n in per_class.items() if 0 < n < min_per_class],
            'semantic': sum(counts.values()), 'hard_negatives': sum(1 for o in ops if o in COSMETIC_OPERATORS),
            'complete': all(n >= min_per_class for n in per_class.values())}


def unmapped_operators() -> list[str]:
    """Semantic operators without a class (must stay empty; a test pins it)."""
    return [o for o in SEMANTIC_OPERATORS if o not in OPERATOR_CWE]
