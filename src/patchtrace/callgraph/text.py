"""Untrusted-text sanitizer for graph labels (plain text only; never executed or interpreted)."""
from __future__ import annotations

import re

from .limits import MAX_LABEL_SHOWN, MAX_LABEL_STORED

# Same character class as secondary.evidence_view._UNSAFE (parity test); copied, not imported,
# so the package has no cross-feature import.
UNSAFE = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩  ]')
_BREAKS = str.maketrans({'\r': ' ', '\n': ' ', '\t': ' '})


def sanitize(value: object, limit: int = MAX_LABEL_STORED) -> str:
    """Single-line plain text: line breaks and tabs become spaces, controls, bidi marks and
    line separators are removed, and the result is capped at `limit` characters with '...'."""
    raw = '' if value is None else str(value)
    text = UNSAFE.sub('', raw.translate(_BREAKS))
    return text if len(text) <= limit else text[:max(0, limit - 3)] + '...'


def one_line(value: object, limit: int = MAX_LABEL_SHOWN) -> str:
    """Display variant of `sanitize` with the shown-label cap."""
    return sanitize(value, limit)
