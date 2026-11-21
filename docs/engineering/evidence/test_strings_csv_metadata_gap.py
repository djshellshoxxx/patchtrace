"""Desired-behavior counterexamples for the existing WB3 CSV metadata follow-up.

These are deliberately retained outside tests/ while the export-format contract
is unresolved. They fail against f4503de3 and are not a completed correction.
"""
from __future__ import annotations

import pytest

from patchtrace.strings.contracts import Harmonized, StringsDelta
from patchtrace.strings.export import document, export_delta


@pytest.mark.parametrize('difference', ['basis', 'truncated', 'redaction'])
def test_empty_csv_preserves_distinct_document_provenance(tmp_path, difference):
    original = StringsDelta(
        older_basis_digest='a' * 64,
        newer_basis_digest='b' * 64,
        comparable=True,
        harmonized=Harmonized(min_length=4, types=('static',)),
        counts={'only-older': 0, 'only-newer': 0},
    )
    altered = original
    reveal = None
    if difference == 'basis':
        altered = original.model_copy(update={'older_basis_digest': 'c' * 64,
                                               'newer_basis_digest': 'd' * 64})
    elif difference == 'truncated':
        altered = original.model_copy(update={'truncated': True})
    else:
        reveal = {}
    assert document(original) != document(altered, reveal=reveal)
    first = tmp_path / 'first.csv'
    second = tmp_path / 'second.csv'
    left = export_delta(original, first, fmt='csv')
    right = export_delta(altered, second, fmt='csv', reveal=reveal)
    assert left.rows == right.rows == 0
    assert first.read_bytes() != second.read_bytes(), (
        f'CSV dropped document-level {difference}; both published files have SHA-256 {left.sha256}'
    )
