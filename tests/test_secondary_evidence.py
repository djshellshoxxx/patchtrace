"""Evidence fusion regression tests: disagreement overrides apparent consensus."""
from patchtrace.secondary.evidence import assess_reports
from patchtrace.secondary.reconcile import Reconciliation, ReconciliationReport


def _report(engine, entries):
    return ReconciliationReport(engine, 'test', tuple(
        Reconciliation(key, status, 0x1000, 0x2000, (), status)
        for key, status in entries), (), ())


def test_disagreement_blocks_two_engine_majority():
    reports = (_report('bindiff', [('m1', 'disagreement')]),
               _report('rz-diff', [('m1', 'agreement')]))
    result = assess_reports(reports).rows[0]
    assert result.verdict == 'contested'
    assert result.tier == 'low'
    assert result.evidence_index == 0
    assert result.contradicting_engines == ('bindiff',)


def test_absence_is_not_negative_evidence():
    result = assess_reports((_report('bindiff', [('m', 'absent')]),)).rows[0]
    assert result.verdict == 'single-engine'
    assert result.contradicting_engines == ()
    assert result.missing_engines == ('bindiff',)


def test_agreement_is_capped_uncalibrated_and_not_a_probability():
    result = assess_reports((_report('bindiff', [('m', 'agreement')]),
                             _report('rz-diff', [('m', 'agreement')]))).rows[0]
    assert result.verdict == 'corroborated'
    assert result.evidence_index == 83
    assert 'uncalibrated' in result.explanation


def test_noncomparable_abstains():
    result = assess_reports((_report('bindiff', [('m', 'not-comparable')]),)).rows[0]
    assert result.verdict == 'insufficient'
    assert result.evidence_index is None


def test_reject_duplicate_engines_and_different_match_sets():
    import pytest
    first = _report('bindiff', [('m', 'agreement')])
    with pytest.raises(ValueError):
        assess_reports((first, first))
    with pytest.raises(ValueError):
        assess_reports((first, _report('rz-diff', [('other', 'agreement')])))


def test_empty_is_explicitly_unassessed():
    result = assess_reports(())
    assert not result.rows
    assert result.warnings
