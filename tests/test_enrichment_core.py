"""SPEC-07 contracts, identity, views and exact attention/1 arithmetic."""
from __future__ import annotations

import subprocess
import sys

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from patchtrace.enrichment import identity
from patchtrace.enrichment.contracts import (
    DEFAULT_WEIGHTS,
    ChangeSignal,
    DetectorOutcome,
    RankingConfig,
    SignalSet,
    SourceLocation,
)
from patchtrace.enrichment.ranking import adjusted_weight, rank, score_signals

H = '0' * 64


def loc(**kw):
    base = dict(side='newer', artifact_id='a', run_id='r', function_id='f', start_line=1, end_line=1,
                excerpt_sha256=H)
    return SourceLocation(**(base | kw))


def sig(detector, confidence, group='1', pairing='p', n=0):
    pid = identity.domain_id('test-pairing', 1, pairing)
    gk = identity.domain_id('test-group', 1, group)
    sid = identity.signal_id(pid, detector, 1, gk, [{'n': n}])
    return ChangeSignal(signal_id=sid, pairing_id=pid, match_id='m-' + pairing, detector=detector,
                        detector_version=1, confidence=confidence, group_key=gk, locations=(loc(),),
                        rationale='synthetic')


def sset(pairing, signals, status='complete'):
    pid = identity.domain_id('test-pairing', 1, pairing)
    return SignalSet(pairing_id=pid, match_id='m-' + pairing, category='modified', signals=tuple(signals),
                     outcomes=(DetectorOutcome(pairing_id=pid, detector='BND', status=status),), status=status)


# --- identity -------------------------------------------------------------

def test_canonical_json_is_order_and_normalization_independent():
    assert identity.canonical_json({'b': 1, 'a': 'e\u0301'}) == identity.canonical_json({'a': '\u00e9', 'b': 1})
    assert identity.canonical_json({'a': [1, 2]}) == b'{"a":[1,2]}'


@pytest.mark.parametrize('bad', [1.0, float('nan'), float('inf'), {1: 2}, object()])
def test_canonical_json_rejects_floats_and_non_json(bad):
    with pytest.raises((TypeError, ValueError)):
        identity.canonical_json({'x': bad})


def test_domain_separation_and_side_order():
    payload = {'x': 1}
    assert identity.domain_id('a', 1, payload) != identity.domain_id('b', 1, payload)
    assert identity.domain_id('a', 1, payload) != identity.domain_id('a', 2, payload)
    assert identity.diff_id('1' * 64, '2' * 64, '3' * 64) != identity.diff_id('2' * 64, '1' * 64, '3' * 64)


def test_address_zero_is_valid_and_garbage_unknown():
    assert identity.parse_address('0x0') == 0
    assert identity.parse_address('00000000') == 0
    assert identity.parse_address('180001000') == 0x180001000
    assert identity.parse_address('EXTERNAL:0001') is None
    assert identity.parse_address(None) is None


@given(st.lists(st.dictionaries(st.text(max_size=5), st.integers(-5, 5), max_size=3), max_size=6))
def test_sorted_unique_is_permutation_invariant(items):
    assert identity.sorted_unique(items) == identity.sorted_unique(list(reversed(items)))


# --- contracts ------------------------------------------------------------

def test_contract_rejects_extra_fields_bools_and_bad_ranges():
    with pytest.raises(ValidationError):
        loc(extra=1)
    with pytest.raises(ValidationError):
        loc(start_line=True)
    with pytest.raises(ValidationError):
        loc(start_line=3, end_line=2)
    with pytest.raises(ValidationError):
        loc(address=-1)
    assert loc(address=0).address == 0


def test_ranking_config_requires_exact_integer_weights():
    RankingConfig()
    with pytest.raises(ValidationError):
        RankingConfig(weights={**DEFAULT_WEIGHTS, 'BND': 30.0})
    with pytest.raises(ValidationError):
        RankingConfig(weights={**DEFAULT_WEIGHTS, 'BND': True})
    with pytest.raises(ValidationError):
        RankingConfig(weights={**DEFAULT_WEIGHTS, 'BND': 101})
    with pytest.raises(ValidationError):
        RankingConfig(weights={k: v for k, v in DEFAULT_WEIGHTS.items() if k != 'WIL'})
    with pytest.raises(ValidationError):
        RankingConfig(weights={**DEFAULT_WEIGHTS, 'XYZ': 1})


# --- ranking arithmetic ---------------------------------------------------

def test_adjusted_weight_golden_values():
    assert adjusted_weight(30, 'strong') == 30
    assert adjusted_weight(30, 'moderate') == 21
    assert adjusted_weight(30, 'weak') == 11  # (1050+50)//100
    assert adjusted_weight(34, 'moderate') == 24  # (2380+50)//100
    assert adjusted_weight(22, 'weak') == 8  # (770+50)//100
    assert adjusted_weight(12, 'unavailable') == 0


def test_one_saturated_group_scores_50_two_independent_score_100():
    cfg = RankingConfig(weights={**DEFAULT_WEIGHTS, 'BND': 100, 'SCRUB': 100})
    score, raw, groups = score_signals([sig('BND', 'strong', '1')], cfg)
    assert (score, raw, groups[0].points) == (50, 40, 40)
    score, raw, _ = score_signals([sig('BND', 'strong', '1'), sig('SCRUB', 'strong', '2')], cfg)
    assert (score, raw) == (100, 80)


def test_group_uses_two_largest_with_quarter_bonus_capped_at_12():
    cfg = RankingConfig()
    # BND moderate 21, OVF moderate 20, VAL weak 7 in one group: 21 + min(12, 20//4=5) = 26
    signals = [sig('BND', 'moderate', 'g', n=1), sig('OVF', 'moderate', 'g', n=2), sig('VAL', 'weak', 'g', n=3)]
    score, raw, groups = score_signals(signals, cfg)
    assert (groups[0].a, groups[0].b, groups[0].points) == (21, 20, 26)
    assert raw == 26 and score == (26 * 100 + 40) // 80 == 33


def test_duplicate_signals_count_once_and_distinct_edits_add():
    cfg = RankingConfig()
    one = sig('SCRUB', 'moderate', 'g')
    assert score_signals([one, one], cfg) == score_signals([one], cfg)
    _, raw_same, _ = score_signals([sig('BND', 'moderate', 'g', n=1), sig('BND', 'moderate', 'g', n=2)], cfg)
    _, raw_distinct, _ = score_signals([sig('BND', 'moderate', 'g1'), sig('BND', 'moderate', 'g2')], cfg)
    assert raw_same == 21 + 21 // 4 and raw_distinct == 42


def test_disabled_detector_and_zero_weight_contribute_nothing():
    signals = [sig('BND', 'strong')]
    assert score_signals(signals, RankingConfig(enabled=('OVF',)))[0] == 0
    assert score_signals(signals, RankingConfig(weights={**DEFAULT_WEIGHTS, 'BND': 0}))[0] == 0


def test_rank_order_score_then_strong_groups_then_pairing_id():
    cfg = RankingConfig()
    sets = [sset('c', [sig('BND', 'moderate', pairing='c')]),
            sset('a', [sig('BND', 'moderate', pairing='a')]),
            sset('b', [sig('SCRUB', 'moderate', pairing='b')]),
            sset('z', [])]
    result = rank(sets, cfg)
    assert [e.rank for e in result.entries] == [1, 2, 3, 4]
    assert result.entries[0].match_id == 'm-b'
    tied = [e.pairing_id for e in result.entries[1:3]]
    assert tied == sorted(tied)
    assert result.entries[-1].score == 0 and result.entries[-1].evidence == 'complete'
    assert rank(list(reversed(sets)), cfg) == result


def test_unavailable_evidence_is_distinct_from_zero_signal():
    result = rank([sset('u', [], status='unavailable'), sset('z', [])], RankingConfig())
    by_match = {e.match_id: e for e in result.entries}
    assert by_match['m-u'].evidence == 'unavailable' and by_match['m-z'].evidence == 'complete'
    assert result.status == 'partial'


def test_config_change_changes_digest_only_for_semantics():
    from patchtrace.enrichment.ranking import config_digest
    assert config_digest(RankingConfig()) == config_digest(RankingConfig(enabled=tuple(reversed(RankingConfig().enabled))))
    assert config_digest(RankingConfig()) != config_digest(RankingConfig(weights={**DEFAULT_WEIGHTS, 'ERR': 13}))


@given(st.lists(st.tuples(st.sampled_from(['BND', 'INT', 'OVF', 'VAL', 'ERR', 'SIZE', 'WIL', 'SCRUB']),
                          st.sampled_from(['strong', 'moderate', 'weak', 'unavailable']),
                          st.sampled_from(['g1', 'g2', 'g3'])), max_size=12),
       st.dictionaries(st.sampled_from(sorted(DEFAULT_WEIGHTS)), st.integers(0, 100)))
def test_score_bounds_and_monotonic_in_added_groups(items, overrides):
    cfg = RankingConfig(weights={**DEFAULT_WEIGHTS, **overrides})
    signals = [sig(d, c, g, n=i) for i, (d, c, g) in enumerate(items)]
    score, raw, groups = score_signals(signals, cfg)
    assert 0 <= raw <= 80 and 0 <= score <= 100
    assert all(0 <= g.points <= 40 for g in groups)
    extra = sig('BND', 'strong', 'new-group', n=999)
    assert score_signals([*signals, extra], cfg)[0] >= score


def test_pure_modules_do_not_import_qt_network_or_subprocess():
    code = ('import sys\n'
            'import patchtrace.enrichment.contracts, patchtrace.enrichment.identity, patchtrace.enrichment.ranking\n'
            'import patchtrace.enrichment.views\n'
            'bad = [m for m in sys.modules if m.split(".")[0] in {"PySide6","urllib3","requests","ssl","subprocess","jpype","pyghidra"} or m in {"http.client","urllib.request"}]\n'
            'print(",".join(bad)); raise SystemExit(1 if bad else 0)\n')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


# --- views ----------------------------------------------------------------

def _sample(tmp_path):
    from patchtrace.service import ProjectService
    service = ProjectService.sample(tmp_path / 'sample')
    return service


def test_views_from_sample_are_deterministic_and_owned(tmp_path):
    from patchtrace.enrichment.views import build_views
    service = _sample(tmp_path)
    try:
        project = service.project
        first, second = build_views(project), build_views(project)
        assert first == second and first.matches
        modified = next(m for m in first.matches if m.category == 'modified')
        assert modified.two_sided and modified.hunks
        loc = modified.newer[0].location(1, 1)
        assert loc.excerpt_sha256 == identity.excerpt_sha256(modified.newer[0].code[:1])
    finally:
        service.close()


def test_views_reject_forged_function_ownership(tmp_path):
    from patchtrace.enrichment.contracts import EnrichmentError
    from patchtrace.enrichment.views import build_views
    service = _sample(tmp_path)
    try:
        project = service.project.model_copy(deep=True)
        match = next(m for m in project.matches if m.older and m.newer)
        match.older[0] = match.older[0].model_copy(update={'artifact_id': match.newer[0].artifact_id})
        with pytest.raises(EnrichmentError, match='OWNERSHIP'):
            build_views(project)
    finally:
        service.close()


def test_manual_rematch_changes_pairing_identity(tmp_path):
    from patchtrace.enrichment.views import build_views
    service = _sample(tmp_path)
    try:
        project = service.project.model_copy(deep=True)
        before = {m.match_id: m.pairing_id for m in build_views(project).matches}
        idx = next(i for i, m in enumerate(project.matches) if m.older and m.newer)
        project.matches[idx] = project.matches[idx].model_copy(update={'manual': True})
        after = {m.match_id: m.pairing_id for m in build_views(project).matches}
        changed = project.matches[idx].id
        assert before[changed] != after[changed]
        assert all(before[k] == after[k] for k in before if k != changed)
    finally:
        service.close()
