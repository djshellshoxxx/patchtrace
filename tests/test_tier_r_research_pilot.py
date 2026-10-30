"""Research selection and observation invariants; no substitute is native evidence."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import research_pilot as P
from tools.calibration.tier_r.schemas import example_labels


def labels():
    return C.load_labels(C.dump_json(C.finalize_labels(example_labels())))


def review(doc):
    keys = [P.function_key(f) for f in doc.functions]
    return {'pair_id': doc.pair_id, 'labels_digest_sha256': doc.digest_sha256,
            'reviewer': 'independent automated test reviewer', 'review_kind': 'test-only',
            'accepted_keys': keys[1:], 'ambiguous_keys': keys[:1], 'evidence': ['synthetic test']}


def test_review_selection_is_bound_and_does_not_rewrite_original_truth():
    doc = labels()
    before = doc.model_dump(mode='json')
    selected, scope = P.select_truth(doc, review(doc))
    assert doc.model_dump(mode='json') == before
    assert selected.functions[0].identity == 'ambiguous'
    assert selected.functions[0].label == 'ambiguous'
    assert scope['status'] == 'reviewed-selection'
    assert scope['original_labels_sha256'] == doc.digest_sha256
    assert len(selected.functions) == len(doc.functions)


@pytest.mark.parametrize('damage', ['digest', 'pair', 'unknown', 'overlap', 'duplicate', 'reviewer', 'incomplete'])
def test_invalid_acceptance_cannot_promote_candidates(damage):
    doc = labels()
    item = review(doc)
    if damage == 'digest':
        item['labels_digest_sha256'] = '0' * 64
    elif damage == 'pair':
        item['pair_id'] = 'different'
    elif damage == 'unknown':
        item['accepted_keys'][0] = [None, 'invented', None, 1, 2]
    elif damage == 'overlap':
        item['ambiguous_keys'] += item['accepted_keys'][:1]
    elif damage == 'duplicate':
        item['accepted_keys'] *= 2
    elif damage == 'reviewer':
        item['reviewer'] = ''
    else:
        item['accepted_keys'] = item['accepted_keys'][:-1]
    with pytest.raises(ValueError):
        P.select_truth(doc, item)


def test_no_review_means_exploratory_not_accepted():
    doc = labels()
    selected, scope = P.select_truth(doc, None)
    assert selected is doc
    assert scope['status'] == 'exploratory-candidates'


def row(old, new, decision, materiality='unknown'):
    return SimpleNamespace(older=tuple(old), newer=tuple(new), decision=decision, materiality=materiality)


def test_unified_only_unique_matched_decisions_enter_correspondence_metrics():
    rows = [row([1], [2], 'matched', 'material'), row([3], [4], 'matched', 'review'),
            row([5], [6], 'matched', 'cosmetic'), row([7], [], 'older-only'),
            row([], [8], 'newer-only'), row([9], [10], 'tentative', 'material'),
            row([11], [12], 'contested'), row([13], [14, 15], 'matched')]
    observations, coverage = P.unified_observations(rows)
    assert observations == [(1, 2, True), (3, 4, None), (5, 6, False), (7, None, None), (None, 8, None)]
    assert coverage['abstained_rows'] == 3
    assert coverage['rows'] == 8
    assert coverage['decisions']['tentative'] == 1


def test_wrong_project_binding_fails_before_reusing_primary():
    doc = labels()
    project = SimpleNamespace(artifacts=[SimpleNamespace(side='older', sha256='0' * 64),
                                         SimpleNamespace(side='newer', sha256=doc.newer.sha256)])
    with pytest.raises(ValueError, match='artifact'):
        P.verify_project(doc, project)


def test_unknown_matched_materiality_is_abstention_on_change():
    observations, _ = P.unified_observations([row([1], [2], 'matched', 'not-applicable')])
    assert observations == [(1, 2, None)]
