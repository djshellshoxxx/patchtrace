"""Hand-computed R1 audit populations; synthetic records are not engine evidence."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import research_audit as R  # noqa: E402
from tools.calibration.tier_r import schemas as S  # noqa: E402


@pytest.fixture
def audit():
    return R


def document(pair='one', **changes):
    doc = S.example_labels()
    doc.update(pair_id=pair, project=pair, lineage=f'L-{pair}', case={})
    for side in ('older', 'newer'):
        for field in ('sha256', 'debug_sha256'):
            doc[side][field] = hashlib.sha256(f'{pair}-{side}-{field}'.encode()).hexdigest()
        doc[side]['source']['suite'] = f'ours/{pair}'
    doc.update(changes)
    return C.load_labels(C.dump_json(C.finalize_labels(doc)))


def test_all_truth_material_denominator_includes_missing_correspondences(audit):
    labels = document()
    result = audit.supplemental_metrics(labels, [(0x1000, 0x1000, False)])
    assert result['counts']['identity_tp'] == 1
    assert result['counts']['identity_fp'] == 0
    assert result['counts']['identity_fn'] == 2
    assert result['denominators']['material_truth_pairs'] == 1
    assert result['rates']['material_detection_recall'] == 0.0
    assert result['counts']['material_unmatched'] == 1
    assert result['rates']['identity_f1'] == 0.5
    assert result['rates']['identity_recall'] == pytest.approx(1 / 3)
    assert result['rates']['correspondence_false_positive_rate'] is None
    assert result['counts']['unmatched_endpoints'] == 6
    assert result['denominators']['eligible_endpoints'] == 8


def test_unknown_and_conflicting_duplicate_verdicts_preserve_identity(audit):
    labels = document()
    predictions = [(0x1010, 0x1010, True), (0x1010, 0x1010, False), (0x1010, 0x1010, True),
                   (0x1000, 0x1000, None), (0x1020, 0x1030, False)]
    result = audit.supplemental_metrics(labels, predictions)
    assert result['counts']['identity_tp'] == 3
    assert result['counts']['identity_fn'] == 0
    assert result['counts']['conflicting_pairs'] == 1
    assert result['counts']['duplicate_observations'] == 2
    assert result['counts']['unknown_change_pairs'] == 2
    assert result['counts']['material_unknown'] == 1
    assert result['counts']['material_detected'] == 0
    assert result['rates']['unknown_change_rate'] == pytest.approx(2 / 3)
    assert result == audit.supplemental_metrics(labels, reversed(predictions))


def test_wrong_edges_and_unlabelled_predictions_have_separate_denominators(audit):
    labels = document()
    result = audit.supplemental_metrics(labels, [(0x1010, 0x1010, True), (0x1000, 0x1030, True),
                                               (0x1040, 0x1050, False), (0x9000, 0x9000, True),
                                               (0x1020, None, None)])
    assert result['counts']['identity_tp'] == 1
    assert result['counts']['identity_fp'] == 2
    assert result['counts']['identity_fn'] == 2
    assert result['counts']['unlabelled_predictions'] == 1
    assert result['counts']['explicit_unpaired_endpoints'] == 1
    assert result['rates']['identity_precision'] == pytest.approx(1 / 3)
    assert result['rates']['false_discovery_rate'] == pytest.approx(2 / 3)
    assert result['rates']['material_detection_recall'] == 1.0


def test_implicit_omission_never_invents_explicit_correspondences(audit):
    labels = document()
    result = audit.supplemental_metrics(labels, [], implicit_unchanged=True)
    assert result['counts']['identity_tp'] == 0
    assert result['counts']['identity_fn'] == 3
    assert result['rates']['identity_precision'] is None
    assert result['rates']['identity_recall'] == 0.0
    assert result['implicit_unchanged_requested'] is True


def test_ambiguous_truth_is_counted_but_never_correct_or_wrong(audit):
    doc = document().model_dump(mode='json')
    next(f for f in doc['functions'] if f['old_rva'] == 0x1000).update(label='ambiguous')
    labels = C.load_labels(C.dump_json(C.finalize_labels(doc)))
    result = audit.supplemental_metrics(labels, [(0x1000, 0x1000, True)])
    assert result['counts']['ambiguous_truth_records'] == 1
    assert result['counts']['ambiguous_predictions'] == 1
    assert result['counts']['identity_fp'] == result['counts']['identity_tp'] == 0
    assert result['denominators']['truth_pairs'] == 2
    assert result['rates']['truth_ambiguity_rate'] == 0.2


def test_empty_truth_has_undefined_rates_and_preserves_unlabelled_observations(audit):
    labels = document(functions=[])
    result = audit.supplemental_metrics(labels, [(0x1000, 0x2000, None)])
    assert result['counts']['unlabelled_predictions'] == 1
    assert result['counts']['identity_tp'] == result['counts']['identity_fp'] == 0
    assert all(value is None for value in result['rates'].values())


def test_unknown_and_known_duplicate_conflict_is_conservative(audit):
    result = audit.supplemental_metrics(document(), [(0x1010, 0x1010, None), (0x1010, 0x1010, True)])
    assert result['counts']['identity_tp'] == 1
    assert result['counts']['conflicting_pairs'] == result['counts']['material_unknown'] == 1
    assert result['rates']['material_detection_recall'] == 0.0


@pytest.mark.parametrize('prediction', [(None, None, None), (True, 5, True), (-1, 5, True),
                                      (5, 6, 1), (5, 6, 'false'), (2**32, 6, None)])
def test_malformed_predictions_fail_closed(audit, prediction):
    with pytest.raises(ValueError):
        audit.supplemental_metrics(document(), [prediction])


def test_disjoint_partitions_pass_and_order_is_irrelevant(audit):
    one, two = document('one'), document('two')
    roles = {'one': 'dev', 'two': 'validation'}
    result = audit.audit_partitions([one, two], roles)
    assert result['passed'] is True
    assert result['findings'] == []
    assert result == audit.audit_partitions([two, one], roles)


@pytest.mark.parametrize('shared', ['project', 'lineage', 'artifact', 'source', 'mutation-template',
                                   'source-mutation', 'nested-template'])
def test_each_declared_identity_cannot_cross_roles(audit, shared):
    one = document('one')
    doc = document('two').model_dump(mode='json')
    if shared in ('project', 'lineage'):
        doc[shared] = getattr(one, shared)
    elif shared == 'artifact':
        doc['newer']['debug_sha256'] = one.older.sha256
    elif shared == 'source':
        doc['newer']['source'] = one.older.source.model_dump(mode='json')
    elif shared == 'source-mutation':
        first = one.model_dump(mode='json')
        first['older']['source']['mutation'] = doc['newer']['source']['mutation'] = 'same-mutant'
        one = C.load_labels(C.dump_json(C.finalize_labels(first)))
    else:
        first = one.model_dump(mode='json')
        case = ({'mutation': {'operator': 'const-change'}} if shared == 'nested-template' else
                {'mutation_template': 'shared-constant-template'})
        first['case'].update(case)
        one = C.load_labels(C.dump_json(C.finalize_labels(first)))
        doc['case'].update(case)
    two = C.load_labels(C.dump_json(C.finalize_labels(doc)))
    result = audit.audit_partitions([one, two], {'one': 'dev', 'two': 'locked-test'})
    assert result['passed'] is False
    kind = 'mutation-template' if shared in {'source-mutation', 'nested-template'} else shared
    assert any(f['kind'] == kind and f['pair_ids'] == ['one', 'two'] for f in result['findings'])


@pytest.mark.parametrize('roles', [{}, {'one': 'dev', 'extra': 'dev'}, {'one': 'train'}, {'one': None}])
def test_partition_roles_must_cover_exact_ids_with_valid_values(audit, roles):
    with pytest.raises(ValueError):
        audit.audit_partitions([document()], roles)


def test_duplicate_pair_ids_are_rejected(audit):
    labels = document()
    with pytest.raises(ValueError, match='duplicate'):
        audit.audit_partitions([labels, labels], {'one': 'dev'})
