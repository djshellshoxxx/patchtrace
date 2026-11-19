"""Raw-observation parsing only: all nonempty PDiff examples are synthetic, never native accuracy evidence."""
from __future__ import annotations

import pytest

from tools.calibration.tier_r.research_observers import ghidriff_image_projection, ghidriff_observations

OLD, NEW = 0x140000000, 0x180000000


def raw(table=None, *, modified=(), added=(), deleted=()):
    return {'matches': {'address_matches': table or {}, 'name_matches': {}},
            'functions': {'modified': list(modified), 'added': list(added), 'deleted': list(deleted)}}


def test_observed_pairs_use_each_side_base_and_never_infer_unchanged():
    document = raw({'140001000': [['180002000', ['ExactBytesFunctionHasher']]],
                    'ram:140001010': [['ram:180002010', ['SymbolsHash']]]})
    assert ghidriff_observations(document, old_base=OLD, new_base=NEW) == [
        (0x1000, 0x2000, None), (0x1010, 0x2010, None)]


def test_explicit_modified_and_unmatched_functions_preserve_engine_change_signals():
    document = raw({'140001000': [['180002000', ['SymbolsHash']]]}, modified=[
        {'old': {'address': '140001000'}, 'new': {'address': '180002000'}, 'diff_type': ['address']}],
        added=[{'address': '180002100', 'name': 'added'}], deleted=[{'address': '140001100', 'name': 'deleted'}])
    assert set(ghidriff_observations(document, old_base=OLD, new_base=NEW)) == {
        (0x1000, 0x2000, True), (None, 0x2100, True), (0x1100, None, True)}


def test_repeated_same_pair_evidence_collapses_without_creating_ambiguity():
    document = raw({'140001000': [['180002000', ['A']], ['180002000', ['B']]]}, modified=[
        {'old': {'address': '140001000'}, 'new': {'address': '180002000'}}])
    assert ghidriff_observations(document, old_base=OLD, new_base=NEW) == [(0x1000, 0x2000, True)]


@pytest.mark.parametrize('document', [
    raw({'140001000': [['180002000', []], ['180002100', []]]}),
    raw({'140001000': [['180002000', []]], '140001100': [['180002000', []]]}),
    raw({'140001000': [['180002000', []]]}, deleted=[{'address': '140001000'}]),
    raw({'140001000': [['180002000', []]]}, added=[{'address': '180002000'}]),
    raw({'140001000': [['180002000', []]]}, modified=[
        {'old': {'address': '140001000'}, 'new': {'address': '180002100'}}]),
])
def test_ambiguous_or_conflicting_identity_is_rejected_instead_of_scored_as_unique(document):
    with pytest.raises(ValueError, match='ambiguous|conflicting'):
        ghidriff_observations(document, old_base=OLD, new_base=NEW)


@pytest.mark.parametrize('document', [None, {}, raw({'140001000': ['180002000']}),
    raw({'140001000': [['180002000', 'not-a-list']]}), raw({'garbage': [['180002000', []]]}),
    raw({'140001000': [[True, []]]}), raw({'13fffffff': [['180002000', []]]}),
    raw({'140001000': [['280000000', []]]}), raw(modified=[{'old': {}, 'new': {'address': '180002000'}}]),
    {'matches': {'address_matches': {}}, 'functions': {'modified': [], 'added': {}, 'deleted': []}},
])
def test_malformed_or_unrepresentable_observations_are_rejected(document):
    with pytest.raises(ValueError):
        ghidriff_observations(document, old_base=OLD, new_base=NEW)


@pytest.mark.parametrize('base', [True, -1, 2**64, '0x140000000'])
def test_invalid_explicit_bases_are_rejected(base):
    with pytest.raises(ValueError):
        ghidriff_observations(raw(), old_base=base, new_base=NEW)


def test_empty_native_preflight_sample_shape_produces_no_fabricated_observations():
    # Shape observed in the genuine zero-function preflight PDiff; no archived binary/raw text is copied.
    document = {'program_options': {}, 'matches': {'address_matches': {}, 'name_matches': {}}, 'stats': {},
                'symbols': {}, 'strings': {}, 'functions': {'added': [], 'deleted': [], 'modified': []},
                'old_meta': {}, 'new_meta': {}, 'md_credits': '', 'html_credits': ''}
    assert ghidriff_observations(document, old_base=OLD, new_base=NEW) == []


def test_input_row_budget_is_enforced_before_parsing(monkeypatch):
    from tools.calibration.tier_r import research_observers
    monkeypatch.setattr(research_observers, 'MAX_FUNCTIONS', 1)
    with pytest.raises(ValueError, match='limit'):
        ghidriff_observations(raw(added=[{'address': '180002000'}, {'address': '180002100'}]),
                              old_base=OLD, new_base=NEW)


def test_native_cjson_namespace_shape_is_projected_with_explicit_unscored_coverage():
    # Genuine native shape:268 keys=221 image+47 external and2 modified. This minimal analogue has3=2+1.
    from copy import deepcopy
    document = raw({'180002b80': [['180002b80', ['SymbolsHash']]],
                    '180003ab0': [['180003ac0', ['SymbolsHash']]],
                    'EXTERNAL:00000011': [['EXTERNAL:00000011', ['SymbolsHash', 'ExternalsName']]]},
                   modified=[{'old': {'address': '180002b80'}, 'new': {'address': '180002b80'}},
                             {'old': {'address': '180003ab0'}, 'new': {'address': '180003ac0'}}])
    before = deepcopy(document)
    projected, coverage = ghidriff_image_projection(document)
    assert document == before and projected['functions'] == document['functions']
    assert coverage['address_keys'] == {'input': 3, 'image': 2, 'external': 1}
    assert coverage['address_edges'] == {'input': 3, 'image': 2, 'external': 1}
    assert ghidriff_observations(projected, old_base=NEW, new_base=NEW) == [
        (0x2b80, 0x2b80, True), (0x3ab0, 0x3ac0, True)]


@pytest.mark.parametrize('table', [
    {'EXTERNAL:garbage': [['EXTERNAL:00000001', []]]},
    {'EXTERNAL:00000001': [['180002000', []]]},
    {'180002000': [['EXTERNAL:00000001', []]]},
    {'UNKNOWN:00000001': [['UNKNOWN:00000001', []]]},
    {'EXTERNAL:00000001': [['EXTERNAL:00000001', 'malformed-types']]},
    {'EXTERNAL:00000001': [['EXTERNAL:00000001']]},
])
def test_projection_rejects_unknown_malformed_or_cross_namespace_edges(table):
    with pytest.raises(ValueError):
        ghidriff_image_projection(raw(table))


@pytest.mark.parametrize('document', [
    raw(modified=[{'old': {'address': 'EXTERNAL:00000001'}, 'new': {'address': 'EXTERNAL:00000001'}}]),
    raw(added=[{'address': 'EXTERNAL:00000001'}]),
    raw(deleted=[{'address': 'EXTERNAL:00000001'}]),
])
def test_projection_explicitly_rejects_external_function_change_records(document):
    with pytest.raises(ValueError, match='external function'):
        ghidriff_image_projection(document)


def test_projection_enforces_edge_budget_including_unscored_externals(monkeypatch):
    from tools.calibration.tier_r import research_observers
    monkeypatch.setattr(research_observers, 'MAX_PREDICTIONS', 1)
    with pytest.raises(ValueError, match='limit'):
        ghidriff_image_projection(raw({'EXTERNAL:1': [['EXTERNAL:1', []], ['EXTERNAL:1', []]]}))
