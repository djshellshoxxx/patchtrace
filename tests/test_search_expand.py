"""WB1 S4: live pair expansion and locator checks."""
from __future__ import annotations

import pytest
from search_builders import make_service

from patchtrace.search import expand
from patchtrace.search.contracts import Attention, Locator
from patchtrace.search.errors import SearchError


@pytest.fixture
def project(tmp_path):
    return make_service(tmp_path / 'project').project


def test_index_resolves_functions_and_names_to_their_pairing(project):
    index = expand.PairIndex.build(project, None)
    assert index.run_id == 'run-1'
    assert index.match_of('f-new-fmt').id == 'm-mod' and index.match_of('m-add').id == 'm-add'
    assert index.by_name[('older', 'RtlCopyMemoryHelper')].id == 'm-rem'
    assert index.at_address(0x140001f00) == ('f-new-chk',)
    assert expand.PairIndex.build(project, 'missing-run').matches == {}


def test_a_name_in_two_pairings_is_not_resolved_by_name(project):
    clone = project.matches[1].model_copy(deep=True)
    clone.id = 'm-add-2'
    for record in clone.newer:
        record.id += '-2'
    project.matches.append(clone)
    assert ('newer', 'CheckLength') not in expand.PairIndex.build(project, None).by_name


def test_expansion_lists_every_counterpart_and_never_invents_a_rank(project):
    modified = project.matches[0]
    shown = expand.expansion(modified, None)
    assert shown.category == 'modified' and {r.side for r in shown.counterparts} == {'older', 'newer'}
    assert shown.attention is None and shown.limitations == (expand.ATTENTION_UNAVAILABLE,)
    ranked = expand.expansion(modified, Attention(rank=2, of=5), 'ignored')
    assert ranked.attention.rank == 2 and ranked.limitations == ()
    unchanged = next(m for m in project.matches if m.category == 'unchanged')
    assert expand.expansion(unchanged, None).limitations == ()
    assert expand.expansion(modified, None, 'Stored ranking is stale.').limitations == ('Stored ranking is stale.',)


def test_locator_is_validated_against_the_live_function(project):
    index = expand.PairIndex.build(project, None)
    locator = expand.function_locator(index, 'f-old-fmt')
    assert (locator.side, locator.run_id, locator.function_id) == ('older', 'run-1', 'f-old-fmt')
    expand.validate_locator(index, locator)
    project.matches[0].older[0].code = 'int FormatLine(int v) { return 0; }'
    with pytest.raises(SearchError) as stale:
        expand.validate_locator(expand.PairIndex.build(project, None), locator)
    assert stale.value.code == 'PT-SEARCH-LOCATOR' and stale.value.recoverable


@pytest.mark.parametrize('changes', [{'side': 'newer'}, {'function_id': 'f-gone'}, {'run_id': 'run-9'}],
                         ids=['side', 'function', 'run'])
def test_locator_with_another_side_function_or_run_is_refused(project, changes):
    index = expand.PairIndex.build(project, None)
    wrong = expand.function_locator(index, 'f-old-fmt').model_copy(update=changes)
    with pytest.raises(SearchError):
        expand.validate_locator(index, wrong)


def test_non_function_locators_and_unknown_subjects_pass_through(project):
    index = expand.PairIndex.build(project, None)
    assert expand.function_locator(index, 'nope') is None
    expand.validate_locator(index, Locator(scheme='note', source_ref='ann#0'))


def test_rename_candidates_are_removed_and_added_names_only(project):
    older, newer = expand.rename_candidates(expand.PairIndex.build(project, None))
    assert [r.name for r in older] == ['RtlCopyMemoryHelper']
    assert [r.name for r in newer] == ['CheckLength', 'FUN_140002000']
