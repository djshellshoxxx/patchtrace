"""WB2 G3: call-delta classes (A3), noise, API hints and the properties that keep them honest."""
from __future__ import annotations

import pytest
from callgraph_delta_support import (
    HINTS,
    analysis,
    by_label,
    class_counts,
    classes,
    modified,
    rename_defaults,
    swap_raw,
    transform,
)
from callgraph_graph_support import snapshot

from patchtrace.callgraph.apis import HintRule, RuleHints, api_hits
from patchtrace.callgraph.contracts_delta import MAX_CHANGES
from patchtrace.callgraph.delta import DeltaContext, compute_delta, compute_deltas
from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.noise import DEFAULT_HUBS, hub_flags

SVC_EXPECTED = {
    'DriverEntry': ('renumber-only', []),
    'FUN_140001500': ('renumber-only', []),
    'FUN_140001600': ('renumber-only', []),
    'FUN_140001800': ('none', [('added-call', 'ntoskrnl.exe::ProbeForRead'),
                               ('call-to-new-function', 'FUN_140001f00')]),
    'FUN_140001c00': ('hub-only', [('added-call', 'ntoskrnl.exe::EtwWriteTransfer')]),
}


@pytest.mark.parametrize('label', list(SVC_EXPECTED), ids=['entry', 'dispatch', 'format', 'parse', 'log'])
def test_svc_exact_classes_and_downgrade(label):
    _, deltas = analysis('svc_pair')
    delta = by_label(deltas, label)
    downgrade, changes = SVC_EXPECTED[label]
    assert delta.state == 'compared' and delta.downgrade == downgrade
    assert classes(delta) == changes
    assert delta.ghidriff_diff_types and 'called' in delta.ghidriff_diff_types


def test_renumber_only_is_not_a_call_change():
    _, deltas = analysis('svc_pair')
    for label in ('DriverEntry', 'FUN_140001500', 'FUN_140001600'):
        assert {c.cls for c in by_label(deltas, label).changes} == {'same-link'}


def test_import_flags_and_api_hits():
    _, deltas = analysis('svc_pair')
    probe = next(c for c in by_label(deltas, 'FUN_140001800').changes if c.newer_label.endswith('ProbeForRead'))
    assert {'import', 'newly-imported', 'api-hint'} <= set(probe.flags)
    assert [(h.rule_id, h.family, h.via) for h in probe.api] == [('R-MEMORY-READ', 'memory-read', 'rule-hint'),
                                                                 ('R-POINTER', 'pointer', 'rule-hint')]
    transfer = next(c for c in by_label(deltas, 'FUN_140001c00').changes if c.cls == 'added-call')
    assert {'hub', 'trace-helper'} <= set(transfer.flags) and not transfer.api


def test_second_call_to_same_callee_is_not_claimed():
    plain = analysis('svc_pair')[1]
    doubled = analysis('svc_pair', lambda raw: modified(raw, 'FUN_140001800')['new']['called'].append(
        'FUN_140001340'))[1]
    assert [d.changes for d in plain] == [d.changes for d in doubled]
    assert 'call counts, order and call sites are not known' in plain[0].limitations[0]


def test_missing_edge_is_unknown_not_removed():
    def mutate(raw):
        modified(raw, 'FUN_140001800')['old']['called'].append('FUN_140001abc')

    delta = by_label(analysis('svc_pair', mutate)[1], 'FUN_140001800')
    unknown = [c for c in delta.changes if c.cls == 'cannot-determine']
    assert [c.older_label for c in unknown] == ['FUN_140001abc'] and unknown[0].reason
    assert not [c for c in delta.changes if c.cls in {'removed-call', 'callee-deleted'}]


def test_dropped_callee_still_present_is_removed_call():
    def mutate(raw):
        called = modified(raw, 'FUN_140001800')['new']['called']
        called.remove('FUN_140001340')

    delta = by_label(analysis('svc_pair', mutate)[1], 'FUN_140001800')
    assert ('removed-call', 'FUN_140001200') in classes(delta)


def test_deleted_callee_is_callee_deleted():
    def mutate(raw):
        raw['functions']['deleted'].append(
            {'name': 'FUN_140001e00', 'fullname': 'FUN_140001e00', 'address': '140001e00', 'code': None,
             'calling': ['FUN_140001800'], 'called': [], 'sym_type': 'FUNCTION', 'external': False})
        modified(raw, 'FUN_140001800')['old']['called'].append('FUN_140001e00')

    delta = by_label(analysis('svc_pair', mutate)[1], 'FUN_140001800')
    assert ('callee-deleted', 'FUN_140001e00') in classes(delta)


def test_without_raw_matches_unmapped_renumbering_is_cannot_determine_never_added():
    _, deltas = analysis('svc_pair', with_raw=False)
    delta = by_label(deltas, 'FUN_140001500')
    assert classes(delta) == [('cannot-determine', 'FUN_140001200'), ('cannot-determine', 'FUN_140001340')]
    assert not class_counts(deltas)['removed-call'] and not class_counts(deltas)['callee-deleted']


def test_second_known_answer_sample_pair():
    _, deltas = analysis('no_matches')
    assert classes(by_label(deltas, 'read_item')) == [('call-to-new-function', 'report_invalid_index')]
    assert by_label(deltas, 'get_version').state == 'unavailable'


@pytest.mark.parametrize('category,state', [('added', 'one-sided'), ('removed', 'one-sided')],
                         ids=['added', 'removed'])
def test_one_sided_state_for_added_and_removed(category, state):
    snap = snapshot('no_matches')
    match_id = next(p.match_id for p in snap.data.pairs if p.category == category)
    delta = compute_delta(snap, match_id)
    assert delta.state == state and not delta.changes


def test_unknown_match_id_is_an_input_error():
    with pytest.raises(GraphError) as caught:
        compute_delta(snapshot('svc_pair'), 'nope')
    assert caught.value.code == 'PT-GRAPH-INPUT'


def test_changes_are_capped_and_the_rest_counted():
    many = [f'FUN_1400{index:05x}' for index in range(MAX_CHANGES + 20)]
    delta = by_label(analysis('svc_pair', lambda raw: modified(raw, 'FUN_140001800')['new']['called'].extend(many))[1],
                     'FUN_140001800')
    assert len(delta.changes) == MAX_CHANGES and delta.omitted > 0
    assert delta.changes[0].cls == 'call-to-new-function'  # real changes sort ahead of the cut


def test_cancel_is_checked_while_computing():
    snap = snapshot('svc_pair')
    with pytest.raises(GraphError) as caught:
        compute_deltas(snap, DeltaContext(), cancel=lambda: True)
    assert caught.value.code == 'PT-GRAPH-CANCEL'


def test_callers_counts_are_context():
    delta = by_label(analysis('svc_pair')[1], 'FUN_140001800')
    assert (delta.callers_listed_older, delta.callers_listed_newer) == (1, 1)


# ---- properties ---------------------------------------------------------------------------------------

def _drop_one_callee(raw):
    modified(raw, 'FUN_140001800')['new']['called'].remove('FUN_140001340')


@pytest.mark.parametrize('mutate', [None, _drop_one_callee], ids=['svc', 'svc-with-removal'])
def test_swap_orientation_swaps_added_and_removed(mutate):
    def swapped_mutate(raw):
        if mutate is not None:
            mutate(raw)
        transform(swap_raw)(raw)

    original = class_counts(analysis('svc_pair', mutate)[1])
    swapped = class_counts(analysis('svc_pair', swapped_mutate)[1])
    gained = lambda counts: counts['added-call'] + counts['call-to-new-function']  # noqa: E731
    lost = lambda counts: counts['removed-call'] + counts['callee-deleted']  # noqa: E731
    assert gained(original) > 0
    assert (gained(swapped), lost(swapped)) == (lost(original), gained(original))
    assert (swapped['same-link'], swapped['cannot-determine']) == (original['same-link'],
                                                                    original['cannot-determine'])


def test_rename_invariance_of_default_names():
    plain = analysis('svc_pair')[1]
    renamed = analysis('svc_pair', transform(rename_defaults))[1]
    assert [sorted(c.cls for c in d.changes) for d in plain] == [sorted(c.cls for c in d.changes) for d in renamed]
    assert [d.downgrade for d in plain] == [d.downgrade for d in renamed]


# ---- noise and hints ----------------------------------------------------------------------------------

@pytest.mark.parametrize('label,fan_in,expected', [
    ('ntoskrnl.exe::EtwWriteTransfer', 0, ('hub', 'trace-helper')),
    ('TraceLoggingWrite', 0, ('hub', 'trace-helper')),
    ('__security_check_cookie', 0, ('hub',)),
    ('Plain', 63, ()),
    ('Plain', 64, ('hub',)),
    ('etwwrite', 0, ()),
], ids=['etw', 'tlg', 'cookie', 'fan63', 'fan64', 'case'])
def test_hub_flags(label, fan_in, expected):
    assert hub_flags(DEFAULT_HUBS, label, fan_in) == expected


def test_hub_registry_is_data_with_provenance():
    assert DEFAULT_HUBS.contract == 'hub-registry/1'
    assert all(rule.source and rule.retrieved for rule in DEFAULT_HUBS.rules)


def test_api_variants_a_w_and_no_port():
    port = RuleHints([HintRule('R-FILE', '2', 'file', ('CreateFile',))])
    assert [h.api for h in api_hits(port, 'kernel32.dll::CreateFileW')] == ['CreateFile']
    assert api_hits(port, 'kernel32.dll::CreateFileExW') == ()
    assert api_hits(port, 'Plain') == () and api_hits(None, 'k.dll::CreateFile') == ()
    assert HINTS.hints('ProbeForRead') and not HINTS.hints('Nope')


def test_hub_downgrade_needs_every_change_to_be_a_hub():
    def mutate(raw):
        modified(raw, 'FUN_140001c00')['new']['called'].append('FUN_140001f00')

    delta = by_label(analysis('svc_pair', mutate)[1], 'FUN_140001c00')
    assert delta.downgrade == 'none'

