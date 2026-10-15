"""WB2 section 5: the synthetic `svc` known answer, where the call graph beats each channel alone."""
from __future__ import annotations

import pytest
from callgraph_delta_support import Entries, analysis, by_label, swap_raw, transform

from patchtrace.callgraph import contracts, contracts_delta
from patchtrace.callgraph.leads import build_leads, signals_for

# Recorded detector channel (a fixture input; detector accuracy is not under test): ties break by RVA.
DETECTOR_ORDER = ['FUN_140001600', 'FUN_140001800']  # F (decoy) then P (real change)
BANNED_FIELDS = ('score', 'confidence', 'combined', 'probability', 'weight')


def test_known_answer_svc_pair_beats_each_channel():
    snap, deltas = analysis('svc_pair')
    called_flagged = [d for d in deltas if 'called' in d.ghidriff_diff_types]
    assert len(called_flagged) == 5
    assert [d.downgrade for d in called_flagged].count('renumber-only') == 3  # `called` cleared 3 of 5

    leads = build_leads(snap, deltas, Entries('DriverEntry'))
    parser = by_label(deltas, 'FUN_140001800')
    assert leads[0].match_id == parser.match_id  # P first; the detector alone ranks the decoy F ahead
    assert DETECTOR_ORDER.index('FUN_140001600') < DETECTOR_ORDER.index('FUN_140001800')

    data_groups = {lead.match_id for lead in leads
                   if {'new-function-called', 'api-hint-called'} <= {s.id for s in lead.signals}}
    assert data_groups == {parser.match_id}
    decoys = {by_label(deltas, name).match_id for name in ('DriverEntry', 'FUN_140001500', 'FUN_140001600')}
    assert not decoys & {lead.match_id for lead in leads}  # decoys in the lead set: 0, ahead of P: 0
    assert [s.id for s in leads[1].signals] == ['hub-only']  # L: hub only, sorted after P

    api = next(s for s in leads[0].signals if s.id == 'api-hint-called')
    assert 'ProbeForRead' in api.meaning and 'R-MEMORY-READ, R-POINTER' in api.meaning
    assert 'memory-read, pointer' in api.meaning
    assert (leads[0].blast.direct_callers, leads[0].entry.hops, leads[0].entry.via) == (1, 2, 'DriverEntry')
    assert leads[0].origin.engine == 'ghidriff-lists' and leads[0].origin.run_id == snap.data.run_id


def test_no_combined_score_field_exists():
    fields = {name for module in (contracts, contracts_delta) for model in vars(module).values()
              if isinstance(model, type) and hasattr(model, 'model_fields') for name in model.model_fields}
    assert not [f for f in fields if any(word in f.lower() for word in BANNED_FIELDS)]


def test_swap_orientation_swaps_added_and_removed():
    _, original = analysis('svc_pair')
    _, swapped = analysis('svc_pair', transform(swap_raw))
    parser = {c.cls for c in by_label(original, 'FUN_140001800').changes}
    assert {'call-to-new-function', 'added-call'} <= parser
    flipped = {c.cls for d in swapped for c in d.changes if c.cls != 'same-link'}
    assert flipped == {'callee-deleted'}  # the new function and the new import are the dropped ones now


def test_second_known_answer_without_a_matches_section():
    snap, deltas = analysis('no_matches')
    leads = build_leads(snap, deltas)
    assert [by_label(deltas, 'read_item').match_id] == [lead.match_id for lead in leads]
    assert [s.id for s in leads[0].signals] == ['new-function-called']
    assert by_label(deltas, 'get_version').state == 'unavailable' and not signals_for(by_label(deltas, 'get_version'))


@pytest.mark.parametrize('name', ['hostile_names', 'count_suffix', 'ambiguous_pair', 'cycle_hub'])
def test_every_fixture_computes_without_error(name):
    snap, deltas = analysis(name)
    assert deltas and build_leads(snap, deltas) is not None
