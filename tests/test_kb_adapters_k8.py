"""K8: KB correlator adapters for KEV, FAB anchors, WB1 search and unified results. Synthetic, hermetic."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from patchtrace.fabric.ids import make_anchor, make_witness
from patchtrace.kbcorrelation.adapters import anchors as fab
from patchtrace.kbcorrelation.adapters import engine, kev
from patchtrace.kbcorrelation.adapters import search as wb1
from patchtrace.kbcorrelation.leads import EngineSignal, KevFact, NullExploitation
from patchtrace.search.contracts import Evidence, Locator, SearchHit, SearchResult
from patchtrace.unified.contracts import SideRef, UnifiedMatch

SNAP = 'c' * 64
HOSTILE = 'evil\x1b[31m‮ name line2\x00'
BAD_CHARS = '\x1b\x00‮ '


class FakePort:
    def __init__(self, table):
        self.table = table

    def lookup(self, cve):
        return self.table.get(cve) or SimpleNamespace(status='unavailable', entry=None, snapshot_id=None)


def _listed():
    return SimpleNamespace(status='listed', entry=SimpleNamespace(date_added='2099-02-12'), snapshot_id=SNAP)


def test_kev_port_absent_is_unknown_not_negative():
    assert kev.KevExploitation(None).status('CVE-2099-20001') == NullExploitation().status('x')


@pytest.mark.parametrize('lookup,state', [
    (_listed(), 'listed'),
    (SimpleNamespace(status='not-listed', entry=None, snapshot_id=SNAP), 'not-listed'),
    (SimpleNamespace(status='unavailable', entry=None, snapshot_id=None), 'no-snapshot'),
    (SimpleNamespace(status='invalid-id', entry=None, snapshot_id=None), 'no-snapshot'),
], ids=['listed', 'not-listed', 'unavailable', 'invalid'])
def test_kev_states(lookup, state):
    fact = kev.KevExploitation(FakePort({'CVE-2099-20001': lookup})).status('CVE-2099-20001')
    assert fact.state == state
    expected = {'listed': ('2099-02-12', SNAP), 'not-listed': (None, SNAP), 'no-snapshot': (None, None)}[state]
    assert (fact.date_added, fact.snapshot_sha256) == expected


def _wit(source, origins, label='x', **facets):
    return make_witness(producer='kb', batch='b1', source=source, origins=origins, label=label, facets=facets)


def _cve_anchor(key, *witnesses):
    return make_anchor(kind='cve', side='none', role='stated', key=key, witnesses=witnesses)


def test_anchor_kev_needs_positive_witness():
    listed = _cve_anchor('CVE-2099-20001', _wit('kev-catalog', ['D_kev'], kev='listed', date_added='2099-02-12',
                                                 snapshot=SNAP))
    plain = _cve_anchor('CVE-2099-20002', _wit('advisory-text', ['D_vendor_text']))
    look = kev.AnchorExploitation([listed, plain])
    assert look.status('CVE-2099-20001') == KevFact('listed', '2099-02-12', SNAP)
    assert look.status('CVE-2099-20002').state == 'no-snapshot'
    assert look.status('CVE-2099-99999').state == 'no-snapshot'


def test_anchor_kev_garbage_facets_are_dropped():
    bad = _cve_anchor('CVE-2099-20001', _wit('kev-catalog', ['D_kev'], kev='listed', date_added='tomorrow',
                                              snapshot='zz'))
    assert kev.AnchorExploitation([bad]).status('CVE-2099-20001') == KevFact('listed', None, None)


def test_first_answer_prefers_a_catalog_answer_over_silence():
    not_listed = SimpleNamespace(status='not-listed', entry=None, snapshot_id=SNAP)
    port = kev.KevExploitation(FakePort({'CVE-2099-20002': not_listed}))
    listed = kev.AnchorExploitation([_cve_anchor('CVE-2099-20001', _wit('kev-catalog', ['D_kev'], kev='listed'))])
    both = kev.FirstAnswer([port, listed])
    assert both.status('CVE-2099-20002').state == 'not-listed'
    assert both.status('CVE-2099-20001').state == 'listed'
    assert both.status('CVE-2099-30000').state == 'no-snapshot'


def test_shared_origin_witnesses_count_once():
    cve = _cve_anchor('CVE-2099-20001', _wit('advisory-text', ['D_vendor_text']), _wit('msrc-cwe', ['D_vendor_text']),
                      _wit('nvd-cwe', ['D_vendor_text']), _wit('kev-catalog', ['D_kev']))
    cwe = make_anchor(kind='cwe', side='none', role='stated', key='CWE-190',
                      witnesses=[_wit('kev-cwe', ['D_vendor_text'], cve='CVE-2099-20001'),
                                 _wit('nvd-cwe', ['D_vendor_text'], cve='CVE-2099-20002')])
    facts = fab.cve_facts([cve, cwe])
    one = facts['CVE-2099-20001']
    assert (one.witnesses, one.independent, one.cwes) == (5, 2, ('CWE-190',))
    assert (facts['CVE-2099-20002'].witnesses, facts['CVE-2099-20002'].independent) == (1, 1)


def test_anchor_labels_are_cleaned_and_bounded():
    anchor = _cve_anchor('CVE-2099-20001', _wit('advisory-text', ['D_vendor_text'], label=HOSTILE * 100))
    (label,) = fab.cve_facts([anchor], label_limit=50)['CVE-2099-20001'].labels
    assert len(label) <= 50 and not any(c in label for c in BAD_CHARS)


def _match(rva_old, rva_new, name='read_item', materiality='unknown', decision=None):
    older = (SideRef(rva=rva_old, name=name, kind='function'),) if rva_old else ()
    newer = (SideRef(rva=rva_new, name=name, kind='function'),) if rva_new else ()
    decision = decision or ('matched' if older and newer else 'older-only' if older else 'newer-only')
    mat = materiality if older and newer else 'not-applicable'
    return UnifiedMatch(row_id=f'{rva_old or 0:x}{rva_new or 0:x}'.ljust(64, '0'), older=older, newer=newer,
                        decision=decision, atoms=(), materiality=mat)


def test_engine_view_orientation_rank_and_silence():
    mod, add = _match(0x1000, 0x1100), _match(None, 0x2000, 'report_invalid_index')
    rem = _match(0x3000, None, 'debug_dump')
    ranking = [SimpleNamespace(match_id=mod.row_id, rank=1)]
    view = engine.engine_view([mod, add, rem], ranking, project_revision=3, run_id='r1', older_sha='a' * 64,
                              newer_sha='b' * 64)
    assert [(r.change, r.attention_rank) for r in view.rows] == [('modified', 1), ('added', None), ('removed', None)]
    assert all(r.verdicts == () for r in view.rows)          # silence is not "unchanged"
    assert (view.older_sha, view.newer_sha) == ('a' * 64, 'b' * 64)


def test_engine_verdicts_keep_conflict():
    m = _match(0x1000, 0x1100, materiality='material')
    view = engine.engine_view([m], None, project_revision=0, run_id=None, older_sha='a' * 64, newer_sha='b' * 64,
                              verdicts={m.row_id: [('bindiff', 'unchanged'), ('ghidriff', 'bogus')]})
    assert view.rows[0].verdicts == (('bindiff', 'unchanged'), ('unified', 'changed'))


def test_engine_names_are_cleaned_and_unknown_rows_skipped():
    m = _match(0x1000, 0x1100, name=HOSTILE)
    skipped = _match(0x5000, 0x5100, decision='unknown')
    view = engine.engine_view([m, skipped], [], project_revision=0, run_id=None, older_sha='a' * 64,
                              newer_sha='b' * 64, signals={m.row_id: [EngineSignal('bounds', 'high', 'g')]})
    (row,) = view.rows
    assert not any(c in row.name for c in BAD_CHARS) and row.signals[0].detector == 'bounds'


def _ev(digest, title='read_item', seen=('ghidra',), fid='f1'):
    return Evidence(kind='function', side='newer', origin=seen[0], title=title, locator=Locator(
        scheme='function', function_id=fid, source_ref='/fn/1'), seen_by=seen, group='names', digest16=digest)


def _result(status, hits=()):
    return SearchResult(status=status, hits=tuple(hits), index_key='d' * 16)


@pytest.mark.parametrize('status', ['indexing', 'error', 'stale', 'cancelled'])
def test_search_incomplete_is_unknown_not_empty(status):
    out = wb1.search_leads(_result(status))
    assert (out.leads, out.complete) == ((), False) and status in out.note


def test_search_none_and_no_results():
    assert wb1.search_leads(None).complete is False
    assert wb1.search_leads(_result('no-results')).complete is True


def test_search_dedupes_documents_and_keeps_provenance():
    ev = _ev('1' * 16, seen=('ghidra', 'pe-parse'))
    other = _ev('2' * 16, 'alloc_items', fid='f2')
    hits = [SearchHit(hit_id='h1', tier=0, change_class=0, components=2, evidence=(ev,), evidence_total=1),
            SearchHit(hit_id='h2', tier=1, change_class=0, components=2, evidence=(ev, other), evidence_total=2)]
    out = wb1.search_leads(_result('ok', hits))
    assert len(out.leads) == 2
    first = next(lead for lead in out.leads if lead.digest16 == '1' * 16)
    assert (first.origins, first.components, first.source_ref) == (('ghidra', 'pe-parse'), 2, '/fn/1')
    assert sorted(wb1.by_function(out)) == ['f1', 'f2']
    assert out.index_key == 'd' * 16


def test_search_title_hostile_text_is_cleaned():
    hit = SearchHit(hit_id='h', tier=0, change_class=0, components=1, evidence=(_ev('3' * 16, HOSTILE),),
                    evidence_total=1)
    (lead,) = wb1.search_leads(_result('ok', [hit])).leads
    assert not any(c in lead.title for c in BAD_CHARS)
