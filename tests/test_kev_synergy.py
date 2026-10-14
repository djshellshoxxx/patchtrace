"""KEV-integration-plan section 5 (items 1-8): KEV beside a real attention/1 ranking and fake KB edges. Hermetic."""
from __future__ import annotations

import datetime
import json
from dataclasses import dataclass

import pytest
from test_enrichment_core import sig, sset

from patchtrace.enrichment.contracts import RankingConfig
from patchtrace.enrichment.ranking import rank
from patchtrace.kev import kb_adapter
from patchtrace.kev.join import lookup
from patchtrace.kev.kb_adapter import summary_line, worklist
from patchtrace.kev.parse import parse_catalog

UTC = datetime.UTC
RELEASED = datetime.datetime(2099, 3, 1, 18, 0, 0, tzinfo=UTC)
C1, C2, C4, C9 = 'CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004', 'CVE-2099-10009'
# Same content as cve.CWE_DETECTORS for the CWEs used here; injected so kev never imports the ranking code.
DETECTORS = {'CWE-787': ('BND', 'SIZE')}


def _entry(cve, vendor, product, added, due, ransomware, triage, cwes):
    return {'cveID': cve, 'vendorProject': vendor, 'product': product, 'vulnerabilityName': f'{product} issue',
            'dateAdded': added, 'shortDescription': 'Synthetic.', 'requiredAction': 'Synthetic.', 'dueDate': due,
            'knownRansomwareCampaignUse': ransomware, 'forensicTriage': triage, 'notes': '', 'cwes': cwes}


def make_catalog(entries=None):
    entries = entries or [
        _entry(C1, 'Microsoft', 'Windows', '2099-02-10', '2099-02-13', 'Known', 'Yes', ['CWE-787']),
        _entry(C4, 'Microsoft', 'Windows', '2099-02-20', '2099-03-01', 'Unknown', 'No', ['CWE-416']),
        _entry(C9, 'Adobe', 'Reader', '2099-02-15', '2099-03-01', 'Unknown', 'No', []),
        _entry('CVE-2099-10010', 'Router ', 'Router ', '2099-02-16', '2099-03-01', 'Unknown', 'No', []),
    ]
    doc = {'title': 'synthetic', 'catalogVersion': '2099.03.01', 'dateReleased': '2099-03-01T18:00:00.0000Z',
           'count': len(entries), 'vulnerabilities': entries}
    return parse_catalog(json.dumps(doc).encode('utf-8'), source='local-import', retrieved_at='2099-03-01T19:00:00Z')


@dataclass(frozen=True)
class Edge:
    kb: str
    cve: str
    cwes: tuple[str, ...]
    released_at: str | None = '2099-02-11'
    orientation_verified: bool = True


@dataclass(frozen=True)
class Row:
    match_id: str
    rank: int
    detectors: frozenset[str]


@dataclass(frozen=True)
class Ranked:
    entries: tuple[Row, ...]


EDGES = (Edge('KB5000001', C1, ('CWE-787',)), Edge('KB5000001', 'CVE-2099-10002', ('CWE-787',)),
         Edge('KB5000001', C4, ('CWE-416',)))


def engine():
    """A real rank() over synthetic signal sets; a KEV-free helper maps each entry to its signal detectors."""
    sets = [sset('F005', [sig('BND', 'strong', '1', 'F005'), sig('SIZE', 'strong', '2', 'F005')]),
            sset('F001', [sig('BND', 'strong', '1', 'F001')]),
            sset('F002', [sig('ERR', 'weak', '1', 'F002')]), sset('F003', [])]
    result = rank(sets, RankingConfig())
    by_pairing = {s.pairing_id: frozenset(x.detector for x in s.signals) for s in sets}
    rows = tuple(Row(e.match_id, e.rank, by_pairing[e.pairing_id]) for e in result.entries)
    return result, Ranked(rows)


def test_lookup_states_and_cells():
    results = lookup(make_catalog(), [C1, 'CVE-2099-10002', C4], RELEASED)
    assert [r.status for r in results] == ['listed', 'not-listed', 'listed']
    sections = worklist(EDGES, make_catalog(), engine()[1], DETECTORS, RELEASED)
    assert [s.cell.text for s in sections] == ['Listed - ransomware known', 'Not listed', 'Listed']


def test_worklist_orders_cves_kev_first_and_keeps_function_order():
    catalog, (_, view) = make_catalog(), engine()
    default = worklist(EDGES, catalog, view, DETECTORS, RELEASED)
    first = worklist(EDGES, catalog, view, DETECTORS, RELEASED, order='kev-first')
    assert [s.cve_id for s in default] == [C1, 'CVE-2099-10002', C4]
    assert [s.cve_id for s in first] == [C1, C4, 'CVE-2099-10002']
    for section in default + first:
        if section.cve_id != C4:
            assert section.candidates == ('m-F005', 'm-F001')  # a KEV boost on 10001 would put F001 first


def test_kev_attachment_leaves_ranking_json_identical():
    result, view = engine()
    before = result.model_dump_json()
    with_kev = worklist(EDGES, make_catalog(), view, DETECTORS, RELEASED, order='kev-first')
    without = worklist(EDGES, None, view, DETECTORS, RELEASED)
    assert result.model_dump_json() == before == engine()[0].model_dump_json()
    assert [s.candidates for s in sorted(with_kev, key=lambda s: s.cve_id)] == [s.candidates for s in without]
    assert [e.match_id for e in result.entries][:2] == ['m-F005', 'm-F001']


def test_section_text_shows_facts_timeline_and_candidates():
    catalog = make_catalog()
    first, second, _ = worklist(EDGES, catalog, engine()[1], DETECTORS, RELEASED)
    text = kb_adapter.section_text(first, catalog, RELEASED)
    assert 'Added to KEV: 2099-02-10' in text and 'CISA due date: 2099-02-13' in text
    assert 'Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).' in text
    assert text.endswith('Candidate functions (engine order): m-F005, m-F001')
    other = kb_adapter.section_text(second, catalog, RELEASED)
    assert 'KEV: not listed' in other and 'not evidence that the CVE is unexploited' in other
    assert 'Candidate functions (engine order): m-F005, m-F001' in other


def test_cwe416_abstains_explicitly():
    catalog = make_catalog()
    section = worklist(EDGES, catalog, engine()[1], DETECTORS, RELEASED)[2]
    assert section.candidates == ()
    assert 'Added to KEV 9 days after the update was released (KB5000001, 2099-02-11).' in kb_adapter.section_text(
        section, catalog, RELEASED)
    assert ('PatchTrace has no CWE-416 detector in this version, so an empty candidate list here is unknown, '
            'not negative.') in kb_adapter.section_text(section, catalog, RELEASED)


@pytest.mark.parametrize('edge, phrase', [
    (Edge('KB5000001', C1, ('CWE-787',), orientation_verified=False), 'Fix release date not established'),
    (Edge('KB5000001', C1, ('CWE-787',), released_at=None), 'Update release date unknown.'),
    (Edge('KB5000001', C1, ('CWE-787',), released_at='2099-02-10'), 'on the day the update was released'),
    (Edge('KB5000001', C1, ('CWE-787',), released_at='2099-02-11'), 'Added to KEV 1 day before'),
    (Edge('KB5000001', C4, ('CWE-416',), released_at='2099-02-19'), 'Added to KEV 1 day after'),
], ids=['swapped', 'no-date', 'same-day', 'before', 'after-singular'])
def test_timeline_phrases_before_after_and_swapped_orientation(edge, phrase):
    [section] = worklist([edge], make_catalog(), engine()[1], DETECTORS, RELEASED)
    assert phrase in section.timeline
    if not edge.orientation_verified:
        assert 'before' not in section.timeline and 'after' not in section.timeline


def test_not_listed_copy_is_neutral():
    catalog = make_catalog()
    sections = worklist(EDGES, catalog, engine()[1], DETECTORS, RELEASED)
    text = kb_adapter.section_text(sections[1], catalog, RELEASED)
    assert 'Not listed' in sections[1].cell.text and sections[1].timeline is None
    for banned in ('safe', 'secure', 'not exploited.', 'unexploited.'):
        assert banned not in text.replace('not evidence that the CVE is unexploited', '')
    assert summary_line(sections, catalog, RELEASED) == (
        '2 of 3 CVEs in this KB are listed in CISA KEV (catalog 2099.03.01, today). '
        'Not listed does not mean not exploited.')


@pytest.mark.parametrize('day, state, age', [(4, 'fresh', 3), (5, 'aging', 4), (15, 'aging', 14), (16, 'stale', 15)],
                         ids=['d3', 'd4', 'd14', 'd15'])
def test_freshness_with_injected_now(day, state, age):
    now = datetime.datetime(2099, 3, day, 9, 0, tzinfo=UTC)
    [result] = lookup(make_catalog(), [C1], now)
    assert (result.freshness, result.age_days) == (state, age)
    line = summary_line(worklist(EDGES[:1], make_catalog(), engine()[1], DETECTORS, now), make_catalog(), now)
    assert f'{age} days old' in line


def test_fullwidth_id_is_invalid_and_hand_typed_decoy_has_no_kb_link():
    catalog = make_catalog()
    bad = worklist([Edge('KB5000001', 'CVE-２０９９-１０００１', ())], catalog, engine()[1], DETECTORS, RELEASED)[0]
    assert bad.cell.text == 'Invalid CVE ID' and bad.timeline is None
    assert 'Not listed' not in kb_adapter.section_text(bad, catalog, RELEASED)
    decoy = lookup(catalog, [C9], RELEASED)[0]
    assert decoy.status == 'listed'
    from patchtrace.kev.view_model import detail_text
    text = detail_text(decoy, catalog, RELEASED)
    assert 'CISA lists this as: Adobe Reader' in text and 'KB5000001' not in text
