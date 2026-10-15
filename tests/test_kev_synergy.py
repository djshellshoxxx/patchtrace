"""KEV K4 synergy: the known-answer scenario of plan section 5, items 1 to 8, end to end.

Everything is synthetic. The catalog is tests/fixtures/kev/kev-synthetic-2099.json; the KB is three edges of KB5000001
(released 2099-02-11, orientation verified); the function evidence is a real ``enrichment.ranking.rank`` result over
synthetic signal sets and a real ``cve.contextual_rank`` over synthetic CVE snapshots. KEV decides which CVE is read
first and nothing else. Item 9 (three exploitation lanes for CVE-2024-38063) needs the KB wave's view model and runs at
the KB wave merge; only its KEV lane can be checked here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import pytest
from kev_helpers import NOW, REAL, SYNTHETIC, at, document, entry, parse_document, parse_fixture, socket_guard

from patchtrace.enrichment import identity
from patchtrace.enrichment.contracts import (
    AttributedValue,
    ChangeSignal,
    CveSnapshot,
    DetectorOutcome,
    RankingConfig,
    SignalSet,
    SourceLocation,
)
from patchtrace.enrichment.cve import ALIGNING_CONFIDENCE, CWE_DETECTORS, contextual_rank
from patchtrace.enrichment.ranking import rank
from patchtrace.kev.kb_adapter import TIMELINE_UNVERIFIED, compose_worklist
from patchtrace.kev.view_model import KevColumnProvider, detail_text

no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)
H = 'a' * 64
KB, RELEASED, VERSION = 'KB5000001', '2099-02-11', '2099.03.01'
KNOWN, NOT_LISTED, UNKNOWN, DECOY, PADDED = ('CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004',
                                             'CVE-2099-10009', 'CVE-2099-10010')
STATED = {KNOWN: ('CWE-787',), NOT_LISTED: ('CWE-787',), UNKNOWN: ('CWE-416',)}      # the advisory's CWE of each CVE
BANNED = re.compile(r'\b(exploitable|vulnerable function|confirmed vulnerab\w*|weaponi[sz]ed|proves?|is safe|fixes this'
                    r'|risk|probab\w*|likelihood)\b|%', re.IGNORECASE)
SANCTIONED = ('does not mean not exploited', 'has not been shown to be unexploited')
REASSURING = re.compile(r'\b(safe|safety|secure|clean|good)\b', re.IGNORECASE)


# --- the function evidence: a real attention ranking over synthetic signal sets -------------------------------------

def pairing(match: str) -> str:
    return identity.domain_id('synergy-pairing', 1, match)


def signal(match: str, detector: str, confidence: str, group: str) -> ChangeSignal:
    p, key = pairing(match), identity.domain_id('synergy-group', 1, f'{match}/{group}')
    place = SourceLocation(side='newer', artifact_id='newer', run_id='run', function_id=match, start_line=1,
                           end_line=1, excerpt_sha256=H)
    return ChangeSignal(signal_id=identity.signal_id(p, detector, 1, key, [{'n': 0}]), pairing_id=p, match_id=match,
                        detector=detector, detector_version=1, confidence=confidence, group_key=key,
                        locations=(place,), rationale='synthetic')


def signal_set(match: str, *signals: ChangeSignal) -> SignalSet:
    p = pairing(match)
    return SignalSet(pairing_id=p, match_id=match, category='modified', signals=signals,
                     outcomes=(DetectorOutcome(pairing_id=p, detector='BND', status='complete'),), status='complete')


SETS = (
    signal_set('F001', signal('F001', 'BND', 'strong', 'g1')),
    signal_set('F002', signal('F002', 'ERR', 'weak', 'g1')),                      # a string anchor only
    signal_set('F003'),
    signal_set('F004', signal('F004', 'BND', 'moderate', 'g1')),                  # aligned, but its match is contested
    signal_set('F005', signal('F005', 'BND', 'strong', 'g1'), signal('F005', 'SIZE', 'strong', 'g2')),
)
CERTAINTY = {'F004': 'contested'}


def snapshot(cve: str, cwe: str) -> CveSnapshot:
    return CveSnapshot(snapshot_id=identity.domain_id('synergy-snapshot', 1, cve), cve_id=cve, normalization_version=1,
                       response_digests={'nvd': H}, retrieved_at='2099-02-14T00:00:00Z',
                       cwes=(AttributedValue(source='nvd', value=cwe),))


def run_engine():
    ranking = rank(SETS, RankingConfig(), CERTAINTY)
    snapshots = [snapshot(cve, cwes[0]) for cve, cwes in STATED.items()]
    return ranking, contextual_rank(ranking, SETS, (), snapshots, ['exampledrv.sys'], {})


def engine_json(pair) -> tuple[bytes, bytes]:
    return pair[0].model_dump_json().encode('utf-8'), pair[1].model_dump_json().encode('utf-8')


def aligned_candidates(ranking) -> dict[str, list[str]]:
    """What the KB lead assignment does with ``CWE_DETECTORS`` (no exclusive allocation: several CVEs may share a
    function; a contested match stays in the review queue). Sorted by match id, deliberately not in engine order."""
    contested = {item.match_id for item in ranking.entries if item.match_certainty == 'contested'}
    found = {}
    for cve, cwes in STATED.items():
        detectors = {name for cwe in cwes for name in CWE_DETECTORS.get(cwe, ())}
        found[cve] = sorted(item.match_id for item in SETS if item.match_id not in contested and any(
            sig.detector in detectors and sig.confidence in ALIGNING_CONFIDENCE for sig in item.signals))
    return found


# --- the KB side -----------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Edge:
    kb: str
    cve: str


EDGES = tuple(Edge(KB, cve) for cve in (KNOWN, NOT_LISTED, UNKNOWN))


def provider(catalog, now=NOW):
    return KevColumnProvider(catalog, now)


def compose(kev, ranking, *, edges=EDGES, verified=True, order='input'):
    return compose_worklist(edges, kev, ranking, candidates=aligned_candidates(ranking), cwes=STATED,
                            detector_cwes=CWE_DETECTORS, release_dates={KB: RELEASED}, orientation_verified=verified,
                            order=order)


@pytest.fixture(scope='module')
def catalog():
    return parse_fixture(SYNTHETIC)


@pytest.fixture(scope='module')
def engine():
    return run_engine()


def by_cve(work) -> dict:
    return {section.cve: section for section in work.sections}


# --- the combination -------------------------------------------------------------------------------------------------

def test_the_function_evidence_is_the_real_engine_at_the_planned_scores(engine):
    ranking, contextual = engine
    scores = {item.match_id: item.score for item in ranking.entries}
    assert (scores['F005'], scores['F001'], scores['F002'], scores['F003']) == (68, 38, 5, 0)
    assert [item.match_id for item in ranking.entries][:2] == ['F005', 'F001']
    assert {item.match_id: item.match_certainty for item in ranking.entries}['F004'] == 'contested'
    assert [item.match_id for item in contextual.entries][:2] == ['F005', 'F001']
    assert aligned_candidates(ranking) == {KNOWN: ['F001', 'F005'], NOT_LISTED: ['F001', 'F005'], UNKNOWN: []}


def test_the_kb_cves_are_listed_not_listed_listed(catalog, engine):
    work = compose(provider(catalog), engine[0])
    assert [(s.cve, s.lookup.status, s.cell.text) for s in work.sections] == [
        (KNOWN, 'listed', 'Listed - ransomware known'), (NOT_LISTED, 'not-listed', 'Not listed'),
        (UNKNOWN, 'listed', 'Listed')]
    assert work.summary == (f'2 of 3 CVEs in this KB are listed in CISA KEV (catalog {VERSION}, 1 day old). Not listed '
                            'does not mean not exploited.')
    assert work.meta is catalog.meta and work.banner is None


def test_worklist_orders_cves_kev_first_and_keeps_function_order(catalog, engine):
    default = compose(provider(catalog), engine[0])
    first = compose(provider(catalog), engine[0], order='kev-first')
    assert [s.cve for s in default.sections] == [KNOWN, NOT_LISTED, UNKNOWN]
    assert [s.cve for s in first.sections] == [KNOWN, UNKNOWN, NOT_LISTED]            # a stable partition, not a score
    assert (default.order, default.order_label) == ('input', 'Input order')
    assert (first.order, first.order_label) == ('kev-first', 'KEV-listed first (reading order, not a score)')
    for work in (default, first):
        assert {s.cve: s.candidates for s in work.sections} == {
            KNOWN: ('F005', 'F001'), NOT_LISTED: ('F005', 'F001'), UNKNOWN: ()}   # the engine's order, whatever KEV says


def test_kev_attachment_leaves_ranking_json_identical(catalog):
    bare = engine_json(run_engine())
    inverted = parse_document(document([entry(1, cveID=NOT_LISTED, dateAdded='2099-02-12', dueDate='2099-02-20')],
                                       catalogVersion=VERSION, dateReleased='2099-03-01T18:00:00.0000Z'))
    arms = {'no catalog': provider(None), 'catalog': provider(catalog), 'listing swapped': provider(inverted)}
    candidates = {}
    for name, kev in arms.items():
        pair = run_engine()
        work = compose(kev, pair[0], order='kev-first')
        assert engine_json(pair) == bare, name                      # byte-identical after composing, with every state
        candidates[name] = {s.cve: s.candidates for s in work.sections}
    assert candidates['catalog'] == candidates['no catalog'] == candidates['listing swapped']
    assert candidates['catalog'][KNOWN] == ('F005', 'F001')
    swapped = [s.cve for s in compose(arms['listing swapped'], run_engine()[0], order='kev-first').sections]
    assert swapped == [NOT_LISTED, KNOWN, UNKNOWN]                         # KEV moved the CVE, never a function


def test_sections_show_kev_facts_the_timeline_and_the_shared_candidates(catalog, engine):
    sections = by_cve(compose(provider(catalog), engine[0]))
    known, absent = sections[KNOWN], sections[NOT_LISTED]
    assert known.kbs == (KB,) and known.note is None and known.abstentions == ()
    assert known.timeline == ('Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).',)
    facts = known.lookup.entry
    assert (facts.date_added, facts.due_date, facts.ransomware_use, facts.forensic_triage, facts.cwes) == (
        '2099-02-10', '2099-02-13', 'known', 'yes', ('CWE-787',))
    assert (facts.vendor_project, facts.product, facts.name) == (
        'Microsoft', 'Windows', 'Microsoft Windows Synthetic Heap Buffer Overflow Vulnerability')
    lines = detail_text(known.lookup, catalog.meta).splitlines()
    for expected in ('Added to KEV: 2099-02-10', 'CISA due date: 2099-02-13', 'Known ransomware campaign use: Known',
                     'Forensic triage required by CISA: Yes', 'CISA lists this as: Microsoft Windows - Microsoft '
                     'Windows Synthetic Heap Buffer Overflow Vulnerability'):
        assert expected in lines
    assert known.candidates == absent.candidates == ('F005', 'F001')
    assert absent.timeline == () and absent.kbs == (KB,)
    assert absent.note == f'Not in the KEV catalog {VERSION}. This does not mean the CVE is unexploited.'


def test_cwe416_abstains_explicitly(catalog, engine):
    sentence = ('PatchTrace has no CWE-416 detector in this version, so an empty candidate list here is unknown, not '
                'negative.')
    assert 'CWE-416' not in CWE_DETECTORS and 'CWE-787' in CWE_DETECTORS             # the premise, from the real table
    for kev in (provider(catalog), provider(None)):                                  # independent of the KEV state
        sections = by_cve(compose(kev, engine[0]))
        gap = sections[UNKNOWN]
        assert gap.candidates == () and gap.abstentions == (sentence,)
        assert sections[KNOWN].abstentions == () and sections[NOT_LISTED].abstentions == ()
    listed = by_cve(compose(provider(catalog), engine[0]))[UNKNOWN]
    assert listed.timeline == ('Added to KEV 9 days after the update was released (KB5000001, 2099-02-11).',)


def test_timeline_phrases_before_after_and_swapped_orientation(catalog, engine):
    verified = {s.cve: s.timeline for s in compose(provider(catalog), engine[0]).sections}
    assert verified == {
        KNOWN: ('Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).',), NOT_LISTED: (),
        UNKNOWN: ('Added to KEV 9 days after the update was released (KB5000001, 2099-02-11).',)}
    swapped = {s.cve: s.timeline for s in compose(provider(catalog), engine[0], verified=False).sections}
    assert swapped == {KNOWN: (TIMELINE_UNVERIFIED,), NOT_LISTED: (), UNKNOWN: (TIMELINE_UNVERIFIED,)}
    assert TIMELINE_UNVERIFIED == 'Fix release date not established for this orientation.'
    assert not re.search(r'before|after', ' '.join(line for lines in swapped.values() for line in lines))


@pytest.mark.parametrize(('now', 'freshness', 'age', 'banner'), [
    (at(2099, 3, 4), 'fresh', 3, None),
    (at(2099, 3, 5), 'aging', 4, 'This catalog is 4 days old. CVEs CISA added since then are not shown as listed.'),
    (at(2099, 3, 15), 'aging', 14, 'This catalog is 14 days old. CVEs CISA added since then are not shown as listed.'),
    (at(2099, 3, 16), 'stale', 15, 'This catalog is 15 days old. A CVE shown as Not listed may have been added since. '
                                   'Update from CISA... or import a newer file.')],
    ids=['day-3-fresh', 'day-4-aging', 'day-14-aging', 'day-15-stale'])
def test_freshness_boundaries_with_an_injected_now(catalog, engine, now, freshness, age, banner):
    work = compose(provider(catalog, now), engine[0])
    assert {(s.lookup.freshness, s.lookup.age_days) for s in work.sections} == {(freshness, age)}
    assert work.banner == banner
    assert work.summary.endswith(f'{age} days old). Not listed does not mean not exploited.')
    assert all(s.cell.italic == (freshness == 'stale') for s in work.sections)       # the non-colour cue


def test_a_fullwidth_cve_id_is_invalid_never_not_listed(catalog, engine):
    edges = (*EDGES, Edge(KB, 'CVE-２０９９-10001'))
    work = compose(provider(catalog), engine[0], edges=edges, order='kev-first')
    bad = work.sections[-1]
    assert (bad.lookup.status, bad.cell.state, bad.cell.text) == ('invalid-id', 'invalid-id', 'Invalid CVE ID')
    assert bad.note is None and bad.timeline == () and bad.candidates == ()
    assert 'not listed' not in (bad.cell.text + bad.cell.accessible).lower()
    assert work.summary.startswith('2 of 3 CVEs')                    # the invalid ID is not one of the CVEs counted


def test_a_decoy_typed_by_hand_is_listed_but_has_no_kb_link(catalog, engine):
    kev = provider(catalog)
    assert kev.cell(DECOY).text == 'Listed'
    shown = detail_text(kev.lookup(DECOY), catalog.meta).splitlines()
    assert 'CISA lists this as: Adobe Reader - Adobe Reader Synthetic Out-of-Bounds Read Vulnerability' in shown
    work = compose(kev, engine[0])
    assert DECOY not in by_cve(work) and {kb for s in work.sections for kb in s.kbs} == {KB}


def test_the_vendor_and_product_text_of_kev_never_filters_the_kb_cves(catalog, engine):
    edges = (*EDGES, Edge(KB, DECOY), Edge(KB, PADDED))
    sections = by_cve(compose(provider(catalog), engine[0], edges=edges))
    assert list(sections) == [KNOWN, NOT_LISTED, UNKNOWN, DECOY, PADDED]             # a different vendor drops nothing
    for cve, who in ((DECOY, 'Adobe Reader'), (PADDED, 'Example Networks Router')):
        assert sections[cve].kbs == (KB,) and sections[cve].cell.state == 'listed'
        assert f'CISA lists this as: {who} - ' in detail_text(sections[cve].lookup, catalog.meta)


def test_not_listed_copy_is_neutral(catalog, engine):
    texts = []
    for now in (at(2099, 3, 2), at(2099, 3, 10), at(2099, 3, 20), at(2099, 2, 27)):
        kev = provider(catalog, now)
        absent = by_cve(compose(kev, engine[0]))[NOT_LISTED]
        assert absent.note == f'Not in the KEV catalog {VERSION}. This does not mean the CVE is unexploited.'
        assert (absent.cell.text, absent.cell.state) == ('Not listed', 'not-listed')
        texts += [absent.note, absent.cell.text, absent.cell.accessible, detail_text(absent.lookup, catalog.meta)]
    for text in texts:
        cleaned = text
        for phrase in SANCTIONED:
            cleaned = cleaned.replace(phrase, '')
        assert not BANNED.search(cleaned) and not REASSURING.search(text), text
        assert text.isascii()                                          # words, never a glyph, carry the meaning


def test_the_kev_lane_of_cve_2024_38063_is_not_listed_in_the_real_trimmed_catalog():
    # Plan item 9 needs three labelled lanes (KEV, MSRC, SSVC); the other two are read by the KB wave's view model.
    kev = provider(parse_fixture(REAL), at(2026, 10, 14))
    assert (kev.cell('CVE-2024-38063').state, kev.cell('CVE-2024-38063').text) == ('not-listed', 'Not listed')
    assert kev.lookup('CVE-2024-38063').status == 'not-listed'
    assert kev.cell('CVE-2021-34527').text == 'Listed - ransomware known'
