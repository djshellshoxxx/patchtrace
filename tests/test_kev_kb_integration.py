"""KEV K4 adapter contract: the Protocol surface, reading order, timeline phrases, candidate order, abstention, hostile
input and limits (plan sections 4, 5 and 8).

The KB wave's real view model is not on this base. The edges here are fakes plus the shape of the base's own
``KbCveEdge``; plan item 9 and the real view-model test run at the KB wave merge.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from kev_helpers import NOW, SYNTHETIC, at, parse_fixture, socket_guard

from patchtrace.kev import limits
from patchtrace.kev.contracts import KevError
from patchtrace.kev.join import lookup
from patchtrace.kev.kb_adapter import (
    TIMELINE_UNKNOWN,
    TIMELINE_UNVERIFIED,
    EdgeLike,
    RankedLike,
    RankingLike,
    compose_worklist,
    no_detector_sentence,
    not_listed_note,
    timeline_phrase,
)
from patchtrace.kev.view_model import KevColumnProvider

FAST = settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)
KB, OTHER_KB = 'KB5000001', 'KB5000002'
KNOWN, NOT_LISTED, UNKNOWN = 'CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004'
CATALOG = parse_fixture(SYNTHETIC)                      # listed: 10001, 10004, 10009, 10010
BANNED = re.compile(r'\b(exploitable|vulnerable function|confirmed vulnerab\w*|weaponi[sz]ed|proves?|is safe|fixes this'
                    r'|risk|probab\w*|likelihood)\b|%', re.IGNORECASE)
SANCTIONED = ('does not mean not exploited', 'has not been shown to be unexploited')
UNSAFE = re.compile('[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]')


@dataclass(frozen=True)
class Edge:
    kb: str
    cve: str


@dataclass(frozen=True)
class Ranked:
    match_id: str
    rank: int


@dataclass(frozen=True)
class Ranking:
    entries: tuple[Ranked, ...] = ()


NO_RANKING = Ranking()


class Lookalike:
    """Not a string, but it prints as one: text from the KB side is accepted only as a plain ``str``."""

    def __init__(self, text: str):
        self.text = text

    def __str__(self) -> str:
        return self.text


class Subclass(str):
    """A ``str`` subclass could override how it compares and prints; only an exact ``str`` is taken."""


def provider(catalog=CATALOG, now=NOW):
    return KevColumnProvider(catalog, now)


def work(edges, *, kev=None, ranking=NO_RANKING, candidates=None, cwes=None, detectors=frozenset({'CWE-787'}),
         dates=None, verified=True, order='input'):
    return compose_worklist(edges, provider() if kev is None else kev, ranking, candidates=candidates or {},
                            cwes=cwes or {}, detector_cwes=detectors,
                            release_dates={KB: '2099-02-11'} if dates is None else dates,
                            orientation_verified=verified, order=order)


def strings(worklist) -> list[str]:
    """Every text a person could read in a worklist."""
    out = [worklist.order_label, worklist.summary or '', worklist.banner or '']
    for section in worklist.sections:
        out += [section.cve, section.cell.text, section.cell.accessible, section.note or '', *section.kbs,
                *section.timeline, *section.abstentions]
    return out


# --- the surface ----------------------------------------------------------------------------------------------------

def test_the_protocols_name_only_what_the_adapter_reads():
    def members(protocol) -> set[str]:
        return {name for name in vars(protocol) if not name.startswith('_')}

    assert members(EdgeLike) == {'kb', 'cve'}
    assert members(RankedLike) == {'match_id', 'rank'}                      # a position, never a score
    assert members(RankingLike) == {'entries'}


def test_a_kb_edge_of_the_base_is_an_edge_like():
    from patchtrace.kbcorrelation.contracts import KbCveEdge
    edge = KbCveEdge.model_construct(kb=KB, cve=KNOWN)                      # the two members the adapter reads
    (section,) = work([edge]).sections
    assert (section.cve, section.kbs, section.cell.state) == (KNOWN, (KB,), 'listed')


def test_sections_and_worklists_are_frozen_values():
    worklist = work([Edge(KB, KNOWN)])
    with pytest.raises(AttributeError):
        worklist.sections[0].cve = 'CVE-2099-10002'
    with pytest.raises(AttributeError):
        worklist.order = 'kev-first'
    assert not hasattr(worklist.sections[0], '__dict__')


# --- the reading order ----------------------------------------------------------------------------------------------

POOL = (KNOWN, NOT_LISTED, UNKNOWN, 'CVE-2099-10009', 'CVE-2099-10010', 'CVE-2099-10099', 'not-a-cve', 'CVE-2099-1')


@given(st.lists(st.tuples(st.sampled_from((KB, OTHER_KB)), st.sampled_from(POOL)), max_size=30))
@FAST
def test_the_reading_order_is_a_stable_partition_of_the_first_seen_order(pairs):
    edges = [Edge(kb, cve) for kb, cve in pairs]
    distinct = list(dict.fromkeys(cve for _, cve in pairs))
    listed = [cve for cve in distinct if cve in CATALOG.by_cve]
    other = [cve for cve in distinct if cve not in CATALOG.by_cve]
    assert [s.cve for s in work(edges).sections] == distinct
    assert [s.cve for s in work(edges, order='kev-first').sections] == listed + other


def test_duplicate_edges_collapse_into_one_section_per_cve():
    edges = [Edge(OTHER_KB, KNOWN), Edge(KB, KNOWN), Edge(KB, KNOWN), Edge(KB, NOT_LISTED)]
    worklist = work(edges, dates={KB: '2099-02-11', OTHER_KB: None})
    assert [s.cve for s in worklist.sections] == [KNOWN, NOT_LISTED]
    known = worklist.sections[0]
    assert known.kbs == (KB, OTHER_KB)
    assert known.timeline == ('Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).',
                              'Update release date unknown.')


def test_an_unverified_orientation_is_said_once_however_many_kbs_list_the_cve():
    worklist = work([Edge(KB, KNOWN), Edge(OTHER_KB, KNOWN)], verified=False)
    assert worklist.sections[0].kbs == (KB, OTHER_KB) and worklist.sections[0].timeline == (TIMELINE_UNVERIFIED,)


def test_a_kb_without_a_release_date_entry_is_unknown_not_an_error():
    (section,) = work([Edge(OTHER_KB, KNOWN)], dates={}).sections
    assert section.timeline == (TIMELINE_UNKNOWN,)


def test_an_empty_edge_list_is_an_empty_worklist():
    worklist = work([])
    assert worklist.sections == () and worklist.summary is None and worklist.banner is None


def test_an_unknown_order_is_refused():
    with pytest.raises(ValueError, match='order'):
        work([Edge(KB, KNOWN)], order='by-score')


def test_more_than_the_lookup_limit_of_cves_is_refused():
    def edges(count):
        return (Edge(KB, f'CVE-2099-{n:05d}') for n in range(count))

    assert len(work(edges(limits.MAX_LOOKUP_CVES)).sections) == limits.MAX_LOOKUP_CVES
    with pytest.raises(KevError) as raised:
        work(edges(limits.MAX_LOOKUP_CVES + 1))
    assert raised.value.code == 'PT-KEV-LIMIT'


# --- candidates stay in the engine's order --------------------------------------------------------------------------

RANKING = Ranking((Ranked('B', 2), Ranked('A', 1), Ranked('C', 3)))        # deliberately not sorted


def test_candidates_follow_the_engine_order_and_unranked_ids_come_last():
    given_order = ['C', 'Z', 'A', 'Y', 'B', 'A']
    (section,) = work([Edge(KB, KNOWN)], ranking=RANKING, candidates={KNOWN: given_order}).sections
    assert section.candidates == ('A', 'B', 'C', 'Z', 'Y')
    assert given_order == ['C', 'Z', 'A', 'Y', 'B', 'A']                       # the caller's list is not touched


def test_a_match_ranked_twice_keeps_its_best_place():
    ranking = Ranking((Ranked('A', 1), Ranked('B', 2), Ranked('A', 3)))
    (section,) = work([Edge(KB, KNOWN)], ranking=ranking, candidates={KNOWN: ['B', 'A']}).sections
    assert section.candidates == ('A', 'B')


def test_candidates_belong_to_their_own_cve_only():
    sections = {s.cve: s for s in work([Edge(KB, KNOWN), Edge(KB, NOT_LISTED)], ranking=RANKING,
                                       candidates={KNOWN: ['B', 'A'], 'CVE-2099-99999': ['C']}).sections}
    assert sections[KNOWN].candidates == ('A', 'B') and sections[NOT_LISTED].candidates == ()


def test_the_kev_state_cannot_change_a_candidate_list():
    cves = (KNOWN, NOT_LISTED, UNKNOWN)
    edges, candidates = [Edge(KB, cve) for cve in cves], {cve: ['C', 'A', 'B'] for cve in cves}
    arms = (provider(), provider(None), provider(CATALOG, at(2099, 3, 20)), provider(CATALOG, at(2099, 2, 27)))
    for kev in arms:                    # every KEV state and both orders: the order moves CVEs, never a function
        for order in ('input', 'kev-first'):
            sections = work(edges, kev=kev, ranking=RANKING, candidates=candidates, order=order).sections
            assert {s.cve: s.candidates for s in sections} == dict.fromkeys(cves, ('A', 'B', 'C'))


# --- timeline phrases -----------------------------------------------------------------------------------------------

def row_added_2099_02_10():
    return lookup(CATALOG, [KNOWN], NOW)[0]


@pytest.mark.parametrize(('released', 'expected'), [
    ('2099-02-12', 'Added to KEV 2 days before the update was released (KB5000001, 2099-02-12).'),
    ('2099-02-11', 'Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).'),
    ('2099-02-10', 'Added to KEV on the day the update was released (KB5000001, 2099-02-10).'),
    ('2099-02-09', 'Added to KEV 1 day after the update was released (KB5000001, 2099-02-09).'),
    ('2099-02-05', 'Added to KEV 5 days after the update was released (KB5000001, 2099-02-05).'),
    ('2099-02-11T09:30:00Z', 'Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).'),
    ('2099-02-11T23:59:59.1234Z', 'Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).'),
    ('2100-02-10', 'Added to KEV 365 days before the update was released (KB5000001, 2100-02-10).')],
    ids=['two-days-before', 'one-day-before', 'same-day', 'one-day-after', 'five-days-after', 'utc-timestamp',
         'fractional-timestamp', 'a-year-before'])
def test_timeline_phrase_table(released, expected):
    assert timeline_phrase(row_added_2099_02_10(), KB, released, orientation_verified=True) == expected


@pytest.mark.parametrize('released', [
    None, '', '2099-02-30', '2099-2-11', '２０９９-02-11', '2099-02-11 ', 'yesterday', 20990211, '2099-02-11T09:30:00',
    '2099-02-11T25:00:00Z', '2099-02-11\x1b[0m', b'2099-02-11', ['2099-02-11'], date(2099, 2, 11),
    Lookalike('2099-02-11')],
    ids=['none', 'empty', 'no-such-day', 'unpadded', 'fullwidth', 'trailing-space', 'word', 'integer', 'no-zone',
         'no-such-hour', 'escape', 'bytes', 'list', 'date-object', 'lookalike'])
def test_an_unusable_release_date_is_unknown_and_an_unverified_orientation_comes_first(released):
    row = row_added_2099_02_10()
    assert timeline_phrase(row, KB, released, orientation_verified=True) == TIMELINE_UNKNOWN
    assert timeline_phrase(row, KB, released, orientation_verified=False) == TIMELINE_UNVERIFIED


def test_the_two_fixed_timeline_sentences():
    assert TIMELINE_UNKNOWN == 'Update release date unknown.'
    assert TIMELINE_UNVERIFIED == 'Fix release date not established for this orientation.'


def test_only_a_listed_cve_has_a_timeline():
    for catalog, cve, status in ((CATALOG, NOT_LISTED, 'not-listed'), (CATALOG, 'CVE-２０９９-10001', 'invalid-id'),
                                 (None, KNOWN, 'unavailable')):
        row = lookup(catalog, [cve], NOW)[0]
        assert row.status == status
        for verified in (True, False):
            assert timeline_phrase(row, KB, '2099-02-11', orientation_verified=verified) is None


# --- abstention -----------------------------------------------------------------------------------------------------

def test_abstention_names_each_stated_cwe_without_a_detector_once_in_numeric_order():
    stated = ['CWE-416', 'CWE-9', 'CWE-787', 'CWE-416', 'NVD-CWE-Other', 'cwe-20', 'CWE-７８７', 'CWE-', 'CWE-1234567',
              'CWE-20 ', 'CWE-416\x1b[0m', 'CWE-1\n', 20, None, Lookalike('CWE-33'), Subclass('CWE-34')]
    (section,) = work([Edge(KB, KNOWN)], cwes={KNOWN: stated}).sections
    assert section.abstentions == (no_detector_sentence('CWE-9'), no_detector_sentence('CWE-416'))
    assert no_detector_sentence('CWE-416') == ('PatchTrace has no CWE-416 detector in this version, so an empty '
                                               'candidate list here is unknown, not negative.')


@pytest.mark.parametrize('detectors', [frozenset({'CWE-787', 'CWE-416'}), {'CWE-787': ('BND',), 'CWE-416': ()},
                                       ['CWE-787', 'CWE-416']], ids=['set', 'mapping', 'list'])
def test_any_collection_of_detector_cwes_works_and_a_covered_cwe_does_not_abstain(detectors):
    (section,) = work([Edge(KB, KNOWN)], cwes={KNOWN: ['CWE-787', 'CWE-416']}, detectors=detectors).sections
    assert section.abstentions == ()


def test_a_cve_that_states_no_cwe_says_nothing_about_detectors():
    sections = work([Edge(KB, KNOWN), Edge(KB, NOT_LISTED)], cwes={NOT_LISTED: []}).sections
    assert [s.abstentions for s in sections] == [(), ()]


# --- no catalog, summary and banner ---------------------------------------------------------------------------------

def test_without_a_catalog_the_worklist_still_names_the_cves_and_their_candidates():
    worklist = work([Edge(KB, KNOWN)], kev=KevColumnProvider(None, NOW), ranking=RANKING, candidates={KNOWN: ['B']})
    (section,) = worklist.sections
    assert (section.cell.state, section.cell.text, section.lookup.status) == ('no-catalog', 'No catalog', 'unavailable')
    assert (section.note, section.timeline, section.candidates) == (None, (), ('B',))
    assert (worklist.summary, worklist.banner, worklist.meta) == (None, None, None)


def test_a_future_dated_catalog_asks_for_a_clock_check():
    worklist = work([Edge(KB, KNOWN)], kev=provider(CATALOG, at(2099, 2, 27)))
    assert worklist.banner == ("The catalog's release time is in the future. Check this computer's clock and treat "
                               'results as unverified.')
    assert worklist.sections[0].cell.italic and worklist.sections[0].lookup.freshness == 'future'


def test_the_banner_reads_the_first_answered_row_not_the_first_row():
    edges = [Edge(KB, 'not-a-cve'), Edge(KB, KNOWN)]
    worklist = work(edges, kev=provider(CATALOG, at(2099, 3, 10)))
    assert worklist.sections[0].lookup.status == 'invalid-id'
    assert worklist.banner == 'This catalog is 9 days old. CVEs CISA added since then are not shown as listed.'


def test_the_summary_counts_distinct_valid_cves_without_a_percentage():
    edges = [Edge(KB, c) for c in (KNOWN, NOT_LISTED, UNKNOWN, KNOWN, 'not-a-cve')]
    assert work(edges).summary == ('2 of 3 CVEs in this KB are listed in CISA KEV (catalog 2099.03.01, 1 day old). Not '
                                   'listed does not mean not exploited.')
    assert work([Edge(KB, 'not-a-cve')]).summary is None


# --- hostile input --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('bad_kb', ['KB5000001\x1b[2J', 'kb5000001', 'KB５０００００１', 'KB123', 'KB' + '9' * 11,
                                    'KB5000001\n', None, 5000001, Lookalike(KB), Subclass(KB)],
                         ids=['escape', 'lowercase', 'fullwidth', 'short', 'long', 'newline', 'none', 'integer',
                              'lookalike', 'str-subclass'])
def test_an_unusable_kb_id_is_dropped_not_printed(bad_kb):
    worklist = work([Edge(bad_kb, KNOWN)])
    (section,) = worklist.sections
    assert (section.kbs, section.timeline, section.cell.state) == ((), (), 'listed')
    assert all(not UNSAFE.search(text) for text in strings(worklist))


def test_hostile_cve_text_is_echoed_clean_and_never_listed():
    hostile = 'CVE-2099-10001\x1b[31m‮evil\n' + 'y' * 200
    worklist = work([Edge(KB, hostile)], candidates={hostile: ['A']})
    (section,) = worklist.sections
    assert section.lookup.status == 'invalid-id' and len(section.cve) <= limits.MAX_ECHO_CHARS
    assert section.timeline == () and section.note is None
    assert all(not UNSAFE.search(text) for text in strings(worklist))


def test_a_hostile_release_date_is_unknown_not_printed():
    worklist = work([Edge(KB, KNOWN)], dates={KB: '2099-02-11\x1b[2J'})
    assert worklist.sections[0].timeline == (TIMELINE_UNKNOWN,)
    assert all(not UNSAFE.search(text) for text in strings(worklist))


# --- copy -----------------------------------------------------------------------------------------------------------

def test_adapter_copy_makes_no_banned_claim_and_stays_plain():
    row = row_added_2099_02_10()
    texts = [TIMELINE_UNKNOWN, TIMELINE_UNVERIFIED, no_detector_sentence('CWE-416'), not_listed_note(CATALOG.meta)]
    texts += [timeline_phrase(row, KB, day, orientation_verified=True)
              for day in ('2099-02-01', '2099-02-10', '2099-02-11', '2099-04-01')]
    for now in (at(2099, 3, 2), at(2099, 3, 10), at(2099, 3, 20), at(2099, 2, 27)):
        texts += strings(work([Edge(KB, c) for c in (KNOWN, NOT_LISTED, UNKNOWN)], kev=provider(CATALOG, now),
                              cwes={UNKNOWN: ['CWE-416']}, order='kev-first'))
    for text in filter(None, texts):
        cleaned = text
        for phrase in SANCTIONED:
            cleaned = cleaned.replace(phrase, '')
        assert not BANNED.search(cleaned), text
        assert text.isascii() and '\n' not in text and len(text) <= 240, text


def test_the_not_listed_note_is_the_plan_sentence():
    assert not_listed_note(CATALOG.meta) == ('Not in the KEV catalog 2099.03.01. This does not mean the CVE is '
                                             'unexploited.')


@pytest.mark.parametrize('bad', ['KB123', 'kb5000001', 'KB5000001\x1b[0m', 'KB５０００００１', '', 'KB5000001 '],
                         ids=['short', 'lowercase', 'escape', 'fullwidth', 'empty', 'trailing-space'])
def test_the_sentence_builders_refuse_text_that_is_not_an_id(bad):
    with pytest.raises(ValueError, match='KB id'):
        timeline_phrase(row_added_2099_02_10(), bad, '2099-02-11', orientation_verified=True)
    with pytest.raises(ValueError, match='CWE'):
        no_detector_sentence(bad)
