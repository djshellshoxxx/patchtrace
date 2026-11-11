"""Regression tests for round-2 search, pilot and buildenv bugs of issue #105 (S4, S5, S6, S7, P1, B1, B2).

Each test reproduces the reported failure on `main` 882d1ca and passes with the fix; the repro scripts are in
docs/qa/bug-repros-20261029/round2/ (`enr_r1`, `enr_r2`, `enr_r7`, `enr_r19`, `pilot_pilot_review_badtime`,
`pilot_be_report_technical`)."""
from __future__ import annotations

import base64

import pytest
from search_builders import make_service
from search_synergy_builders import _spec, attention, extra_specs, make_project

from patchtrace.buildenv.contracts import BuildFingerprint, BuiltFrom, PeBuildFacts, RichEntry, RichFacts
from patchtrace.buildenv.delta import compute_delta
from patchtrace.buildenv.report import build_section, render_markdown, section_data
from patchtrace.buildenv.view_model import provenance_block
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.pilot import review, store
from patchtrace.pilot.contracts import ReviewEvent
from patchtrace.search.contracts import SearchRequest
from patchtrace.search.errors import SearchError
from patchtrace.search.query import parse_query
from patchtrace.search.segment import SegmentDoc
from patchtrace.search.service import SearchService
from patchtrace.service import ProjectService


def _search(service: SearchService, text: str, **kw):
    return service.search(SearchRequest(plan=parse_query(text), **kw))


@pytest.fixture
def synergy(tmp_path):
    return SearchService(make_project(tmp_path / 'project'), tmp_path / 'cache', attention=attention,
                         extra_specs=extra_specs)


# --- S4: an address past the SQLite integer range is a query that finds nothing, not an OverflowError ----------
@pytest.mark.parametrize('address', ['0x8000000000000000', '18446744073709551615'])
def test_an_address_past_the_sqlite_range_finds_nothing_without_crashing(synergy, address):
    assert _search(synergy, address).status == 'no-results'


# --- S5: a crafted page cursor is a typed input error ------------------------------------------------------------
@pytest.mark.parametrize('body', [b'{"o": 1e999}', b'{"o": Infinity}'])
def test_a_cursor_with_an_infinite_offset_is_a_typed_error(synergy, body):
    cursor = base64.urlsafe_b64encode(body).decode().rstrip('=')
    with pytest.raises(SearchError) as caught:
        _search(synergy, 'container', cursor=cursor)
    assert caught.value.code == 'PT-SEARCH-INPUT'


# --- S6: in:signature honours phrases and excluded words ---------------------------------------------------------
def test_signature_search_honours_phrases_and_excludes(tmp_path):
    service = SearchService(make_service(tmp_path / 'p'), tmp_path / 'cache')   # FormatLine: 'int FormatLine(int v)'

    def titles(text):
        return [h.evidence[0].title for h in _search(service, text).hits]

    assert titles('FormatLine in:signature') == ['FormatLine']
    assert titles('"zzz nomatch" in:signature') == []
    assert titles('FormatLine -int in:signature') == []


# --- S7: the exact-id upgrade needs the whole id, not a prefix of a longer one -----------------------------------
def test_an_id_is_exact_only_for_the_whole_id(tmp_path):
    def specs(_request):
        exact = SegmentDoc('advisory', None, 'CVE-2099-10001', 'CVE-2099-10001', 0, text_title='CVE-2099-10001',
                           text_body='the real one')
        longer = SegmentDoc('advisory', None, 'CVE-2099-100011', 'CVE-2099-100011', 1,
                            text_title='CVE-2099-100011', text_body='related to CVE-2099-10001 but a different one')
        return (_spec('adv', ('advisory',), None, [exact, longer]),)

    service = SearchService(make_project(tmp_path / 'p'), tmp_path / 'cache', attention=attention, extra_specs=specs)
    exact = {h.evidence[0].title for h in _search(service, 'CVE-2099-10001').hits if h.tier == 0}
    assert exact == {'CVE-2099-10001'}


# --- P1: a stored review row with an impossible time is skipped, not a crash -------------------------------------
def test_an_impossible_review_time_is_refused_and_a_stored_one_is_skipped(tmp_path):
    body = {'contract': 'pilot-review/1', 'candidate_key': 'a' * 64, 'cve': None, 'action': 'pin', 'text': '',
            'created_utc': '2026-13-45T99:99:99Z'}
    with pytest.raises(ValueError):
        ReviewEvent.model_validate(body)
    with ProjectService.sample(tmp_path / 'case') as service:
        enrichment = EnrichmentStore(service.store)
        enrichment.ensure()
        guard = Guard(service.project.id, review.GUARD_RUN, 'a' * 64, 'b' * 64)
        row_id = 'pilot-review:11111111-1111-4111-8111-111111111111'
        enrichment.publish(store.KIND, guard, guard, 1, 'complete', body, row_id)
        events = review.read(enrichment)
    assert events.events == () and events.skipped == (row_id,)


# --- B1 / B2: the provenance block keeps its line breaks; the technical list holds what the view makes ------------
def _fingerprint(side: str, sha: str, entries: int, anomalies: int) -> BuildFingerprint:
    rich = RichFacts(offset=0x80, key=1, checksum_ok=True, signature='a' * 64, truncated=False,
                     entries=tuple(RichEntry(product_id=i, build=i, count=1) for i in range(entries)))
    pe = PeBuildFacts(linker_field=(14, 0), os_field=None, image_field=None, subsystem_field=None, subsystem=None,
                      dll_characteristics=(), guard_flags=None, security_cookie_set=None, debug_entry_types=(),
                      repro=False, rich=rich, clr=None, runtime_families=(), entropy_exec_max=None, overlay_size=0,
                      overlay_entropy=None, sampled=False, anomalies=tuple(f'anom-{i}' for i in range(anomalies)))
    return BuildFingerprint(artifact_sha256=sha, side=side, pe=pe, die=None, facts=(),
                            anomalies=tuple(f'x-{i}' for i in range(anomalies)),
                            built_from=BuiltFrom(pe_facts_version=pe.facts_version, die_cache_key=None))


def test_the_provenance_block_keeps_its_line_breaks():
    older, newer = _fingerprint('older', '1' * 64, 3, 0), _fingerprint('newer', '2' * 64, 3, 0)
    block = provenance_block(older, newer)
    assert '\\n' not in block and block.split('\n')[0] == f'OLDER artifact sha256 {"1" * 64}'
    markdown = render_markdown(section_data(build_section(older, newer, compute_delta(older, newer))))
    assert f'- OLDER artifact sha256 {"1" * 64}' in markdown and '\\\\n' not in markdown


def test_the_technical_section_holds_every_line_the_view_makes():
    older, newer = _fingerprint('older', '1' * 64, 64, 16), _fingerprint('newer', '2' * 64, 64, 16)
    section = build_section(older, newer, compute_delta(older, newer), technical=True)
    assert len(section.technical) == 160
