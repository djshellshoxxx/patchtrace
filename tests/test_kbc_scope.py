"""K1: search scope and two-axis coverage arithmetic (KB-integration-plan 6, 7.1 rows 4-5). SYNTHETIC/mocked."""
from __future__ import annotations

import copy

import kbc_helpers as h
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from kbc_k1_support import NOW, import_doc, no_sockets  # noqa: F401

from patchtrace.kbcorrelation.sources import scope
from patchtrace.kbcorrelation.sources.cvrf import SourceError

pytestmark = pytest.mark.usefixtures('no_sockets')
DOC = 'a' * 64


def cov(requested, inspected, **kw):
    sc = kw.pop('scope', scope.months_scope(['2099-Jan']))
    return scope.build_coverage(source_kind='cvrf-month', scope=sc, requested=requested, inspected=inspected,
                                retrieved_at=NOW, **kw)


def test_months_parse_in_both_spellings_sorted_and_unique():
    assert scope.parse_months('2099-03, 2099-Feb,2099-02') == ('2099-Feb', '2099-Mar')
    assert scope.month_range('2098-11', '2099-02') == ('2098-Nov', '2098-Dec', '2099-Jan', '2099-Feb')
    for bad in ('', ',', '2099-13', '99-01', 'Feb-2099', '2099-Febr'):
        with pytest.raises(SourceError) as info:
            scope.parse_months(bad)
        assert info.value.code == 'PT-KBC-SCOPE'


def test_at_most_24_months_per_scope():
    many = ','.join(scope.month_range('2097-01', '2098-12'))
    assert len(scope.parse_months(many)) == 24
    with pytest.raises(SourceError, match='at most 24'):
        scope.parse_months(many + ',2099-01')
    with pytest.raises(SourceError, match='at most 24'):
        scope.months_scope(scope.month_range('2097-01', '2099-01'))


def test_scope_file_kinds():
    assert scope.parse_scope_file('# c\n2099-02\n2099-Jan  # inline\n').months == ('2099-Feb', '2099-Jan')  # K0 order: alphabetical strings
    docs = scope.parse_scope_file(f'{DOC}\n{"b" * 64}\n')
    assert docs.kind == 'provided_files' and docs.doc_ids == (DOC, 'b' * 64)
    mixed = scope.parse_scope_file(f'2099-Feb\n{DOC}')
    assert mixed.kind == 'mixed' and mixed.corpus_digest
    for bad in ('', '# only a comment', 'whatever', 'A' * 64):
        with pytest.raises(SourceError):
            scope.parse_scope_file(bad)


def test_complete_in_scope_iff_requested_equals_inspected():
    assert cov(['2099-Jan', '2099-Feb'], ['2099-Jan', '2099-Feb']).state == 'complete_in_scope'
    assert cov(['2099-Jan', '2099-Feb'], ['2099-Jan']).state == 'partial_in_scope'
    assert cov(['2099-Jan'], []).state == 'not_searched'
    assert cov([], []).state == 'not_searched'
    failed = cov(['2099-Jan', '2099-Feb'], ['2099-Jan', '2099-Feb'], failed=[('2099-Jan', 'unreadable')])
    assert failed.state == 'partial_in_scope' and failed.inspected_ids == ('2099-Feb',)
    assert cov(['2099-Jan', '2099-Feb'], ['2099-Jan', '2099-Feb'], unfetchable=['2099-Feb']).state == 'partial_in_scope'
    assert cov(['2099-Jan'], ['2099-Jan'], scope_known=False).state == 'unknown_scope'
    assert cov(['2099-Jan'], ['2099-Jan'], stale=True).state == 'stale_cache'
    assert cov(['2099-Jan', '2099-Feb'], ['2099-Jan'], stale=True).state == 'partial_in_scope'
    assert cov(['2099-Jan'], ['2099-Jan', 'other']).inspected_ids == ('2099-Jan',)  # strays are not inspected


@settings(max_examples=80, deadline=None)
@given(st.sets(st.sampled_from(list('abcdef'))), st.sets(st.sampled_from(list('abcdef'))),
       st.sets(st.sampled_from(list('abcdef'))))
def test_property_complete_iff_everything_requested_was_inspected(requested, inspected, failed):
    c = cov(sorted(requested), sorted(inspected), failed=[(i, 'x') for i in sorted(failed & requested)])
    clean = requested and requested <= inspected and not (failed & requested)
    assert (c.state == 'complete_in_scope') == bool(clean)
    assert c.exhaustive_for_history is False


def test_coverage_id_is_deterministic_and_content_bound():
    assert cov(['a'], ['a']).coverage_id == cov(['a'], ['a']).coverage_id
    assert cov(['a'], ['a']).coverage_id != cov(['a', 'b'], ['a']).coverage_id


def test_coverage_text_never_says_no_cves_and_always_carries_the_lag_note():
    texts = [scope.coverage_text(c) for c in (
        cov(['2099-Jan', '2099-Feb'], ['2099-Jan', '2099-Feb'], watermark='2099-02-13T00:00:00Z'),
        cov(['2099-Jan', '2099-Feb'], ['2099-Jan'], failed=[('2099-Feb', 'unreadable')]),
        cov(['2099-Jan'], []), cov(['2099-Jan'], ['2099-Jan'], stale=True),
        cov(['2099-Jan'], ['2099-Jan'], scope_known=False))]
    assert 'Checked 2 of 2 documents (2099-Jan to 2099-Feb)' in texts[0] and 'newest revision seen 2099-02-13' in texts[0]
    assert '1 unreadable' in texts[1] and 'not loaded' in texts[1] or '1 requested document' in texts[1]
    assert 'Nothing was searched' in texts[2] and 'older than the staleness policy' in texts[3]
    assert 'not known' in texts[4]
    for t in texts:
        assert 'nothing else was checked' in t or 'Nothing was searched' in t
        assert 'Revised CVEs may sit in earlier documents' in t and 'no CVEs' not in t


def revised_doc(release: str, current: str, vulns=()):
    doc = h.cvrf_document(list(vulns), release_id=release)
    doc['document']['current_release_date'] = current
    return import_doc(doc)


def test_coverage_two_axes():
    """Plan 6 `test_coverage_two_axes`: a month window selects by document id; a CVE revised later stays in its original
    document, so the second axis (currentReleaseDate) finds documents the month window misses."""
    jan = revised_doc('2099-Jan', '2099-03-05', [h.vulnerability('CVE-2099-50001', 'revised', remediations=[
        h.remediation(2, '5099501', [h.PRODUCT_CLIENT])])])
    feb = revised_doc('2099-Feb', '2099-02-13')
    mar = revised_doc('2099-Mar', '2099-03-12')
    docs = [jan.source, feb.source, mar.source]
    window = scope.months_scope(['2099-Feb', '2099-Mar'])
    assert set(window.months) == {feb.source.release_id, mar.source.release_id}
    assert window.months == ('2099-Feb', '2099-Mar')
    assert jan.source.release_id not in window.months  # axis 1 misses the revised January document
    missed = scope.docs_revised_since(docs, '2099-Feb')  # axis 2
    assert [d.release_id for d in missed] == ['2099-Jan']
    assert scope.docs_revised_since(docs, '2099-Apr') == ()
    assert scope.docs_revised_since([feb.source], '2099-Feb') == ()  # not before the window
    c = scope.build_coverage(source_kind='cvrf-month', scope=window, requested=window.months,
                             inspected=window.months, watermark=max(d.current_release_date for d in docs[1:]),
                             retrieved_at=NOW)
    assert c.state == 'complete_in_scope' and c.watermark_current_release_date == '2099-03-12T00:00:00Z'
    assert scope.REVISION_LAG_NOTE in scope.coverage_text(c).lower().replace('revised cves','revised CVEs')


def test_corpus_digest_is_order_independent_and_content_bound():
    assert scope.corpus_digest(['b', 'a']) == scope.corpus_digest(['a', 'b', 'a'])
    assert scope.corpus_digest(['a']) != scope.corpus_digest(['a', 'b'])
    sc = scope.corpus_scope([DOC])
    assert sc.kind == 'cached_corpus' and sc.corpus_digest == scope.corpus_digest([DOC])
    assert scope.files_scope([DOC, DOC]).doc_ids == (DOC,)


def test_release_ordinals_order_across_years():
    ids = ['2099-Jan', '2098-Dec', '2099-Feb']
    assert sorted(ids, key=scope.release_ordinal) == ['2098-Dec', '2099-Jan', '2099-Feb']
    assert copy.copy(scope.MONTHS)[0] == 'Jan'
