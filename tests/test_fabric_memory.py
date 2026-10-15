"""FAB-0 in-memory sink and reader (docs/specs/program-e/FAB-integration-plan.md s7).

Covers: publish (added, merged, unchanged), replacement per (producer, batch), retraction, atomicity, the limits, the
origin and orientation guards, `get`/`find` (filters, canonical order, paging, pair-member subjects), `resolve`
(found, ambiguous, unknown; never absent), order independence and idempotence, concurrent writers and the null
implementations. Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import itertools
import threading
from concurrent.futures import ThreadPoolExecutor

import fabric_support as fs
import pytest

from patchtrace.fabric import contracts, ids
from patchtrace.fabric.contracts import AnchorQuery, PublishReport
from patchtrace.fabric.limits import FabricError, FabricLimits
from patchtrace.fabric.memory import MemoryAnchorStore, NullAnchorReader, NullAnchorSink

P = 'proj-1'
SMALL = FabricLimits(f01_anchors_per_publish=2, f02_anchors_per_project=3, f03_witnesses_per_anchor=2, f09_page_rows=3)


def raised(call, *args, **kwargs) -> FabricError:
    with pytest.raises(FabricError) as info:
        call(*args, **kwargs)
    return info.value


def store(**kwargs) -> MemoryAnchorStore:
    return MemoryAnchorStore(**kwargs)


# --- publish: identity, merge, replace ----------------------------------------------------------------------------

def test_publish_reports_added_unchanged_and_merged():
    s, subject = store(), fs.pair_key()
    first = fs.import_anchor('RtlULongAdd', subject=subject, producer='cap', source='capa', batch='cap1')
    assert s.publish(P, [first]) == PublishReport(added=1)
    assert s.publish(P, [first]) == PublishReport(unchanged=1)
    second = fs.import_anchor('RtlULongAdd', subject=subject, producer='ue', source='call-label', batch='ue1')
    assert second.anchor_id == first.anchor_id
    assert s.publish(P, [second]) == PublishReport(merged=1)
    merged = s.get(P, first.anchor_id)
    assert {w.producer for w in merged.witnesses} == {'cap', 'ue'} and len(merged.witnesses) == 2
    ids.verify_anchor(merged)


def test_a_duplicate_inside_one_call_collapses():
    s = store()
    a = fs.cve_anchor()
    assert s.publish(P, [a, a]) == PublishReport(added=1)
    assert len(s.get(P, a.anchor_id).witnesses) == 1


def test_publish_replaces_the_previous_generation_of_each_batch_it_names():
    s = store()
    keep, drop = fs.import_anchor('Keep', batch='cap1'), fs.import_anchor('Drop', batch='cap1')
    s.publish(P, [keep, drop])
    assert s.publish(P, [keep]) == PublishReport(unchanged=1, removed=1)
    assert s.get(P, drop.anchor_id) is None and s.get(P, keep.anchor_id) == keep


def test_replacement_never_touches_another_producers_witness():
    s = store()
    shared_cap = fs.import_anchor('Foo', producer='cap', source='capa', batch='cap1')
    shared_ue = fs.import_anchor('Foo', producer='ue', source='call-label', batch='ue1')
    s.publish(P, [shared_cap, shared_ue])
    assert s.publish(P, [fs.import_anchor('Other', batch='cap1')]) == PublishReport(added=1, merged=1)
    survivor = s.get(P, shared_cap.anchor_id)
    assert [w.producer for w in survivor.witnesses] == ['ue']


def test_a_batch_name_is_scoped_to_its_producer():
    s = store()
    a = fs.import_anchor('A', producer='cap', source='capa', batch='same')
    b = fs.import_anchor('B', producer='ue', source='call-label', batch='same')
    s.publish(P, [a])
    assert s.publish(P, [b]) == PublishReport(added=1)
    assert s.get(P, a.anchor_id) is not None


def test_retract_removes_exactly_one_batch():
    s = store()
    a = fs.import_anchor('Foo', producer='cap', source='capa', batch='cap1')
    b = fs.import_anchor('Foo', producer='ue', source='call-label', batch='ue1')
    only = fs.import_anchor('Solo', producer='cap', source='capa', batch='cap1')
    s.publish(P, [a, b, only])
    assert s.retract(P, 'cap', 'cap1') == PublishReport(merged=1, removed=1)
    assert s.get(P, only.anchor_id) is None and [w.producer for w in s.get(P, a.anchor_id).witnesses] == ['ue']
    assert s.retract(P, 'cap', 'cap1') == PublishReport()
    assert s.retract('never-seen', 'cap', 'cap1') == PublishReport()


@pytest.mark.parametrize('producer,batch', [('gui', 'b1'), ('cap', 7), (None, 'b1')], ids=['producer', 'batch', 'none'])
def test_retract_names_a_known_producer_and_a_batch(producer, batch):
    err = raised(store().retract, P, producer, batch)
    assert (err.code, err.reason) == ('PT-FAB-INPUT', 'batch')


def test_a_store_may_clamp_pages_to_its_own_limit_and_still_reports_the_total():
    s = store(limits=FabricLimits(f01_anchors_per_publish=10, f02_anchors_per_project=10, f09_page_rows=2))
    s.publish(P, [fs.import_anchor(name) for name in ('A', 'B', 'C', 'D', 'E')])
    page = s.find(P, AnchorQuery())
    assert (len(page.items), page.total) == (2, 5)
    assert [a.key for a in s.find(P, AnchorQuery(offset=4)).items] == ['e']


def test_publish_is_atomic():
    s = store()
    s.publish(P, [fs.cve_anchor('CVE-2099-0001')])
    before = s.digest(P)
    forged = fs.import_anchor('Foo', origin=('D_ghidra',))  # source capa with a Ghidra lineage
    replacing = fs.cve_anchor('CVE-2099-0002')  # same (kb, run1) batch as the stored anchor: it would replace it
    err = raised(s.publish, P, [replacing, forged])
    assert err.code == 'PT-FAB-ORIGIN' and s.digest(P) == before
    assert s.find(P, AnchorQuery()).total == 1


def test_the_digest_of_an_untouched_project_is_the_empty_digest():
    assert store().digest(P) == ids.anchors_digest([])


# --- limits and input ---------------------------------------------------------------------------------------------

def test_the_publish_size_limit_is_checked_before_anything_changes():
    s = store(limits=SMALL)
    err = raised(s.publish, P, [fs.import_anchor(n) for n in ('A', 'B', 'C')])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'publish-size') and s.find(P, AnchorQuery()).total == 0


def test_the_project_size_limit_leaves_the_stored_state_alone():
    s = store(limits=SMALL)
    s.publish(P, [fs.import_anchor('A'), fs.import_anchor('B')])
    s.publish(P, [fs.import_anchor('C', producer='ue', source='call-label', batch='u1')])
    before = s.digest(P)
    err = raised(s.publish, P, [fs.import_anchor('D', producer='ue', source='call-label', batch='u2')])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'project-size') and s.digest(P) == before


def test_the_witness_limit_applies_to_merged_anchors():
    s = store(limits=SMALL)
    s.publish(P, [fs.import_anchor('Foo', producer='cap', source='capa', batch='b1')])
    s.publish(P, [fs.import_anchor('Foo', producer='ue', source='call-label', batch='b2')])
    err = raised(s.publish, P, [fs.import_anchor('Foo', producer='wbq', source='pe-import', batch='b3')])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'witnesses')
    assert len(s.get(P, fs.import_anchor('Foo').anchor_id).witnesses) == 2


@pytest.mark.parametrize('project', ['', '../etc', 'a b', 'x' * 129, '-lead', 7, None],
                         ids=['empty', 'dots', 'space', 'long', 'dash', 'int', 'none'])
def test_project_keys_are_validated(project):
    s = store()
    for call in (lambda: s.publish(project, []), lambda: s.find(project, AnchorQuery()), lambda: s.get(project, 'a' * 64),
                 lambda: s.resolve(project, 'cve', None, None), lambda: s.retract(project, 'cap', 'b'),
                 lambda: s.digest(project)):
        err = raised(call)
        assert (err.code, err.reason) == ('PT-FAB-INPUT', 'project-key')


def test_publish_accepts_only_anchor_records():
    s = store()
    for bad in (['text'], [object()], [fs.wit()], [{'kind': 'cve'}]):
        err = raised(s.publish, P, bad)
        assert (err.code, err.reason) == ('PT-FAB-INPUT', 'not-an-anchor')
    assert raised(s.publish, P, None).code == 'PT-FAB-INPUT'


def test_publish_rejects_a_tampered_or_semantically_invalid_anchor():
    s = store()
    good = fs.cve_anchor()
    forged = good.model_copy(update={'anchor_id': '0' * 64})
    assert raised(s.publish, P, [forged]).code == 'PT-FAB-INTEGRITY'
    assert s.find(P, AnchorQuery()).total == 0


def test_the_origin_guard_rejects_unknown_sources_and_forged_lineages():
    s = store()
    unknown = fs.anchor('cve', 'CVE-2099-0001', 'none', 'stated', producer='kb', source='mystery', origin=('D_bytes',))
    assert raised(s.publish, P, [unknown]).reason == 'unknown-origin-source'
    assert raised(s.publish, P, [fs.import_anchor('Foo', origin=('D_bytes',))]).reason == 'origin-mismatch'


# --- orientation --------------------------------------------------------------------------------------------------

def test_a_bound_project_rejects_swapped_and_foreign_anchors_and_changes_nothing():
    s = store()
    s.bind_pair(P, fs.OLDER, fs.NEWER)
    s.publish(P, [fs.pair_anchor(), fs.import_anchor('Foo', 'newer', subject=fs.pair_key())])
    before = s.digest(P)
    swapped = fs.anchor('function', None, 'both', 'observed', producer='ue', source='pairing',
                        pair=fs.pair_ref(older_sha=fs.NEWER, newer_sha=fs.OLDER))
    wrong_side = fs.import_anchor('Bar', 'older', input_sha=fs.NEWER)
    for bad, reason in ((swapped, 'orientation-swapped'), (wrong_side, 'orientation-swapped')):
        err = raised(s.publish, P, [fs.cve_anchor('CVE-2099-0009'), bad])
        assert (err.code, err.reason) == ('PT-FAB-ORIENTATION', reason)
    assert s.digest(P) == before


def test_an_unbound_project_cannot_check_orientation_and_accepts_the_anchor():
    s = store()
    swapped = fs.anchor('function', None, 'both', 'observed', producer='ue', source='pairing',
                        pair=fs.pair_ref(older_sha=fs.NEWER, newer_sha=fs.OLDER))
    assert s.publish(P, [swapped]) == PublishReport(added=1)


def test_swapping_the_pair_yields_different_anchor_identities():
    forward = fs.pair_anchor()
    backward = fs.anchor('function', None, 'both', 'observed', producer='ue', source='pairing',
                         pair=fs.pair_ref(older=(fs.F_NEW,), newer=(fs.F_OLD,), older_sha=fs.NEWER, newer_sha=fs.OLDER))
    assert forward.anchor_id != backward.anchor_id and forward.key != backward.key


@pytest.mark.parametrize('older,newer', [('x' * 64, fs.NEWER), (fs.OLDER, 'short'), (1, fs.NEWER)],
                         ids=['bad-older', 'bad-newer', 'int'])
def test_bind_pair_validates_the_hashes(older, newer):
    assert raised(store().bind_pair, P, older, newer).code == 'PT-FAB-INPUT'


# --- find ---------------------------------------------------------------------------------------------------------

def corpus() -> MemoryAnchorStore:
    s = store()
    s.bind_pair(P, fs.OLDER, fs.NEWER)
    pair = fs.pair_key()
    s.publish(P, [
        fs.pair_anchor(), fs.pair_anchor(older=(fs.G_OLD,), newer=(fs.G_NEW,)),
        fs.import_anchor('RtlULongAdd', subject=pair), fs.import_anchor('RtlULongAdd'),
        fs.import_anchor('RtlULongAdd', role='hint', producer='kb', source='advisory-text', batch='kb1'),
        fs.anchor('capability', 'create process', 'newer', 'observed', subject=pair),
        fs.anchor('string', ids.string_key('hello'), 'newer', 'observed', subject=f'image:{fs.NEWER}:rva:0x{fs.F_NEW:x}',
                  producer='wb3', source='floss'),
        fs.anchor('string', ids.string_key('hello'), 'older', 'observed', producer='wb3', source='floss'),
        fs.cve_anchor(), fs.cwe_anchor(190), fs.cwe_anchor(787, role='hint', producer='pil', source='advisory-text'),
    ])
    return s


def count(s, **query) -> int:
    return s.find(P, AnchorQuery(**query)).total


@pytest.mark.parametrize('query,expected', [
    ({}, 11), ({'kind': 'import'}, 3), ({'kind': 'import', 'key': 'rtlulongadd'}, 3),
    ({'kind': 'import', 'role': 'hint'}, 1), ({'side': 'newer'}, 4), ({'side': 'both'}, 2), ({'side': 'none'}, 4),
    ({'side': 'older'}, 1), ({'role': 'stated'}, 2), ({'role': 'hint'}, 2), ({'role': 'observed'}, 7),
    ({'producer': 'wb3'}, 2), ({'producer': 'kb'}, 3), ({'kind': 'cwe'}, 2), ({'kind': 'string', 'side': 'older'}, 1)],
    ids=['all', 'imports', 'import-key', 'import-hint', 'newer', 'both', 'none', 'older', 'stated', 'hint', 'observed',
         'wb3', 'kb', 'cwe', 'old-string'])
def test_find_filters_combine_with_and(query, expected):
    assert count(corpus(), **query) == expected


def test_find_order_is_canonical_whatever_the_publish_order():
    items = [a for a in corpus().find(P, AnchorQuery(limit=500)).items]
    keys = [(contracts.KINDS.index(a.kind), a.key, contracts.SIDES.index(a.side), contracts.ROLES.index(a.role),
             a.subject or '', a.anchor_id) for a in items]
    assert keys == sorted(keys)
    reversed_store = store()
    reversed_store.publish(P, list(reversed(items)))
    assert [a.anchor_id for a in reversed_store.find(P, AnchorQuery(limit=500)).items] == [a.anchor_id for a in items]


def test_find_order_breaks_ties_by_subject_with_no_subject_first():
    s = store()
    subjects = [None, *[fs.pair_key(older=(n,), newer=(n + 1,)) for n in range(1, 8)]]
    s.publish(P, [fs.import_anchor('Tie', subject=subject) for subject in subjects])
    items = s.find(P, AnchorQuery(kind='import')).items
    assert [a.subject for a in items] == sorted(subjects, key=lambda subject: subject or '')


def test_find_pages_report_the_total_and_do_not_overlap():
    s = corpus()
    seen = []
    for offset in range(0, 12, 4):
        page = s.find(P, AnchorQuery(offset=offset, limit=4))
        assert page.total == 11 and len(page.items) == min(4, max(0, 11 - offset))
        seen += [a.anchor_id for a in page.items]
    assert len(seen) == len(set(seen)) == 11
    assert s.find(P, AnchorQuery(offset=50)).items == ()


@pytest.mark.parametrize('change', [{'offset': -1}, {'limit': 0}, {'limit': 501}, {'kind': 'api'}, {'side': 'sideways'},
                                    {'role': 'claimed'}, {'producer': 'gui'}, {'key': 7}],
                         ids=['offset', 'limit-zero', 'limit-over', 'kind', 'side', 'role', 'producer', 'key'])
def test_the_query_validates_its_fields(change):
    err = raised(AnchorQuery, **change)
    assert err.code == ('PT-FAB-KIND' if 'kind' in change else 'PT-FAB-INPUT')


def test_a_pair_subject_also_matches_its_member_image_subjects():
    s = corpus()
    kinds = {a.kind for a in s.find(P, AnchorQuery(subject=fs.pair_key())).items}
    assert kinds == {'import', 'capability', 'string'}  # the string is about the newer image function of the pair
    assert count(s, subject=fs.pair_key(older=(fs.G_OLD,), newer=(fs.G_NEW,))) == 0
    assert count(s, subject=f'image:{fs.NEWER}:rva:0x{fs.F_NEW:x}') == 1  # an image subject does not expand upward
    assert count(s, subject='pair:' + 'e' * 64) == 0


def test_get_returns_the_stored_anchor_or_none():
    s, a = store(), fs.cve_anchor()
    s.publish(P, [a])
    assert s.get(P, a.anchor_id) == a and s.get(P, 'f' * 64) is None and s.get('other', a.anchor_id) is None
    assert s.get(P, 'not-an-id') is None


# --- resolve ------------------------------------------------------------------------------------------------------

def test_resolve_finds_exactly_one_anchor():
    s = corpus()
    result = s.resolve(P, 'cve', 'cve-2099-0001', None)
    assert result.status == 'found' and result.count == 1 and result.label == 'evidence'
    assert result.anchor_id == fs.cve_anchor().anchor_id and result.candidates == ()


def test_resolve_lists_candidates_instead_of_choosing_the_first():
    s = corpus()
    result = s.resolve(P, 'import', 'RtlULongAdd', None)
    assert (result.status, result.count, result.anchor_id) == ('ambiguous', 2, None)  # the hint is not code evidence
    file_level = fs.import_anchor('RtlULongAdd').anchor_id
    function_level = fs.import_anchor('RtlULongAdd', subject=fs.pair_key()).anchor_id
    assert result.candidates == (file_level, function_level)  # canonical order: no subject sorts first
    assert s.resolve(P, 'import', 'RtlULongAdd', 'older').status == 'unknown'


def test_resolve_treats_older_and_newer_as_present_on_both():
    s = store()
    s.publish(P, [fs.anchor('string', ids.string_key('shared'), 'both', 'observed', producer='wb3', source='floss')])
    for side in ('older', 'newer', 'both', None):
        assert s.resolve(P, 'string', 'Shared', side).status == 'found', side
    assert s.resolve(P, 'string', 'Shared', 'none').status == 'unknown'


def test_resolve_ignores_hints_and_statements_for_code_side_kinds_only():
    s = store()
    s.publish(P, [fs.import_anchor('Foo', role='hint', producer='kb', source='advisory-text', batch='kb1'),
                  fs.cwe_anchor(190, role='hint')])
    assert s.resolve(P, 'import', 'Foo', None).status == 'unknown'
    assert s.resolve(P, 'cwe', '190', None).status == 'found'


def test_resolve_finds_a_function_by_key_or_by_its_name_facet():
    s = store()
    named = fs.pair_anchor(facets=(('name', 'ParsePacket'),))
    s.publish(P, [named, fs.image_anchor('newer', 0x2000, facets=(('name', 'ParsePacket'),))])
    assert s.resolve(P, 'function', named.key, 'both').anchor_id == named.anchor_id
    by_name = s.resolve(P, 'function', 'ParsePacket', None)
    assert (by_name.status, by_name.count) == ('ambiguous', 2)
    assert s.resolve(P, 'function', 'ParsePacket', 'older').status == 'found'  # the pair is present on older; image is not
    assert s.resolve(P, 'function', 'parsepacket', None).status == 'unknown'


def test_resolve_without_a_value_asks_for_any_anchor_of_the_kind():
    s = corpus()
    assert s.resolve(P, 'cwe', None, None).status == 'ambiguous'
    assert s.resolve(P, 'kb', None, None).status == 'unknown'


def test_resolve_caps_the_candidate_list():
    s = store()
    s.publish(P, [fs.anchor('capability', f'rule {i:02d}', 'newer', 'observed') for i in range(25)])
    result = s.resolve(P, 'capability', None, 'newer')
    assert (result.status, result.count, len(result.candidates)) == ('ambiguous', 25, 20)


def test_resolve_never_says_absent_and_says_unknown_when_nothing_ran():
    s = store()
    for kind in contracts.KINDS:
        assert s.resolve(P, kind, None, None).status == 'unknown'
    assert s.resolve(P, 'capability', 'create process', 'newer').status == 'unknown'
    assert 'absent' not in contracts.RESOLVE_STATUSES


def test_resolve_validates_kind_side_and_value():
    s = store()
    assert raised(s.resolve, P, 'api', None, None).code == 'PT-FAB-KIND'
    assert raised(s.resolve, P, 'cve', None, 'sideways').code == 'PT-FAB-INPUT'
    assert raised(s.resolve, P, 'cve', 'banana', None).code == 'PT-FAB-KEY'


# --- order independence, idempotence, threads ---------------------------------------------------------------------

def _batches():
    pair = fs.pair_key()
    return [
        [fs.pair_anchor(batch='u1'), fs.image_anchor('newer', 0x2000, batch='u1')],
        [fs.import_anchor('Foo', subject=pair, batch='c1'), fs.anchor('capability', 'x', 'newer', 'observed', batch='c1')],
        [fs.import_anchor('Foo', subject=pair, producer='ue', source='call-label', batch='u2'),
         fs.cwe_anchor(190, batch='k1')],
        [fs.cwe_anchor(190, producer='kev', source='kev-cwe', batch='v1'), fs.cve_anchor(batch='k2')],
    ]


def test_the_publish_order_of_different_batches_does_not_change_the_result():
    digests = set()
    for order in itertools.permutations(_batches()):
        s = store()
        for batch in order:
            s.publish(P, batch)
        digests.add(s.digest(P))
    assert len(digests) == 1


def test_publishing_every_batch_twice_changes_nothing():
    s = store()
    for batch in _batches():
        s.publish(P, batch)
    once = s.digest(P)
    for batch in _batches():
        assert s.publish(P, batch).added == 0
    assert s.digest(P) == once


def test_concurrent_writers_of_different_batches_end_in_the_sequential_state():
    sequential = store()
    for batch in _batches():
        sequential.publish(P, batch)
    shared = store()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda batch: shared.publish(P, batch), _batches()))
    assert shared.digest(P) == sequential.digest(P)


def test_a_second_writer_waits_for_the_first_instead_of_overwriting_it():
    """Hold writer A inside the critical section (the store reads a limit there) and start writer B: without the lock B
    would build its state from the same starting point and one of the two results would be lost."""
    armed, entered, second, release = (threading.Event() for _ in range(4))
    reads = []

    class Gated(FabricLimits):
        def __getattribute__(self, name):
            if name == 'f03_witnesses_per_anchor' and armed.is_set():
                reads.append(name)
                (entered if len(reads) == 1 else second).set()
                release.wait(5)
            return super().__getattribute__(name)

    s = store(limits=Gated())
    armed.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(s.publish, P, [fs.import_anchor('A', batch='b1')])
        assert entered.wait(5)
        b = pool.submit(s.publish, P, [fs.import_anchor('B', producer='ue', source='call-label', batch='b2')])
        second.wait(0.2)  # a correct store keeps B out of the critical section while A is inside it
        release.set()
        a.result(5)
        b.result(5)
    assert s.find(P, AnchorQuery()).total == 2


def test_projects_are_independent():
    s = store()
    s.publish('proj-a', [fs.cve_anchor()])
    assert s.find('proj-b', AnchorQuery()).total == 0 and s.digest('proj-a') != s.digest('proj-b')


# --- null implementations -----------------------------------------------------------------------------------------

def test_the_null_sink_accepts_everything_and_the_null_reader_knows_nothing():
    sink, reader = NullAnchorSink(), NullAnchorReader()
    assert sink.publish(P, [fs.cve_anchor()]) == PublishReport() and sink.retract(P, 'kb', 'b') == PublishReport()
    assert reader.get(P, 'a' * 64) is None
    assert reader.find(P, AnchorQuery()).total == 0 and reader.find(P, AnchorQuery()).items == ()
    result = reader.resolve(P, 'cve', 'CVE-2099-0001', None)
    assert (result.status, result.anchor_id, result.count) == ('unsupported', None, 0)
