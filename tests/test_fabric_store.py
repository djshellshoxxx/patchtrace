"""FAB-1 enrichment-backed anchor store (docs/specs/program-e/FAB-integration-plan.md s7 "Store as built").

Covers: the row layout and guard, a round trip through a second store, a step-by-step and a random-sequence
differential against the reference `MemoryAnchorStore`, replacement and retraction by row, staleness (a moved origin
table, a guard stored moved), the orientation bound from the project (also across a real swap), per-anchor
skip-and-count and unreadable rows, the checks and the error mapping, retention and old readers (the kind is known,
never derived, never deleted) and the read cache. Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
from pathlib import Path

import fabric_store_support as fss
import fabric_support as fs
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.enrichment import storage
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.fabric import ids, origins
from patchtrace.fabric import store as fabric_store
from patchtrace.fabric.contracts import AnchorQuery, PublishReport
from patchtrace.fabric.limits import FabricError, FabricLimits
from patchtrace.fabric.memory import MemoryAnchorStore
from patchtrace.fabric.store import BatchStatus, EnrichmentAnchorStore, FabricBatch
from patchtrace.sample import create_sample
from patchtrace.secondary import load_secondary
from patchtrace.secondary.store import current_sets

P = fss.PROJECT
PAIR = fs.pair_key()
FUTURE = '9999-01-01T00:00:00+00:00'
ALL = AnchorQuery(limit=500)
GOLDEN_BATCH_DIGEST = '511f29a089c9e2a6df7ea23e0ae121c276bf65a92a88cce868e3a98f6e67c2f4'


def raised(call, *args, **kwargs) -> FabricError:
    with pytest.raises(FabricError) as info:
        call(*args, **kwargs)
    return info.value


@pytest.fixture
def project(tmp_path):
    handle = fss.make_project(tmp_path)
    yield handle
    if not handle.closed:
        handle.close()


@pytest.fixture
def store(project):
    return fss.make_store(project)


def calls() -> dict[str, list]:
    """Four producers' calls, one batch each; the import about the pair is seen by two of them, CWE-190 by two."""
    return {
        'ue': [fs.pair_anchor(batch='u1'), fs.pair_anchor(older=(fs.G_OLD,), newer=(fs.G_NEW,), batch='u1'),
               fs.import_anchor('RtlULongAdd', subject=PAIR, producer='ue', source='call-label', batch='u1')],
        'cap': [fs.import_anchor('RtlULongAdd', subject=PAIR, batch='c1'),
                fs.anchor('capability', 'create process', 'newer', 'observed', subject=PAIR, batch='c1')],
        'kb': [fs.cwe_anchor(190, batch='k1'), fs.cve_anchor(batch='k1'),
               fs.import_anchor('RtlULongAdd', role='hint', producer='kb', source='advisory-text', batch='k1')],
        'kev': [fs.cwe_anchor(190, producer='kev', source='kev-cwe', batch='v1')]}


def publish_all(target) -> None:
    for call in calls().values():
        target.publish(P, call)


def reference() -> MemoryAnchorStore:
    ref = MemoryAnchorStore()
    ref.bind_pair(P, fs.OLDER, fs.NEWER)
    return ref


def put_row(project, producer: str, batch: str, anchors, *, contract: str = fabric_store.CONTRACT,
            origins_digest: str | None = None, guard_project: str = P, row_id: str | None = None,
            digest: str = 'd' * 64, current_digest: str | None = None, **extra) -> None:
    """Store a row the way another version of PatchTrace may have written it (bypassing the store under test)."""
    body = {'contract': contract, 'producer': producer, 'batch': batch,
            'origins_digest': origins.digest() if origins_digest is None else origins_digest,
            'anchors': anchors, **extra}
    guard = Guard(guard_project, fabric_store.GUARD_RUN, '', digest)
    current = guard if current_digest is None else Guard(guard_project, fabric_store.GUARD_RUN, '', current_digest)
    EnrichmentStore(project).publish(fabric_store.KIND, guard, current, 3, 'complete', body,
                                     row_id or fabric_store.row_id(producer, batch))


def as_json(anchor) -> dict:
    return json.loads(anchor.model_dump_json())


# --- rows and round trip ------------------------------------------------------------------------------------------

def test_the_kind_is_known_and_never_derived():
    assert fabric_store.KIND == 'anchor-batch' and fabric_store.KIND in storage.KINDS
    assert fabric_store.KIND not in storage.DERIVED_KINDS


def test_publish_writes_one_row_per_producer_and_batch(project, store):
    c = calls()
    assert store.publish(P, [*c['ue'], *c['cap']]) == PublishReport(added=4)
    stored = fss.rows(project)
    assert set(stored) == {'fabric:ue:u1', 'fabric:cap:c1'}
    for row_id, row in stored.items():
        batch = FabricBatch.model_validate_json(json.dumps(row['body']))
        assert row_id == fabric_store.row_id(batch.producer, batch.batch) and batch.contract == 'fabric-batch/1'
        assert batch.origins_digest == origins.digest() and not row['stale'] and row['revision'] == 3
        assert row['status'] == 'complete'
        assert [a.anchor_id for a in batch.anchors] == sorted(a.anchor_id for a in batch.anchors)
        assert all((w.producer, w.batch) == (batch.producer, batch.batch) for a in batch.anchors for w in a.witnesses)
        digest = fabric_store.batch_digest(batch.producer, batch.batch, batch.origins_digest, batch.anchors)
        assert row['guard'] == (P, 'fabric', '', digest)
    assert len(FabricBatch.model_validate_json(json.dumps(stored['fabric:ue:u1']['body'])).anchors) == 3
    assert len(FabricBatch.model_validate_json(json.dumps(stored['fabric:cap:c1']['body'])).anchors) == 2


def test_an_anchor_seen_by_two_batches_is_stored_once_per_batch_and_read_back_merged(project, store):
    c = calls()
    store.publish(P, [*c['ue'], *c['cap']])
    shared = fs.import_anchor('RtlULongAdd', subject=PAIR).anchor_id
    holders = {row_id: [a['anchor_id'] for a in row['body']['anchors']] for row_id, row in fss.rows(project).items()}
    assert shared in holders['fabric:ue:u1'] and shared in holders['fabric:cap:c1']
    merged = store.get(P, shared)
    assert sorted((w.producer, w.batch) for w in merged.witnesses) == [('cap', 'c1'), ('ue', 'u1')]
    ids.verify_anchor(merged)


def test_a_second_store_reads_back_what_the_first_published(project, store):
    publish_all(store)
    again = fss.make_store(project)
    assert again.digest(P) == store.digest(P) != ids.anchors_digest([])
    assert again.find(P, ALL).items == store.find(P, ALL).items and again.find(P, ALL).total == 7
    assert again.batches(P) == store.batches(P)
    assert again.get(P, fs.cve_anchor(batch='k1').anchor_id).label == 'evidence'


def test_two_witnesses_of_one_anchor_in_one_batch_make_one_stored_anchor(project, store):
    one = fs.cwe_anchor(190, batch='k1', label='from the advisory')
    two = fs.cwe_anchor(190, source='nvd-cwe', batch='k1', label='from the NVD record')
    assert one.anchor_id == two.anchor_id
    assert store.publish(P, [one, two]) == PublishReport(added=1)
    (stored,) = fss.rows(project)['fabric:kb:k1']['body']['anchors']
    assert sorted(w['source'] for w in stored['witnesses']) == ['advisory-text', 'nvd-cwe']
    assert fss.make_store(project).get(P, one.anchor_id) == store.get(P, one.anchor_id)
    assert len(store.get(P, one.anchor_id).witnesses) == 2


def test_one_anchor_with_witnesses_of_two_batches_is_stored_in_both_rows(project, store):
    both = ids.make_anchor(kind='cwe', key='CWE-190', side='none', role='stated', witnesses=(
        fs.wit('kb', 'advisory-text', batch='k1', label='advisory'), fs.wit('kev', 'kev-cwe', batch='v1', label='kev')))
    assert store.publish(P, [both]) == PublishReport(added=1)
    rows = fss.rows(project)
    assert set(rows) == {'fabric:kb:k1', 'fabric:kev:v1'}
    for row_id, producer in (('fabric:kb:k1', 'kb'), ('fabric:kev:v1', 'kev')):
        (stored,) = rows[row_id]['body']['anchors']
        assert [w['producer'] for w in stored['witnesses']] == [producer]  # each row keeps its own batch's witness
    assert fss.make_store(project).get(P, both.anchor_id) == store.get(P, both.anchor_id) == both
    assert store.retract(P, 'kev', 'v1') == PublishReport(merged=1)
    assert [w.producer for w in store.get(P, both.anchor_id).witnesses] == ['kb']


def test_a_row_may_not_hold_more_anchors_than_the_contract_allows(project, monkeypatch):
    loose = fss.make_store(project, limits=FabricLimits(f01_anchors_per_publish=100, f02_anchors_per_project=200,
                                                                     f09_page_rows=100))
    monkeypatch.setattr(fabric_store, '_L', FabricLimits(f01_anchors_per_publish=2, f02_anchors_per_project=3,
                                                         f09_page_rows=3))
    err = raised(loose.publish, P, [fs.import_anchor(name, batch='c1') for name in ('A', 'B', 'C')])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'publish-size') and fss.row_ids(project) == set()


def test_the_batch_digest_follows_the_planned_formula_and_is_pinned():
    a = fs.cve_anchor('CVE-2099-0001', batch='k1')
    digest = fabric_store.batch_digest('kb', 'k1', 'e' * 64, [a])
    payload = {'producer': 'kb', 'batch': 'k1', 'origins_digest': 'e' * 64,
               'anchors_digest': ids.anchors_digest([a])}
    head = b'patchtrace\x00fabric-batch\x001\x00'
    text = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    assert digest == hashlib.sha256(head + text).hexdigest() == GOLDEN_BATCH_DIGEST
    others = [fabric_store.batch_digest('kb', 'k2', 'e' * 64, [a]),
              fabric_store.batch_digest('cap', 'k1', 'e' * 64, [a]),
              fabric_store.batch_digest('kb', 'k1', 'f' * 64, [a]),
              fabric_store.batch_digest('kb', 'k1', 'e' * 64, [])]
    assert len({digest, *others}) == 5  # each of producer, batch, origin table and anchors is part of it


def test_the_row_body_is_deterministic(project, store):
    store.publish(P, calls()['kb'])
    first = fss.rows(project)['fabric:kb:k1']
    store.publish(P, list(reversed(calls()['kb'])))
    second = fss.rows(project)['fabric:kb:k1']
    assert second['body_sha256'] == first['body_sha256'] and second['body'] == first['body']


def test_reads_create_nothing_on_a_project_that_never_published(project, store):
    assert store.find(P, ALL).total == 0 and store.get(P, 'a' * 64) is None
    assert store.resolve(P, 'cve', None, None).status == 'unknown' and store.batches(P) == ()
    assert store.digest(P) == ids.anchors_digest([]) and not fss.has_table(project)


# --- differential against the reference ---------------------------------------------------------------------------

def compare(store, ref, project) -> None:
    assert store.digest(P) == ref.digest(P)
    assert fss.make_store(project).digest(P) == ref.digest(P)  # what is stored reads back as the reference holds it
    assert store.find(P, ALL) == ref.find(P, ALL)


def test_every_step_gives_the_answers_of_the_reference(project, store):
    c, ref = calls(), reference()
    steps = [('publish', c['ue']), ('publish', c['cap']), ('publish', [*c['kb'], *c['kev']]),
             ('publish', c['cap'][:1]), ('retract', ('ue', 'u1')), ('publish', c['ue']), ('retract', ('kb', 'k1')),
             ('retract', ('kb', 'k1')), ('retract', ('wb3', 'never')), ('publish', []), ('publish', c['ue'])]
    for name, argument in steps:
        got = getattr(store, name)(P, *((argument,) if name == 'publish' else argument))
        want = getattr(ref, name)(P, *((argument,) if name == 'publish' else argument))
        assert got == want, (name, argument)
        compare(store, ref, project)
    for kind, value, side in (('import', 'RtlULongAdd', 'newer'), ('import', 'RtlULongAdd', None), ('cwe', '190', None),
                              ('capability', 'create process', 'newer'), ('function', PAIR, 'both'),
                              ('cve', None, None), ('kb', None, None)):
        assert store.resolve(P, kind, value, side) == ref.resolve(P, kind, value, side), (kind, value, side)
    for query in (AnchorQuery(subject=PAIR), AnchorQuery(kind='import', role='hint'), AnchorQuery(producer='kev')):
        assert store.find(P, query) == ref.find(P, query)


POOL = [anchor for call in calls().values() for anchor in call] + [
    fs.anchor('string', ids.string_key('hello'), 'newer', 'observed', producer='wb3', source='floss', batch='w1',
              subject=ids.image_key(fs.NEWER, fs.F_NEW)),
    fs.import_anchor('RtlULongAdd', producer='wbq', source='pe-import', batch='p1'),
    fs.import_anchor('Other', subject=PAIR, batch='c2'),
    fs.cwe_anchor(190, source='nvd-cwe', batch='k1'),  # a second witness of CWE-190 inside the same batch
    fs.cwe_anchor(787, role='hint', producer='pil', batch='l1', source='advisory-text')]
BATCHES = sorted({(w.producer, w.batch) for a in POOL for w in a.witnesses})
OPERATIONS = st.lists(st.one_of(
    st.tuples(st.just('publish'), st.lists(st.sampled_from(range(len(POOL))), max_size=6)),
    st.tuples(st.just('retract'), st.sampled_from(BATCHES))), max_size=8)


@settings(max_examples=25, deadline=None)
@given(OPERATIONS)
def test_random_operation_sequences_match_the_reference(operations):
    with tempfile.TemporaryDirectory() as root:
        project = fss.make_project(Path(root))
        try:
            store, ref = fss.make_store(project), reference()
            for name, argument in operations:
                if name == 'publish':
                    call = [POOL[i] for i in argument]
                    assert store.publish(P, call) == ref.publish(P, call)
                else:
                    assert store.retract(P, *argument) == ref.retract(P, *argument)
                compare(store, ref, project)
        finally:
            project.close()


# --- replacement and retraction by row ----------------------------------------------------------------------------

def test_republishing_a_batch_replaces_its_row_and_leaves_the_others(project, store):
    publish_all(store)
    untouched = {row_id: row['body_sha256'] for row_id, row in fss.rows(project).items() if row_id != 'fabric:cap:c1'}
    keep = calls()['cap'][:1]
    assert store.publish(P, keep) == PublishReport(unchanged=1, removed=1)
    stored = fss.rows(project)
    assert [a['kind'] for a in stored['fabric:cap:c1']['body']['anchors']] == ['import']
    assert {row_id: row['body_sha256'] for row_id, row in stored.items() if row_id != 'fabric:cap:c1'} == untouched
    assert store.resolve(P, 'capability', 'create process', 'newer').status == 'unknown'


def test_retract_deletes_exactly_one_row(project, store):
    publish_all(store)
    others = fss.row_ids(project) - {'fabric:cap:c1'}
    assert store.retract(P, 'cap', 'c1') == PublishReport(merged=1, removed=1)
    assert fss.row_ids(project) == others
    shared = store.get(P, fs.import_anchor('RtlULongAdd', subject=PAIR).anchor_id)
    assert [w.producer for w in shared.witnesses] == ['ue']
    assert store.retract(P, 'cap', 'c1') == PublishReport()
    assert fss.make_store(project).digest(P) == store.digest(P)


def test_retract_on_a_project_that_never_published_creates_nothing(project, store):
    assert store.retract(P, 'cap', 'c1') == PublishReport() and not fss.has_table(project)


def test_retract_names_a_known_producer(store):
    assert raised(store.retract, P, 'gui', 'b1').reason == 'batch'


def test_a_retraction_deletes_batch_rows_only(project, store):
    store.publish(P, calls()['cap'])
    guard = Guard(P, 'r', 'a' * 64, 'b' * 64)
    EnrichmentStore(project).publish('patch-intent', guard, guard, 1, 'complete', {'x': 1}, 'fabric:kb:k1')
    assert store.retract(P, 'kb', 'k1') == PublishReport()  # a row of another kind under the id of the batch row
    assert fss.row_ids(project, 'patch-intent') == {'fabric:kb:k1'}


def test_a_publish_sees_the_rows_another_store_wrote(project, store):
    other = fss.make_store(project)
    store.publish(P, calls()['cap'])
    other.publish(P, calls()['ue'])
    ref = reference()
    ref.publish(P, calls()['cap'])
    ref.publish(P, calls()['ue'])
    assert store.publish(P, calls()['cap'][:1]) == ref.publish(P, calls()['cap'][:1]) == PublishReport(
        unchanged=1, removed=1)
    assert store.digest(P) == ref.digest(P) == fss.make_store(project).digest(P)


# --- staleness ----------------------------------------------------------------------------------------------------

def test_a_changed_origin_table_marks_batches_stale_but_keeps_their_anchors(project, store):
    publish_all(store)
    assert not any(b.stale for b in store.batches(P))
    moved = fss.make_store(project, registry=origins.DefaultOriginRegistry(version=2))
    assert moved.digest(P) == store.digest(P) and moved.find(P, ALL).total == 7
    assert [b.stale for b in moved.batches(P)] == [True] * 4 and all(b.readable for b in moved.batches(P))
    assert moved.publish(P, calls()['kev']) == PublishReport(unchanged=1)  # a producer republishes under the new table
    assert {b.producer: b.stale for b in moved.batches(P)} == {'cap': True, 'kb': True, 'kev': False, 'ue': True}
    stored = fss.rows(project)['fabric:kev:v1']['body']
    assert stored['origins_digest'] == origins.DefaultOriginRegistry(version=2).digest()


def test_a_row_stored_with_a_moved_guard_is_listed_stale_and_still_read(project, store):
    anchor = fs.import_anchor('Foo', batch='c1')
    put_row(project, 'cap', 'c1', [as_json(anchor)], current_digest='e' * 64)
    assert fss.rows(project)['fabric:cap:c1']['stale'] is True
    status = store.batches(P)
    assert status == (BatchStatus('fabric:cap:c1', 'cap', 'c1', anchors=1, skipped=0, stale=True, readable=True),)
    assert store.get(P, anchor.anchor_id) == anchor


def test_a_stale_flag_set_without_a_new_body_is_noticed(project, store):
    store.publish(P, [fs.import_anchor('Foo', batch='c1')])
    assert store.batches(P)[0].stale is False  # loaded and cached
    body = fss.rows(project)['fabric:cap:c1']['body']
    guard = Guard(P, fabric_store.GUARD_RUN, '', 'd' * 64)
    moved = Guard(P, fabric_store.GUARD_RUN, '', 'e' * 64)
    EnrichmentStore(project).publish(fabric_store.KIND, guard, moved, 3, 'complete', body, 'fabric:cap:c1')
    assert store.batches(P)[0].stale is True


def test_swapping_the_orientation_skips_what_was_made_for_the_old_one(project, store):
    publish_all(store)
    fss.write_snapshot(project, fss.snapshot_text(older=fs.NEWER, newer=fs.OLDER))
    survivors = {a.kind for a in store.find(P, ALL).items}
    assert survivors == {'cve', 'cwe', 'import'}  # statements and the hint: nothing in them names an image
    assert store.find(P, ALL).total == 3
    assert {b.producer: (b.anchors, b.skipped) for b in store.batches(P)} == {
        'ue': (0, 3), 'cap': (0, 2), 'kb': (3, 0), 'kev': (1, 0)}
    assert raised(store.publish, P, [fs.import_anchor('Foo', batch='c9')]).code == 'PT-FAB-ORIENTATION'
    fss.write_snapshot(project, fss.snapshot_text())  # swapped back: nothing was deleted
    assert store.find(P, ALL).total == 7 and not any(b.skipped for b in store.batches(P))


def test_a_real_project_swap_hides_the_old_orientation(tmp_path):
    svc = create_sample(tmp_path / 'real')
    try:
        older = next(a.sha256 for a in svc.project.artifacts if a.side == 'older')
        witness = ids.make_witness(producer='cap', batch='c1', source='capa', origins=('D_vivisect',), label='Foo',
                                   input_sha256=older)
        seen = ids.make_anchor(kind='import', key=ids.api_key('Foo'), side='older', role='observed',
                               witnesses=(witness,))
        target = EnrichmentAnchorStore(EnrichmentStore(svc.store))
        key = svc.project.id
        assert target.publish(key, [seen, fs.cve_anchor(batch='k1')]) == PublishReport(added=2)
        assert target.find(key, ALL).total == 2
        svc.swap_orientation()
        assert [a.kind for a in target.find(key, ALL).items] == ['cve']
        assert [(b.producer, b.skipped) for b in target.batches(key)] == [('cap', 1), ('kb', 0)]
    finally:
        svc.close()


# --- per-anchor skip and count, unreadable rows ---------------------------------------------------------------------

def test_unreadable_anchors_are_skipped_and_counted_and_the_rest_is_read(project, store):
    store.publish(P, [fs.import_anchor('Kept', batch='c1')])
    good = fs.import_anchor('Fine', batch='c2')
    unknown_kind = as_json(fs.import_anchor('Future', batch='c2')) | {'kind': 'future-kind'}
    extra_field = as_json(fs.import_anchor('Extra', batch='c2')) | {'confidence': 'high'}
    tampered = as_json(fs.import_anchor('Tampered', batch='c2'))
    tampered['witnesses'][0]['label'] = 'changed after the id was derived'
    foreign = as_json(fs.import_anchor('Foreign', batch='other'))
    swapped = as_json(fs.import_anchor('Swapped', 'older', input_sha=fs.NEWER, batch='c2'))
    put_row(project, 'cap', 'c2', [as_json(good), unknown_kind, extra_field, tampered, foreign, swapped])
    reader = fss.make_store(project)
    by_batch = {b.batch: b for b in reader.batches(P)}
    assert (by_batch['c2'].anchors, by_batch['c2'].skipped, by_batch['c2'].readable) == (1, 5, True)
    assert (by_batch['c1'].anchors, by_batch['c1'].skipped) == (1, 0)
    assert {a.key for a in reader.find(P, ALL).items} == {'kept', 'fine'}
    assert reader.get(P, good.anchor_id) == good


def fine() -> list:
    return [as_json(fs.import_anchor('Fine', batch='c2'))]


def corrupt_hash(project):
    put_row(project, 'cap', 'c2', fine())
    changed = project.connection.execute(
        "UPDATE enrichment_entries SET body=replace(body, 'evidence', 'evidenCe') WHERE id=?", ('fabric:cap:c2',))
    project.connection.commit()
    assert changed.rowcount == 1
    assert fss.rows(project)['fabric:cap:c2']['body']['anchors'][0]['witnesses'][0]['label'] == 'evidenCe'


# case -> (writes the broken row, the (producer, batch) its row id names)
UNREADABLE = {
    'hash': (corrupt_hash, ('cap', 'c2')),
    'newer-contract': (lambda p: put_row(p, 'cap', 'c2', fine(), contract='fabric-batch/2'), ('cap', 'c2')),
    'other-project': (lambda p: put_row(p, 'cap', 'c2', fine(), guard_project='proj-2'), ('cap', 'c2')),
    'row-id': (lambda p: put_row(p, 'cap', 'c2', fine(), row_id='fabric:cap:c9'), ('cap', 'c9')),
    'extra-key': (lambda p: put_row(p, 'cap', 'c2', fine(), notes='x'), ('cap', 'c2')),
    'not-a-list': (lambda p: put_row(p, 'cap', 'c2', {'kind': 'import'}), ('cap', 'c2')),
    'unknown-producer': (lambda p: put_row(p, 'robot', 'c2', fine(), row_id='fabric:robot:c2'), ('robot', 'c2'))}


@pytest.mark.parametrize('case', sorted(UNREADABLE), ids=sorted(UNREADABLE))
def test_an_unreadable_row_is_listed_and_does_not_hide_the_others(project, store, case):
    store.publish(P, [fs.import_anchor('Kept', batch='c1')])
    write, named = UNREADABLE[case]
    write(project)
    reader = fss.make_store(project)
    status = {b.row_id: b for b in reader.batches(P)}
    assert len(status) == 2 and status['fabric:cap:c1'].readable
    broken = next(b for row_id, b in status.items() if row_id != 'fabric:cap:c1')
    assert (broken.readable, broken.anchors, broken.skipped, broken.stale) == (False, 0, 0, False)
    assert (broken.producer, broken.batch) == named
    assert [a.key for a in reader.find(P, ALL).items] == ['kept']


def test_a_witness_beyond_the_limit_is_skipped_when_rows_are_merged(project, store):
    c = calls()
    store.publish(P, [c['cap'][0]])
    store.publish(P, [c['ue'][2]])
    tight = fss.make_store(project, limits=FabricLimits(f03_witnesses_per_anchor=1))
    assert {b.producer: (b.anchors, b.skipped) for b in tight.batches(P)} == {'cap': (1, 0), 'ue': (0, 1)}
    assert [w.producer for w in tight.get(P, c['cap'][0].anchor_id).witnesses] == ['cap']


# --- checks, limits and errors --------------------------------------------------------------------------------------

@pytest.mark.parametrize('key,reason', [('../etc', 'project-key'), ('', 'project-key'), ('proj-2', 'foreign-project')],
                         ids=['dots', 'empty', 'other-project'])
def test_a_store_answers_for_its_own_project_only(store, key, reason):
    for call in (lambda: store.publish(key, []), lambda: store.retract(key, 'cap', 'c1'),
                 lambda: store.get(key, 'a' * 64), lambda: store.find(key, AnchorQuery()),
                 lambda: store.resolve(key, 'cve', None, None), lambda: store.digest(key), lambda: store.batches(key)):
        err = raised(call)
        assert (err.code, err.reason) == ('PT-FAB-INPUT', reason)


def test_an_unsaved_project_reads_as_empty_and_takes_no_publish(tmp_path):
    bare = fss.make_project(tmp_path, snapshot=False)
    try:
        target = fss.make_store(bare)
        assert target.find(P, ALL).total == 0 and target.batches(P) == ()
        put_row(bare, 'cap', 'c1', [as_json(fs.import_anchor('Foo', batch='c1'))])  # a row no project can own
        assert fss.make_store(bare).find(P, ALL).total == 0 and fss.make_store(bare).batches(P) == ()
        err = raised(target.publish, P, [fs.cve_anchor()])
        assert (err.code, err.reason) == ('PT-FAB-STORAGE', 'project-unsaved')
    finally:
        bare.close()


ARTIFACTS = [{'side': 'older', 'sha256': fs.OLDER}, {'side': 'newer', 'sha256': fs.NEWER}]


@pytest.mark.parametrize('payload,reason', [
    ({'id': 'not a key!', 'revision': 1, 'artifacts': ARTIFACTS}, 'project-id'),
    ({'id': P, 'revision': 1, 'artifacts': ARTIFACTS[:1]}, 'project-pair'),
    ({'id': P, 'revision': 1, 'artifacts': [ARTIFACTS[0], {'side': 'newer', 'sha256': 'X' * 64}]}, 'project-pair'),
    ({'id': P, 'revision': 1, 'artifacts': 5}, 'project-pair')],
    ids=['key', 'one-artifact', 'bad-hash', 'not-a-list'])
def test_a_snapshot_the_fabric_cannot_use_is_a_storage_error(project, store, payload, reason):
    fss.write_snapshot(project, json.dumps(payload))
    err = raised(store.find, P, ALL)
    assert (err.code, err.reason) == ('PT-FAB-STORAGE', reason)


def test_the_pair_is_bound_from_the_project_so_a_swapped_publish_changes_nothing(project, store):
    store.publish(P, calls()['kb'])
    before = (store.digest(P), fss.rows(project))
    swapped = fs.anchor('function', None, 'both', 'observed', producer='ue', source='pairing', batch='u1',
                        pair=fs.pair_ref(older_sha=fs.NEWER, newer_sha=fs.OLDER))
    wrong_side = fs.import_anchor('Bar', 'older', input_sha=fs.NEWER, batch='c1')
    for bad in (swapped, wrong_side):
        err = raised(store.publish, P, [fs.cve_anchor('CVE-2099-0009', batch='k9'), bad])
        assert (err.code, err.reason) == ('PT-FAB-ORIENTATION', 'orientation-swapped')
        assert (store.digest(P), fss.rows(project)) == before


def test_the_origin_guard_and_the_integrity_check_of_the_reference_apply(project, store):
    forged = fs.import_anchor('Foo', origin=('D_ghidra',))
    assert raised(store.publish, P, [forged]).reason == 'origin-mismatch'
    tampered = fs.cve_anchor().model_copy(update={'anchor_id': '0' * 64})
    assert raised(store.publish, P, [tampered]).code == 'PT-FAB-INTEGRITY'
    assert raised(store.publish, P, ['text']).reason == 'not-an-anchor'
    assert fss.row_ids(project) == set()


def test_the_reference_limits_apply_and_nothing_is_written(project):
    tight = fss.make_store(project, limits=FabricLimits(f01_anchors_per_publish=2, f02_anchors_per_project=3,
                                                       f03_witnesses_per_anchor=2, f09_page_rows=3))
    err = raised(tight.publish, P, [fs.import_anchor(n, batch='c1') for n in ('A', 'B', 'C')])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'publish-size') and not fss.has_table(project)
    tight.publish(P, [fs.import_anchor(n, batch='c1') for n in ('A', 'B')])
    err = raised(tight.publish, P, [fs.import_anchor(n, batch='c2') for n in ('C', 'D')])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'project-size')
    assert fss.row_ids(project) == {'fabric:cap:c1'} and tight.find(P, AnchorQuery()).total == 2


def test_a_row_above_the_row_cap_is_refused_before_anything_is_written(project, store, monkeypatch):
    store.publish(P, calls()['kb'])
    before, digest = fss.rows(project), store.digest(P)
    monkeypatch.setattr(fabric_store, 'MAX_BODY_BYTES', 2_000)
    big = [fs.import_anchor(f'Name{n}', batch='c1') for n in range(8)]
    err = raised(store.publish, P, [*big, fs.cve_anchor('CVE-2099-0002', batch='k9')])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'row-size')
    assert fss.rows(project) == before and store.digest(P) == digest  # the mutated reference state was dropped
    assert store.publish(P, big[:1]) == PublishReport(added=1)


def test_the_row_cap_is_measured_on_the_stored_size(project, store, monkeypatch):
    call = [fs.import_anchor('Foo', batch='c1', label='Größe geprüft')]  # non-ASCII text is stored as UTF-8, unescaped
    store.publish(P, call)
    size = project.connection.execute(
        "SELECT LENGTH(CAST(body AS BLOB)) FROM enrichment_entries WHERE id='fabric:cap:c1'").fetchone()[0]
    monkeypatch.setattr(fabric_store, 'MAX_BODY_BYTES', size)
    assert store.publish(P, call) == PublishReport(unchanged=1)  # a row of exactly the cap is stored
    monkeypatch.setattr(fabric_store, 'MAX_BODY_BYTES', size - 1)
    assert raised(store.publish, P, call).reason == 'row-size'


def test_the_project_byte_cap_maps_to_a_fabric_limit(project, store, monkeypatch):
    store.publish(P, calls()['kb'])
    before, digest = fss.rows(project), store.digest(P)
    monkeypatch.setattr(storage, 'MAX_TOTAL', 100)
    err = raised(store.publish, P, calls()['cap'])
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'project-bytes')
    assert fss.rows(project) == before and store.digest(P) == digest


def test_a_store_written_by_a_newer_patchtrace_is_read_only(project, store):
    publish_all(store)
    project.connection.execute("UPDATE enrichment_meta SET value='3' WHERE key='extension_version'")
    project.connection.commit()
    reader = fss.make_store(project)
    assert reader.find(P, ALL).total == 7
    digest = reader.digest(P)
    for call in (lambda: reader.publish(P, [fs.cwe_anchor(787, batch='k1')]), lambda: reader.retract(P, 'kev', 'v1')):
        err = raised(call)
        assert (err.code, err.reason) == ('PT-FAB-STALE', 'read-only-store')
        assert reader.digest(P) == digest  # what the refused call would have changed was never served
    assert fss.row_ids(project) == {'fabric:ue:u1', 'fabric:cap:c1', 'fabric:kb:k1', 'fabric:kev:v1'}


def test_a_closed_project_and_another_thread_are_storage_errors(project, store):
    found = []

    def other_thread():
        try:
            store.find(P, AnchorQuery())
        except FabricError as exc:
            found.append(exc)
    worker = threading.Thread(target=other_thread)
    worker.start()
    worker.join()
    assert [(e.code, e.reason) for e in found] == [('PT-FAB-STORAGE', 'wrong-thread')]
    project.close()
    err = raised(store.find, P, AnchorQuery())
    assert (err.code, err.reason) == ('PT-FAB-STORAGE', 'project-closed')


def test_a_failing_row_write_leaves_a_state_that_repeating_the_call_completes(project, store, monkeypatch):
    c = calls()
    store.publish(P, [*c['ue'][:1], *c['cap'][:1]])
    call = [*c['ue'], *c['cap']]
    written = []
    real = EnrichmentStore.publish

    def failing(self, kind, *args, **kwargs):
        if written:
            raise EnrichmentError('PT-ENRICH-INPUT', 'disk is full')
        written.append(kind)
        return real(self, kind, *args, **kwargs)
    monkeypatch.setattr(EnrichmentStore, 'publish', failing)
    err = raised(store.publish, P, call)
    assert (err.code, err.reason) == ('PT-FAB-STORAGE', 'enrichment')
    partial = fss.make_store(project).digest(P)
    assert store.digest(P) == partial  # the reads show what is stored, not what the failed call meant to store
    monkeypatch.undo()
    ref = reference()
    ref.publish(P, [*c['ue'][:1], *c['cap'][:1]])
    ref.publish(P, call)
    assert partial != ref.digest(P)
    store.publish(P, call)
    assert store.digest(P) == ref.digest(P) == fss.make_store(project).digest(P)


# --- retention and old readers --------------------------------------------------------------------------------------

def test_batch_rows_survive_enrichment_retention(project, store):
    publish_all(store)
    put_row(project, 'cap', 'old', [as_json(fs.import_anchor('Old', batch='old'))], current_digest='e' * 64)
    enrichment = EnrichmentStore(project)
    g = Guard(P, 'r', 'a' * 64, 'b' * 64)
    for n in range(12):  # enough derived generations that retention has real work to do
        rid = f'r{n}'
        for kind in ('signals', 'ranking', 'wil'):
            enrichment.publish(kind, g, g, 0, 'complete', {'pad': 'x' * 64}, f'{kind}:{rid}')
        enrichment.publish('pipeline', g, g, 0, 'complete', {'stage_ids': {'ranking': rid, 'wil': rid},
                                                             'config_digest': 'c'}, f'pipeline:{rid}')
    kept = fss.row_ids(project)
    assert len(kept) == 5
    assert enrichment.apply_retention(g, started=FUTURE) > 0
    enrichment.prune_runs(keep=0)
    enrichment.make_room(1, g)
    assert fss.row_ids(project) == kept
    after = fss.make_store(project)
    assert after.find(P, ALL).total == 8 and {b.row_id: b.stale for b in after.batches(P)}['fabric:cap:old'] is True


def test_an_old_reader_ignores_the_kind(tmp_path, monkeypatch):
    svc = create_sample(tmp_path / 'real')
    try:
        enrichment = EnrichmentStore(svc.store)
        enrichment.ensure()
        before = (load_secondary(enrichment), current_sets(enrichment))
        target = EnrichmentAnchorStore(enrichment)
        key = svc.project.id
        target.publish(key, [fs.cve_anchor(batch='k1'), fs.cwe_anchor(190, batch='k1')])
        meta = svc.store.connection.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'")
        assert meta.fetchone()[0] == '1'  # no extension_version bump: v1 clients keep full access
        old_kinds = frozenset(storage.KINDS) - {fabric_store.KIND}
        monkeypatch.setattr(storage, 'KINDS', old_kinds)  # a reader from before the fabric: queries known kinds only
        old = EnrichmentStore(svc.store)
        for kind in sorted(old_kinds):
            assert all(e.kind == kind for e in old.entries(kind))
        assert (load_secondary(old), current_sets(old)) == before
        old.apply_retention(Guard(key, 'r', 'a' * 64, 'b' * 64), started=FUTURE)
        assert fss.row_ids(svc.store) == {'fabric:kb:k1'}
        svc.store.save(svc.store.load())  # the v1 project contract still opens and saves with the rows present
        stored = json.loads(svc.store.connection.execute(
            "SELECT body FROM enrichment_entries WHERE kind='anchor-batch'").fetchone()[0])
        assert stored['contract'] == 'fabric-batch/1'
        monkeypatch.undo()
        assert EnrichmentAnchorStore(EnrichmentStore(svc.store)).find(key, ALL).total == 2  # a PatchTrace that knows it
    finally:
        svc.close()


# --- the read cache ---------------------------------------------------------------------------------------------------

def test_reads_load_the_rows_once_until_something_changes(project, monkeypatch):
    enrichment = EnrichmentStore(project)
    reader = EnrichmentAnchorStore(enrichment)
    reader.publish(P, calls()['cap'])
    loads = []
    real = EnrichmentStore.entries

    def counting(self, *args, **kwargs):
        loads.append(self is enrichment)
        return real(self, *args, **kwargs)
    monkeypatch.setattr(EnrichmentStore, 'entries', counting)
    statements = []
    project.connection.set_trace_callback(statements.append)
    for _ in range(3):
        reader.find(P, ALL)
        reader.get(P, 'a' * 64)
        reader.resolve(P, 'capability', None, None)
        reader.digest(P)
        reader.batches(P)
    assert loads.count(True) == 1
    assert not [sql for sql in statements if 'json_extract' in sql]  # a snapshot can be large: read once, not per call
    fss.make_store(project).publish(P, calls()['kb'])  # another writer on the same database
    assert reader.find(P, ALL).total == 5 and loads.count(True) == 2
    statements.clear()
    fss.write_snapshot(project, fss.snapshot_text(older=fs.NEWER, newer=fs.OLDER))  # the pair moved: read again
    assert reader.find(P, ALL).total == 3 and loads.count(True) == 3
    assert len([sql for sql in statements if 'json_extract' in sql]) == 1  # the saved snapshot moved: parsed once

