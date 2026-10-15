"""FAB-4 analyst pins (docs/specs/program-e/FAB-integration-plan.md s7 "Pins as built").

Covers: the event row and its guard, the fold of events into pins (the sequence decides, not the clock), re-pin and
unpin, the gate that pins survive batch replacement, retraction and enrichment retention, the note rules (plain text,
2 KiB, never cut), orientation (a pin made for the other orientation is refused, an old one is listed stale),
skip-and-count of unreadable events, the checks and error mapping, old readers and a model-based random sequence.
Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import ast
import hashlib
import itertools
import json
import tempfile
import threading
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import fabric_store_support as fss
import fabric_support as fs
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.enrichment import storage
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.fabric import pins as fabric_pins
from patchtrace.fabric.contracts import AnchorQuery
from patchtrace.fabric.limits import FabricError
from patchtrace.fabric.pins import EnrichmentPinStore, Pin, PinEvent, PinList, PinPort
from patchtrace.sample import create_sample
from patchtrace.secondary import load_secondary
from patchtrace.secondary.store import current_sets

P = fss.PROJECT
PAIR = fs.pair_key()
KIND = fabric_pins.KIND
CREATED = '2099-03-01T12:00:00+00:00'
FUTURE = '9999-01-01T00:00:00+00:00'
ALL = AnchorQuery(limit=500)


def raised(call, *args, **kwargs) -> FabricError:
    with pytest.raises(FabricError) as info:
        call(*args, **kwargs)
    return info.value


def fixed_clock() -> datetime:
    return datetime(2099, 3, 1, 12, 0, 0, tzinfo=UTC)  # every event in the same tick: only the sequence can order them


def counting_ids():
    counter = itertools.count(1)
    return lambda: str(uuid.UUID(int=next(counter)))


@pytest.fixture
def project(tmp_path):
    handle = fss.make_project(tmp_path)
    yield handle
    if not handle.closed:
        handle.close()


@pytest.fixture
def pins(project):
    return fss.make_pins(project, clock=fixed_clock, new_id=counting_ids())


def row(n: int) -> str:
    return f'fabric-pin:{uuid.UUID(int=n)}'


def foo(name: str = 'Foo', **w):
    return fs.import_anchor(name, subject=PAIR, **w)


# --- the event row ------------------------------------------------------------------------------------------------

def test_the_kind_is_known_and_never_derived():
    assert KIND == 'anchor-pin' and KIND in storage.KINDS and KIND not in storage.DERIVED_KINDS


def test_pin_writes_one_event_row_with_the_identity_of_the_anchor(project, pins):
    anchor = foo('RtlULongAdd', label='RtlULongAdd call')
    pin = pins.pin(P, anchor, 'check the overflow guard', via='related')
    ((row_id, stored),) = fss.rows(project, KIND).items()
    assert row_id == row(1)
    event = PinEvent.model_validate_json(json.dumps(stored['body']))
    assert (event.contract, event.seq, event.action) == ('fabric-pin/1', 1, 'pin')
    assert (event.anchor_id, event.kind, event.key, event.side, event.role, event.subject) == (
        anchor.anchor_id, 'import', 'rtlulongadd', 'newer', 'observed', PAIR)
    assert (event.label, event.note, event.via) == ('RtlULongAdd call', 'check the overflow guard', 'related')
    assert (event.older_sha256, event.newer_sha256, event.created_utc) == (fs.OLDER, fs.NEWER, CREATED)
    assert stored['guard'][:3] == (P, 'fabric', '') and stored['revision'] == 3 and stored['status'] == 'complete'
    assert not stored['stale'] and stored['guard'][3] == fabric_pins.event_digest(event)
    assert pin == Pin(anchor.anchor_id, 'import', 'rtlulongadd', 'newer', 'observed', PAIR, 'RtlULongAdd call',
                      'check the overflow guard', 'related', CREATED, 1, False)


def test_the_event_digest_follows_the_planned_formula_and_is_pinned(project, pins):
    pins.pin(P, fs.cve_anchor(), 'x')
    event = PinEvent.model_validate_json(json.dumps(fss.rows(project, KIND)[row(1)]['body']))
    head = b'patchtrace\x00fabric-pin\x001\x00'
    text = json.dumps(event.model_dump(mode='json'), sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    assert fabric_pins.event_digest(event) == hashlib.sha256(head + text.encode()).hexdigest()
    assert fabric_pins.event_digest(event) == GOLDEN_EVENT_DIGEST
    changed = event.model_copy(update={'note': 'y'})
    assert fabric_pins.event_digest(changed) != fabric_pins.event_digest(event)


GOLDEN_EVENT_DIGEST = '37f10b95333385c81f107c824f0a8c94dfb93bd44858b123475bb65fa8d2cd4b'


def test_a_second_store_reads_back_what_the_first_wrote(project, pins):
    pins.pin(P, foo(), 'first')
    pins.pin(P, fs.cve_anchor(), 'second')
    again = fss.make_pins(project)
    assert again.pins(P) == pins.pins(P) and len(again.pins(P).pins) == 2


# --- the fold of events -------------------------------------------------------------------------------------------

def test_pins_are_listed_newest_first(pins):
    anchors = [foo(f'Api{n}') for n in range(3)]
    for index, anchor in enumerate(anchors):
        pins.pin(P, anchor, f'note {index}')
    listed = pins.pins(P)
    assert [p.anchor_id for p in listed.pins] == [a.anchor_id for a in reversed(anchors)]
    assert [p.seq for p in listed.pins] == [3, 2, 1] and listed.skipped == 0


def test_pinning_again_with_another_note_replaces_it_and_with_the_same_note_writes_nothing(project, pins):
    anchor = foo()
    first = pins.pin(P, anchor, 'first look')
    assert pins.pin(P, anchor, 'first look') == first and len(fss.rows(project, KIND)) == 1
    second = pins.pin(P, anchor, 'second look')
    assert (second.note, second.seq) == ('second look', 2) and len(fss.rows(project, KIND)) == 2
    assert pins.pins(P).pins == (second,)
    assert pins.pin(P, anchor, 'second look') == second and len(fss.rows(project, KIND)) == 2


def test_unpin_appends_an_event_and_deletes_nothing(project, pins):
    anchor = foo()
    pins.pin(P, anchor, 'keep an eye on this')
    assert pins.unpin(P, anchor.anchor_id) is True
    assert pins.pins(P) == PinList((), 0)
    stored = fss.rows(project, KIND)
    assert sorted(r['body']['action'] for r in stored.values()) == ['pin', 'unpin']
    unpinned = next(r['body'] for r in stored.values() if r['body']['action'] == 'unpin')
    assert (unpinned['anchor_id'], unpinned['note'], unpinned['seq']) == (anchor.anchor_id, '', 2)
    assert unpinned['via'] == 'analyst'
    assert unpinned['label'] == anchor.label and unpinned['key'] == anchor.key  # the history is self-describing
    assert pins.unpin(P, anchor.anchor_id) is False and len(fss.rows(project, KIND)) == 2  # not set: nothing written
    assert pins.unpin(P, 'f' * 64) is False and pins.unpin(P, None) is False and pins.unpin(P, ['x']) is False


def test_the_sequence_orders_events_that_share_a_clock_tick(pins):
    anchor = foo()
    for step in ('pin', 'unpin', 'pin', 'unpin', 'pin'):
        if step == 'pin':
            pins.pin(P, anchor, 'a')
        else:
            pins.unpin(P, anchor.anchor_id)
    assert [p.anchor_id for p in pins.pins(P).pins] == [anchor.anchor_id]
    pins.unpin(P, anchor.anchor_id)
    pins.pin(P, anchor, 'back again')
    assert [(p.note, p.seq) for p in pins.pins(P).pins] == [('back again', 7)]


def test_the_sequence_decides_even_when_the_row_ids_say_otherwise(project):
    counter = itertools.count(1000, -1)  # the row ids fall while the events are made: only `seq` can order them
    pins = fss.make_pins(project, clock=fixed_clock, new_id=lambda: str(uuid.UUID(int=next(counter))))
    anchor = foo()
    pins.pin(P, anchor, 'first')
    pins.pin(P, anchor, 'second')
    pins.unpin(P, anchor.anchor_id)
    pins.pin(P, anchor, 'third')
    assert [(p.note, p.seq) for p in pins.pins(P).pins] == [('third', 4)]
    other = foo('Other')
    pins.pin(P, other, 'o')
    assert [p.note for p in pins.pins(P).pins] == ['o', 'third']


def test_the_sequence_counts_on_past_the_largest_stored_one(project, pins):
    pins.pin(P, foo(), 'one')
    row_id, stored = next(iter(fss.rows(project, KIND).items()))
    big = {**stored['body'], 'seq': 41}
    guard = Guard(P, 'fabric', '', 'd' * 64)
    EnrichmentStore(project).publish(KIND, guard, guard, 3, 'complete', big, row_id)
    assert pins.pin(P, fs.cve_anchor(), 'two').seq == 42


# --- the gate: pins outlive the batches that offered the anchors ----------------------------------------------------

def test_pins_survive_batch_replacement_and_retraction(project, pins):
    store = fss.make_store(project)
    keep, drop = fs.import_anchor('Keep', batch='c1'), fs.import_anchor('Drop', batch='c1')
    store.publish(P, [keep, drop])
    pins.pin(P, drop, 'look here')
    pins.pin(P, keep)
    before = fss.rows(project, KIND)
    listed = pins.pins(P)

    store.publish(P, [keep])  # the producer replaces its batch without `drop`
    assert store.get(P, drop.anchor_id) is None and pins.pins(P) == listed
    store.retract(P, 'cap', 'c1')  # and then retracts it altogether
    assert store.find(P, ALL).total == 0 and pins.pins(P) == listed
    store.publish(P, [drop])  # the batch is back: the identity is the same, so the pin points at the anchor again
    assert store.get(P, drop.anchor_id) is not None and drop.anchor_id in {p.anchor_id for p in pins.pins(P).pins}
    assert fss.rows(project, KIND) == before  # no pin row was touched


def test_the_analyst_producer_cannot_reach_pins_either(project, pins):
    store = fss.make_store(project)
    anchor = fs.cwe_anchor(190, producer='analyst', source='analyst', batch='main')
    store.publish(P, [anchor])
    pins.pin(P, anchor, 'mine')
    store.retract(P, 'analyst', 'main')
    assert store.get(P, anchor.anchor_id) is None and [p.note for p in pins.pins(P).pins] == ['mine']


def test_pin_rows_survive_enrichment_retention(project, pins):
    for n in range(3):
        pins.pin(P, foo(f'Api{n}'), f'note {n}')
    pins.unpin(P, foo('Api1').anchor_id)
    enrichment = EnrichmentStore(project)
    g = Guard(P, 'r', 'a' * 64, 'b' * 64)
    for n in range(12):  # enough derived generations that retention has real work to do
        rid = f'r{n}'
        for kind in ('signals', 'ranking', 'wil'):
            enrichment.publish(kind, g, g, 0, 'complete', {'pad': 'x' * 64}, f'{kind}:{rid}')
        enrichment.publish('pipeline', g, g, 0, 'complete', {'stage_ids': {'ranking': rid, 'wil': rid},
                                                             'config_digest': 'c'}, f'pipeline:{rid}')
    before = fss.rows(project, KIND)
    assert len(before) == 4
    assert enrichment.apply_retention(g, started=FUTURE) > 0
    enrichment.prune_runs(keep=0)
    enrichment.make_room(1, g)
    assert fss.rows(project, KIND) == before and len(fss.make_pins(project).pins(P).pins) == 2


# --- notes --------------------------------------------------------------------------------------------------------

def test_a_note_is_plain_text_that_may_span_lines(pins):
    bidi = chr(0x202E) + chr(0x2066)
    note = pins.pin(P, foo(), f'line one\r\nline\ttwo\x07{bidi}\rline three').note
    assert note == 'line one\nline two\nline three'


@pytest.mark.parametrize('note,fits', [('a' * 2048, True), ('a' * 2049, False), ('é' * 1024, True),
                                       ('é' * 1025, False), ('a\n' * 1024, True), ('a\n' * 1025, False)],
                         ids=['ascii-at-cap', 'ascii-over', 'two-byte-at-cap', 'two-byte-over', 'lines-at-cap',
                              'lines-over'])
def test_the_note_cap_is_2_kib_of_utf8_and_a_longer_note_is_refused_not_cut(project, pins, note, fits):
    if fits:
        assert pins.pin(P, foo(), note).note == note
    else:
        err = raised(pins.pin, P, foo(), note)
        assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'note-size') and not fss.row_ids(project, KIND)


def test_a_pin_is_pinned_again_when_it_is_stale_so_that_it_says_the_files_now(project, pins):
    statement = fs.cwe_anchor(190)  # nothing in it names an image, so it can be pinned in either orientation
    pins.pin(P, statement, 'same words')
    fss.write_snapshot(project, fss.snapshot_text(older=fs.NEWER, newer=fs.OLDER))
    assert [p.stale for p in pins.pins(P).pins] == [True]
    refreshed = pins.pin(P, statement, 'same words')
    assert (refreshed.stale, refreshed.seq) == (False, 2) and pins.pins(P).pins == (refreshed,)
    assert pins.pin(P, statement, 'same words') == refreshed and len(fss.rows(project, KIND)) == 2


def test_the_time_is_stored_in_utc(project):
    plus_two = datetime(2099, 3, 1, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    target = fss.make_pins(project, clock=lambda: plus_two, new_id=counting_ids())
    assert target.pin(P, foo()).pinned_utc == CREATED


def test_no_note_is_a_bare_pin(pins):
    assert pins.pin(P, foo()).note == '' and pins.pin(P, foo(), None).note == ''


# --- orientation --------------------------------------------------------------------------------------------------

def test_an_anchor_made_for_the_other_orientation_cannot_be_pinned(project, pins):
    wrong = fs.import_anchor('Bar', 'older', input_sha=fs.NEWER, batch='c1')
    err = raised(pins.pin, P, wrong, 'x')
    assert (err.code, err.reason) == ('PT-FAB-ORIENTATION', 'orientation-swapped') and not fss.row_ids(project, KIND)


def test_a_pin_made_before_a_swap_is_listed_stale_not_hidden(project, pins):
    anchor = foo()
    pins.pin(P, anchor, 'before')
    fss.write_snapshot(project, fss.snapshot_text(older=fs.NEWER, newer=fs.OLDER))
    (listed,) = pins.pins(P).pins
    assert listed.stale is True and listed.note == 'before'
    assert raised(pins.pin, P, anchor, 'again').code == 'PT-FAB-ORIENTATION'  # the anchor itself is for the old way
    neutral = fs.cwe_anchor(190)
    assert pins.pin(P, neutral, 'after').stale is False
    fss.write_snapshot(project, fss.snapshot_text())  # swapped back: the first is current, the second was made swapped
    assert [p.stale for p in pins.pins(P).pins] == [True, False]


# --- unreadable events --------------------------------------------------------------------------------------------

def event_json(anchor, **changes) -> dict:
    event = PinEvent(seq=1, action='pin', anchor_id=anchor.anchor_id, kind=anchor.kind, key=anchor.key,
                     side=anchor.side, role=anchor.role, subject=anchor.subject, label=anchor.label, note='', via='related',
                     older_sha256=fs.OLDER, newer_sha256=fs.NEWER, created_utc=CREATED)
    return json.loads(event.model_dump_json()) | changes


def put_event(project, body, *, n: int = 900, guard_project: str = P, row_id: str | None = None, stale_to=None) -> None:
    guard = Guard(guard_project, 'fabric', '', 'd' * 64)
    current = guard if stale_to is None else Guard(guard_project, 'fabric', '', stale_to)
    EnrichmentStore(project).publish(KIND, guard, current, 3, 'complete', body, row_id or row(n))


def corrupt_hash(project):
    put_event(project, event_json(foo('Hash')))
    changed = project.connection.execute("UPDATE enrichment_entries SET body=replace(body, 'related', 'relatEd') "
                                         "WHERE id=?", (row(900),))
    project.connection.commit()
    assert changed.rowcount == 1


BAD_EVENTS = {
    'hash': corrupt_hash,
    'newer-contract': lambda p: put_event(p, event_json(foo('Bad'), contract='fabric-pin/2')),
    'extra-field': lambda p: put_event(p, event_json(foo('Bad'), priority='high')),
    'identity': lambda p: put_event(p, event_json(foo('Bad'), key='somethingelse')),
    'unknown-kind': lambda p: put_event(p, event_json(foo('Bad'), kind='future-kind')),
    'other-project': lambda p: put_event(p, event_json(foo('Bad')), guard_project='proj-2'),
    'row-id': lambda p: put_event(p, event_json(foo('Bad')), row_id='fabric-pin:not-a-uuid'),
    'not-an-object': lambda p: put_event(p, ['pin'])}


@pytest.mark.parametrize('case', sorted(BAD_EVENTS), ids=sorted(BAD_EVENTS))
def test_an_unreadable_event_is_counted_and_does_not_hide_the_pins(project, pins, case):
    pins.pin(P, foo('Good'), 'kept')
    BAD_EVENTS[case](project)
    listed = fss.make_pins(project).pins(P)
    assert listed.skipped == 1 and [p.note for p in listed.pins] == ['kept']


def test_a_pin_event_stored_with_a_moved_guard_is_listed_stale(project, pins):
    put_event(project, event_json(foo('Moved'), note='x'), stale_to='e' * 64)
    (listed,) = fss.make_pins(project).pins(P).pins
    assert listed.stale is True and listed.key == 'moved'


# --- checks and errors --------------------------------------------------------------------------------------------

@pytest.mark.parametrize('key,reason', [('../etc', 'project-key'), ('', 'project-key'), ('proj-2', 'foreign-project')],
                         ids=['dots', 'empty', 'other-project'])
def test_a_store_answers_for_its_own_project_only(pins, key, reason):
    for call in (lambda: pins.pin(key, foo()), lambda: pins.unpin(key, 'a' * 64), lambda: pins.pins(key)):
        err = raised(call)
        assert (err.code, err.reason) == ('PT-FAB-INPUT', reason)


def test_only_a_verified_anchor_can_be_pinned(project, pins):
    for bad in ('text', None, fs.wit(), {'kind': 'import'}):
        err = raised(pins.pin, P, bad, 'x')
        assert (err.code, err.reason) == ('PT-FAB-INPUT', 'not-an-anchor')
    tampered = foo().model_copy(update={'anchor_id': '0' * 64})
    assert raised(pins.pin, P, tampered, 'x').code == 'PT-FAB-INTEGRITY'
    assert not fss.row_ids(project, KIND)


@pytest.mark.parametrize('via', ['', 'Related', 'a b', 'x' * 49, 7, None],
                         ids=['empty', 'upper', 'space', 'long', 'int', 'none'])
def test_via_is_a_slug(project, pins, via):
    err = raised(pins.pin, P, foo(), 'x', via)
    assert (err.code, err.reason) == ('PT-FAB-INPUT', 'via') and not fss.row_ids(project, KIND)


def test_an_unsaved_project_reads_as_empty_and_takes_no_pin(tmp_path):
    bare = fss.make_project(tmp_path, snapshot=False)
    try:
        target = fss.make_pins(bare)
        assert target.pins(P) == PinList((), 0) and target.unpin(P, 'a' * 64) is False
        put_event(bare, event_json(foo('Orphan')))  # a row no project can own
        assert target.pins(P) == PinList((), 0) and target.unpin(P, foo('Orphan').anchor_id) is False
        err = raised(target.pin, P, foo(), 'x')
        assert (err.code, err.reason) == ('PT-FAB-STORAGE', 'project-unsaved')
    finally:
        bare.close()


def test_a_store_written_by_a_newer_patchtrace_is_read_only(project, pins):
    pins.pin(P, foo(), 'x')
    project.connection.execute("UPDATE enrichment_meta SET value='3' WHERE key='extension_version'")
    project.connection.commit()
    reader = fss.make_pins(project)
    assert len(reader.pins(P).pins) == 1
    err = raised(reader.pin, P, foo('Other'), 'y')
    assert (err.code, err.reason) == ('PT-FAB-STALE', 'read-only-store')
    err = raised(reader.unpin, P, foo().anchor_id)
    assert (err.code, err.reason) == ('PT-FAB-STALE', 'read-only-store')
    assert len(fss.rows(project, KIND)) == 1


def test_the_project_byte_cap_maps_to_a_fabric_limit(project, pins, monkeypatch):
    pins.pin(P, foo(), 'x')
    monkeypatch.setattr(storage, 'MAX_TOTAL', 100)
    err = raised(pins.pin, P, foo('Other'), 'y')
    assert (err.code, err.reason) == ('PT-FAB-LIMIT', 'project-bytes') and len(fss.rows(project, KIND)) == 1


def test_another_failure_of_the_enrichment_store_is_a_storage_error(project, pins, monkeypatch):
    def refuse(self, *args, **kwargs):
        raise EnrichmentError('PT-ENRICH-INPUT', 'disk is full')
    monkeypatch.setattr(EnrichmentStore, 'publish', refuse)
    err = raised(pins.pin, P, foo(), 'x')
    assert (err.code, err.reason) == ('PT-FAB-STORAGE', 'enrichment')


def test_a_closed_project_and_another_thread_are_storage_errors(project, pins):
    found = []

    def other_thread():
        try:
            pins.pins(P)
        except FabricError as exc:
            found.append(exc)
    worker = threading.Thread(target=other_thread)
    worker.start()
    worker.join()
    assert [(e.code, e.reason) for e in found] == [('PT-FAB-STORAGE', 'wrong-thread')]
    project.close()
    assert raised(pins.pins, P).reason == 'project-closed'


def test_pins_default_to_the_system_clock_and_random_ids(project):
    target = fss.make_pins(project)
    first, second = target.pin(P, foo('A')), target.pin(P, foo('B'))
    stamps = [datetime.fromisoformat(pin.pinned_utc) for pin in (first, second)]
    assert stamps[0].tzinfo is not None and stamps[0] <= stamps[1]
    versions = [uuid.UUID(row_id.removeprefix('fabric-pin:')).version for row_id in fss.row_ids(project, KIND)]
    assert versions == [4, 4]


# --- old readers --------------------------------------------------------------------------------------------------

def test_an_old_reader_ignores_the_kind(tmp_path, monkeypatch):
    svc = create_sample(tmp_path / 'real')
    try:
        enrichment = EnrichmentStore(svc.store)
        enrichment.ensure()
        before = (load_secondary(enrichment), current_sets(enrichment))
        target = EnrichmentPinStore(enrichment)
        key = svc.project.id
        target.pin(key, fs.cve_anchor(), 'a statement worth keeping')
        meta = svc.store.connection.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'")
        assert meta.fetchone()[0] == '1'  # no extension_version bump: v1 clients keep full access
        old_kinds = frozenset(storage.KINDS) - {KIND, 'anchor-batch'}
        monkeypatch.setattr(storage, 'KINDS', old_kinds)  # a reader from before the fabric: queries known kinds only
        old = EnrichmentStore(svc.store)
        for kind in sorted(old_kinds):
            assert all(e.kind == kind for e in old.entries(kind))
        assert (load_secondary(old), current_sets(old)) == before
        old.apply_retention(Guard(key, 'r', 'a' * 64, 'b' * 64), started=FUTURE)
        assert len(fss.row_ids(svc.store, KIND)) == 1
        svc.store.save(svc.store.load())  # the v1 project contract still opens and saves with the row present
        monkeypatch.undo()
        assert [p.note for p in EnrichmentPinStore(EnrichmentStore(svc.store)).pins(key).pins] == [
            'a statement worth keeping']
    finally:
        svc.close()


# --- the port -----------------------------------------------------------------------------------------------------

def test_the_port_is_a_protocol_of_three_methods_with_no_behaviour():
    assert getattr(PinPort, '_is_protocol', False)
    assert {name for name in vars(PinPort) if not name.startswith('_')} == {'pin', 'unpin', 'pins'}
    tree = ast.parse(Path(fabric_pins.__file__).read_text(encoding='utf-8'))
    port = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'PinPort')
    for node in port.body:
        if isinstance(node, ast.FunctionDef):
            body = [b for b in node.body if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))]
            assert not body, f'{node.name} has behaviour; a port is a Protocol only'


def test_the_store_satisfies_the_port(pins):
    assert isinstance(pins, PinPort) and not isinstance(object(), PinPort)


# --- a random sequence against a model ------------------------------------------------------------------------------

ANCHORS = [foo(f'Api{n}') for n in range(4)]
NOTES = ['', 'a', 'b']
STEPS = st.lists(st.one_of(
    st.tuples(st.just('pin'), st.integers(0, 3), st.sampled_from(NOTES)),
    st.tuples(st.just('unpin'), st.integers(0, 3), st.just(''))), max_size=14)


@settings(max_examples=25, deadline=None)
@given(STEPS)
def test_random_pin_sequences_match_a_model(steps):
    with tempfile.TemporaryDirectory() as root:
        project = fss.make_project(Path(root))
        try:
            target = fss.make_pins(project, clock=fixed_clock, new_id=counting_ids())
            model: dict[str, str] = {}  # anchor id -> note, in the order the pins were last set (oldest first)
            for name, index, note in steps:
                anchor = ANCHORS[index]
                if name == 'pin':
                    if model.get(anchor.anchor_id) != note:
                        model.pop(anchor.anchor_id, None)
                        model[anchor.anchor_id] = note
                    assert target.pin(P, anchor, note).note == note
                else:
                    assert target.unpin(P, anchor.anchor_id) is (anchor.anchor_id in model)
                    model.pop(anchor.anchor_id, None)
                listed = target.pins(P)
                assert [(p.anchor_id, p.note) for p in listed.pins] == list(reversed(model.items()))
                assert not listed.skipped
                assert fss.make_pins(project).pins(P) == listed
        finally:
            project.close()
