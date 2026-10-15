"""FAB adversarial tests (docs/specs/program-e/FAB-integration-plan.md s7 and s9): hostile text, size bounds, retraction,
pins that outlive batches, and corrupt rows that are skipped and counted one anchor at a time.

Synthetic data only; nothing here is live evidence. Large inputs are built once per test and never written to disk.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import fabric_store_support as fss
import fabric_support as fs
import pytest

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.fabric import contracts, convert, origins
from patchtrace.fabric import store as fabric_store
from patchtrace.fabric.contracts import AnchorQuery
from patchtrace.fabric.limits import FabricError, FabricLimits
from patchtrace.fabric.store import KIND

P = fss.PROJECT
ALL = AnchorQuery(limit=500)
TEN_MB = 10 * 1024 * 1024
UNSAFE = ('‮', '⁦', ' ', '\x00', '\x9b', '\ud800')
HOSTILE = {
    'bidi-override': 'pay‮PLAN',
    'bidi-isolate': 'a⁦b⁩c',
    'zero-width': 'zero​width⁠joiner',
    'line-separator': 'one two',
    'nul-byte': 'nul\x00byte',
    'c1-control': 'c1\x9bcsi',
    'lone-surrogate': 'ok\ud800end',
    'newline-and-tab': 'line\nnext\tcol',
}


TIGHT = FabricLimits(f01_anchors_per_publish=3, f02_anchors_per_project=5, f09_page_rows=3)


def as_json(anchor) -> dict:
    return json.loads(anchor.model_dump_json())


def raised(call, *args, **kwargs) -> FabricError:
    with pytest.raises(FabricError) as info:
        call(*args, **kwargs)
    return info.value


def k_record(kind: str, value: str, source: str = 'csaf-note'):
    return SimpleNamespace(kind=kind, value=value, source=source, pointer=None, quality='stated')


@pytest.fixture
def project(tmp_path):
    handle = fss.make_project(tmp_path)
    yield handle
    if not handle.closed:
        handle.close()


@pytest.fixture
def store(project):
    return fss.make_store(project)


@pytest.fixture
def pins(project):
    return fss.make_pins(project)


# --- hostile text -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('text', list(HOSTILE.values()), ids=list(HOSTILE))
def test_hostile_label_is_plain_text_and_survives_a_store_round_trip(project, store, text):
    anchor = fs.import_anchor('Evil', batch='c1', label=text)
    label = anchor.witnesses[0].label
    assert not any(char in label for char in UNSAFE)
    contracts.plain_line(label)
    store.publish(P, [anchor])
    assert fss.make_store(project).get(P, anchor.anchor_id) == anchor


def test_a_ten_megabyte_label_is_cut_to_the_label_limit_and_still_stored(project, store):
    anchor = fs.import_anchor('Big', batch='c1', label='x' * TEN_MB)
    label = anchor.witnesses[0].label
    assert len(label) == 200 and label.endswith('...')
    store.publish(P, [anchor])
    assert store.find(P, ALL).total == 1


def test_a_ten_megabyte_bidi_label_is_stripped_then_cut(store):
    anchor = fs.import_anchor('Big', batch='c1', label='a‮' * (TEN_MB // 2))
    label = anchor.witnesses[0].label
    assert len(label) <= 200 and not any(char in label for char in UNSAFE)
    store.publish(P, [anchor])
    assert store.get(P, anchor.anchor_id) is not None


@pytest.mark.parametrize('name', ['x' * TEN_MB, 'a b', 'name\x00'], ids=['ten-mb', 'space', 'nul'])
def test_a_hostile_import_name_is_refused_with_a_typed_error(name):
    assert raised(fs.import_anchor, name).code in {'PT-FAB-KEY', 'PT-FAB-INPUT'}


def test_a_ten_megabyte_string_value_hashes_to_a_bounded_key():
    anchor = convert.from_k_anchor(k_record('string', 'q' * TEN_MB), batch='kb-1')
    assert len(anchor.key) == 64 and len(anchor.witnesses[0].label) == 200


@pytest.mark.parametrize('value', ['lone\ud800', '\udfff'], ids=['high', 'low'])
def test_a_lone_surrogate_value_is_a_typed_key_error_not_a_crash(value):
    assert raised(convert.from_k_anchor, k_record('string', value), batch='kb-1').code == 'PT-FAB-KEY'


# --- bounds from limits.py -----------------------------------------------------------------------------------------

def test_a_publish_of_one_anchor_more_than_the_limit_is_refused_and_nothing_is_written(project):
    limits = TIGHT
    tight = fss.make_store(project, limits=limits)
    batch = [fs.import_anchor(f'F{i}', batch='c1') for i in range(4)]
    assert raised(tight.publish, P, batch).code == 'PT-FAB-LIMIT'
    assert tight.find(P, ALL).total == 0 and not fss.rows(project)


def test_a_project_over_its_anchor_limit_is_refused_and_the_old_state_stays(project):
    tight = fss.make_store(project, limits=TIGHT)
    tight.publish(P, [fs.import_anchor(f'A{i}', batch='c1') for i in range(3)])
    more = [fs.import_anchor(f'B{i}', batch='c2') for i in range(3)]
    assert raised(tight.publish, P, more).code == 'PT-FAB-LIMIT'
    assert tight.find(P, ALL).total == 3


def test_a_query_limit_above_the_page_size_is_refused():
    assert raised(AnchorQuery, limit=501).reason == 'limit'


@pytest.mark.parametrize('size', [2048, 2049], ids=['at-cap', 'over-cap'])
def test_a_note_at_the_cap_is_kept_and_one_byte_over_is_refused(pins, size):
    anchor = fs.import_anchor('Note', batch='c1')
    if size == 2048:
        assert pins.pin(P, anchor, note='n' * size).note == 'n' * size
    else:
        assert raised(pins.pin, P, anchor, note='n' * size).reason == 'note-size'


def test_a_ten_megabyte_note_is_refused_and_nothing_is_pinned(pins):
    anchor = fs.import_anchor('Note', batch='c1')
    assert raised(pins.pin, P, anchor, note='n' * TEN_MB).code == 'PT-FAB-LIMIT'


def test_a_note_of_multibyte_text_is_counted_in_bytes(pins):
    anchor = fs.import_anchor('Note', batch='c1')
    assert raised(pins.pin, P, anchor, note='é' * 1025).reason == 'note-size'


def test_a_hostile_note_keeps_its_lines_and_drops_its_unsafe_characters(pins):
    anchor = fs.import_anchor('Note', batch='c1')
    pinned = pins.pin(P, anchor, note='line one‮\nline\tTwo\x00')
    assert pinned.note == 'line one\nline Two'


# --- retraction and pins ------------------------------------------------------------------------------------------

def test_retracting_a_hostile_batch_leaves_no_row_and_no_trace(project, store):
    hostile = fs.import_anchor('Evil', batch='c1', label=HOSTILE['bidi-override'])
    store.publish(P, [hostile])
    store.retract(P, 'cap', 'c1')
    assert store.find(P, ALL).total == 0 and not fss.row_ids(project)
    assert store.digest(P) == fss.make_store(project).digest(P)


def test_pins_keep_their_label_through_replacement_and_retraction(project, store, pins):
    anchor = fs.import_anchor('Kept', batch='c1', label='pinned label')
    store.publish(P, [anchor])
    pins.pin(P, anchor, note='keep')
    store.publish(P, [fs.import_anchor('Other', batch='c1', label='‮swapped')])
    store.retract(P, 'cap', 'c1')
    listed = pins.pins(P).pins
    assert [(pin.anchor_id, pin.label, pin.note) for pin in listed] == [(anchor.anchor_id, 'pinned label', 'keep')]


def test_a_pin_of_an_unknown_anchor_is_still_listed_after_its_batch_is_gone(store, pins):
    anchor = fs.import_anchor('Gone', batch='c1')
    store.publish(P, [anchor])
    pins.pin(P, anchor)
    store.retract(P, 'cap', 'c1')
    assert store.get(P, anchor.anchor_id) is None
    assert [pin.anchor_id for pin in pins.pins(P).pins] == [anchor.anchor_id]


# --- corrupt rows: skipped and counted, one anchor at a time ------------------------------------------------------

def put_raw_row(project, batch: str, anchors: list, body_extra: dict | None = None) -> None:
    """Store a batch row the way another version of PatchTrace may have written it."""
    body = {'contract': fabric_store.CONTRACT, 'producer': 'cap', 'batch': batch,
            'origins_digest': origins.digest(), 'anchors': anchors, **(body_extra or {})}
    guard = Guard(P, fabric_store.GUARD_RUN, '', 'd' * 64)
    EnrichmentStore(project).publish(KIND, guard, guard, 3, 'complete', body, fabric_store.row_id('cap', batch))


def test_hostile_anchor_entries_are_each_skipped_and_counted(project):
    good = as_json(fs.import_anchor('Fine', batch='c2'))
    too_long = dict(good, key='k' * TEN_MB)
    put_raw_row(project, 'c2', [good, None, 'text', 5, [1, 2], {'anchor_id': 'not-an-id'}, too_long])
    status = {b.batch: b for b in fss.make_store(project).batches(P)}['c2']
    assert (status.anchors, status.skipped, status.readable) == (1, 6, True)
    assert [a.key for a in fss.make_store(project).find(P, ALL).items] == [good['key']]


def test_an_unreadable_row_hides_no_other_batch(project, store):
    store.publish(P, [fs.import_anchor('Kept', batch='c1')])
    put_raw_row(project, 'c9', [], body_extra={'contract': 'fabric-batch/9'})
    readers = {b.batch: b for b in fss.make_store(project).batches(P)}
    assert readers['c1'].anchors == 1 and not readers['c9'].readable
    assert [a.key for a in fss.make_store(project).find(P, ALL).items] == [fs.import_anchor('Kept').key]
