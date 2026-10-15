"""FAB property tests (docs/specs/program-e/FAB-integration-plan.md s7 and s9): round trips, deterministic ordering,
retraction, pins that survive batch replacement, pin ordering, the note bound and the K converter, over generated
hostile text. Small `max_examples`: each example opens a real project database. Synthetic data only.
"""
from __future__ import annotations

import tempfile
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import fabric_store_support as fss
import fabric_support as fs
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.fabric import convert, ids
from patchtrace.fabric.contracts import AnchorQuery, clean_line, plain_line
from patchtrace.fabric.limits import FabricError
from patchtrace.fabric.memory import MemoryAnchorStore
from patchtrace.fabric.pins import MAX_NOTE_BYTES, clean_note

P = fss.PROJECT
ALL = AnchorQuery(limit=500)
BATCHES = ('c1', 'c2', 'c3')
NAMES = ('Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Zeta')
HOSTILE = st.sampled_from(['\u202e', '\u2066', '\u200b', '\u2028', '\x00', '\x9b', '\ud800', '\udfff', '\t', '\n',
                           'é', '\u0301', '\U0001f600', ' '])
HOSTILE_TEXT = st.text(alphabet=st.one_of(HOSTILE, st.characters()), max_size=60)
LABEL = st.one_of(st.none(), HOSTILE_TEXT, st.just('x' * 5000))
SLOW = settings(max_examples=12, deadline=None)
FAST = settings(max_examples=60, deadline=None)


@contextmanager
def project_and_stores():
    with tempfile.TemporaryDirectory() as tmp:
        project = fss.make_project(Path(tmp))
        try:
            yield project
        finally:
            project.close()


def _label(text: str | None) -> str:
    """A label that keeps at least one character once cleaned (an empty label is a refused witness, not a case here)."""
    return text if clean_line(text) else 'label'


@st.composite
def plans(draw):
    """Per batch, a few imports named from a fixed list (so batches share anchors) with hostile labels."""
    chosen = draw(st.lists(st.sampled_from(BATCHES), min_size=1, max_size=3, unique=True))
    plan = {}
    for batch in chosen:
        names = draw(st.lists(st.sampled_from(NAMES), min_size=1, max_size=4, unique=True))
        plan[batch] = [fs.import_anchor(name, batch=batch, label=_label(draw(LABEL))) for name in names]
    return plan


def _utf8(text: str) -> bool:
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def listing(store) -> tuple:
    return tuple(a.anchor_id for a in store.find(P, ALL).items)


@SLOW
@given(plans())
def test_a_batch_survives_a_reopen_and_matches_the_reference(plan):
    reference = MemoryAnchorStore()
    reference.bind_pair(P, fs.OLDER, fs.NEWER)
    with project_and_stores() as project:
        store = fss.make_store(project)
        for anchors in plan.values():
            store.publish(P, anchors)
            reference.publish(P, anchors)
        reopened = fss.make_store(project)
        assert reopened.find(P, ALL).items == reference.find(P, ALL).items == store.find(P, ALL).items


@SLOW
@given(plans())
def test_the_listing_does_not_depend_on_the_order_of_publishing(plan):
    orders = []
    for ordering in (list(plan), list(reversed(list(plan)))):
        with project_and_stores() as project:
            store = fss.make_store(project)
            for batch in ordering:
                store.publish(P, plan[batch])
            orders.append((listing(store), store.digest(P)))
    assert orders[0] == orders[1]


@SLOW
@given(plans(), st.sampled_from(BATCHES))
def test_retracting_a_batch_leaves_exactly_what_the_others_published(plan, victim):
    with project_and_stores() as project:
        store = fss.make_store(project)
        for anchors in plan.values():
            store.publish(P, anchors)
        store.retract(P, 'cap', victim)
        with project_and_stores() as other:
            only_rest = fss.make_store(other)
            for batch, anchors in plan.items():
                if batch != victim:
                    only_rest.publish(P, anchors)
            assert listing(store) == listing(only_rest)


@SLOW
@given(plans(), st.lists(st.sampled_from(BATCHES), max_size=4), st.data())
def test_pins_keep_their_identity_and_label_through_any_batch_changes(plan, changes, data):
    with project_and_stores() as project:
        store = fss.make_store(project)
        pins = fss.make_pins(project)
        first = plan[next(iter(plan))]
        pinned = data.draw(st.lists(st.sampled_from(first), min_size=1, unique_by=lambda a: a.anchor_id))
        for anchor in pinned:
            store.publish(P, [anchor])
            pins.pin(P, anchor)
        before = [(p.anchor_id, p.label) for p in pins.pins(P).pins]
        for batch in changes:
            store.retract(P, 'cap', batch)
            if batch in plan:
                store.publish(P, plan[batch])
        assert [(p.anchor_id, p.label) for p in pins.pins(P).pins] == before


@SLOW
@given(plans(), st.data())
def test_pins_are_listed_newest_first_and_reopen_the_same(plan, data):
    with project_and_stores() as project:
        store = fss.make_store(project)
        pins = fss.make_pins(project)
        anchors = [a for batch in plan.values() for a in batch]
        for anchor in anchors:
            store.publish(P, [anchor])
        order = data.draw(st.permutations(sorted({a.anchor_id: a for a in anchors}.values(),
                                                key=lambda a: a.anchor_id)))
        for anchor in order:
            pins.pin(P, anchor)
        expected = [a.anchor_id for a in reversed(order)]
        assert [p.anchor_id for p in pins.pins(P).pins] == expected
        assert [p.anchor_id for p in fss.make_pins(project).pins(P).pins] == expected


@FAST
@given(HOSTILE_TEXT)
def test_a_pinned_note_is_the_clean_note_or_a_limit_error(text):
    try:
        expected = clean_note(text)
    except FabricError as exc:
        assert exc.reason == 'note-size'
        with project_and_stores() as project:
            anchor = fs.import_anchor('Note', batch='c1')
            assert _refused(fss.make_pins(project).pin, P, anchor, note=text) == 'note-size'
        return
    assert len(expected.encode('utf-8')) <= MAX_NOTE_BYTES
    with project_and_stores() as project:
        pinned = fss.make_pins(project).pin(P, fs.import_anchor('Note', batch='c1'), note=text)
    assert pinned.note == expected
    for line in pinned.note.split('\n'):
        plain_line(line)


def _refused(call, *args, **kwargs) -> str:
    try:
        call(*args, **kwargs)
    except FabricError as exc:
        return exc.reason
    raise AssertionError('the call was not refused')


@FAST
@given(st.text(alphabet=st.one_of(HOSTILE, st.characters()), min_size=1, max_size=80).filter(_utf8))
def test_a_converted_string_has_a_plain_label_a_verified_identity_and_an_nfc_key(value):
    record = SimpleNamespace(kind='string', value=value, source='csaf-note', pointer=None, quality='stated')
    if not clean_line(value):
        assert _refused(convert.from_k_anchor, record, batch='kb-1') == 'witness-label'
        return
    anchor = convert.from_k_anchor(record, batch='kb-1')
    ids.verify_anchor(anchor)
    plain_line(anchor.witnesses[0].label)
    assert anchor.key == ids.string_key(unicodedata.normalize('NFC', value))
