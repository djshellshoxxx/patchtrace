"""Authored offline controls for PW-01 source admission races."""
from __future__ import annotations

import socket

import kbc_helpers as h
import pytest
import test_kbc_inventory_selection as s
from kbc_k3_support import FixedClock

from patchtrace.kbcorrelation import inventory_selection as selected
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore
from patchtrace.kbcorrelation.workflow import Event


@pytest.fixture(autouse=True)
def refuse_network(monkeypatch):
    def refused(*args, **kwargs):
        raise AssertionError('source race probe is offline')
    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, refused)


def competing_source(svc):
    raw = h.render_json(s.document(builds=('10.0.26100.9002',), release='2099-Mar'))
    imported = import_bytes(raw, now=s.NOW)
    with WorkspaceStore(svc.root) as ws:
        assert ws.add_document(imported, raw)


def must_refuse(call, svc, state, before):
    try:
        outcome = call()
    except KbcStoreError as exc:
        assert exc.code == 'PT-KBC-STALE'
    else:
        after = s.snapshot(svc, state[0])
        pytest.fail(f'stale selection accepted: exit={outcome.exit}, '
                    f'revision={before[0].revision}->{after[0].revision}, '
                    f'decisions={len(before[1])}->{len(after[1])}')
    assert s.snapshot(svc, state[0]) == before


def test_conflicting_source_before_cas_cannot_publish_selection(tmp_path):
    svc = s.service(tmp_path)
    state = s.start(svc)
    identity = s.inventory(svc, tmp_path)
    before = s.snapshot(svc, state[0])
    added = []

    def fault(point):
        if point == 'before_cas' and not added:
            competing_source(svc)
            added.append(True)

    racing = wiring.build_service(svc.root, clock=FixedClock(), fault=fault)
    must_refuse(lambda: s.select(racing, state, identity), svc, state, before)
    assert added == [True]


@pytest.mark.parametrize('repeat', [False, True])
def test_source_change_during_inventory_replay_refuses_new_and_noop_selection(tmp_path, monkeypatch, repeat):
    svc = s.service(tmp_path)
    state = s.start(svc)
    identity = s.inventory(svc, tmp_path)
    if repeat:
        first = s.select(svc, state, identity)
        state = state[0], state[1], first.result['revision']
    before = s.snapshot(svc, state[0])
    original = selected.get_inventory
    added = []

    def racing_get(*args, **kwargs):
        record = original(*args, **kwargs)
        if not added:
            competing_source(svc)
            added.append(True)
        return record

    monkeypatch.setattr(selected, 'get_inventory', racing_get)
    must_refuse(lambda: s.select(svc, state, identity), svc, state, before)
    assert added == [True]


def test_source_change_during_index_read_cannot_bind_later_snapshot(tmp_path, monkeypatch):
    svc = s.service(tmp_path)
    state = s.start(svc)
    identity = s.inventory(svc, tmp_path)
    before = s.snapshot(svc, state[0])
    original = WorkspaceStore.read_object
    added = []

    def racing_read(ws, digest):
        if ws.root == svc.root and not added:
            competing_source(svc)
            added.append(True)
        return original(ws, digest)

    monkeypatch.setattr(WorkspaceStore, 'read_object', racing_read)
    must_refuse(lambda: s.select(svc, state, identity), svc, state, before)
    assert added == [True]


def test_unchanged_source_accepts_and_repeat_is_idempotent(tmp_path):
    svc = s.service(tmp_path)
    state = s.start(svc)
    identity = s.inventory(svc, tmp_path)
    first = s.select(svc, state, identity)
    assert first.exit == 0
    state = state[0], state[1], first.result['revision']
    before = s.snapshot(svc, state[0])
    second = s.select(svc, state, identity)
    assert second.exit == 0
    assert s.snapshot(svc, state[0]) == before


def test_noop_selection_refuses_concurrent_revision_without_discarding_it(tmp_path, monkeypatch):
    svc = s.service(tmp_path)
    state = s.start(svc)
    identity = s.inventory(svc, tmp_path)
    first = s.select(svc, state, identity)
    state = state[0], state[1], first.result['revision']
    original = selected.get_inventory
    competing = []

    def racing_get(*args, **kwargs):
        record = original(*args, **kwargs)
        if not competing:
            with WorkspaceStore(svc.root) as ws:
                rev = ws.current_revision(state[0])
                ws.apply(rev, Event('product_selected', rev.revision, scope_id=state[1]))
            competing.append(s.snapshot(svc, state[0]))
        return record

    monkeypatch.setattr(selected, 'get_inventory', racing_get)
    with pytest.raises(KbcStoreError) as raised:
        s.select(svc, state, identity)
    assert raised.value.code == 'PT-KBC-STALE'
    assert len(competing) == 1
    assert s.snapshot(svc, state[0]) == competing[0]


def test_preexisting_competing_source_is_a_real_eligibility_conflict(tmp_path):
    svc = s.service(tmp_path)
    state = s.start(svc)
    identity = s.inventory(svc, tmp_path)
    competing_source(svc)
    before = s.snapshot(svc, state[0])
    with pytest.raises(KbcStoreError) as raised:
        s.select(svc, state, identity)
    assert raised.value.code == 'PT-KBC-INPUT'
    assert 'advisory builds conflict' in raised.value.message
    assert s.snapshot(svc, state[0]) == before
