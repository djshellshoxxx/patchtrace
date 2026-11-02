"""Second-pass identity and flag preparation share the caller's cancellation/deadline budget."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import threading

import pytest
from test_unified_wire_compute import files_of, probe, run
from unified_s0_fixtures import bd, bindiff_set

from patchtrace.unified.compute import close_ir, refacts_stage
from patchtrace.unified.exchange import WorkerRefacts
from patchtrace.unified.limits import Budget, BudgetExhausted
from patchtrace.unified.sources import LoadedSecondary, SnapshotFunction, SnapshotMatch
from patchtrace.unified.sources import secondary as secondary_source


@pytest.fixture
def staged(tmp_path):
    data, addr, ir = probe(tmp_path)
    base = ir.older.manifest.image_base
    function = SnapshotFunction(name='manual', address=f'{base + 0x1000:x}', code='return 1;')
    matches = tuple(SnapshotMatch(id=f'manual-{i}', category='modified', manual=True,
                                  older=(function,), newer=(function,)) for i in range(8))
    normalized = bindiff_set([bd(0x1000 + i * 16, 0x1000 + i * 16, base=base) for i in range(8)],
                             older=data.older_sha256, newer=data.newer_sha256)
    body = json.dumps(normalized.model_dump(mode='json'), sort_keys=True, separators=(',', ':'))

    def secondary():
        return LoadedSecondary.from_verified_body('persisted', normalized, body, hashlib.sha256(body.encode()).hexdigest())

    data = dataclasses.replace(data, matches=matches, secondary=(secondary(),))
    try:
        _manifest, directory = run(tmp_path, data, addr, ir=ir)
        # The second worker independently reloads validated inputs; prior in-process caches are not authority.
        fresh = dataclasses.replace(data, secondary=(secondary(),))
        yield fresh, addr, ir, directory
    finally:
        close_ir(ir)


def stopping_budget(kind):
    cancel = threading.Event()
    now = [0.0]
    budget = Budget(deadline=1.0, cancel=cancel, check_every=1, clock=lambda: now[0])

    def stop():
        cancel.set() if kind == 'cancel' else now.__setitem__(0, 1.0)

    return budget, stop


@pytest.mark.parametrize('kind', ['cancel', 'timeout'])
def test_refacts_stops_during_manual_identity_without_rewriting_staged_result(staged, monkeypatch, kind):
    data, addr, ir, directory = staged
    before = files_of(directory)
    budget, stop = stopping_budget(kind)
    calls = []
    original = SnapshotMatch.model_dump

    def dumping(self, *args, **kwargs):
        calls.append(self.id)
        if len(calls) == 3:
            stop()
        return original(self, *args, **kwargs)

    monkeypatch.setattr(SnapshotMatch, 'model_dump', dumping)
    with pytest.raises(BudgetExhausted) as rejected:
        refacts_stage(data, addr, result_dir=directory, ir=ir, refacts=WorkerRefacts(), budget=budget)
    assert rejected.value.code == f'PT-UNIFIED-{kind.upper()}'
    assert len(calls) == 3 and data._manual_digest is None
    assert files_of(directory) == before


@pytest.mark.parametrize('kind', ['cancel', 'timeout'])
def test_refacts_stops_during_secondary_flag_ordering_without_rewriting_staged_result(staged, monkeypatch, kind):
    data, addr, ir, directory = staged
    before = files_of(directory)
    budget, stop = stopping_budget(kind)
    calls = []
    original = secondary_source._record_key

    def ordering(record):
        calls.append(record)
        if len(calls) == 3:
            stop()
        return original(record)

    monkeypatch.setattr(secondary_source, '_record_key', ordering)
    texts = WorkerRefacts(pairs=((0x1000, 0x1000),), older=((0x1000, 'return 1;'),), newer=((0x1000, 'return 2;'),))
    with pytest.raises(BudgetExhausted) as rejected:
        refacts_stage(data, addr, result_dir=directory, ir=ir, refacts=texts, budget=budget)
    assert rejected.value.code == f'PT-UNIFIED-{kind.upper()}'
    assert len(calls) == 3 and data.secondary[0]._ordered is None
    assert files_of(directory) == before
