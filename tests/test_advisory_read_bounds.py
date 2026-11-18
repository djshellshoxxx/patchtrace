"""Bounded reads of hostile retained advisory files; no large allocation or native engine."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path

import pytest
from test_intel_storage import REV1, add, store_for

from patchtrace.intelligence import storage
from patchtrace.intelligence.contracts import IntelError
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as value:
        yield value


def refuse_unbounded_read(monkeypatch, path, maximum):
    """Instrument the actual file object by inode, across path and descriptor opens."""
    original = io.open
    identity = (path.stat().st_dev, path.stat().st_ino)
    requests = []

    class Budgeted:
        def __init__(self, handle):
            self.handle = handle

        def read(self, size=-1):
            requests.append(size)
            assert 0 <= size <= maximum + 1, 'retained file requested an unbounded or over-budget read'
            return self.handle.read(size)

        def __getattr__(self, name):
            return getattr(self.handle, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

    def opened(file, mode='r', *args, **kwargs):
        handle = original(file, mode, *args, **kwargs)
        info = os.fstat(handle.fileno())
        return Budgeted(handle) if mode == 'rb' and (info.st_dev, info.st_ino) == identity else handle

    monkeypatch.setattr(io, 'open', opened)
    return requests


def test_verified_sidecar_never_requests_an_unbounded_read(service, monkeypatch):
    store = store_for(service)
    stored = add(store, REV1)
    path = service.root / stored.source.raw_path
    cap = 64 * 1024 * 1024
    requests = refuse_unbounded_read(monkeypatch, path, cap)
    assert store.read_verified(stored.source.raw_path, stored.source.sha256) == REV1
    assert requests and all(0 <= amount <= cap + 1 for amount in requests)


def test_existing_object_reuse_never_reads_more_than_the_expected_object(service, monkeypatch):
    store = store_for(service)
    stored = add(store, REV1)
    path = service.root / stored.source.raw_path
    requests = refuse_unbounded_read(monkeypatch, path, len(REV1))
    before = path.stat().st_mtime_ns
    store._write(stored.source.raw_path, REV1)
    assert requests and path.stat().st_mtime_ns == before


def test_oversized_existing_object_is_repaired_without_reading_it(service, monkeypatch):
    store = store_for(service)
    stored = add(store, REV1)
    path = service.root / stored.source.raw_path
    path.write_bytes(REV1 + b' ' * 100)
    requests = refuse_unbounded_read(monkeypatch, path, len(REV1))
    store._write(stored.source.raw_path, REV1)
    assert requests == []  # the held file size rejects it before any content allocation
    assert path.read_bytes() == REV1


def test_a_matching_digest_cannot_override_the_read_byte_budget(service, monkeypatch):
    monkeypatch.setattr(storage, 'MAX_SIDECAR_BYTES', 32, raising=False)
    path = service.root / 'oversized.json'
    data = b'x' * 33
    path.write_bytes(data)
    with pytest.raises(IntelError):
        store_for(service).read_verified('oversized.json', hashlib.sha256(data).hexdigest())


def test_oversized_normalized_facts_are_refused_before_any_import_write(service, monkeypatch):
    before = list(service.root.rglob('*'))
    monkeypatch.setattr(storage, 'MAX_SIDECAR_BYTES', 32, raising=False)
    with pytest.raises(IntelError) as caught:
        add(store_for(service), REV1)
    assert caught.value.code == 'PT-INTEL-LIMIT'
    assert list(service.root.rglob('*')) == before


def test_raw_recovery_uses_the_recorded_source_size_bound(service, monkeypatch):
    store = store_for(service)
    stored = add(store, REV1)
    for path in (service.root / 'intelligence/csaf/facts').glob('*.json'):
        path.unlink()
    raw = service.root / stored.source.raw_path
    requests = refuse_unbounded_read(monkeypatch, raw, stored.source.size)
    advisories, warnings = store.advisories()
    assert len(advisories) == 1 and advisories[0].facts == stored.facts and warnings
    assert requests and max(requests) <= stored.source.size + 1


def test_oversized_source_recovery_is_unavailable_without_reading_bytes(service, monkeypatch):
    store = store_for(service)
    stored = add(store, REV1)
    for path in (service.root / 'intelligence/csaf/facts').glob('*.json'):
        path.unlink()
    raw = service.root / stored.source.raw_path
    raw.write_bytes(REV1 + b' ')
    requests = refuse_unbounded_read(monkeypatch, raw, stored.source.size)
    advisories, warnings = store.advisories()
    assert advisories == [] and warnings and requests == []


def test_digest_mismatch_remains_an_integrity_failure(service):
    store = store_for(service)
    stored = add(store, REV1)
    with pytest.raises(IntelError) as caught:
        store.read_verified(stored.source.raw_path, '0' * 64)
    assert caught.value.code == 'PT-INTEL-INTEGRITY'


def test_symlink_sidecar_stays_refused(service, tmp_path):
    outside = tmp_path / 'outside.json'
    outside.write_bytes(REV1)
    link = service.root / 'linked.json'
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip('symlink creation is unavailable on this platform')
    with pytest.raises(IntelError):
        store_for(service).read_verified('linked.json', hashlib.sha256(REV1).hexdigest())
