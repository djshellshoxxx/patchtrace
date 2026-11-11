"""Security regression: an atomic writer leaves the old file or the whole new one, never a temporary file behind.

A refused replace is simulated by making os.replace raise. Every writer must clean up its own temporary file and
must keep the previous content of the target.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from patchtrace import ui_capabilities_setup as capa
from patchtrace.enrichment import profiles
from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import transport as csaf_transport
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.intelligence.tools import store as tools_store
from patchtrace.kbcorrelation import store as kbc_store
from patchtrace.nway import series as nway_series
from patchtrace.unified import exchange

CUSTOM = {'name': 'triage', 'weights': {'BND': 60, 'INT': 22, 'OVF': 28, 'VAL': 20, 'ERR': 0,
                                        'SIZE': 24, 'WIL': 12, 'SCRUB': 34},
          'enabled': ['BND', 'INT', 'OVF', 'VAL', 'SIZE', 'WIL', 'SCRUB'],
          'feature_ids': None, 'symbol_policy': 'disabled', 'cve_providers': ['nvd'],
          'snapshot_max_age_days': 7, 'cache_dir': None, 'cache_budget_gib': 5}


def _refuse(*_args, **_kwargs):
    raise OSError(13, 'locked by another process')


def _advisory_write(target: Path, data: bytes) -> None:
    # The writer only needs the root; building a full store would add nothing to what is under test.
    store = AdvisoryStore.__new__(AdvisoryStore)
    store.root = target.parent
    store._write(target.name, data)


def _capa_place(target: Path, data: bytes) -> None:
    capa._place(data, target.parent, target.name)


BYTE_WRITERS = [
    pytest.param(kbc_store.atomic_write, id='kbcorrelation'),
    pytest.param(tools_store._atomic_write, id='intelligence-tools'),
    pytest.param(csaf_transport._atomic_write, id='csaf-transport'),
    pytest.param(exchange.write_atomic, id='unified-exchange'),
    pytest.param(_advisory_write, id='advisory-storage'),
    pytest.param(_capa_place, id='capa-setup'),
]


@pytest.mark.parametrize('write', BYTE_WRITERS)
def test_a_refused_replace_keeps_the_old_file_and_leaves_no_temporary(tmp_path, monkeypatch, write):
    target = tmp_path / 'artifact.json'
    target.write_bytes(b'old')
    monkeypatch.setattr(os, 'replace', _refuse)
    with pytest.raises((OSError, IntelError)):
        write(target, b'new')
    assert target.read_bytes() == b'old'
    assert [p.name for p in tmp_path.iterdir()] == ['artifact.json']


@pytest.mark.parametrize('write', BYTE_WRITERS)
def test_a_refused_replace_of_a_new_file_creates_nothing(tmp_path, monkeypatch, write):
    monkeypatch.setattr(os, 'replace', _refuse)
    with pytest.raises((OSError, IntelError)):
        write(tmp_path / 'new.json', b'new')
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('write', BYTE_WRITERS)
def test_a_successful_write_leaves_only_the_target(tmp_path, write):
    write(tmp_path / 'artifact.json', b'new')
    assert (tmp_path / 'artifact.json').read_bytes() == b'new'
    assert [p.name for p in tmp_path.iterdir()] == ['artifact.json']


def test_a_refused_replace_of_a_series_leaves_no_temporary(tmp_path, monkeypatch):
    monkeypatch.setattr(nway_series, 'dumps', lambda _value: '{"series": []}')
    monkeypatch.setattr(os, 'replace', _refuse)
    with pytest.raises(OSError):
        nway_series.save(object(), tmp_path / 'series.json')
    assert list(tmp_path.iterdir()) == []


def test_a_refused_replace_of_a_profile_leaves_no_temporary(tmp_path, monkeypatch):
    store = profiles.ProfileStore(tmp_path / 'profiles')
    monkeypatch.setattr(os, 'replace', _refuse)
    with pytest.raises(OSError):
        store.save(profiles.build(CUSTOM))
    assert list((tmp_path / 'profiles').iterdir()) == []


def test_exchange_write_never_writes_through_a_planted_temporary_name(tmp_path):
    # The old writer used the fixed name `<target>.part`, so a symlink planted there received the bytes.
    outside = tmp_path / 'outside.txt'
    outside.write_bytes(b'keep')
    target = tmp_path / 'report.json'
    (tmp_path / 'report.json.part').symlink_to(outside)
    exchange.write_atomic(target, b'new')
    assert outside.read_bytes() == b'keep'
    assert target.read_bytes() == b'new' and not target.is_symlink()
