"""A damaged pair pathname must not discard otherwise readable series hops."""
import threading
from pathlib import Path

import pytest
from test_nway_series import builds, populated  # noqa: F401
from test_nway_view_model import rank_pairs

from patchtrace.nway import series as store
from patchtrace.nway import view_model
from patchtrace.nway.contracts import PairRef
from patchtrace.nway.pair_access import DiskPairReader


def _ref():
    return PairRef(from_ordinal=0, to_ordinal=1, path='pair', project_id='project', revision=0)


@pytest.mark.parametrize('error_type', [OSError, RuntimeError, ValueError])
def test_pair_reader_classifies_path_resolution_errors(tmp_path, monkeypatch, error_type):
    target = tmp_path / 'pair'
    resolve = Path.resolve

    def fail_one(path, *args, **kwargs):
        if path == target:
            raise error_type(f'untrusted path details: {target}')
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'resolve', fail_one)
    snapshot = DiskPairReader().read(tmp_path, _ref(), '0' * 64, '1' * 64, frozenset())
    assert snapshot.state == 'unreadable'
    assert snapshot.reason == 'pair project path cannot be read'
    assert snapshot.ranking is None and not snapshot.match_names


def test_pair_reader_classifies_project_stat_failure(tmp_path, monkeypatch):
    target = tmp_path / 'pair' / 'project.sqlite3'
    is_file = Path.is_file

    def fail_one(path):
        if path == target:
            raise PermissionError(f'private path: {target}')
        return is_file(path)

    monkeypatch.setattr(Path, 'is_file', fail_one)
    snapshot = DiskPairReader().read(tmp_path, _ref(), '0' * 64, '1' * 64, frozenset())
    assert snapshot.state == 'unreadable'
    assert snapshot.reason == 'pair project path cannot be read'


@pytest.mark.parametrize('operation', ['resolve', 'is_file'])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError, ValueError])
def test_series_retains_healthy_hop_after_path_error(
        builds, tmp_path, capsys, monkeypatch, operation, error_type):  # noqa: F811
    root = tmp_path / 'series'
    pairs, _ = populated(capsys, builds, root)
    rank_pairs(pairs, capsys)
    series_path = root / 'series.json'
    original = getattr(Path, operation)
    target = pairs[0] if operation == 'resolve' else pairs[0] / 'project.sqlite3'

    def fail_one(path, *args, **kwargs):
        if path == target:
            raise error_type(f'private path: {target}')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, operation, fail_one)
    series = store.load(series_path)
    staleness = store.staleness(series, series_path)
    assert staleness.pairs == frozenset({0})
    assert staleness.reasons == ('pair 0→1: project path cannot be read',)
    loaded = view_model.load_view(series_path, DiskPairReader(), threading.Event())
    assert loaded.state == 'partial'
    assert [pair.state for pair in loaded.pairs] == ['unreadable', 'ok']
    [row] = loaded.rows
    assert row.stale and row.hops[0].score_state == 'pair-unavailable'
    assert row.hops[1].score_state == 'scored'
    assert str(root) not in loaded.message


def test_pair_reader_classifies_real_symlink_loop(tmp_path):
    target = tmp_path / 'pair'
    try:
        target.symlink_to(target.name, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('host cannot create a directory symlink')
    snapshot = DiskPairReader().read(tmp_path, _ref(), '0' * 64, '1' * 64, frozenset())
    assert snapshot.state == 'unreadable'
    assert snapshot.reason == 'pair project path cannot be read'
