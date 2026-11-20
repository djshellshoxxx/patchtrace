"""Offline source-admission controls; all index bytes are synthetic and never executed."""
from __future__ import annotations

from pathlib import Path

import pytest

from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.kbcorrelation.wiring import WorkspaceFileIndex

NAME = 'exampledrv.sys'
DATE = '2099-02-12'
PLAIN = f'{NAME}@{DATE}.json'
GZIP = f'{PLAIN}.gz'


def _index(tmp_path: Path) -> Path:
    folder = tmp_path / 'winbindex'
    folder.mkdir()
    return folder


@pytest.mark.parametrize('reverse', [False, True])
def test_same_date_plain_and_gzip_claims_are_refused_before_parsing(tmp_path, reverse):
    folder = _index(tmp_path)
    candidates = [(PLAIN, b'first raw source'), (GZIP, b'different raw source')]
    for name, data in (reversed(candidates) if reverse else candidates):
        (folder / name).write_bytes(data)
    source = WorkspaceFileIndex(tmp_path)

    with pytest.raises(KbcStoreError) as error:
        source.rows_for(NAME, '11-24H2')
    assert error.value.code == 'PT-KBC-SOURCE'
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == dict(candidates)


def test_latest_unique_record_wins_without_rejecting_irrelevant_historical_collision(tmp_path):
    folder = _index(tmp_path)
    (folder / PLAIN).write_bytes(b'old-plain')
    (folder / GZIP).write_bytes(b'old-gzip')
    newer = folder / f'{NAME}@2099-02-13.json'
    newer.write_bytes(b'new')
    source = WorkspaceFileIndex(tmp_path)

    assert source._record(NAME) == (newer, '2099-02-13', False)
    assert newer.read_bytes() == b'new'


@pytest.mark.parametrize('compressed', [False, True])
def test_unique_plain_or_gzip_record_has_stable_selection(tmp_path, compressed):
    folder = _index(tmp_path)
    name = GZIP if compressed else PLAIN
    path = folder / name
    path.write_bytes(b'authored index bytes')
    assert WorkspaceFileIndex(tmp_path)._record(NAME) == (path, DATE, compressed)


def test_matching_symlink_record_refused_without_reading_foreign_bytes(tmp_path):
    folder = _index(tmp_path)
    foreign = tmp_path / 'foreign-source.json'
    foreign.write_bytes(b'foreign content is never a Winbindex record')
    link = folder / PLAIN
    try:
        link.symlink_to(foreign)
    except (OSError, NotImplementedError):
        pytest.skip('this host cannot construct an index symlink')

    with pytest.raises(KbcStoreError) as error:
        WorkspaceFileIndex(tmp_path).rows_for(NAME, '11-24H2')
    assert error.value.code == 'PT-KBC-SOURCE'
    assert foreign.read_bytes() == b'foreign content is never a Winbindex record'


def test_symlinked_index_directory_is_not_considered_an_offline_source(tmp_path):
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    (foreign / PLAIN).write_bytes(b'foreign data')
    try:
        (tmp_path / 'winbindex').symlink_to(foreign, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('this host cannot construct a directory symlink')

    source = WorkspaceFileIndex(tmp_path)
    for read in (source.available, lambda: source.rows_for(NAME, '11-24H2')):
        with pytest.raises(KbcStoreError) as error:
            read()
        assert error.value.code == 'PT-KBC-SOURCE'
    assert (foreign / PLAIN).read_bytes() == b'foreign data'


def test_missing_record_still_means_no_rows_and_does_not_create_directories(tmp_path):
    source = WorkspaceFileIndex(tmp_path)
    assert not source.available()
    assert not source.has_record(NAME)
    assert source.rows_for(NAME, '11-24H2') == []
    assert not (tmp_path / 'winbindex').exists()
