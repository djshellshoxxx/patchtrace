"""Real descriptor controls for bounded Tier-W document ingestion."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tools.calibration.tier_w import paths


@pytest.mark.parametrize('limit', [-1, True, False, 1.5, '8', None])
def test_invalid_byte_limit_is_typed_input_error(tmp_path, limit):
    path = tmp_path / 'input.json'
    path.write_bytes(b'{}')
    with pytest.raises(paths.TierWError, match='PT-TIERW-INPUT'):
        paths.read_bytes(path, limit)


def test_document_read_never_uses_unbounded_path_read(tmp_path, monkeypatch):
    path = tmp_path / 'input.json'
    path.write_bytes(b'{"ok":true}')

    def forbidden(*args, **kwargs):
        pytest.fail('bounded reader used unbounded Path.read_bytes')

    monkeypatch.setattr(Path, 'read_bytes', forbidden)
    assert paths.read_bytes(path, 64) == b'{"ok":true}'


def test_growth_after_descriptor_admission_is_refused(tmp_path, monkeypatch):
    path = tmp_path / 'input.json'
    path.write_bytes(b'{}')
    real_stat, real_read = os.fstat, os.read
    calls, reads = [], []

    def changed(fd):
        value = real_stat(fd)
        calls.append(fd)
        if len(calls) == 1:
            with path.open('ab') as out:
                out.write(b'x' * 128)
        return value

    def bounded(fd, count):
        reads.append(count)
        assert 0 <= count <= 65
        return real_read(fd, count)

    monkeypatch.setattr(paths.os, 'fstat', changed)
    monkeypatch.setattr(paths.os, 'read', bounded)
    with pytest.raises(paths.TierWError, match='PT-TIERW-(LIMIT|INPUT)'):
        paths.read_bytes(path, 64)
    assert calls and reads


def test_regular_empty_file_and_exact_limit(tmp_path):
    path = tmp_path / 'empty'
    path.write_bytes(b'')
    assert paths.read_bytes(path, 0) == b''
    path.write_bytes(b'abcd')
    assert paths.read_bytes(path, 4) == b'abcd'
    with pytest.raises(paths.TierWError, match='PT-TIERW-LIMIT'):
        paths.read_bytes(path, 3)


def test_directory_is_refused_as_typed_input(tmp_path):
    with pytest.raises(paths.TierWError, match='PT-TIERW-INPUT'):
        paths.read_bytes(tmp_path, 64)
