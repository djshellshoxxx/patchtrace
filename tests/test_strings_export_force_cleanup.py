"""Forced failures close anonymous/held sources and preserve unrelated pathnames."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError


@pytest.mark.parametrize('prior_target', [False, True], ids=['new-target', 'prior-export'])
@pytest.mark.parametrize('foreign_entry', [False, True], ids=['no-foreign-entry', 'foreign-entry'])
@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux exclusive-link boundary')
def test_force_io_failure_preserves_prior_target_and_foreign_entry(tmp_path, monkeypatch, prior_target, foreign_entry):
    target = tmp_path / 'report.json'
    if prior_target:
        target.write_bytes(b'prior complete export')
    foreign = tmp_path / '.report.foreign.tmp'
    descriptors = []

    def refuse(source, destination, **kwargs):
        assert destination == target.name and kwargs['follow_symlinks'] is True
        descriptor = int(str(source).rsplit('/', 1)[-1])
        assert os.fstat(descriptor).st_nlink == 0
        descriptors.append(descriptor)
        if foreign_entry:
            foreign.write_bytes(b'foreign contents')
        raise OSError(13, 'authored publication refusal')

    monkeypatch.setattr(export.os, 'link', refuse)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'expected export bytes', force=True)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert 'authored publication refusal' in caught.value.message
    assert str(tmp_path) not in caught.value.message
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    if prior_target:
        assert target.read_bytes() == b'prior complete export'
    else:
        assert not target.exists()
    expected = {target} if prior_target else set()
    if foreign_entry:
        assert foreign.read_bytes() == b'foreign contents'
        expected.add(foreign)
    assert set(tmp_path.iterdir()) == expected


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt, RuntimeError])
def test_force_fdopen_failure_closes_the_owned_descriptor_without_unlink(tmp_path, monkeypatch, error_type):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior export')
    descriptors = []
    failure = OSError(5, 'authored fdopen refusal') if error_type is OSError else error_type('authored interruption')

    def refuse(descriptor, _mode, **kwargs):
        assert kwargs['closefd'] is False
        descriptors.append(descriptor)
        raise failure

    monkeypatch.setattr(export.os, 'fdopen', refuse)
    with pytest.raises(StringsError if error_type is OSError else error_type) as caught:
        export.write_atomic(target, b'never written', force=True)
    assert len(descriptors) == 1 and target.read_bytes() == b'prior export'
    assert list(tmp_path.iterdir()) == [target]
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    if error_type is OSError:
        assert caught.value.code == 'PT-STR-EXPORT' and 'authored fdopen refusal' in caught.value.message
    else:
        assert caught.value is failure


def test_force_partial_write_failure_discards_owned_source_and_closes_descriptor(tmp_path, monkeypatch):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior export')
    descriptors = []
    real_fdopen = os.fdopen

    class PartialWriter:
        def __init__(self, descriptor, mode, **kwargs):
            descriptors.append(descriptor)
            self.stream = real_fdopen(descriptor, mode, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.stream.close()

        def write(self, data):
            self.stream.write(data[:7])
            self.stream.flush()
            raise OSError(28, 'authored partial-write failure')

    monkeypatch.setattr(export.os, 'fdopen', PartialWriter)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'partial export bytes', force=True)
    assert caught.value.code == 'PT-STR-EXPORT' and 'authored partial-write failure' in caught.value.message
    assert target.read_bytes() == b'prior export'
    assert list(tmp_path.iterdir()) == [target]
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
