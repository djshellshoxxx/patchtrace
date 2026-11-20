"""Forced failures discard anonymous/held sources and retain mutable Linux stage names."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError


@pytest.mark.parametrize('prior_target', [False, True], ids=['new-target', 'prior-export'])
@pytest.mark.parametrize('substitute', [False, True], ids=['owned-stage', 'foreign-replacement'])
@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux linked-stage rename boundary')
def test_force_io_failure_preserves_stage_and_previous_target(tmp_path, monkeypatch, prior_target, substitute):
    target = tmp_path / 'report.json'
    if prior_target:
        target.write_bytes(b'prior complete export')
    owned = tmp_path / 'moved-owned-stage'
    stages = []
    real_replace = os.replace

    def refuse(stage, destination, **kwargs):
        stage = tmp_path / stage
        assert tmp_path / destination == target
        assert kwargs['src_dir_fd'] == kwargs['dst_dir_fd']
        stages.append(stage)
        if substitute:
            real_replace(stage, owned)
            stage.write_bytes(b'foreign replacement bytes')
        raise OSError(13, 'authored replacement refusal')

    monkeypatch.setattr(export.os, 'replace', refuse)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'expected export bytes', force=True)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert 'authored replacement refusal' in caught.value.message
    assert str(tmp_path) not in caught.value.message
    assert len(stages) == 1
    if prior_target:
        assert target.read_bytes() == b'prior complete export'
    else:
        assert not target.exists()
    assert stages[0].read_bytes() == (b'foreign replacement bytes' if substitute else b'expected export bytes')
    if substitute:
        assert owned.read_bytes() == b'expected export bytes'
    elif os.name != 'nt':
        assert stages[0].stat().st_mode & 0o777 == 0o600


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
