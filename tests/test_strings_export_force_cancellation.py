"""Linux force requests retain exclusive-publication cancellation and cleanup ownership."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace.strings import export


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('arriving', [False, True], ids=['absent-destination', 'concurrent-destination'])
@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux exclusive-link boundary')
def test_non_io_force_failure_preserves_evidence_and_destination(tmp_path, monkeypatch, error_type, arriving):
    target = tmp_path / 'report.json'
    prior = tmp_path / 'prior.json'
    prior.write_bytes(b'prior complete export')
    descriptors = []
    failure = error_type('authored force interruption')

    def interrupt(source, destination, **kwargs):
        assert destination == target.name and kwargs['follow_symlinks'] is True
        descriptor = int(str(source).rsplit('/', 1)[-1])
        assert os.fstat(descriptor).st_nlink == 0
        descriptors.append(descriptor)
        if arriving:
            target.write_bytes(b'concurrent complete export')
        raise failure

    monkeypatch.setattr(export.os, 'link', interrupt)
    with pytest.raises(error_type) as caught:
        export.write_atomic(target, b'expected export bytes', force=True)

    assert caught.value is failure
    assert prior.read_bytes() == b'prior complete export'
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    if arriving:
        assert target.read_bytes() == b'concurrent complete export'
        assert set(tmp_path.iterdir()) == {target, prior}
    else:
        assert not target.exists()
        assert list(tmp_path.iterdir()) == [prior]
