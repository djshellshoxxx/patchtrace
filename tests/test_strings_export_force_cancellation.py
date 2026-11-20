"""Forced export cancellation must not gain pathname cleanup authority."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace.strings import export


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('substitute', [False, True], ids=['owned-stage', 'foreign-replacement'])
@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux linked-stage rename boundary')
def test_non_io_force_failure_preserves_stage_and_destination(tmp_path, monkeypatch, error_type, substitute):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    owned = tmp_path / 'moved-owned-stage'
    stages = []
    failure = error_type('authored force interruption')
    real_replace = os.replace

    def interrupt(stage, destination, **kwargs):
        stage = tmp_path / stage
        assert tmp_path / destination == target
        assert kwargs['src_dir_fd'] == kwargs['dst_dir_fd']
        stages.append(stage)
        if substitute:
            real_replace(stage, owned)
            stage.write_bytes(b'foreign replacement bytes')
        raise failure

    # The Linux source handle stays open, but its final linked name can still
    # change. Cancellation must not grant authority to unlink that mutable name.
    monkeypatch.setattr(export.os, 'replace', interrupt)
    with pytest.raises(error_type) as caught:
        export.write_atomic(target, b'expected export bytes', force=True)

    assert caught.value is failure
    assert target.read_bytes() == b'prior complete export'
    assert len(stages) == 1
    if substitute:
        assert owned.read_bytes() == b'expected export bytes'
        assert stages[0].read_bytes() == b'foreign replacement bytes'
    else:
        assert stages[0].read_bytes() == b'expected export bytes'
