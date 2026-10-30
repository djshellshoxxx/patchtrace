"""Positive controls for tests/liveness_support.py: every negative check can fail, so none passes vacuously."""
from __future__ import annotations

import subprocess
import sys

from liveness_support import cancel_when_started, heartbeat_code, heartbeat_stopped, never_appears, wait_for


def test_heartbeat_stopped_fails_when_the_child_never_started(tmp_path):
    assert heartbeat_stopped(tmp_path / 'beat', settle=0.1, start_timeout=0.2) is False


def test_heartbeat_stopped_fails_while_the_child_keeps_beating(tmp_path):
    beat = tmp_path / 'beat'
    child = subprocess.Popen([sys.executable, '-c', heartbeat_code(beat, beats=200)])
    try:
        assert heartbeat_stopped(beat, settle=0.5) is False
    finally:
        child.kill()
        child.wait()


def test_heartbeat_stopped_passes_once_the_child_is_dead(tmp_path):
    beat = tmp_path / 'beat'
    child = subprocess.Popen([sys.executable, '-c', heartbeat_code(beat, beats=200)])
    assert wait_for(lambda: beat.exists() and beat.stat().st_size > 0)
    child.kill()
    child.wait()
    assert heartbeat_stopped(beat, settle=0.3) is True


def test_never_appears_fails_when_the_file_appears(tmp_path):
    marker = tmp_path / 'marker'
    marker.write_text('x', encoding='utf-8')
    assert never_appears(marker, within=0.2) is False
    assert never_appears(tmp_path / 'absent', within=0.1) is True


def test_cancel_when_started_sets_on_the_started_file(tmp_path):
    started = tmp_path / 'started'
    cancel = cancel_when_started(started, timeout=5.0)
    assert not cancel.wait(0.1)
    started.write_text('x', encoding='utf-8')
    assert cancel.wait(5.0)
