"""Regression tests from the 2026-11-07 trust-boundary audit (docs/qa/audit-trust-boundaries-20261107.md).

Synthetic hostile inputs only; nothing here executes or loads a target binary."""
from __future__ import annotations

import os
import stat
import time

import pytest

from patchtrace.acquisition import quarantine
from patchtrace.acquisition import transport as tr
from patchtrace.hostile_text import is_hostile
from patchtrace.ingestion import display_text


# TB-01 sweep_staging followed a symlink named like a staging directory and chmod-ed its target
@pytest.mark.skipif(os.name == 'nt', reason='symlink and POSIX mode assertions')
def test_sweep_staging_ignores_symlinked_staging_names(tmp_path):
    parent = tmp_path / 'shared-tmp'
    parent.mkdir()
    victim = tmp_path / 'victim'
    victim.mkdir()
    victim.chmod(0o755)
    keepsake = tmp_path / 'keepsake.txt'
    keepsake.write_text('x')
    keepsake.chmod(0o444)
    old = time.time() - 3 * 24 * 3600
    for target in (victim, keepsake):
        os.utime(target, (old, old))
    os.symlink(victim, parent / (quarantine.STAGING_PREFIX + 'dir'))
    os.symlink(keepsake, parent / (quarantine.STAGING_PREFIX + 'file'))
    quarantine.sweep_staging(parent)
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755
    assert stat.S_IMODE(keepsake.stat().st_mode) == 0o444


# TB-02 a Last-Modified header at the edge of the date range raised OverflowError out of fetch_metadata
@pytest.mark.parametrize('value', ['Fri, 31 Dec 9999 23:59:59 -0100', 'Fri, 31 Dec 9999 23:59:59 -2359'])
def test_last_modified_out_of_range_is_ignored_not_raised(value):
    assert tr._date(value) is None


# TB-03 U+2028 / U+2029 split a one-line GUI label into two lines but were not treated as hostile
@pytest.mark.parametrize('char', ['\u2028', '\u2029'])
def test_line_and_paragraph_separators_are_hostile(char):
    assert is_hostile(char)
    assert display_text(f'good{char}FAKE') == 'good?FAKE'
