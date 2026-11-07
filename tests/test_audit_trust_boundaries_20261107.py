"""Regression tests from the 2026-11-07 trust-boundary audit (docs/qa/audit-trust-boundaries-20261107.md).

Synthetic hostile inputs only; nothing here executes or loads a target binary."""
from __future__ import annotations

import os
import stat
import time

import pytest

from patchtrace.acquisition import quarantine


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
