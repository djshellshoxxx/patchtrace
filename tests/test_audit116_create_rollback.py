"""Audit #116 P2: a failed project creation must leave nothing that blocks a retry."""
from pathlib import Path

import pytest

from patchtrace.service import ProjectService
from tests.pe_builder import build_pe


@pytest.mark.xfail(strict=True, reason='audit116#2: ProjectService.create leaves .patchtrace.lock and copied '
                   'artifacts after a failed create; owner service.py/WS-integrator')
def test_failed_create_leaves_no_owned_files_and_retry_works(tmp_path):
    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    bad = tmp_path / 'newer.exe'
    bad.write_bytes(b'MZ not a pe')
    root = tmp_path / 'case'
    with pytest.raises((ValueError, OSError)):
        ProjectService.create(older, bad, 'x', root)
    leftovers = sorted(p.name for p in Path(root).rglob('*')) if root.exists() else []
    assert leftovers == [], f'failed creation stranded {leftovers}'
    bad.write_bytes(build_pe())
    service = ProjectService.create(older, bad, 'x', root)
    service.store.close()
