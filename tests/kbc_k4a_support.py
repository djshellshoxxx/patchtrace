"""Helpers of the K4a tests (leads, view model, synergy). SYNTHETIC data only; offline.

``analysed_project`` builds the plan s5 (c) project through the real ``kb import-pair`` (so the advisory context is
attached) and applies a synthetic Ghidriff-shaped diff with five changed functions: ``read_item`` (null/index guard),
``alloc_items`` (multiplication guard before the allocation), ``get_version``, added ``report_invalid_index`` and removed
``debug_dump``. ``rank`` stores the ranking exactly as ``python -m patchtrace rank P`` does.
"""
from __future__ import annotations

import json
from pathlib import Path

from kbc_k3_support import BASELINE, Kb, write_pair

from patchtrace import cli as main_cli
from patchtrace.models import AnalysisRun
from patchtrace.sample import sample_diff
from patchtrace.service import ProjectService

OLD_ALLOC = '''void *alloc_items(size_t count, size_t size) {
    size_t total = count * size;
    void *p = ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'tag1');
    memcpy(p, src, total);
    return p;
}'''
NEW_ALLOC = '''void *alloc_items(size_t count, size_t size) {
    if (size != 0 && 0xffffffff / count < size) {
        return NULL;
    }
    size_t total = count * size;
    void *p = ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'tag1');
    memcpy(p, src, total);
    return p;
}'''


def _function(name: str, address: str, code: str) -> dict:
    return {'name': name, 'fullname': name, 'address': address, 'code': code, 'calling': [], 'called': [],
            'instructions': -1, 'sig': f'void {name}(...)', 'sym_type': 'FUNCTION', 'external': False}


def two_cve_diff(project) -> dict:
    diff = sample_diff(project)
    diff['functions']['modified'].append({
        'old': _function('alloc_items', '180001800', OLD_ALLOC), 'new': _function('alloc_items', '180001880', NEW_ALLOC),
        'diff_type': ['code', 'address'], 'ratio': 0.7, 'match_types': ['Symbols']})
    diff['stats']['modified_funcs_len'] = 3
    return diff


def apply_diff(project_dir: Path, scratch: Path) -> None:
    service = ProjectService.open(project_dir, maintenance=False)
    try:
        raw = scratch / 'two-cve.ghidriff.json'
        raw.write_text(json.dumps(two_cve_diff(service.project)), encoding='utf-8')
        service.apply_analysis(raw, AnalysisRun(status='completed', backend='synthetic-sample', backend_version='1',
                                                settings={'synthetic': True}))
    finally:
        service.close()


def attached_project(kb: Kb, root: Path, *, load: tuple[str, ...] = (BASELINE,)) -> Path:
    """Import the documents, search KB5099001 and import the pair; returns the project directory (no run yet)."""
    kb.loaded(*load)
    code, doc = kb.search('KB5099001')
    assert code == 0
    older, newer = write_pair(root)
    project = root / 'P'
    code, _, _ = kb('import-pair', doc['result']['investigation_id'], '--older', str(older), '--newer', str(newer),
                    '--project', str(project))
    assert code == 0
    return project


def analysed_project(kb: Kb, root: Path, capsys, *, rank: bool = True) -> Path:
    project = attached_project(kb, root)
    apply_diff(project, root)
    if rank:
        assert main_cli.main(['rank', str(project)]) == 0
        capsys.readouterr()
    return project
