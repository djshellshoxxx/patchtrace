"""Session cache provenance regressions: synthetic build receipts; no compiler or target execution."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r.build import BuildResult, BuildSpec
from tools.calibration.tier_r.debuginfo import Inventory
from tools.calibration.tier_r.labeler import SideData
from tools.calibration.tier_r.toolchain import Toolchain


def build_result(tmp_path):
    return BuildResult(
        spec=BuildSpec(project='cache-unit', source_root=tmp_path / 'source', files=('unit.c',),
                       output='unit.dll', opt='O2', variant='first'),
        recipe_digest='a' * 64, debug_image=tmp_path / 'debug.dll', engine_image=tmp_path / 'engine.dll',
        pdb=None, sha256='b' * 64, debug_sha256='c' * 64, pdb_sha256=None, size=1024,
        image_base=0x180000000, compiler='synthetic', compiler_version='unit-only', source_digest='d' * 64)


@pytest.mark.parametrize('change', ['opt', 'variant', 'source-root', 'source-digest', 'recipe-digest'])
def test_equal_debug_bytes_do_not_reuse_another_builds_provenance(tmp_path, monkeypatch, change):
    """An artifact-only key returns O2/source-A provenance when the caller requested another build context."""
    first = build_result(tmp_path)
    second = first
    old_root = first.spec.source_root
    new_root = old_root
    if change == 'opt':
        second = replace(first, spec=replace(first.spec, opt='O3'))
    elif change == 'variant':
        second = replace(first, spec=replace(first.spec, variant='second'))
    elif change == 'source-root':
        new_root = tmp_path / 'other-source'
    elif change == 'source-digest':
        second = replace(first, source_digest='e' * 64)
    else:
        second = replace(first, recipe_digest='f' * 64)

    def analyze(result, tools, source_root):
        return SideData(result, Inventory(), {}, Path(source_root))

    monkeypatch.setattr(F, 'analyze', analyze)
    session = F.Session(Toolchain(), tmp_path / 'store')
    before = session.side(first, old_root)
    after = session.side(second, new_root)
    assert after is not before
    assert after.build == second
    assert after.source_root == new_root
    assert before.build == first and before.source_root == old_root


def test_equal_build_and_resolved_source_context_reuses_cached_analysis(tmp_path, monkeypatch):
    """Adding provenance to the key must retain reuse for semantically equal requests."""
    first = build_result(tmp_path)

    def analyze(result, tools, source_root):
        return SideData(result, Inventory(), {}, Path(source_root))

    monkeypatch.setattr(F, 'analyze', analyze)
    session = F.Session(Toolchain(), tmp_path / 'store')
    before = session.side(first, first.spec.source_root)
    after = session.side(replace(first), first.spec.source_root / 'child' / '..')
    assert after is before
