"""R1: an ambiguous source/body cross-check cannot verify an unchanged control.

These are hermetic evidence-record tests, not compiler or matching-engine acceptance.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r.build import BuildResult, BuildSpec  # noqa: E402
from tools.calibration.tier_r.debuginfo import ImageFunction, Inventory  # noqa: E402
from tools.calibration.tier_r.labeler import SideData, label_diff  # noqa: E402


def side(root: Path, source: str, body: str) -> SideData:
    root.mkdir()
    (root / 'f.c').write_text(source, encoding='utf-8')
    build = BuildResult(
        spec=BuildSpec('r1-control', root, ('f.c',), 'control.dll'),
        recipe_digest='0' * 64, debug_image=root / 'debug.dll', engine_image=root / 'engine.dll', pdb=None,
        sha256='1' * 64, debug_sha256='2' * 64, pdb_sha256=None, size=512, image_base=0x180000000,
        compiler='synthetic-evidence', compiler_version='none', source_digest='3' * 64,
    )
    function = ImageFunction('f', 'f.c', 'f.c', 1, 0x1000, 8, None, 'f.c', 'project')
    return SideData(build, Inventory(functions=[function]), {0x1000: (body, body)}, root)


@pytest.mark.parametrize(('new_source', 'new_body', 'reason'), [
    ('int f(void) { return 1; }', 'different', 'source span unchanged but code differs'),
    ('int f(void) { return 2; }', 'original', 'source changed but code identical'),
], ids=['induced-code-change', 'optimized-away-source-change'])
def test_ambiguous_unchanged_control_is_unchecked(tmp_path, new_source, new_body, reason):
    old = side(tmp_path / 'old', 'int f(void) { return 1; }', 'original')
    new = side(tmp_path / 'new', new_source, new_body)

    records = label_diff(old, new, label_source='source-diff', declared_unchanged=('f',))

    assert len(records) == 1
    assert records[0]['label'] == 'ambiguous'
    assert records[0]['check'] == 'unchecked'
    assert reason in records[0]['notes']


@pytest.mark.parametrize(('new_source', 'new_body', 'label', 'check'), [
    ('int f(void) { return 1; }', 'original', 'unchanged', 'ok'),
    ('int f(void) { /* comment */ return 1; }', 'original', 'cosmetic', 'ok'),
    ('int f(void) { return 2; }', 'different', 'changed', 'disagree'),
], ids=['verified-unchanged', 'verified-cosmetic', 'conflicting-material-change'])
def test_decisive_unchanged_control_checks_are_preserved(tmp_path, new_source, new_body, label, check):
    old = side(tmp_path / 'old', 'int f(void) { return 1; }', 'original')
    new = side(tmp_path / 'new', new_source, new_body)

    record, = label_diff(old, new, label_source='source-diff', declared_unchanged=('f',))

    assert (record['label'], record['check']) == (label, check)
